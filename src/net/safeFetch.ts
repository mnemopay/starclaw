import * as dns from 'node:dns';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';

export interface SafeFetchOptions {
  allowPrivateAddresses: boolean;
  maxBytes: number;
  timeoutMs: number;
}
export interface SafeFetchResponse {
  status: number;
  headers: Record<string, string>;
  /** Present for 3xx with a Location header (NOT followed here: the caller re-authorizes each hop). */
  redirectTo?: string;
  body: string;
  truncated: boolean;
  remoteAddress?: string;
}

export function isPrivateAddress(addr: string): boolean {
  const v = net.isIP(addr);
  if (v === 4) {
    const [a, b] = addr.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224
    );
  }
  if (v === 6) {
    const l = addr.toLowerCase();
    if (l === '::' || l === '::1') return true;
    if (l.startsWith('::ffff:')) {
      const rest = l.slice(7);
      if (net.isIP(rest) === 4) return isPrivateAddress(rest);
      return true; // hex form of a mapped address: refuse rather than parse
    }
    return l.startsWith('fc') || l.startsWith('fd') || /^fe[89ab]/.test(l) || l.startsWith('ff') || l.startsWith('2001:db8');
  }
  return true; // not an IP: refuse
}

/** The hostname/URL checks that do not need DNS. Throws with a reason. */
export function parseHttpUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('invalid URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`protocol ${u.protocol} is not allowed (http/https only)`);
  if (u.username || u.password) throw new Error('URLs with embedded credentials are not allowed');
  return u;
}

/**
 * GET with: scheme allow-list, SSRF guard applied to the address actually connected to (checked inside the
 * socket `lookup`, so DNS rebinding cannot swap it afterwards), size and time caps, no automatic redirects,
 * and no cookies/auth headers. Body is decoded as UTF-8 text.
 */
export function safeGet(rawUrl: string, opts: SafeFetchOptions): Promise<SafeFetchResponse> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = parseHttpUrl(rawUrl);
    } catch (e) {
      return reject(e);
    }
    // IP-literal hosts never go through socket lookup(), so they must be checked here.
    const literal = u.hostname.replace(/^\[/, '').replace(/\]$/, '');
    if (!opts.allowPrivateAddresses && net.isIP(literal) && isPrivateAddress(literal)) {
      return reject(Object.assign(new Error(`blocked: ${literal} is a private/loopback address`), { code: 'ERR_SSRF_BLOCKED' }));
    }
    const lookup = (hostname: string, options: any, cb: any) => {
      dns.lookup(hostname, { ...options, all: true }, (err, addrs: any) => {
        const list: Array<{ address: string; family: number }> = Array.isArray(addrs) ? addrs : [];
        if (err) return cb(err);
        if (!opts.allowPrivateAddresses) {
          const bad = list.find((a) => isPrivateAddress(a.address));
          if (bad) return cb(Object.assign(new Error(`blocked: ${hostname} resolves to private/loopback address ${bad.address}`), { code: 'ERR_SSRF_BLOCKED' }));
        }
        if (options && options.all) return cb(null, list);
        cb(null, list[0].address, list[0].family);
      });
    };
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(
      u,
      { method: 'GET', lookup: lookup as any, headers: { 'user-agent': 'starclaw/2', accept: 'text/*, application/json;q=0.9, */*;q=0.1', 'accept-encoding': 'identity' }, timeout: opts.timeoutMs },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        res.on('data', (c: Buffer) => {
          if (size >= opts.maxBytes) return;
          const room = opts.maxBytes - size;
          if (c.length > room) {
            chunks.push(c.subarray(0, room));
            size += room;
            truncated = true;
            res.destroy();
          } else {
            chunks.push(c);
            size += c.length;
          }
        });
        const done = () => {
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) if (typeof v === 'string') headers[k] = v;
          const status = res.statusCode ?? 0;
          let redirectTo: string | undefined;
          if (status >= 300 && status < 400 && headers.location) {
            try {
              redirectTo = new URL(headers.location, u).toString();
            } catch {
              /* ignore bad location */
            }
          }
          resolve({ status, headers, redirectTo, body: Buffer.concat(chunks).toString('utf8'), truncated, remoteAddress: res.socket?.remoteAddress });
        };
        res.on('end', done);
        res.on('close', () => {
          if (truncated) done();
        });
        res.on('error', (e) => (truncated ? done() : reject(e)));
      },
    );
    req.on('timeout', () => req.destroy(new Error(`request timed out after ${opts.timeoutMs} ms`)));
    req.on('error', reject);
    req.end();
  });
}
