/**
 * Client for the MnemoPay Native Browser control API (`mnemopay-control/v1`), reimplemented here so StarClaw has no
 * dependency on the browser repo. Zero dependencies beyond node:http.
 *
 * Properties this file is responsible for:
 *  - the bearer token lives in one private field and is never part of a message, a JSON dump or an inspect() view;
 *  - any text that leaves this module (errors, server messages) is scrubbed of the token;
 *  - only literal loopback over plain http is ever contacted, redirects are never followed;
 *  - node:http, not fetch: undici adds `Sec-Fetch-Mode`, which the control API treats as a web page calling it.
 */
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export const CONTROL_API_VERSION = 'mnemopay-control/v1';
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const CLIENT_REF_RE = /^[A-Za-z0-9._-]{1,64}$/;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export class ControlError extends Error {
  constructor(
    message: string,
    public readonly info: { code?: string; status?: number; retryable?: boolean; details?: unknown; receipt?: unknown; requestId?: string; /** the server answered (so page-derived text may be in the message) */ answered?: boolean } = {},
  ) {
    super(message);
    this.name = 'ControlError';
  }
  get code() {
    return this.info.code ?? 'client_error';
  }
  get status() {
    return this.info.status ?? 0;
  }
}

/** Where the browser writes its address and token on this OS (same rules as the browser's own Node client). */
export function defaultDiscoveryPath(env: NodeJS.ProcessEnv = process.env, platform: string = process.platform): string {
  if (env.MNEMOPAY_CONTROL_DISCOVERY) return env.MNEMOPAY_CONTROL_DISCOVERY;
  if (platform === 'win32') return path.join(env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'MnemoPayBrowser', 'control.json');
  if (platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'MnemoPayBrowser', 'control.json');
  return path.join(env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'MnemoPayBrowser', 'control.json');
}

/** Only literal loopback over plain http, with an explicit port, no credentials. Returns the normalised origin. */
export function assertLoopbackUrl(raw: unknown): string {
  let u: URL;
  try {
    u = new URL(String(raw));
  } catch {
    throw new ControlError('invalid control url');
  }
  if (u.protocol !== 'http:') throw new ControlError('control url must be http on loopback');
  if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') throw new ControlError('control url must be 127.0.0.1 or localhost');
  if (!u.port) throw new ControlError('control url must include the port');
  if (u.username || u.password) throw new ControlError('control url must not carry credentials');
  return `http://${u.hostname}:${u.port}`;
}

export interface Discovery {
  url: string;
  token: string;
}

/** Read and validate the discovery file. Fails closed with a message that never contains file contents. */
export function readDiscovery(file: string = defaultDiscoveryPath()): Discovery {
  let doc: any;
  try {
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    throw new ControlError('the browser control API is not available: no readable discovery file (is the MnemoPay browser running with MNEMOPAY_CONTROL_API=1?)', { code: 'unavailable' });
  }
  if (!doc || typeof doc !== 'object') throw new ControlError('the browser discovery file is malformed', { code: 'unavailable' });
  if (doc.api !== CONTROL_API_VERSION) throw new ControlError(`unsupported browser control api version: ${String(doc.api).slice(0, 40)}`, { code: 'unavailable' });
  if (typeof doc.token !== 'string' || !TOKEN_RE.test(doc.token)) throw new ControlError('the browser discovery file carries no valid token', { code: 'unavailable' });
  return { url: assertLoopbackUrl(doc.url), token: doc.token };
}

function rawRequest(url: string, method: string, headers: Record<string, string>, payload: string | undefined, timeoutMs: number): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (size > MAX_RESPONSE_BYTES) {
          req.destroy(new Error('response too large'));
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.setTimeout(timeoutMs, () => req.destroy(Object.assign(new Error('timed out'), { code: 'ETIMEDOUT_CLIENT' })));
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

export interface Envelope {
  budget_cents: number;
  max_actions: number;
  allowed_domains: string[];
  ttl_seconds?: number;
  action_cost_cents?: number;
}

export interface ControlOk {
  ok: true;
  api: string;
  request_id?: string;
  tab_id?: string;
  untrusted?: boolean;
  data?: any;
  receipt?: unknown;
}

export class ControlClient {
  readonly #token: string;
  readonly #base: string;
  readonly #timeoutMs: number;

  constructor(d: Discovery, opts: { timeoutMs?: number } = {}) {
    if (typeof d.token !== 'string' || !TOKEN_RE.test(d.token)) throw new ControlError('a valid control token is required');
    this.#base = assertLoopbackUrl(d.url);
    this.#token = d.token;
    this.#timeoutMs = opts.timeoutMs ?? 70_000;
  }

  /** Never let the token leak through logging or serialisation. */
  toJSON() {
    return { url: this.#base, token: '[redacted]' };
  }
  [Symbol.for('nodejs.util.inspect.custom')]() {
    return `ControlClient { url: '${this.#base}', token: [redacted] }`;
  }

  /** Remove the token from any string (defence in depth: a server or a network error could echo it). */
  scrub(s: string): string {
    return s.split(this.#token).join('[REDACTED]');
  }

  async #call(method: string, p: string, body?: unknown, clientRef?: string): Promise<ControlOk> {
    if (clientRef !== undefined && !CLIENT_REF_RE.test(clientRef)) throw new ControlError('clientRef must be 1-64 chars of [A-Za-z0-9._-]');
    const headers: Record<string, string> = { authorization: `Bearer ${this.#token}`, accept: 'application/json' };
    if (clientRef) headers['x-client-ref'] = clientRef;
    let payload: string | undefined;
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    let res: { status: number; text: string };
    try {
      res = await rawRequest(this.#base + p, method, headers, payload, this.#timeoutMs);
    } catch (e: any) {
      throw new ControlError(`browser control api unreachable: ${e?.code === 'ETIMEDOUT_CLIENT' ? 'timed out' : 'connection failed'}`, { code: 'unreachable', retryable: true });
    }
    if (res.status >= 300 && res.status < 400) throw new ControlError('browser control api answered with a redirect; refusing to follow', { code: 'redirect', status: res.status, answered: true });
    let json: any;
    try {
      json = JSON.parse(res.text);
    } catch {
      throw new ControlError('browser control api returned a non-JSON response', { code: 'bad_response', status: res.status, answered: true });
    }
    if (json?.api !== CONTROL_API_VERSION) throw new ControlError('unexpected api version in browser control response', { code: 'bad_response', status: res.status, answered: true });
    if (!json.ok) {
      const e = json.error ?? {};
      throw new ControlError(this.scrub(String(e.message ?? 'request failed')).slice(0, 300), {
        code: typeof e.code === 'string' ? this.scrub(e.code).slice(0, 60) : 'error',
        status: res.status,
        retryable: !!e.retryable,
        details: undefined, // server-provided details are not propagated (they could be page-derived)
        receipt: json.receipt,
        requestId: typeof json.request_id === 'string' ? json.request_id.slice(0, 80) : undefined,
        answered: true,
      });
    }
    return json as ControlOk;
  }

  async health(): Promise<any> {
    return (await this.#call('GET', '/v1/health')).data;
  }
  openTab(url: string, envelope: Envelope, clientRef?: string) {
    return this.#call('POST', '/v1/tabs', { url, envelope }, clientRef);
  }
  private tabPath(id: string, verb = '') {
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(id)) throw new ControlError('the browser returned an unusable tab id');
    return `/v1/tabs/${encodeURIComponent(id)}${verb}`;
  }
  navigate(id: string, url: string, clientRef?: string) {
    return this.#call('POST', this.tabPath(id, '/navigate'), { url }, clientRef);
  }
  readText(id: string, maxBytes: number, clientRef?: string) {
    return this.#call('POST', this.tabPath(id, '/read_text'), { max_bytes: maxBytes }, clientRef);
  }
  readLinks(id: string, maxLinks: number, clientRef?: string) {
    return this.#call('POST', this.tabPath(id, '/read_links'), { max_links: maxLinks }, clientRef);
  }
  tabStatus(id: string) {
    return this.#call('GET', this.tabPath(id));
  }
  closeTab(id: string, clientRef?: string) {
    return this.#call('DELETE', this.tabPath(id), undefined, clientRef);
  }
}
