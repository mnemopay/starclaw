import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RouteRequest {
  rawBody: Buffer;
  headers: http.IncomingHttpHeaders;
}
export interface RouteResponse {
  status: number;
  /** JSON-serialised unless a string is given. */
  body?: unknown;
}
export interface ChannelRoute {
  path: string;
  /** Must verify the request signature itself before trusting anything in the body. Must not throw secrets. */
  handle(req: RouteRequest): Promise<RouteResponse>;
  /** Optional GET handler (only WhatsApp's one-time webhook verification uses it). Routes without it stay POST-only. */
  get?(query: URLSearchParams): Promise<RouteResponse>;
}

/**
 * The webhook listener for Slack and Discord. Loopback only: it is bound to 127.0.0.1 and there is no option to change
 * that. Slack/Discord can only reach it through a tunnel or reverse proxy that YOU run; that proxy is then the exposed
 * surface and the signature checks in the routes are what authenticate callers. POST only, a hard body cap, short
 * timeouts, and no request detail is ever echoed or logged.
 */
export function createChannelServer(o: { routes: ChannelRoute[]; maxBodyBytes: number; log?: (s: string) => void }): http.Server {
  const routes = new Map(o.routes.map((r) => [r.path, r]));
  const log = o.log ?? (() => {});
  const server = http.createServer((req, res) => {
    const send = (status: number, body?: unknown) => {
      if (res.headersSent || res.writableEnded) return;
      const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
      res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      res.end(text);
    };
    const [path, qs = ''] = (req.url ?? '').split('?', 2);
    const route = routes.get(path);
    if (!route) return send(404, { error: 'not found' });
    if (req.method === 'GET' && route.get) {
      if (qs.length > 2000) return send(414, { error: 'too long' });
      route
        .get(new URLSearchParams(qs))
        .then((r) => send(r.status, r.body))
        .catch(() => send(500, { error: 'internal error' }));
      return;
    }
    if (req.method !== 'POST') {
      res.setHeader('allow', route.get ? 'GET, POST' : 'POST');
      return send(405, { error: 'method not allowed' });
    }
    const declared = Number(req.headers['content-length'] ?? '0');
    if (Number.isFinite(declared) && declared > o.maxBodyBytes) {
      send(413, { error: 'too large' });
      req.destroy();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let dead = false;
    req.on('data', (c: Buffer) => {
      if (dead) return;
      size += c.length;
      if (size > o.maxBodyBytes) {
        dead = true;
        send(413, { error: 'too large' });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('error', () => {
      dead = true;
    });
    req.on('end', () => {
      if (dead) return;
      route
        .handle({ rawBody: Buffer.concat(chunks), headers: req.headers })
        .then((r) => send(r.status, r.body))
        .catch((e) => {
          log(`channel route ${path} failed: ${String(e?.message ?? e).slice(0, 200)}`);
          send(500, { error: 'internal error' });
        });
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  return server;
}

/** Listen on 127.0.0.1 only. `port` 0 picks a free port (tests). */
export function listenLoopback(server: http.Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve((server.address() as AddressInfo).port);
    });
  });
}

export function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}
