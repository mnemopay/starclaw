import { redactString } from '../governance/canonical';

export class LlmError extends Error {
  constructor(
    msg: string,
    public readonly kind: 'http' | 'rate-limit' | 'malformed' | 'too-large' | 'network' | 'config',
    public readonly status?: number,
    public readonly retryAfterSeconds?: number,
  ) {
    super(msg);
    this.name = 'LlmError';
  }
}

export interface PostJsonOptions {
  url: string;
  headers: Record<string, string>;
  body: unknown;
  timeoutMs: number;
  maxResponseBytes: number;
  /** Secrets that must never appear in an error message (the API key). */
  secrets?: string[];
  fetchImpl?: typeof fetch;
}

/** Remove known secrets and well-known key shapes from text that may be shown or logged. */
export function scrub(text: string, secrets: string[] = []): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 6) out = out.split(s).join('[REDACTED]');
  return redactString(out);
}

/** http is only allowed to loopback (local model servers); anything else must be https so keys never travel in clear. */
export function assertSafeBaseUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new LlmError('llm.baseUrl is not a valid URL', 'config');
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) throw new LlmError('llm.baseUrl must be https (plain http is only allowed for localhost / 127.0.0.1 / ::1)', 'config');
  if (u.username || u.password) throw new LlmError('llm.baseUrl must not contain credentials', 'config');
  return u;
}

/** POST JSON, read at most maxResponseBytes, parse JSON. Never throws a message containing the API key. */
export async function postJson(o: PostJsonOptions): Promise<any> {
  const f = o.fetchImpl ?? fetch;
  let res: Response;
  try {
    res = await f(o.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...o.headers },
      body: JSON.stringify(o.body),
      signal: AbortSignal.timeout(o.timeoutMs),
      redirect: 'error', // never follow a redirect with credentials attached
    });
  } catch (e: any) {
    throw new LlmError(`LLM request failed: ${scrub(String(e?.cause?.code ?? e?.message ?? e), o.secrets)}`, 'network');
  }
  // Bounded read: a hostile or broken server cannot make us buffer an unbounded body.
  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > o.maxResponseBytes) {
        await reader.cancel().catch(() => {});
        throw new LlmError(`LLM response exceeds ${o.maxResponseBytes} bytes`, 'too-large', res.status);
      }
      chunks.push(value);
    }
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (res.status === 429) {
    const ra = Number(res.headers.get('retry-after'));
    throw new LlmError('LLM provider rate limit (HTTP 429)', 'rate-limit', 429, Number.isFinite(ra) && ra >= 0 ? Math.min(ra, 3600) : undefined);
  }
  if (!res.ok) throw new LlmError(`LLM provider returned HTTP ${res.status}: ${scrub(text.slice(0, 300), o.secrets)}`, 'http', res.status);
  try {
    return JSON.parse(text);
  } catch {
    throw new LlmError('LLM provider returned malformed JSON', 'malformed', res.status);
  }
}
