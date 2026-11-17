import { createHash } from 'node:crypto';

/** Deterministic JSON: object keys sorted, no whitespace. Used for everything that is hashed or signed. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('canonicalize: non-finite number');
    return JSON.stringify(value === undefined ? null : value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

const SECRET_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{16,}/g,
  /\bgsk_[A-Za-z0-9]{16,}/g,
  /\bghp_[A-Za-z0-9]{20,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/g, // Telegram bot token shape
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, // Slack bot/user/app tokens
  /\bxapp-[A-Za-z0-9-]{10,}/g, // Slack app-level token
  /\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/g, // Discord bot token shape
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/gi,
  /\bBSA[A-Za-z0-9_-]{20,}/g, // Brave Search API key shape
  /\bAIza[0-9A-Za-z_-]{30,}/g, // Google API key shape
  /\b(x-api-key|x-subscription-token|api[_-]?key|apikey|authorization)(["'\s]*[:=]["'\s]*)(?!\[REDACTED\])[A-Za-z0-9._~+/=-]{12,}/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

/** Best-effort redaction of well-known secret shapes. NOT a guarantee: unknown formats pass through. */
export function redactString(s: string): string {
  let out = s;
  for (const re of SECRET_PATTERNS) out = out.replace(re, '[REDACTED]');
  return out;
}

export function redactDeep<T>(v: T): T {
  if (typeof v === 'string') return redactString(v) as unknown as T;
  if (Array.isArray(v)) return v.map(redactDeep) as unknown as T;
  if (v && typeof v === 'object') {
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) o[k] = redactDeep(val);
    return o as T;
  }
  return v;
}
