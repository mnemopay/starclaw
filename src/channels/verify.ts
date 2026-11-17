import { createHmac, createPublicKey, timingSafeEqual, verify as edVerify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/** Why a signed request was refused. Only ever logged as a bare reason code: never the body, headers or secret. */
export type VerifyFailure = 'missing' | 'malformed' | 'stale' | 'bad-signature' | 'replay';
export type VerifyResult = { ok: true } | { ok: false; reason: VerifyFailure };

const FAIL = (reason: VerifyFailure): VerifyResult => ({ ok: false, reason });

function checkTimestamp(ts: string | undefined, nowMs: number, toleranceSec: number): VerifyResult | { ts: string } {
  if (ts === undefined || ts === '') return FAIL('missing');
  if (!/^\d{9,12}$/.test(ts)) return FAIL('malformed');
  if (Math.abs(nowMs / 1000 - Number(ts)) > toleranceSec) return FAIL('stale');
  return { ts };
}

/**
 * Slack request signing: v0=hex(HMAC-SHA256(signingSecret, "v0:" + timestamp + ":" + rawBody)), compared in constant time,
 * and the timestamp must be within `toleranceSec` of now (either direction). Must be given the RAW body bytes.
 */
export function verifySlackSignature(o: {
  signingSecret: string;
  timestamp: string | undefined;
  signature: string | undefined;
  rawBody: Buffer;
  nowMs: number;
  toleranceSec: number;
}): VerifyResult {
  if (!o.signingSecret) return FAIL('bad-signature'); // fail closed: never "verify" with an empty secret
  const t = checkTimestamp(o.timestamp, o.nowMs, o.toleranceSec);
  if (!('ts' in t)) return t;
  if (o.signature === undefined || o.signature === '') return FAIL('missing');
  if (!/^v0=[0-9a-f]{64}$/.test(o.signature)) return FAIL('malformed');
  const mac = createHmac('sha256', o.signingSecret).update(`v0:${t.ts}:`).update(o.rawBody).digest();
  const given = Buffer.from(o.signature.slice(3), 'hex');
  return given.length === mac.length && timingSafeEqual(given, mac) ? { ok: true } : FAIL('bad-signature');
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Build a verification key from the 32-byte hex public key Discord shows in the developer portal. Throws on a malformed key. */
export function discordPublicKey(hex: string): KeyObject {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('the Discord public key must be 64 hex characters');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
}

/** Discord interactions: Ed25519 over (X-Signature-Timestamp + rawBody) with X-Signature-Ed25519, plus the same freshness window. */
export function verifyDiscordSignature(o: {
  publicKey: KeyObject;
  timestamp: string | undefined;
  signature: string | undefined;
  rawBody: Buffer;
  nowMs: number;
  toleranceSec: number;
}): VerifyResult {
  const t = checkTimestamp(o.timestamp, o.nowMs, o.toleranceSec);
  if (!('ts' in t)) return t;
  if (o.signature === undefined || o.signature === '') return FAIL('missing');
  if (!/^[0-9a-fA-F]{128}$/.test(o.signature)) return FAIL('malformed');
  try {
    const ok = edVerify(null, Buffer.concat([Buffer.from(t.ts, 'utf8'), o.rawBody]), o.publicKey, Buffer.from(o.signature, 'hex'));
    return ok ? { ok: true } : FAIL('bad-signature');
  } catch {
    return FAIL('bad-signature');
  }
}

/**
 * Remembers signatures that already verified, for as long as they could still pass the timestamp check, so a captured
 * request cannot be replayed inside the freshness window. Only entries that PASSED verification are stored, so an
 * attacker cannot fill it with junk; the size cap evicts the oldest.
 */
export class ReplayGuard {
  private seen = new Map<string, number>();
  constructor(private readonly ttlMs: number, private readonly maxEntries = 10_000) {}

  /** True if `key` was already accepted (a replay). Otherwise records it and returns false. */
  isReplay(key: string, nowMs = Date.now()): boolean {
    for (const [k, exp] of this.seen) {
      if (exp > nowMs) break; // insertion order = expiry order
      this.seen.delete(k);
    }
    if (this.seen.has(key)) return true;
    this.seen.set(key, nowMs + this.ttlMs);
    while (this.seen.size > this.maxEntries) this.seen.delete(this.seen.keys().next().value as string);
    return false;
  }
  get size() {
    return this.seen.size;
  }
}

/** Bounded set of ids already processed (Slack event ids: Slack redelivers events it thinks were not acknowledged). */
export class SeenIds {
  private ids = new Map<string, number>();
  constructor(private readonly ttlMs = 600_000, private readonly maxEntries = 5000) {}
  firstTime(id: string, nowMs = Date.now()): boolean {
    for (const [k, exp] of this.ids) {
      if (exp > nowMs) break;
      this.ids.delete(k);
    }
    if (this.ids.has(id)) return false;
    this.ids.set(id, nowMs + this.ttlMs);
    while (this.ids.size > this.maxEntries) this.ids.delete(this.ids.keys().next().value as string);
    return true;
  }
}
