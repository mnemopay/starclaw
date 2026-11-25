import { createHash } from 'node:crypto';
import { canonicalize, sha256Hex, verifyBundle, type ChainBundle } from '@mnemopay/sdk/governance/audit-chain';
import type { AuditRecord, VerifyResult } from './audit';

/**
 * MnemoPay AuditChain `ChainBundle` v1 view of a StarClaw audit log — the format `verifyBundle` from @mnemopay/sdk
 * recomputes a `merkle_root` for, and the one on-chain anchoring sinks (e.g. AgentAudit's AuditVault sink) take.
 *
 * The StarClaw log stays the record of truth; this is an export. It is deterministic: the same verified log always
 * gives byte-identical output. AuditChain.emit() would stamp a random id and the export time, so events are built
 * here instead: id derived from the record hash, sequence = the record's seq, occurred_at = the record's ts, and the
 * original seq/prev/hash/sig carried in the payload so the Ed25519 signatures can still be checked from the bundle.
 * The root is rolled with the SDK's own canonicalize/sha256Hex, and the bundle is refused unless the SDK's
 * verifyBundle accepts it.
 */
export const CHAIN_BUNDLE_FORMAT = 'starclaw-chainbundle/1';

export interface ChainBundleMeta extends Record<string, unknown> {
  format: typeof CHAIN_BUNDLE_FORMAT;
  source: 'starclaw';
  log_records: number;
  log_first_seq: number;
  log_last_hash: string;
  public_key_hex: string | null;
  key_pinned: boolean;
  /**
   * Number of events in this bundle (= `events.length` = `log_records`). Added in 2.0.0-alpha.15 so anchoring sinks
   * (e.g. AgentAudit's) can record the event count without walking `events`. It is in `meta` only, so it changes the
   * file's sha256 but not `merkle_root` (leaves are the events). Fixture v1 predates it and is frozen; see v2.
   */
  event_count: number;
  /** sha256 of the Article 12 bundle written alongside, when there is one. */
  article12_bundle_sha256?: string;
}

/** UUID-shaped id derived from the record hash (stable across exports; not random). */
export function eventIdFor(record: AuditRecord): string {
  const h = createHash('sha256').update(`starclaw:${record.hash}`).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function rollRoot(events: ChainBundle['events']): string {
  if (events.length === 0) return '';
  let layer = events.map((e) => sha256Hex(canonicalize(e)));
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) next.push(sha256Hex(layer[i] + (layer[i + 1] ?? layer[i])));
    layer = next;
  }
  return layer[0];
}

export function buildChainBundle(
  records: AuditRecord[],
  verification: VerifyResult,
  extra: { article12BundleSha256?: string } = {},
): ChainBundle<ChainBundleMeta> {
  if (!verification.ok) throw new Error('audit log failed verification, refusing to build a chain bundle');
  if (records.length === 0) throw new Error('audit log is empty');
  const events = records.map((r) => ({
    id: eventIdFor(r),
    sequence: r.seq,
    occurred_at: r.ts,
    kind: r.type,
    payload: { data: r.data, starclaw: { seq: r.seq, prev: r.prev, hash: r.hash, sig: r.sig } },
  }));
  const meta: ChainBundleMeta = {
    format: CHAIN_BUNDLE_FORMAT,
    source: 'starclaw',
    log_records: records.length,
    log_first_seq: records[0].seq,
    log_last_hash: verification.lastHash,
    public_key_hex: verification.publicKeyHex ?? null,
    key_pinned: verification.keyPinned,
    event_count: records.length,
    ...(extra.article12BundleSha256 ? { article12_bundle_sha256: extra.article12BundleSha256 } : {}),
  };
  // built_at = the last record's timestamp, so the same log always gives the same bytes.
  const bundle: ChainBundle<ChainBundleMeta> = { version: 1, built_at: records[records.length - 1].ts, meta, events, merkle_root: rollRoot(events) };
  const check = verifyBundle(bundle);
  if (!check.ok) throw new Error(`internal error: chain bundle does not verify (${check.reason})`);
  return bundle;
}

/** Bytes written to chain-bundle.json: pretty JSON + newline, LF only. */
export function serializeChainBundle(bundle: ChainBundle<ChainBundleMeta>): string {
  return JSON.stringify(bundle, null, 2) + '\n';
}
