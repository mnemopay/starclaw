import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { buildArticle12Bundle, MerkleAudit, type Article12Bundle, type AuditEvent, type Charter, type MissionResult } from '@mnemopay/sdk';
import { verifyAuditFile, type AuditRecord, type VerifyResult } from './audit';

/**
 * EU AI Act Article 12 export of a StarClaw audit log, built with MnemoPay's bundle writer.
 *
 * The StarClaw log stays the record of truth: it is verified first (chain, Ed25519 signatures, head checkpoint) and
 * the export is refused if that fails. Each event in the bundle keeps the original record's seq/prev/hash/sig, and
 * event 0 is the log's `audit.open` carrying the public key, so a reader can re-check the signatures from the bundle
 * alone. The MnemoPay chain (chain.txt) is a second hash chain over those events, rebuilt here with the ORIGINAL
 * timestamps (MerkleAudit.record() would stamp the export time instead).
 */
export interface Article12ExportOptions {
  pinnedPublicKeyHex?: string;
  allowMissingHead?: boolean;
  operatorId?: string;
  retentionMonths?: number;
  /** Charter budget cap to state in mission.json. The log does not record the policy, so 0 unless given. */
  budgetMaxUsd?: number;
  name?: string;
}

export interface Article12Export {
  bundle: Article12Bundle;
  verification: VerifyResult;
  events: number;
}

export function exportArticle12(file: string, opts: Article12ExportOptions = {}): Article12Export {
  const verification = verifyAuditFile(file, { pinnedPublicKeyHex: opts.pinnedPublicKeyHex, allowMissingHead: opts.allowMissingHead });
  if (!verification.ok) {
    throw new Error(`audit log failed verification, refusing to export: ${verification.errors.map((e) => `line ${e.line}: ${e.reason}`).join('; ')}`);
  }
  const records: AuditRecord[] = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  if (records.length !== verification.records) throw new Error('audit log changed while it was being exported');

  const events: AuditEvent[] = [];
  const chain: string[] = [];
  let prev = '';
  for (const r of records) {
    // Same key order and hashing as MerkleAudit.record(): sha256(prevChainHash + JSON.stringify({ ts, type, data })).
    const ev: AuditEvent = { ts: r.ts, type: r.type, data: { payload: r.data, starclaw: { seq: r.seq, prev: r.prev, hash: r.hash, sig: r.sig } } };
    prev = createHash('sha256').update(prev).update(JSON.stringify(ev)).digest('hex');
    events.push(ev);
    chain.push(prev);
  }
  const audit = MerkleAudit.fromJSON({ events, chain });
  if (!audit.verify()) throw new Error('internal error: rebuilt MnemoPay chain does not verify');

  let microcents = 0;
  for (const r of records) if (r.type === 'llm.usage' && typeof r.data.microcents === 'number') microcents += r.data.microcents;
  const name = opts.name ?? 'starclaw';
  const charter: Charter = {
    name,
    goal: `StarClaw agent audit log (${records.length} records, key ${verification.keyPinned ? 'pinned' : 'taken from the log'})`,
    budget: { maxUsd: opts.budgetMaxUsd ?? 0, approvalThresholdUsd: 0 },
    agents: [],
    outputs: [],
  };
  const result: MissionResult = {
    charterName: name,
    status: records.some((r) => r.type === 'goal.failed') ? 'error' : 'ok',
    // LLM spend only (llm.usage microcents); payments made through the spend authority are not included.
    spentUsd: microcents / 100_000_000,
    outputs: [],
    auditDigest: verification.lastHash,
    startedAt: records[0].ts,
    finishedAt: records[records.length - 1].ts,
  };
  const bundle = buildArticle12Bundle({ charter, result, audit, retentionMonths: opts.retentionMonths, operatorId: opts.operatorId });
  return { bundle, verification, events: events.length };
}
