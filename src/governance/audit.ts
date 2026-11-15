import * as fs from 'node:fs';
import { canonicalize, redactDeep, sha256Hex } from './canonical';
import { Signer, Verifier, verifierFromHex, fingerprint } from './signer';

export const GENESIS_PREV = '0'.repeat(64);

export interface AuditRecord {
  v: 1;
  seq: number;
  ts: string;
  prev: string;
  type: string;
  data: Record<string, unknown>;
  hash: string;
  sig: string;
}

interface HeadCheckpoint {
  seq: number;
  hash: string;
  sig: string;
}

function recordBody(r: Pick<AuditRecord, 'v' | 'seq' | 'ts' | 'prev' | 'type' | 'data'>): string {
  return canonicalize({ v: r.v, seq: r.seq, ts: r.ts, prev: r.prev, type: r.type, data: r.data });
}
function headMessage(seq: number, hash: string): string {
  return `starclaw-audit-head:${seq}:${hash}`;
}
export function headPath(logPath: string): string {
  return logPath + '.head';
}

/**
 * Append-only, hash-chained, Ed25519-signed JSONL log.
 *
 * - Each record commits to the previous record's hash (edit/delete/reorder is detected).
 * - Each record hash is signed (forgery without the key is detected).
 * - A signed head checkpoint (`<log>.head`) commits to the latest seq+hash (tail truncation is detected).
 *
 * Limits (see SECURITY.md): someone who can read the signing key can forge everything; someone who
 * can restore an OLD consistent (log, head) pair can roll history back unless the head hash was
 * recorded somewhere else.
 */
export class AuditLog {
  private seq = -1;
  private lastHash = GENESIS_PREV;

  constructor(readonly path: string, private readonly signer: Signer) {
    if (fs.existsSync(path) && fs.statSync(path).size > 0) {
      // Fail closed: refuse to append to a log that does not verify.
      const res = verifyAuditFile(path, { pinnedPublicKeyHex: signer.publicKeyHex });
      if (!res.ok) {
        throw new Error(`Audit log ${path} failed verification, refusing to append: ${res.errors.map((e) => e.reason).join('; ')}`);
      }
      this.seq = res.records - 1;
      this.lastHash = res.lastHash;
    }
    this.append('audit.open', { publicKey: signer.publicKeyHex, fingerprint: fingerprint(signer.publicKeyHex), pid: process.pid });
  }

  append(type: string, data: Record<string, unknown>): AuditRecord {
    const clean = redactDeep(JSON.parse(canonicalize(data)) as Record<string, unknown>);
    const base = { v: 1 as const, seq: this.seq + 1, ts: new Date().toISOString(), prev: this.lastHash, type, data: clean };
    const hash = sha256Hex(recordBody(base));
    const rec: AuditRecord = { ...base, hash, sig: this.signer.sign(hash) };
    fs.appendFileSync(this.path, JSON.stringify(rec) + '\n', { encoding: 'utf8' });
    this.seq = rec.seq;
    this.lastHash = hash;
    this.writeHead(rec);
    return rec;
  }

  private writeHead(rec: AuditRecord) {
    const head: HeadCheckpoint = { seq: rec.seq, hash: rec.hash, sig: this.signer.sign(headMessage(rec.seq, rec.hash)) };
    const p = headPath(this.path);
    const tmp = p + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(head) + '\n');
    fs.renameSync(tmp, p);
  }

  get headHash(): string {
    return this.lastHash;
  }
  get length(): number {
    return this.seq + 1;
  }
}

export interface VerifyOptions {
  /** Hex Ed25519 public key to trust. If omitted, the key embedded in the first record is used (weaker: see SECURITY.md). */
  pinnedPublicKeyHex?: string;
  /** Do not fail when the head checkpoint file is missing (tail truncation then cannot be ruled out). */
  allowMissingHead?: boolean;
}
export interface VerifyError {
  line: number;
  reason: string;
}
export interface VerifyResult {
  ok: boolean;
  records: number;
  lastHash: string;
  errors: VerifyError[];
  warnings: string[];
  publicKeyHex?: string;
  keyPinned: boolean;
  headChecked: boolean;
}

export function verifyAuditFile(file: string, opts: VerifyOptions = {}): VerifyResult {
  const errors: VerifyError[] = [];
  const warnings: string[] = [];
  const res: VerifyResult = { ok: false, records: 0, lastHash: GENESIS_PREV, errors, warnings, keyPinned: !!opts.pinnedPublicKeyHex, headChecked: false };
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e: any) {
    errors.push({ line: 0, reason: `cannot read log: ${e.message}` });
    return res;
  }
  if (text.length === 0) {
    errors.push({ line: 0, reason: 'log is empty' });
    return res;
  }
  if (!text.endsWith('\n')) errors.push({ line: 0, reason: 'log does not end with a newline (partial/truncated last record)' });
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();

  let verifier: Verifier | undefined;
  try {
    verifier = opts.pinnedPublicKeyHex ? verifierFromHex(opts.pinnedPublicKeyHex) : undefined;
  } catch (e: any) {
    errors.push({ line: 0, reason: `invalid pinned public key: ${e.message}` });
    return res;
  }
  let prev = GENESIS_PREV;
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let r: AuditRecord;
    try {
      r = JSON.parse(lines[i]);
    } catch {
      errors.push({ line: lineNo, reason: 'not valid JSON' });
      break;
    }
    const shapeOk =
      r && r.v === 1 && Number.isInteger(r.seq) && typeof r.ts === 'string' && typeof r.prev === 'string' &&
      typeof r.type === 'string' && r.data && typeof r.data === 'object' && typeof r.hash === 'string' && typeof r.sig === 'string';
    if (!shapeOk) {
      errors.push({ line: lineNo, reason: 'malformed record' });
      break;
    }
    if (r.seq !== i) errors.push({ line: lineNo, reason: `sequence mismatch (expected ${i}, found ${r.seq}): record deleted, duplicated or reordered` });
    if (r.prev !== prev) errors.push({ line: lineNo, reason: 'prev-hash does not match previous record: record deleted, inserted or reordered' });
    let recomputed: string;
    try {
      recomputed = sha256Hex(recordBody(r));
    } catch {
      errors.push({ line: lineNo, reason: 'record cannot be canonicalised' });
      break;
    }
    if (recomputed !== r.hash) errors.push({ line: lineNo, reason: 'hash mismatch: record content was modified' });
    if (!verifier) {
      // Unpinned: trust the key declared in the first record (must be an audit.open).
      const pub = r.type === 'audit.open' ? (r.data as any).publicKey : undefined;
      if (typeof pub !== 'string') {
        errors.push({ line: lineNo, reason: 'first record is not an audit.open with a public key' });
        break;
      }
      try {
        verifier = verifierFromHex(pub);
      } catch {
        errors.push({ line: lineNo, reason: 'embedded public key is invalid' });
        break;
      }
      warnings.push('public key taken from the log itself (not pinned): pass --pubkey to rule out a fully re-signed log');
    }
    if (!verifier.verify(r.hash, r.sig)) errors.push({ line: lineNo, reason: 'signature invalid' });
    if (r.type === 'audit.open' && (r.data as any).publicKey !== verifier.publicKeyHex) {
      errors.push({ line: lineNo, reason: 'audit.open declares a different public key' });
    }
    prev = r.hash;
    count++;
  }
  res.records = count;
  res.lastHash = prev;
  res.publicKeyHex = verifier?.publicKeyHex;

  // Head checkpoint: detects truncation of the tail.
  const hp = headPath(file);
  if (!fs.existsSync(hp)) {
    if (opts.allowMissingHead) warnings.push('head checkpoint missing: tail truncation cannot be ruled out');
    else errors.push({ line: 0, reason: `head checkpoint ${hp} is missing: tail truncation cannot be ruled out` });
  } else if (verifier) {
    try {
      const head: HeadCheckpoint = JSON.parse(fs.readFileSync(hp, 'utf8'));
      if (!verifier.verify(headMessage(head.seq, head.hash), head.sig)) {
        errors.push({ line: 0, reason: 'head checkpoint signature invalid' });
      } else if (head.seq + 1 > count) {
        errors.push({ line: 0, reason: `log was truncated: head checkpoint covers ${head.seq + 1} records but only ${count} are present` });
      } else if (head.seq + 1 < count) {
        errors.push({ line: 0, reason: `log has ${count - (head.seq + 1)} record(s) beyond the signed head checkpoint` });
      } else if (head.hash !== prev) {
        errors.push({ line: 0, reason: 'head checkpoint hash does not match last record' });
      } else {
        res.headChecked = true;
      }
    } catch {
      errors.push({ line: 0, reason: 'head checkpoint unreadable' });
    }
  }
  res.ok = errors.length === 0;
  return res;
}
