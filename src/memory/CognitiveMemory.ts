import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256Hex } from '../governance/canonical';
import type { Signer } from '../governance/signer';

export type MemoryKind = 'note' | 'skill';

export interface MemoryEntry {
  id: string;
  seq: number;
  kind: MemoryKind;
  content: string;
  meta: Record<string, unknown>;
  /** Written while the session was tainted (untrusted provenance). */
  tainted: boolean;
  timestamp: number;
  importance: number;
  retention: number;
  activation: number;
  last_used: number;
}

export interface MemoryVerifyReport {
  ok: boolean;
  total: number;
  /** Rows whose own hash/signature do not match their content (modified). */
  tampered: Array<{ id: string; seq: number; reason: string }>;
  /** Chain-level problems: deletions, reordering, tail truncation, bad head. */
  chainErrors: string[];
}

const GENESIS = '0'.repeat(64);

function rowBody(r: { seq: number; id: string; ts: number; kind: string; content: string; meta: string; tainted: number; prev: string }): string {
  return canonicalize({ seq: r.seq, id: r.id, ts: r.ts, kind: r.kind, content: r.content, meta: r.meta, tainted: r.tainted, prev: r.prev });
}

export interface MemoryOptions {
  /** TEST-ONLY control: skip integrity verification on recall, to prove the tamper tests fail without it. */
  _unsafeSkipVerify?: boolean;
  onQuarantine?: (info: { id: string; seq: number; reason: string }) => void;
}

/**
 * Cognitive memory on Node's built-in `node:sqlite` (FTS5 verified to work; no native add-on).
 *
 * Integrity: every memory row is part of a hash chain (row_hash covers content, kind, meta, taint flag, seq and the
 * previous row's hash) and carries an Ed25519 signature over row_hash. A signed head records the latest (seq, hash).
 * Recall verifies each row it is about to return; a row that fails is quarantined and never returned.
 * Mutable ranking fields (importance, access count, ...) are deliberately NOT covered, so they are not protected.
 * Anyone holding the signing key can forge rows; see SECURITY.md.
 */
export class CognitiveMemory {
  private db: DatabaseSync;
  quarantinedThisSession = 0;

  constructor(dbPath: string, private readonly signer: Signer, private readonly opts: MemoryOptions = {}) {
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    this.init();
  }

  close() {
    this.db.close();
  }

  private init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memories (
        seq INTEGER PRIMARY KEY,
        id TEXT NOT NULL UNIQUE,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        content TEXT NOT NULL,
        meta TEXT NOT NULL,
        tainted INTEGER NOT NULL,
        prev_hash TEXT NOT NULL,
        row_hash TEXT NOT NULL,
        sig TEXT NOT NULL,
        importance REAL NOT NULL DEFAULT 1.0,
        access_count INTEGER NOT NULL DEFAULT 0,
        last_used INTEGER NOT NULL DEFAULT 0,
        error_count INTEGER NOT NULL DEFAULT 0,
        quarantined INTEGER NOT NULL DEFAULT 0,
        quarantine_reason TEXT
      );
      CREATE TABLE IF NOT EXISTS memory_head (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(content, mid UNINDEXED);
    `);
  }

  private head(): { seq: number; hash: string; sig: string } | undefined {
    const r = this.db.prepare("SELECT v FROM memory_head WHERE k='head'").get() as { v: string } | undefined;
    return r ? JSON.parse(r.v) : undefined;
  }

  private static headMsg(seq: number, hash: string) {
    return `starclaw-memory-head:${seq}:${hash}`;
  }

  remember(content: string, opts: { kind?: MemoryKind; meta?: Record<string, unknown>; tainted?: boolean; importance?: number } = {}): string {
    const id = randomUUID();
    const ts = Date.now();
    const kind = opts.kind ?? 'note';
    const meta = canonicalize(opts.meta ?? {});
    const tainted = opts.tainted ? 1 : 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const last = this.db.prepare('SELECT seq, row_hash FROM memories ORDER BY seq DESC LIMIT 1').get() as { seq: number; row_hash: string } | undefined;
      const seq = last ? last.seq + 1 : 0;
      const prev = last ? last.row_hash : GENESIS;
      const row_hash = sha256Hex(rowBody({ seq, id, ts, kind, content, meta, tainted, prev }));
      const sig = this.signer.sign(row_hash);
      this.db
        .prepare('INSERT INTO memories (seq,id,ts,kind,content,meta,tainted,prev_hash,row_hash,sig,importance,last_used) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(seq, id, ts, kind, content, meta, tainted, prev, row_hash, sig, opts.importance ?? 1.0, ts);
      this.db.prepare('INSERT INTO memories_fts (content, mid) VALUES (?, ?)').run(content, id);
      const headVal = JSON.stringify({ seq, hash: row_hash, sig: this.signer.sign(CognitiveMemory.headMsg(seq, row_hash)) });
      this.db.prepare("INSERT INTO memory_head (k,v) VALUES ('head',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(headVal);
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return id;
  }

  private verifyRow(r: any): string | undefined {
    const expect = sha256Hex(rowBody({ seq: r.seq, id: r.id, ts: r.ts, kind: r.kind, content: r.content, meta: r.meta, tainted: r.tainted, prev: r.prev_hash }));
    if (expect !== r.row_hash) return 'content/fields do not match the recorded hash (row was modified)';
    if (!this.signer.verify(r.row_hash, r.sig)) return 'signature invalid (row was forged or modified)';
    return undefined;
  }

  private quarantine(r: any, reason: string) {
    this.db.prepare('UPDATE memories SET quarantined=1, quarantine_reason=? WHERE id=?').run(reason, r.id);
    this.quarantinedThisSession++;
    this.opts.onQuarantine?.({ id: r.id, seq: r.seq, reason });
  }

  /** Cognitive recall: FTS5 candidates, integrity-checked, re-ranked by activation/retention/importance. */
  search(query: string, limit = 5): MemoryEntry[] {
    const safeQuery = query.replace(/[^\p{L}\p{N}\s]/gu, ' ').trim().split(/\s+/).filter(Boolean).map((w) => `"${w}"`).join(' OR ');
    if (!safeQuery) return [];
    // The FTS table is only used to find candidate ids; content always comes from the verified main row.
    const ids = this.db.prepare('SELECT mid FROM memories_fts WHERE memories_fts MATCH ? LIMIT 50').all(safeQuery) as Array<{ mid: string }>;
    const now = Date.now();
    const out: MemoryEntry[] = [];
    const get = this.db.prepare('SELECT * FROM memories WHERE id=? AND quarantined=0');
    for (const { mid } of ids) {
      const r = get.get(mid) as any;
      if (!r) continue;
      if (!this.opts._unsafeSkipVerify) {
        const bad = this.verifyRow(r);
        if (bad) {
          this.quarantine(r, bad);
          continue;
        }
      }
      const ageMin = (now - r.ts) / 60000;
      out.push({
        id: r.id,
        seq: r.seq,
        kind: r.kind,
        content: r.content,
        meta: JSON.parse(r.meta),
        tainted: r.tainted === 1,
        timestamp: r.ts,
        importance: r.importance,
        retention: Math.min(1.0, r.importance * (1 + Math.log(1 + r.access_count))),
        activation: 1 / (1 + Math.log(1 + ageMin)),
        last_used: r.last_used,
      });
    }
    out.sort((a, b) => 0.4 * b.activation + 0.4 * b.retention + 0.2 * b.importance - (0.4 * a.activation + 0.4 * a.retention + 0.2 * a.importance));
    const top = out.slice(0, limit);
    top.forEach((e) => this.reinforce(e.id, 0.05));
    return top;
  }

  reinforce(id: string, weight = 0.1) {
    this.db.prepare('UPDATE memories SET importance=importance+?, access_count=access_count+1, last_used=? WHERE id=?').run(weight, Date.now(), id);
  }

  reportError(id: string) {
    this.db.prepare('UPDATE memories SET error_count=error_count+1 WHERE id=?').run(id);
  }

  count(): { total: number; quarantined: number } {
    const t = this.db.prepare('SELECT COUNT(*) c, SUM(quarantined) q FROM memories').get() as any;
    return { total: Number(t.c), quarantined: Number(t.q ?? 0) };
  }

  /** Full audit: every row, the chain between rows, and the signed head. Quarantines every modified row. */
  verifyAll(): MemoryVerifyReport {
    const rows = this.db.prepare('SELECT * FROM memories ORDER BY seq').all() as any[];
    const tampered: MemoryVerifyReport['tampered'] = [];
    const chainErrors: string[] = [];
    let prev = GENESIS;
    let expectSeq = 0;
    for (const r of rows) {
      if (r.seq !== expectSeq) chainErrors.push(`sequence gap before seq ${r.seq} (expected ${expectSeq}): rows were deleted`);
      expectSeq = r.seq + 1;
      if (r.prev_hash !== prev) chainErrors.push(`chain broken at seq ${r.seq}: previous row missing, replaced or reordered`);
      const bad = this.verifyRow(r);
      if (bad) {
        tampered.push({ id: r.id, seq: r.seq, reason: bad });
        if (!r.quarantined) this.quarantine(r, bad);
      }
      prev = r.row_hash;
    }
    const head = this.head();
    if (rows.length === 0) {
      if (head) chainErrors.push('head exists but there are no rows: all memories were deleted');
    } else if (!head) {
      chainErrors.push('signed head is missing');
    } else if (!this.signer.verify(CognitiveMemory.headMsg(head.seq, head.hash), head.sig)) {
      chainErrors.push('signed head is invalid');
    } else {
      const last = rows[rows.length - 1];
      if (head.seq !== last.seq || head.hash !== last.row_hash) chainErrors.push(`tail does not match signed head (head seq ${head.seq}, last row seq ${last.seq}): rows were truncated or replaced`);
    }
    return { ok: tampered.length === 0 && chainErrors.length === 0, total: rows.length, tampered, chainErrors };
  }
}
