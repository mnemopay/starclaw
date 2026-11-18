import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * The console's conversation record: one append-only JSONL file per session under `<stateDir>/console/`.
 *
 * It is what the person SEES (their messages and the agent's final replies), not the agent's context: after a
 * restart, earlier sessions are shown read-only and the agent starts clean. Feeding an old transcript back into a
 * new session would carry untrusted (tainted) content into a session the governor believes is clean.
 * The signed audit log stays the record of what the agent did; this file is not evidence.
 */

export type EntryKind = 'user' | 'agent' | 'error' | 'denied';
export interface Entry { at: string; kind: EntryKind; text: string; jobId?: string; tainted?: boolean }
export interface SessionInfo { id: string; startedAt: string; entries: number; preview: string }

const SESSION_ID = /^\d{8}T\d{6}Z-[0-9a-f]{8}$/;
const MAX_TEXT = 20_000;
const MAX_SESSIONS_LISTED = 50;

export function isSessionId(x: unknown): x is string {
  return typeof x === 'string' && SESSION_ID.test(x);
}

export class Transcript {
  private current: string;
  constructor(private readonly dir: string, private readonly now: () => Date = () => new Date()) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.current = this.newId();
  }

  private newId(): string {
    const ts = this.now().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
    return `${ts}-${randomBytes(4).toString('hex')}`;
  }
  private file(id: string): string {
    if (!isSessionId(id)) throw new Error('bad session id');
    return path.join(this.dir, `${id}.jsonl`);
  }

  get sessionId(): string {
    return this.current;
  }

  /** Start a new session file (the previous one is kept, read-only). */
  rotate(): string {
    this.current = this.newId();
    return this.current;
  }

  append(kind: EntryKind, text: string, extra: { jobId?: string; tainted?: boolean } = {}): Entry {
    const e: Entry = { at: this.now().toISOString(), kind, text: String(text).slice(0, MAX_TEXT), ...extra };
    fs.appendFileSync(this.file(this.current), JSON.stringify(e) + '\n', { mode: 0o600 });
    return e;
  }

  read(id: string = this.current): Entry[] {
    const f = this.file(id);
    if (!fs.existsSync(f)) return [];
    const out: Entry[] = [];
    for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
      if (!line) continue;
      try {
        out.push(JSON.parse(line));
      } catch {
        /* a torn last line from a crash is skipped, not fatal */
      }
    }
    return out;
  }

  /** Earlier sessions, newest first (the current one is excluded). */
  sessions(): SessionInfo[] {
    const ids = fs.readdirSync(this.dir).filter((n) => n.endsWith('.jsonl')).map((n) => n.slice(0, -6)).filter((id) => isSessionId(id) && id !== this.current);
    ids.sort().reverse();
    return ids.slice(0, MAX_SESSIONS_LISTED).map((id) => {
      const entries = this.read(id);
      const first = entries.find((e) => e.kind === 'user');
      return { id, startedAt: entries[0]?.at ?? '', entries: entries.length, preview: (first?.text ?? '').slice(0, 120) };
    });
  }
}

export interface SearchHit { sessionId: string; at: string; kind: EntryKind; text: string; tainted: boolean; before?: Entry; after?: Entry }

/**
 * Search every session in `dir` (newest first) for entries containing ALL query terms (case-insensitive). Each hit carries
 * its neighbouring entries for context. Bounded in files read and hits returned. Missing dir = no hits.
 */
export function searchTranscripts(dir: string, query: string, o: { limit?: number; maxSessions?: number } = {}): SearchHit[] {
  const terms = query.toLowerCase().split(/\s+/).filter((t) => t.length >= 2).slice(0, 10);
  if (!terms.length || !fs.existsSync(dir)) return [];
  const limit = Math.min(o.limit ?? 20, 100);
  const ids = fs.readdirSync(dir).filter((n) => n.endsWith('.jsonl')).map((n) => n.slice(0, -6)).filter(isSessionId).sort().reverse().slice(0, o.maxSessions ?? 500);
  const hits: SearchHit[] = [];
  for (const id of ids) {
    let entries: Entry[];
    try {
      entries = fs.readFileSync(path.join(dir, `${id}.jsonl`), 'utf8').split('\n').filter(Boolean).flatMap((l) => { try { return [JSON.parse(l) as Entry]; } catch { return []; } });
    } catch {
      continue;
    }
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = entries[i];
      const t = String(e.text ?? '').toLowerCase();
      if (!terms.every((term) => t.includes(term))) continue;
      hits.push({ sessionId: id, at: e.at, kind: e.kind, text: e.text, tainted: !!e.tainted, before: entries[i - 1], after: entries[i + 1] });
      if (hits.length >= limit) return hits;
    }
  }
  return hits;
}
