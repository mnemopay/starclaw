import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { Provenance, TaintKind, TaintSource } from './types';

/**
 * Session taint. Once untrusted content (web pages, non-owner messages, output of host commands,
 * memories/files that were themselves written while tainted) enters the agent's context, the whole
 * session is tainted until a human starts a new session. Taint only ever escalates decisions.
 */
export class TaintTracker {
  private sources: TaintSource[] = [];
  constructor(private readonly onMark?: (s: TaintSource) => void) {}

  mark(kind: TaintKind, ref: string): void {
    const s: TaintSource = { kind, ref: ref.slice(0, 300), at: new Date().toISOString() };
    // Keep the log bounded but always keep the first source of each (kind, ref).
    if (!this.sources.some((x) => x.kind === s.kind && x.ref === s.ref)) {
      if (this.sources.length < 200) this.sources.push(s);
      this.onMark?.(s);
    }
  }

  get tainted(): boolean {
    return this.sources.length > 0;
  }

  provenance(): Provenance {
    return { tainted: this.tainted, sources: [...this.sources] };
  }

  /** A sub-agent starts with everything its parent has seen: each source is re-marked (and so audited) in this tracker. */
  inherit(from: Provenance): void {
    for (const s of from.sources) this.mark(s.kind, s.ref);
  }

  /** A human-initiated reset (new conversation). Never called by agent code. */
  reset(): void {
    this.sources = [];
  }
}

/** Content-bound provenance. Only matching clean broker writes are trusted across sessions. */
export class TaintedFileStore {
  // Only a content hash produced by a clean broker write establishes trust.
  // Legacy lists, missing/corrupt stores and external edits are unknown, hence tainted.
  private clean = new Map<string, string>();
  constructor(private readonly file?: string) {
    if (!file || !fs.existsSync(file)) return;
    try {
      const state = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (state.version === 2 && Array.isArray(state.clean)) {
        for (const pair of state.clean) {
          if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string' || !/^[a-f0-9]{64}$/.test(pair[1])) throw new Error('invalid provenance');
          this.clean.set(this.key(pair[0]), pair[1]);
        }
      }
    } catch { this.clean.clear(); }
  }
  private key(p: string) { return process.platform === 'win32' ? p.toLowerCase() : p; }
  private hash(bytes: Buffer) { return createHash('sha256').update(bytes).digest('hex'); }
  add(p: string) { this.clean.delete(this.key(p)); this.persist(); }
  remove(p: string, bytes?: Buffer) {
    this.clean.set(this.key(p), this.hash(bytes ?? fs.readFileSync(p)));
    this.persist();
  }
  has(p: string, bytes?: Buffer): boolean {
    const hash = this.clean.get(this.key(p));
    if (!hash) return true;
    try { return hash !== this.hash(bytes ?? fs.readFileSync(p)); }
    catch { return true; }
  }
  private persist() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const temp = `${this.file}.${randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temp, JSON.stringify({ version: 2, clean: [...this.clean] }), { flag: 'wx', mode: 0o600 });
      fs.renameSync(temp, this.file);
    } finally { if (fs.existsSync(temp)) fs.unlinkSync(temp); }
  }
}
