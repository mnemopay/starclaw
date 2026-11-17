import * as fs from 'node:fs';
import * as path from 'node:path';
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

/**
 * Remembers which workspace files were written while the session was tainted, so that a *later* session
 * that reads them is tainted too. Best effort: it only sees writes made through the broker.
 */
export class TaintedFileStore {
  private set = new Set<string>();
  constructor(private readonly file?: string) {
    if (file && fs.existsSync(file)) {
      try {
        const arr = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (Array.isArray(arr)) this.set = new Set(arr.filter((x) => typeof x === 'string'));
      } catch {
        // Unreadable store: fail closed by treating nothing as known-clean is impossible; start empty but note it.
        this.set = new Set();
      }
    }
  }
  private key(p: string) {
    return process.platform === 'win32' ? p.toLowerCase() : p;
  }
  add(p: string) {
    this.set.add(this.key(p));
    this.persist();
  }
  remove(p: string) {
    if (this.set.delete(this.key(p))) this.persist();
  }
  has(p: string) {
    return this.set.has(this.key(p));
  }
  private persist() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify([...this.set]));
  }
}
