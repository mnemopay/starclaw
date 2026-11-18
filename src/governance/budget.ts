import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';

export interface LlmUsage {
  inputTokens: number;
  outputTokens: number;
}
export interface LlmPrice {
  /** Integer cents per million tokens. tokens * (cents/Mtok) is exactly microcents (1e-6 cent): all-integer math. */
  inputCentsPerMTok: number;
  outputCentsPerMTok: number;
}

export function costMicrocents(u: LlmUsage, p: LlmPrice): number {
  return u.inputTokens * p.inputCentsPerMTok + u.outputTokens * p.outputCentsPerMTok;
}

export class BudgetExceeded extends Error {
  constructor(public readonly scope: 'run' | 'day', msg: string) {
    super(msg);
    this.name = 'BudgetExceeded';
  }
}

const MICRO = 1_000_000;

/**
 * Built-in backends reserve a conservative request estimate before dispatch, then reconcile usage.
 * Reservations share an atomic, exclusively locked daily ledger. Failed/unknown requests retain
 * their reservation. Limits depend on configured prices and provider token accounting; this is
 * not a guarantee about a provider's invoice. Custom LLMs may use post-call record() accounting.
 */
export class LlmBudget {
  private runMicro = 0;
  private inMemoryDay = { date: '', micro: 0 };
  /** Microcents handed to still-open sub-agent slices: unavailable to this run until the slice is closed. */
  private carvedMicro = 0;
  constructor(
    private readonly perRunCents: number,
    private readonly perDayCents: number,
    private readonly file?: string,
    private readonly today: () => string = () => new Date().toISOString().slice(0, 10),
  ) {}

  private readDay(): { date: string; micro: number } {
    const date = this.today();
    if (!this.file) return this.inMemoryDay.date === date ? { ...this.inMemoryDay } : { date, micro: 0 };
    if (!fs.existsSync(this.file)) return { date, micro: 0 };
    try {
      const j = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (typeof j.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(j.date) || j.date > date || !Number.isSafeInteger(j.micro) || j.micro < 0) throw new Error('invalid ledger');
      return { date, micro: j.date === date ? j.micro : 0 };
    } catch { throw new BudgetExceeded('day', 'LLM budget ledger is corrupt; refusing to reset spending to zero'); }
  }

  private changeDay(delta: number, enforce: boolean): void {
    if (!this.file) {
      const day = this.readDay();
      const micro = day.micro + delta;
      if (!Number.isSafeInteger(micro) || micro < 0) throw new Error('invalid LLM balance');
      if (enforce && micro > this.perDayCents * MICRO) throw new BudgetExceeded('day', 'request exceeds remaining daily LLM budget');
      this.inMemoryDay = { date: day.date, micro };
      return;
    }
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const lock = `${this.file}.lock`;
    let fd: number;
    try { fd = fs.openSync(lock, 'wx', 0o600); }
    catch { throw new BudgetExceeded('day', 'LLM budget ledger is locked; retry after the other writer finishes'); }
    const tmp = `${this.file}.${randomUUID()}.tmp`;
    try {
      const day = this.readDay();
      const micro = day.micro + delta;
      if (!Number.isSafeInteger(micro) || micro < 0) throw new Error('invalid LLM ledger balance');
      if (enforce && micro > this.perDayCents * MICRO) throw new BudgetExceeded('day', 'request exceeds remaining daily LLM budget');
      fs.writeFileSync(tmp, JSON.stringify({ date: day.date, micro }), { flag: 'wx', mode: 0o600 });
      fs.renameSync(tmp, this.file);
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lock);
      if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
    }
  }

  get availableMicro(): number {
    return Math.max(0, Math.min(this.perRunCents * MICRO - this.runMicro - this.carvedMicro, this.perDayCents * MICRO - this.readDay().micro));
  }

  /** Reserve BEFORE sending a request. An error/unknown outcome keeps the full reservation charged. */
  reserve(micro: number): { settle: (actual: number) => void } {
    if (!Number.isSafeInteger(micro) || micro < 0) throw new Error('invalid LLM reservation');
    if (micro > this.perRunCents * MICRO - this.runMicro - this.carvedMicro) throw new BudgetExceeded('run', 'request exceeds remaining per-run LLM budget');
    this.changeDay(micro, true);
    this.runMicro += micro;
    const date = this.today();
    let settled = false;
    return { settle: (actual) => {
      if (settled) throw new Error('LLM reservation already settled');
      if (!Number.isSafeInteger(actual) || actual < 0) throw new Error('invalid LLM cost');
      // A provider can report more than its configured token/price estimate: record the debt and stop.
      const delta = actual - micro;
      if (this.today() === date) this.changeDay(delta, false);
      else if (delta > 0) this.changeDay(delta, false); // never refund yesterday's reservation from today's balance
      this.runMicro += delta;
      settled = true;
      if (delta > 0) throw new BudgetExceeded('run', 'provider usage exceeded the reserved estimate; usage recorded, run stopped');
    }};
  }

  assertCanSpend(): void {
    if (this.runMicro + this.carvedMicro >= this.perRunCents * MICRO) throw new BudgetExceeded('run', `per-run LLM budget of ${this.perRunCents} cents exhausted`);
    if (this.readDay().micro >= this.perDayCents * MICRO) throw new BudgetExceeded('day', `per-day LLM budget of ${this.perDayCents} cents exhausted`);
  }

  record(microcents: number): void {
    if (!Number.isSafeInteger(microcents) || microcents < 0) throw new Error('invalid LLM cost');
    this.changeDay(microcents, false);
    this.runMicro += microcents;
  }

  /** Whole cents that can still be carved into a sub-agent's budget right now. */
  get availableRunCents(): number {
    return Math.max(0, Math.floor((this.perRunCents * MICRO - this.runMicro - this.carvedMicro) / MICRO));
  }

  /**
   * Carve `cents` of this run's remaining budget into a separate budget for a sub-agent. The slice is held (unavailable to
   * this run and to other slices) until close(); close() adds what the child ACTUALLY spent to this run and gives the rest
   * back, so concurrent children cannot jointly exceed the parent. The per-day total is shared: the child writes the same
   * file, and close() does not write it again. `consumeAll` (a child that timed out and may still be mid-call) charges the
   * whole slice.
   */
  carve(cents: number): { budget: LlmBudget; close: (consumeAll?: boolean) => { spentMicro: number } } {
    if (!Number.isSafeInteger(cents) || cents <= 0) throw new Error('invalid LLM slice');
    if (cents > this.availableRunCents) throw new BudgetExceeded('run', `cannot carve ${cents} cents: only ${this.availableRunCents} are left in this run's budget`);
    this.carvedMicro += cents * MICRO;
    const budget = new LlmBudget(cents, this.perDayCents, this.file, this.today);
    let closedSpent: number | undefined;
    return {
      budget,
      close: (consumeAll = false) => {
        if (closedSpent === undefined) {
          closedSpent = consumeAll ? Math.max(budget.runMicro, cents * MICRO) : budget.runMicro;
          this.carvedMicro -= cents * MICRO;
          this.runMicro += closedSpent;
        }
        return { spentMicro: closedSpent };
      },
    };
  }

  newRun(): void {
    this.runMicro = 0;
  }

  get runCentsCeil(): number {
    return Math.ceil(this.runMicro / MICRO);
  }
  get dayCentsCeil(): number {
    return Math.ceil(this.readDay().micro / MICRO);
  }
}
