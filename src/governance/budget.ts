import * as fs from 'node:fs';
import * as path from 'node:path';

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
 * LLM cost accounting against per-run and per-day caps (integer cents; accounted in microcents).
 * The cap is checked BEFORE each call and the actual usage is added AFTER it, so one call can overshoot by at
 * most its own cost. The per-day total is persisted to a plain JSON file: it is a convenience limit, not a
 * tamper-proof one (anyone who can edit that file can reset it).
 */
export class LlmBudget {
  private runMicro = 0;
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
    if (this.file && fs.existsSync(this.file)) {
      try {
        const j = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        if (j.date === date && Number.isSafeInteger(j.micro) && j.micro >= 0) return { date, micro: j.micro };
      } catch {
        /* fall through */
      }
    }
    return { date, micro: 0 };
  }

  assertCanSpend(): void {
    if (this.runMicro + this.carvedMicro >= this.perRunCents * MICRO) throw new BudgetExceeded('run', `per-run LLM budget of ${this.perRunCents} cents exhausted`);
    if (this.readDay().micro >= this.perDayCents * MICRO) throw new BudgetExceeded('day', `per-day LLM budget of ${this.perDayCents} cents exhausted`);
  }

  record(microcents: number): void {
    if (!Number.isSafeInteger(microcents) || microcents < 0) throw new Error('invalid LLM cost');
    this.runMicro += microcents;
    if (this.file) {
      const d = this.readDay();
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify({ date: d.date, micro: d.micro + microcents }));
    }
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
