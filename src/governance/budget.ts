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
    if (this.runMicro >= this.perRunCents * MICRO) throw new BudgetExceeded('run', `per-run LLM budget of ${this.perRunCents} cents exhausted`);
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
