import type { GoalResult } from '../engine';

/**
 * Serialises goals from every chat channel (Telegram, Slack, Discord). They all share ONE engine conversation and ONE
 * session taint, so two goals must never interleave. Bounded: a flood of non-owner messages cannot build an unbounded backlog.
 */
export class GoalQueue {
  private tail: Promise<void> = Promise.resolve();
  private depth = 0;
  constructor(private readonly maxPending = 20) {}

  /** Returns the promise for this job, or undefined if the queue is full (the caller should tell the sender it is busy). */
  enqueue(fn: () => Promise<void>): Promise<void> | undefined {
    if (this.depth >= this.maxPending) return undefined;
    this.depth++;
    const p = this.tail.then(fn).finally(() => {
      this.depth--;
    });
    this.tail = p.catch(() => {});
    return p;
  }
  get pending() {
    return this.depth;
  }
}

/** Plain-text body for a finished goal (same shape the Telegram gateway sends). */
export function renderGoalResult(r: GoalResult): string {
  const body = r.success
    ? [r.reply, r.stdout, r.result === undefined || r.result === null ? '' : typeof r.result === 'string' ? r.result : JSON.stringify(r.result)].filter(Boolean).join('\n') || 'Done.'
    : `Failed: ${r.error}`;
  return body + (r.tainted ? '\n[session tainted]' : '');
}
