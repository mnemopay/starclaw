import type { AuditLog } from '../governance/audit';
import type { Policy } from '../governance/policy';
import type { GoalResult } from '../engine';
import { nextFire, parseSchedule } from './cron';
import type { Job, JobStore } from './JobStore';

/** What the scheduler needs from the engine (kept small so tests can fake it). */
export interface ScheduledRunner {
  runScheduled(job: Job, o: { triggerAt: string; deadlineAt: number }): Promise<GoalResult>;
}

export interface SchedulerOptions {
  store: JobStore;
  runner: ScheduledRunner;
  audit: AuditLog;
  policy: Policy['scheduled'];
  log?: (m: string) => void;
  /** Called when a job is auto-paused so the owner can be told (rate-limited elsewhere). */
  onPaused?: (job: Job, reason: string) => void | Promise<void>;
}

export interface TickReport {
  ran: string[];
  skipped: Array<{ jobId: string; reason: string }>;
  paused: string[];
}

const MAX_BACKOFF_S = 6 * 3600;

/**
 * Fires due jobs one at a time. Unattended runs are always `origin: scheduled`: the engine gives each its own
 * Governor (own taint, own run context, own LLM-budget view), so nothing a scheduled run does can loosen or taint an
 * owner conversation, and no scheduled run can ever answer its own approval.
 *
 * A job that was due while the daemon was down runs ONCE when it comes back (missed runs are coalesced, never
 * replayed), then moves to its next future slot.
 */
export class Scheduler {
  private timer?: NodeJS.Timeout;
  private ticking = false;
  constructor(private readonly o: SchedulerOptions) {}

  start(intervalMs = 15_000) {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick().catch((e) => this.o.log?.(`scheduler tick error: ${e?.message ?? e}`)), intervalMs);
    this.timer.unref?.();
    this.o.audit.append('scheduler.start', { jobs: this.o.store.list().length });
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.o.audit.append('scheduler.stop', {});
  }

  private next(job: Job, from: number): number | undefined {
    return nextFire(parseSchedule(job.schedule, this.o.policy.timezone), from, this.o.policy.timezone);
  }

  async tick(now = Date.now()): Promise<TickReport> {
    const rep: TickReport = { ran: [], skipped: [], paused: [] };
    if (this.ticking) return rep; // never overlap ticks
    this.ticking = true;
    try {
      const due = this.o.store
        .list()
        .filter((j) => !j.paused && j.nextRunAt !== undefined && j.nextRunAt <= now)
        .sort((a, b) => a.nextRunAt! - b.nextRunAt!);
      for (const job of due) {
        const reason = this.o.store.limitReason(job.id, now);
        if (reason) {
          this.o.audit.append('scheduler.skipped', { jobId: job.id, name: job.name, reason });
          this.o.store.update(job.id, { nextRunAt: this.next(job, now), lastStatus: `skipped: ${reason}` });
          rep.skipped.push({ jobId: job.id, reason });
          continue;
        }
        await this.runOne(job, now, rep);
      }
    } finally {
      this.ticking = false;
    }
    return rep;
  }

  private async runOne(job: Job, now: number, rep: TickReport) {
    const p = this.o.policy;
    const triggerAt = new Date(job.nextRunAt ?? now).toISOString();
    // Counted and audited BEFORE the run starts.
    this.o.store.reserveRun(job.id, now);
    this.o.audit.append('scheduler.run.start', { jobId: job.id, name: job.name, kind: job.kind, triggerAt, createdBy: job.createdBy, createdTainted: job.createdTainted });
    const deadlineAt = Date.now() + p.maxRunSeconds * 1000;
    let res: GoalResult | undefined;
    let err: string | undefined;
    try {
      // The deadline stops governed actions and LLM calls in the run; this race also releases the scheduler loop.
      res = await Promise.race([
        this.o.runner.runScheduled(job, { triggerAt, deadlineAt }),
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error(`run exceeded scheduled.maxRunSeconds (${p.maxRunSeconds}s)`)), p.maxRunSeconds * 1000 + 30_000).unref?.()),
      ]);
    } catch (e: any) {
      err = String(e?.message ?? e);
    }
    const ok = !!res?.success;
    if (res) this.o.store.addLlmCents(res.llmCostCentsCeil, Date.now());
    const failures = ok ? 0 : job.consecutiveFailures + 1;
    const status = ok ? 'ok' : `failed: ${(err ?? res?.error ?? 'unknown').slice(0, 200)}`;
    let nextRunAt = this.next(job, Date.now());
    const patch: Partial<Job> = { lastRunAt: Date.now(), lastStatus: status, consecutiveFailures: failures };
    if (!ok) {
      const backoff = Math.min(MAX_BACKOFF_S, p.backoffBaseSeconds * 2 ** Math.max(0, failures - 1)) * 1000;
      nextRunAt = Math.max(nextRunAt ?? 0, Date.now() + backoff);
    }
    patch.nextRunAt = nextRunAt;
    let pausedNow = false;
    if (!ok && failures >= p.maxConsecutiveFailures) {
      patch.paused = true;
      patch.pausedReason = `${failures} consecutive failures; last: ${status}`;
      pausedNow = true;
    }
    this.o.store.update(job.id, patch);
    this.o.audit.append('scheduler.run.end', { jobId: job.id, name: job.name, triggerAt, ok, status, denied: res?.denied?.by, llmCents: res?.llmCostCentsCeil, consecutiveFailures: failures, nextRunAt: nextRunAt ? new Date(nextRunAt).toISOString() : null, paused: pausedNow });
    rep.ran.push(job.id);
    if (pausedNow) {
      rep.paused.push(job.id);
      this.o.audit.append('scheduler.job.paused', { jobId: job.id, reason: patch.pausedReason });
      try {
        await this.o.onPaused?.({ ...job, ...patch } as Job, patch.pausedReason!);
      } catch {
        /* notification is best effort */
      }
    }
  }
}
