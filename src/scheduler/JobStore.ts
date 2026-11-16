import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Policy } from '../governance/policy';
import { minGapSeconds, nextFire, parseSchedule } from './cron';

export type JobKind = 'goal' | 'heartbeat';
/** Who made the job. `agent` jobs were proposed by a model and approved by a human (schedule.create always asks). */
export type JobCreator = 'owner-cli' | 'agent-approved';

export interface Job {
  id: string;
  name: string;
  kind: JobKind;
  /** Cron expression or "@every 30m". */
  schedule: string;
  goal: string;
  createdAt: string;
  createdBy: JobCreator;
  /** True when the session that proposed the job already held untrusted content: every run starts tainted. */
  createdTainted: boolean;
  /** 'agent' = only tools.notifyOwner may message the owner; 'summary' = also send a one-line result; 'never'. */
  notify: 'agent' | 'summary' | 'never';
  paused: boolean;
  pausedReason?: string;
  nextRunAt?: number;
  lastRunAt?: number;
  lastStatus?: string;
  consecutiveFailures: number;
  runDay?: string;
  runsToday: number;
}

interface StateFile {
  version: 1;
  jobs: Job[];
  day: string;
  runsToday: number;
  llmCentsToday: number;
}

export class JobError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'JobError';
  }
}

export interface NewJob {
  name: string;
  schedule: string;
  goal: string;
  kind?: JobKind;
  notify?: Job['notify'];
  createdBy: JobCreator;
  createdTainted?: boolean;
}

const utcDay = (t: number) => new Date(t).toISOString().slice(0, 10);

/** Persistent job list + daily counters. Atomic writes; every mutation is synchronous. */
export class JobStore {
  private state: StateFile;
  constructor(private readonly file: string, private readonly policy: () => Policy['scheduled']) {
    this.state = this.read();
  }

  private read(): StateFile {
    try {
      const j = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (j && j.version === 1 && Array.isArray(j.jobs)) return j as StateFile;
    } catch {
      /* missing or corrupt: start empty (jobs are re-creatable; a corrupt file never runs anything) */
    }
    return { version: 1, jobs: [], day: utcDay(Date.now()), runsToday: 0, llmCentsToday: 0 };
  }

  private save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.state, null, 1));
    fs.renameSync(tmp, this.file);
  }

  list(): Job[] {
    return this.state.jobs.map((j) => ({ ...j }));
  }
  get(id: string): Job | undefined {
    const j = this.state.jobs.find((x) => x.id === id);
    return j ? { ...j } : undefined;
  }

  /** Validate WITHOUT adding (used before a human is asked to approve an agent-proposed job). */
  validate(n: Pick<NewJob, 'name' | 'schedule' | 'goal'>): { nextRunAt: number; gapSeconds: number } {
    const p = this.policy();
    if (this.state.jobs.length >= p.maxJobsTotal) throw new JobError(`job limit reached (scheduled.maxJobsTotal = ${p.maxJobsTotal})`);
    if (!/^[\w .:-]{1,60}$/.test(n.name)) throw new JobError('job name must be 1-60 characters of letters, digits, space, . : _ -');
    if (n.goal.trim().length < 3 || n.goal.length > 2000) throw new JobError('goal must be 3-2000 characters');
    let spec;
    try {
      spec = parseSchedule(n.schedule, p.timezone);
    } catch (e: any) {
      throw new JobError(`invalid schedule: ${e.message}`);
    }
    const gap = minGapSeconds(spec);
    if (gap < p.minIntervalSeconds) throw new JobError(`schedule can fire every ${gap}s but scheduled.minIntervalSeconds is ${p.minIntervalSeconds}`);
    const next = nextFire(spec, Date.now(), p.timezone);
    if (next === undefined) throw new JobError('schedule never fires');
    return { nextRunAt: next, gapSeconds: gap };
  }

  add(n: NewJob, now = Date.now()): Job {
    const v = this.validate(n);
    const job: Job = {
      id: randomUUID(),
      name: n.name,
      kind: n.kind ?? 'goal',
      schedule: n.schedule.trim(),
      goal: n.goal,
      createdAt: new Date(now).toISOString(),
      createdBy: n.createdBy,
      createdTainted: !!n.createdTainted,
      notify: n.notify ?? (n.kind === 'heartbeat' ? 'agent' : 'summary'),
      paused: false,
      nextRunAt: nextFire(parseSchedule(n.schedule, this.policy().timezone), now, this.policy().timezone) ?? v.nextRunAt,
      consecutiveFailures: 0,
      runsToday: 0,
    };
    this.state.jobs.push(job);
    this.save();
    return { ...job };
  }

  remove(id: string): boolean {
    const n = this.state.jobs.length;
    this.state.jobs = this.state.jobs.filter((j) => j.id !== id);
    if (this.state.jobs.length === n) return false;
    this.save();
    return true;
  }

  update(id: string, patch: Partial<Job>): Job | undefined {
    const j = this.state.jobs.find((x) => x.id === id);
    if (!j) return undefined;
    Object.assign(j, patch);
    this.save();
    return { ...j };
  }

  // ---- daily counters (UTC day) ---------------------------------------------------------------------------------

  private roll(now: number) {
    const d = utcDay(now);
    if (this.state.day !== d) {
      this.state.day = d;
      this.state.runsToday = 0;
      this.state.llmCentsToday = 0;
    }
    for (const j of this.state.jobs) if (j.runDay !== d) { j.runDay = d; j.runsToday = 0; }
  }

  counters(now = Date.now()): { runsToday: number; llmCentsToday: number } {
    this.roll(now);
    return { runsToday: this.state.runsToday, llmCentsToday: this.state.llmCentsToday };
  }

  /** Count a run BEFORE it starts (a crash mid-run still counts). */
  reserveRun(id: string, now = Date.now()) {
    this.roll(now);
    const j = this.state.jobs.find((x) => x.id === id);
    this.state.runsToday++;
    if (j) j.runsToday++;
    this.save();
  }

  addLlmCents(cents: number, now = Date.now()) {
    this.roll(now);
    this.state.llmCentsToday += Math.max(0, Math.ceil(cents));
    this.save();
  }

  /** Why this job may not run right now (limits), or undefined. */
  limitReason(id: string, now = Date.now()): string | undefined {
    const p = this.policy();
    this.roll(now);
    if (this.state.runsToday >= p.maxRunsPerDay) return `scheduled.maxRunsPerDay (${p.maxRunsPerDay}) reached`;
    if (this.state.llmCentsToday >= p.maxLlmCentsPerDay) return `scheduled.maxLlmCentsPerDay (${p.maxLlmCentsPerDay}) reached`;
    const j = this.state.jobs.find((x) => x.id === id);
    if (j && j.runsToday >= p.maxRunsPerJobPerDay) return `scheduled.maxRunsPerJobPerDay (${p.maxRunsPerJobPerDay}) reached`;
    return undefined;
  }
}
