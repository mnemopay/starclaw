import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vm from 'node:vm';
import { Broker } from './broker';
import { AuditLog } from './governance/audit';
import { BudgetExceeded, LlmBudget, costMicrocents } from './governance/budget';
import { sha256Hex } from './governance/canonical';
import { Governor } from './governance/governor';
import { Policy, defaultPolicy } from './governance/policy';
import { Ed25519Signer, Signer } from './governance/signer';
import { MnemoPaySpendAuthority, NoPaymentRail, PaymentRail, SpendAuthority } from './governance/spend';
import { TaintTracker, TaintedFileStore } from './governance/taint';
import { Action, Approver, Decision, GovernorDenied } from './governance/types';
import type { ChatTurn, LLM, LlmResult } from './llm/types';
import { CognitiveMemory, MemoryVerifyReport } from './memory/CognitiveMemory';
import type { RunResult, Sandbox } from './sandbox/types';
import { SelectingSandbox } from './sandbox/select';
import type { ProbeReport } from './sandbox/probe';
import { SkillStore, sanitizeSkillName } from './skills/SkillStore';
import { NotifyLimiter, OwnerNotifier } from './notify/Notifier';
import { Job, JobStore } from './scheduler/JobStore';
import { ShellRunner } from './shell/ShellRunner';

export type Origin = 'owner' | 'non-owner';

export interface EngineOptions {
  id?: string;
  llm: LLM;
  stateDir?: string;
  workspaceDir?: string;
  policy?: Policy;
  approver?: Approver;
  rail?: PaymentRail;
  /** Offer to save successful code as a reusable skill (each save still needs approval). Default false. */
  learnSkills?: boolean;
  /** Where proactive messages to the owner go (e.g. TelegramNotifier). Without one, tools.notifyOwner is unavailable. */
  notifier?: OwnerNotifier;
  /** Injection point for tests. By default a ShellRunner over the workspace (a container only starts when tools.shell runs). */
  shell?: ShellRunner;
  /** Injection points for tests. */
  signer?: Signer;
  sandbox?: Sandbox;
  log?: (msg: string) => void;
}

export interface GoalOptions {
  /** Who sent the goal. Anything other than 'owner' taints the session from the start. */
  origin?: Origin;
  originRef?: string;
  onLog?: (msg: string) => void;
}

export interface GoalResult {
  success: boolean;
  kind: 'conversation' | 'task';
  result?: unknown;
  reply?: string;
  stdout?: string;
  error?: string;
  denied?: Decision;
  tainted: boolean;
  llmCostCentsCeil: number;
}

export interface BootReport {
  sandbox: ProbeReport;
  memory: MemoryVerifyReport;
}

const MAX_FIX_ATTEMPTS = 2;

/** Everything one run needs that must NOT be shared between an owner conversation and an unattended job. */
interface RunCtx {
  governor: Governor;
  broker: Broker;
  budget: LlmBudget;
  history: ChatTurn[];
  scheduled?: { jobId: string };
}

/** The goal text a heartbeat job runs: the agent speaks first only when it has something worth saying. */
export function heartbeatGoal(task: string): string {
  return (
    `HEARTBEAT (scheduled, unattended; nobody is watching this run). Check the following and act only within your tools:\n${task}\n\n` +
    `If, and only if, something needs the owner's attention, call tools.notifyOwner({ text }) once with a short, factual message ` +
    `(no secrets, no links you did not verify). If there is nothing to report, send nothing and return "nothing to report".`
  );
}

export class StarClawEngine {
  readonly id: string;
  readonly governor: Governor;
  readonly audit: AuditLog;
  readonly memory: CognitiveMemory;
  readonly sandbox: Sandbox;
  broker: Broker;
  readonly budget: LlmBudget;
  readonly skills: SkillStore;
  readonly policy: Policy;
  readonly stateDir: string;
  readonly workspaceDir: string;
  readonly jobs: JobStore;
  readonly shell: ShellRunner;
  private notifier?: OwnerNotifier;
  private readonly notifyLimiter: NotifyLimiter;
  private readonly taintedFiles: TaintedFileStore;
  private readonly spendAuthority: SpendAuthority;
  private readonly rail: PaymentRail;
  private approver?: Approver;
  private history: ChatTurn[] = [];
  private readonly llm: LLM;
  private readonly learnSkills: boolean;
  /** At most one generated-code run (and so at most one sandbox container) at a time, across owner and scheduled runs. */
  private sandboxLock: Promise<unknown> = Promise.resolve();
  private readonly main: RunCtx;

  constructor(o: EngineOptions) {
    this.id = o.id ?? 'starclaw';
    this.llm = o.llm;
    this.learnSkills = !!o.learnSkills;
    this.policy = o.policy ?? defaultPolicy();
    this.stateDir = path.resolve(o.stateDir ?? '.starclaw');
    this.workspaceDir = path.resolve(o.workspaceDir ?? this.policy.workspace);
    fs.mkdirSync(this.stateDir, { recursive: true });
    const signer = o.signer ?? Ed25519Signer.loadOrCreate(this.stateDir);
    this.audit = new AuditLog(path.join(this.stateDir, 'audit.jsonl'), signer);
    const taint = new TaintTracker((s) => this.audit.append('taint.mark', { kind: s.kind, ref: s.ref }));
    this.spendAuthority = new MnemoPaySpendAuthority(this.id, this.policy.spend, { ledgerFile: path.join(this.stateDir, 'spend-ledger.json') });
    this.rail = o.rail ?? new NoPaymentRail();
    this.approver = o.approver;
    this.notifier = o.notifier;
    this.governor = new Governor({ policy: this.policy, audit: this.audit, taint, approver: o.approver, spendAuthority: this.spendAuthority, rail: this.rail });
    this.memory = new CognitiveMemory(path.join(this.stateDir, 'memory.db'), signer, {
      onQuarantine: (q) => this.audit.append('memory.quarantine', q),
    });
    this.skills = new SkillStore(path.join(this.stateDir, 'skills'));
    this.budget = new LlmBudget(this.policy.llmBudget.perRunCents, this.policy.llmBudget.perDayCents, path.join(this.stateDir, 'llm-budget.json'));
    this.sandbox =
      o.sandbox ??
      new SelectingSandbox({
        mode: this.policy.sandbox.mode,
        requireContainer: this.policy.sandbox.requireContainer,
        workspaceDir: this.workspaceDir,
        timeoutMs: this.policy.sandbox.timeoutSeconds * 1000,
        maxOutputBytes: this.policy.sandbox.maxOutputBytes,
        memoryMb: this.policy.sandbox.memoryMb,
        maxBrokerCalls: this.policy.sandbox.maxBrokerCalls,
        containerImage: this.policy.sandbox.containerImage,
        containerPidsLimit: this.policy.sandbox.containerPidsLimit,
        containerRuntime: this.policy.sandbox.containerRuntime,
      });
    this.taintedFiles = new TaintedFileStore(path.join(this.stateDir, 'tainted-files.json'));
    this.jobs = new JobStore(path.join(this.stateDir, 'scheduler.json'), () => this.policy.scheduled);
    this.notifyLimiter = new NotifyLimiter(path.join(this.stateDir, 'notify-log.json'), this.policy.notify);
    fs.mkdirSync(this.workspaceDir, { recursive: true });
    this.shell =
      o.shell ??
      new ShellRunner({
        workspace: fs.realpathSync.native(this.workspaceDir),
        stateDir: fs.realpathSync.native(this.stateDir),
        policy: this.policy.shell,
        runtime: this.policy.sandbox.containerRuntime,
      });
    this.broker = this.makeBroker(this.governor);
    this.main = { governor: this.governor, broker: this.broker, budget: this.budget, history: this.history };
    this.audit.append('engine.start', { id: this.id, node: process.version, platform: process.platform, learnSkills: this.learnSkills, approver: o.approver?.name ?? 'none', notifier: o.notifier?.name ?? 'none' });
  }

  private makeBroker(governor: Governor): Broker {
    return new Broker({
      governor,
      workspaceDir: this.workspaceDir,
      stateDir: this.stateDir,
      taintedFiles: this.taintedFiles,
      shell: this.shell,
      notifier: this.notifier,
      notifyLimiter: this.notifyLimiter,
      jobs: this.jobs,
    });
  }

  get tainted(): boolean {
    return this.governor.taint.tainted;
  }

  setApprover(a: Approver | undefined) {
    this.approver = a;
    this.governor.setApprover(a);
  }

  setNotifier(n: OwnerNotifier | undefined) {
    this.notifier = n;
    // The main broker was built before the notifier existed: rebuild it with the same governor.
    this.broker = this.makeBroker(this.governor);
    this.main.broker = this.broker;
  }

  /**
   * A message from StarClaw ITSELF (not from the model): e.g. "job X was paused after 5 failures". Same owner-only channel and
   * rate limits as tools.notifyOwner; the audit record is written before the send. Never throws.
   */
  async notifySystem(text: string): Promise<boolean> {
    if (!this.notifier) return false;
    const body = `[StarClaw] ${text}`.slice(0, this.policy.notify.maxChars);
    try {
      this.notifyLimiter.check();
      this.audit.append('notify.system', { chars: body.length, channel: this.notifier.name });
      await this.notifier.send(body);
      this.notifyLimiter.record();
      return true;
    } catch (e: any) {
      this.audit.append('notify.system.failed', { error: String(e?.message ?? e).slice(0, 300) });
      return false;
    }
  }

  /** Probe the sandbox (fail closed) and verify memory integrity. Throws SandboxUnavailable if unsafe. */
  async boot(): Promise<BootReport> {
    const memory = this.memory.verifyAll();
    this.audit.append('memory.verify', { ok: memory.ok, total: memory.total, tampered: memory.tampered.length, chainErrors: memory.chainErrors });
    let sandbox: ProbeReport;
    try {
      sandbox = await this.sandbox.ensureSafe();
    } catch (e: any) {
      this.audit.append('sandbox.probe', { ok: false, error: String(e.message).slice(0, 1000) });
      throw e;
    }
    this.audit.append('sandbox.probe', { ok: sandbox.ok, layer: sandbox.layer ?? this.sandbox.kind, active: this.sandbox.describe().slice(0, 600), node: sandbox.nodeVersion, checks: sandbox.results.length, skipped: sandbox.skipped });
    return { sandbox, memory };
  }

  /** Start a fresh conversation: clears history and the session taint. Only a human-facing layer should call this. */
  newSession() {
    this.history.length = 0;
    this.governor.taint.reset();
    this.audit.append('session.new', {});
  }

  private async llmCall<T>(ctx: RunCtx, fn: () => Promise<LlmResult<T>>, what: string): Promise<T> {
    const dl = ctx.governor.runContext?.deadlineAt;
    if (dl !== undefined && Date.now() > dl) throw new Error('the scheduled run exceeded its wall-clock limit (scheduled.maxRunSeconds)');
    ctx.budget.assertCanSpend();
    const r = await fn();
    const micro = costMicrocents(r.usage, r.price);
    ctx.budget.record(micro);
    this.audit.append('llm.usage', { what, jobId: ctx.scheduled?.jobId, inputTokens: r.usage.inputTokens, outputTokens: r.usage.outputTokens, microcents: micro, priceAssumed: r.priceAssumed ?? false, runCentsCeil: ctx.budget.runCentsCeil, dayCentsCeil: ctx.budget.dayCentsCeil });
    return r.value;
  }

  private runSandbox(code: string, broker: Broker): Promise<RunResult> {
    const next = this.sandboxLock.then(() => this.sandbox.run(code, (call) => broker.handle(call)));
    this.sandboxLock = next.catch(() => {});
    return next;
  }

  async executeGoal(goal: string, o: GoalOptions = {}): Promise<GoalResult> {
    return this.runGoal(this.main, goal, o);
  }

  /**
   * Run one unattended job. The run gets its OWN Governor (own taint, run context `origin: scheduled`, deadline), Broker,
   * LLM-budget view and history: nothing it does can taint or loosen an owner conversation, and it can only be
   * approved through an asynchronous approver (Telegram). Anything the policy does not auto-allow is denied.
   */
  async runScheduled(job: Job, o: { triggerAt: string; deadlineAt: number }): Promise<GoalResult> {
    const taint = new TaintTracker((s) => this.audit.append('taint.mark', { kind: s.kind, ref: s.ref, jobId: job.id }));
    const governor = new Governor({ policy: this.policy, audit: this.audit, taint, approver: this.approver, spendAuthority: this.spendAuthority, rail: this.rail });
    governor.setRunContext({ origin: 'scheduled', jobId: job.id, triggerAt: o.triggerAt, deadlineAt: o.deadlineAt });
    if (job.createdTainted) taint.mark('scheduled-job', job.id);
    const ctx: RunCtx = {
      governor,
      broker: this.makeBroker(governor),
      budget: new LlmBudget(this.policy.llmBudget.perRunCents, this.policy.llmBudget.perDayCents, path.join(this.stateDir, 'llm-budget.json')),
      history: [],
      scheduled: { jobId: job.id },
    };
    const goal = job.kind === 'heartbeat' ? heartbeatGoal(job.goal) : job.goal;
    const r = await this.runGoal(ctx, goal, { origin: 'owner', originRef: `job:${job.id}` });
    if (job.notify === 'summary' && this.notifier) {
      const body = r.success ? [r.reply, r.stdout, typeof r.result === 'string' ? r.result : r.result == null ? '' : JSON.stringify(r.result)].filter(Boolean).join('\n') || 'done' : `FAILED: ${r.error}`;
      try {
        await ctx.broker.handle({ name: 'notifyOwner', args: { text: `${job.name}: ${body}`.slice(0, 900) } });
      } catch {
        /* denied, rate-limited or send failed: all already audited */
      }
    }
    return r;
  }

  private async runGoal(ctx: RunCtx, goal: string, o: GoalOptions): Promise<GoalResult> {
    const log = (m: string) => (o.onLog ? o.onLog(m) : undefined);
    const gov = ctx.governor;
    const scheduled = !!ctx.scheduled;
    ctx.budget.newRun();
    const origin = o.origin ?? 'owner';
    if (origin !== 'owner') gov.taint.mark('non-owner-message', o.originRef ?? 'non-owner');
    this.audit.append('goal.received', { origin: scheduled ? 'scheduled' : origin, originRef: o.originRef, jobId: ctx.scheduled?.jobId, goal: goal.slice(0, 2000) });
    const fail = (kind: GoalResult['kind'], error: string, extra: Partial<GoalResult> = {}): GoalResult => {
      this.audit.append('goal.failed', { error: error.slice(0, 500), denied: extra.denied?.by, jobId: ctx.scheduled?.jobId });
      return { success: false, kind, error, tainted: gov.taint.tainted, llmCostCentsCeil: ctx.budget.runCentsCeil, ...extra };
    };
    try {
      ctx.history.push({ role: 'user', content: goal });
      // Unattended jobs are always tasks: a "conversation" reply would go nowhere.
      const intent = scheduled ? 'task' : await this.llmCall(ctx, () => this.llm.classifyIntent(goal), 'classify');
      if (intent === 'conversation') {
        const reply = await this.llmCall(ctx, () => this.llm.converse(goal, ctx.history.slice(0, -1)), 'converse');
        ctx.history.push({ role: 'assistant', content: reply });
        this.audit.append('goal.completed', { kind: 'conversation' });
        return { success: true, kind: 'conversation', reply, tainted: gov.taint.tainted, llmCostCentsCeil: ctx.budget.runCentsCeil };
      }

      // 1. Recall (verified). Tainted memories taint the session.
      const memories = this.memory.search(goal, 3);
      for (const m of memories) if (m.tainted) gov.taint.mark('tainted-memory', m.id);
      const memoryContext = memories.filter((m) => m.kind === 'note').map((m) => `- ${m.content}`).join('\n');

      // 2. Reuse a verified skill if one matches; otherwise generate.
      let code = '';
      let reusedId: string | undefined;
      const skillMem = memories.find((m) => m.kind === 'skill');
      if (skillMem) {
        try {
          code = this.skills.load(String(skillMem.meta.name), String(skillMem.meta.sha256));
          reusedId = skillMem.id;
          log(`Reusing verified skill ${skillMem.meta.name}`);
        } catch (e: any) {
          this.audit.append('skill.rejected', { name: skillMem.meta.name, error: e.message });
          log(`Skill rejected: ${e.message}`);
        }
      }
      if (!code) {
        code = await this.llmCall(ctx, () => this.llm.generateCode({ goal, memoryContext, history: ctx.history.slice(0, -1), tainted: gov.taint.tainted }), 'codegen');
        code = await this.validateAndHeal(ctx, goal, code);
      }

      // 3. Fail closed on the sandbox BEFORE asking a human to approve anything.
      await this.sandbox.ensureSafe();

      // 4. Approval to execute (decision is audited before the code runs).
      const codeHash = sha256Hex(code);
      const execAction: Action = {
        class: 'exec',
        target: 'sandbox:js',
        summary: `Run generated JavaScript (sha256 ${codeHash.slice(0, 12)}, ${code.length} chars) in the isolated sandbox; its tool calls are governed individually`,
        detail: code,
      };
      const d = await gov.authorize(execAction);
      if (!d.allowed) {
        ctx.history.push({ role: 'assistant', content: `I was not permitted to run code for that goal (${d.reason}).` });
        return fail('task', `execution not permitted: ${d.reason}`, { denied: d });
      }

      this.audit.append('exec.start', { decisionId: d.id, codeSha256: codeHash, tainted: gov.taint.tainted, jobId: ctx.scheduled?.jobId });
      const run: RunResult = await this.runSandbox(code, ctx.broker);
      this.audit.append('exec.result', {
        decisionId: d.id,
        codeSha256: codeHash,
        ok: run.ok,
        error: run.error?.slice(0, 500),
        timedOut: run.timedOut,
        brokerCalls: run.brokerCalls,
        stdoutBytes: run.stdout.length,
        durationMs: run.durationMs,
        taintedAfter: gov.taint.tainted,
      });
      if (!run.ok) {
        if (reusedId) this.memory.reportError(reusedId);
        return fail('task', run.error ?? 'execution failed', { stdout: run.stdout });
      }

      // 5. Persist what was learned (each write is itself governed; denial is not a failure of the goal).
      const content = `Completed: ${goal.slice(0, 300)}`;
      const memAction: Action = { class: 'memory.write', target: 'memory.db', summary: `Remember: ${content}`, detail: content };
      const md = await gov.authorize(memAction);
      if (md.allowed) this.memory.remember(content, { tainted: gov.taint.tainted });
      if (this.learnSkills && !reusedId && !scheduled) await this.maybeSaveSkill(gov, goal, code, codeHash);

      ctx.history.push({ role: 'assistant', content: `Ran code (sha256 ${codeHash.slice(0, 12)}); result: ${JSON.stringify(run.value ?? null).slice(0, 300)}` });
      this.audit.append('goal.completed', { kind: 'task', tainted: gov.taint.tainted, jobId: ctx.scheduled?.jobId });
      return { success: true, kind: 'task', result: run.value, stdout: run.stdout, tainted: gov.taint.tainted, llmCostCentsCeil: ctx.budget.runCentsCeil };
    } catch (e: any) {
      if (e instanceof GovernorDenied) return fail('task', e.message, { denied: e.decision });
      if (e instanceof BudgetExceeded) return fail('task', `LLM budget: ${e.message}`);
      return fail('task', String(e?.message ?? e));
    }
  }

  private async maybeSaveSkill(gov: Governor, goal: string, code: string, codeHash: string) {
    const name = sanitizeSkillName(goal.slice(0, 40));
    const action: Action = { class: 'skill.save', target: name, summary: `Save the code that just ran as reusable skill "${name}" (sha256 ${codeHash.slice(0, 12)})`, detail: code };
    const d = await gov.authorize(action);
    if (!d.allowed) return;
    const saved = this.skills.save(name, code);
    this.memory.remember(`SKILL ${saved.name}: ${goal.slice(0, 300)}`, { kind: 'skill', meta: { name: saved.name, sha256: saved.sha256 }, tainted: gov.taint.tainted });
    this.audit.append('skill.saved', { name: saved.name, sha256: saved.sha256 });
  }

  /** Syntax-check generated code (parse only, never run) and ask the LLM to repair parse errors. */
  private async validateAndHeal(ctx: RunCtx, goal: string, code: string): Promise<string> {
    let current = code;
    for (let attempt = 0; ; attempt++) {
      try {
        new vm.Script('(function (module, exports, tools, require) {\n' + current + '\n})', { filename: 'generated.js' });
        return current;
      } catch (err: any) {
        if (attempt >= MAX_FIX_ATTEMPTS) throw new Error(`generated code does not parse after ${MAX_FIX_ATTEMPTS} repair attempts: ${err.message}`);
        const msg = String(err.message);
        current = await this.llmCall(ctx, () => this.llm.fixCode(goal, current, msg), 'fixCode');
      }
    }
  }
}
