import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vm from 'node:vm';
import { randomUUID } from 'node:crypto';
import { Broker } from './broker';
import { AuditLog, AuditSink, scopedAudit } from './governance/audit';
import { BudgetExceeded, LlmBudget, costMicrocents } from './governance/budget';
import { canonicalize, sha256Hex } from './governance/canonical';
import { withActionLifetime } from './governance/lifetime';
import { Governor } from './governance/governor';
import { Policy, defaultPolicy } from './governance/policy';
import { ParentLimits, SpawnRequestSchema, SpendPool, SpendSlice, SubagentRejected, SubagentScope, attenuate, rootScope, scopeSha256, scopeSummary } from './governance/subagent';
import { Ed25519Signer, Signer } from './governance/signer';
import { MnemoPaySpendAuthority, NoPaymentRail, PaymentRail, SpendAuthority } from './governance/spend';
import { TaintTracker, TaintedFileStore } from './governance/taint';
import { Action, Approver, Decision, GovernorDenied, SubagentRef } from './governance/types';
import type { ChatTurn, LLM, LlmResult, LlmCallOptions } from './llm/types';
import { CognitiveMemory, MemoryVerifyReport } from './memory/CognitiveMemory';
import { DEFAULT_TOOL_NAMES, type RunResult, type Sandbox } from './sandbox/types';
import { SelectingSandbox } from './sandbox/select';
import type { ProbeReport } from './sandbox/probe';
import { SkillStore, sanitizeSkillName } from './skills/SkillStore';
import { NotifyLimiter, OwnerNotifier } from './notify/Notifier';
import { Job, JobStore } from './scheduler/JobStore';
import { ShellRunner } from './shell/ShellRunner';
import { SkillRegistry, SkillRefused, InstallOptions, InstallResult } from './skills/registry/registry';
import { AttenuatedGovernor, attenuatedHandler, unmetRequirements } from './skills/registry/attenuate';

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
  /** Host-side path of the browser control.json (tests; default is the OS location). */
  browserDiscoveryPath?: string;
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
  /** Identifies this run in the audit log; a sub-agent's parent id points at it. New for every goal. */
  runId: string;
  /** Where this run's spend slices are carved from. */
  pool: SpendPool;
  /** Children this run has started (reset for every goal). */
  spawned: { total: number; live: number };
  audit: AuditSink;
  /** Present only for a sub-agent run. */
  sub?: { ref: SubagentRef; scope: SubagentScope };
}

/** What a parent's code gets back from tools.spawnAgent. Everything in it is untrusted data. */
export interface SubagentResult {
  untrusted: true;
  childId: string;
  ok: boolean;
  result?: unknown;
  resultTruncated?: boolean;
  stdout?: string;
  error?: string;
  deniedBy?: string;
  childTainted: boolean;
  llmCostCents: number;
  spentCents: number;
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
  /** Signed, owner-approved skills (policy skillsRegistry; disabled by default). Separate from the agent's own hash-pinned `skills`. */
  readonly registry: SkillRegistry;
  readonly policy: Policy;
  readonly stateDir: string;
  readonly workspaceDir: string;
  readonly jobs: JobStore;
  readonly shell: ShellRunner;
  private notifier?: OwnerNotifier;
  private readonly browserDiscoveryPath?: string;
  private readonly notifyLimiter: NotifyLimiter;
  private readonly taintedFiles: TaintedFileStore;
  private readonly spendAuthority: SpendPool;
  private readonly rail: PaymentRail;
  private approver?: Approver;
  private history: ChatTurn[] = [];
  private readonly llm: LLM;
  private readonly learnSkills: boolean;
  /** At most one generated-code run (and so at most one sandbox container) at a time, across owner and scheduled runs. */
  private sandboxLock: Promise<unknown> = Promise.resolve();
  private readonly main: RunCtx;
  private ownerQueue: Promise<unknown> = Promise.resolve();
  private ownerPending = 0;

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
    this.spendAuthority = new SpendPool(new MnemoPaySpendAuthority(this.id, this.policy.spend, { ledgerFile: path.join(this.stateDir, 'spend-ledger.json') }), this.policy.spend.maxTotalCents);
    this.rail = o.rail ?? new NoPaymentRail();
    this.approver = o.approver;
    this.notifier = o.notifier;
    this.browserDiscoveryPath = o.browserDiscoveryPath;
    this.governor = new Governor({ policy: this.policy, audit: this.audit, taint, approver: o.approver, spendAuthority: this.spendAuthority, rail: this.rail });
    this.memory = new CognitiveMemory(path.join(this.stateDir, 'memory.db'), signer, {
      onQuarantine: (q) => this.audit.append('memory.quarantine', q),
    });
    this.skills = new SkillStore(path.join(this.stateDir, 'skills'));
    this.registry = new SkillRegistry({
      dir: path.join(this.stateDir, 'skills-registry'),
      signer,
      audit: this.audit,
      policy: () => this.policy.skillsRegistry,
      authorize: (a) => this.governor.authorize(a),
    });
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
    this.main = { governor: this.governor, broker: undefined as unknown as Broker, budget: this.budget, history: this.history, runId: randomUUID(), pool: this.spendAuthority, spawned: { total: 0, live: 0 }, audit: this.audit };
    this.broker = this.makeBroker(this.governor, () => this.main);
    this.main.broker = this.broker;
    this.audit.append('engine.start', { id: this.id, node: process.version, platform: process.platform, learnSkills: this.learnSkills, approver: o.approver?.name ?? 'none', notifier: o.notifier?.name ?? 'none' });
  }

  private makeBroker(governor: Governor, ctx: () => RunCtx, scope?: SubagentScope): Broker {
    return new Broker({
      scope,
      spawn: (args) => this.spawnSubagent(ctx(), args),
      governor,
      workspaceDir: this.workspaceDir,
      stateDir: this.stateDir,
      taintedFiles: this.taintedFiles,
      shell: this.shell,
      notifier: this.notifier,
      notifyLimiter: this.notifyLimiter,
      jobs: this.jobs,
      browserDiscoveryPath: this.browserDiscoveryPath,
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
    this.broker = this.makeBroker(this.governor, () => this.main);
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
  newSession(): boolean {
    if (this.ownerPending) return false; // Never clear provenance held by an active or queued run.
    this.history.length = 0;
    this.governor.taint.reset();
    this.governor.setRunContext(undefined);
    this.audit.append('session.new', {});
    return true;
  }

  private async llmCall<T>(ctx: RunCtx, fn: (options: LlmCallOptions) => Promise<LlmResult<T>>, what: string): Promise<T> {
    const dl = ctx.governor.runContext?.deadlineAt;
    if (dl !== undefined && Date.now() > dl) throw new Error(ctx.sub ? 'the sub-agent exceeded its wall-clock deadline' : ctx.scheduled ? 'the scheduled run exceeded its wall-clock limit (scheduled.maxRunSeconds)' : 'the agent exceeded its wall-clock deadline');
    ctx.budget.assertCanSpend();
    const r = await fn({ budget: ctx.budget });
    const micro = costMicrocents(r.usage, r.price);
    if (!r.prepaid) ctx.budget.record(micro);
    ctx.audit.append('llm.usage', { what, jobId: ctx.scheduled?.jobId, inputTokens: r.usage.inputTokens, outputTokens: r.usage.outputTokens, microcents: micro, priceAssumed: r.priceAssumed ?? false, runCentsCeil: ctx.budget.runCentsCeil, dayCentsCeil: ctx.budget.dayCentsCeil });
    return r.value;
  }

  private runSandbox(code: string, broker: Pick<Broker, 'handle'>, unlocked = false): Promise<RunResult> {
    // A sub-agent runs INSIDE its parent's brokered call, so the parent holds the lock: waiting for it would deadlock.
    // Sub-agent runs are capped by subagents.maxConcurrent instead.
    const invoke = async () => {
      let live = true;
      try {
        return await this.sandbox.run(code, (call) => withActionLifetime(() => live, () => broker.handle(call)));
      } finally { live = false; }
    };
    if (unlocked) return invoke();
    const next = this.sandboxLock.then(invoke);
    this.sandboxLock = next.catch(() => {});
    return next;
  }

  private enqueueOwner<T>(fn: () => Promise<T>): Promise<T> {
    this.ownerPending++;
    const pending = this.ownerQueue.then(fn).finally(() => { this.ownerPending--; });
    this.ownerQueue = pending.catch(() => {});
    return pending;
  }

  async executeGoal(goal: string, o: GoalOptions = {}): Promise<GoalResult> {
    return this.enqueueOwner(() => {
      this.governor.setRunContext(undefined);
      return this.runGoal(this.main, goal, o);
    });
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
      broker: undefined as unknown as Broker,
      budget: new LlmBudget(this.policy.llmBudget.perRunCents, this.policy.llmBudget.perDayCents, path.join(this.stateDir, 'llm-budget.json')),
      history: [],
      scheduled: { jobId: job.id },
      runId: randomUUID(),
      pool: this.spendAuthority,
      spawned: { total: 0, live: 0 },
      audit: this.audit,
    };
    ctx.broker = this.makeBroker(governor, () => ctx);
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

  // ---- governed sub-agents -----------------------------------------------------------------------------------------

  /** What this run can hand to a child right now: its own scope plus live availability. */
  private parentLimits(parent: RunCtx): ParentLimits {
    return {
      scope: parent.sub?.scope ?? rootScope(DEFAULT_TOOL_NAMES),
      spendAvailableCents: parent.pool.availableCents,
      llmAvailableCents: parent.budget.availableRunCents,
      actionsRemaining: parent.governor.actionsRemaining,
      now: Date.now(),
      ttlCeilingSeconds: this.policy.sandbox.timeoutSeconds,
    };
  }

  /**
   * tools.spawnAgent. The child is a separate run (own Governor, taint, budget, history, broker) whose authority is the
   * parent's INTERSECTED with what the parent asked for: a request that asks for more than the parent holds is rejected
   * before a child exists. Order of events, all in the one audit chain: rejection or the spawn decision (decision.request/
   * decision.result, then subagent.spawn) BEFORE the child's first record; the child's records carry runId/parentRunId;
   * subagent.result AFTER. The answer is untrusted data and taints the parent's session.
   */
  private async spawnSubagent(parent: RunCtx, raw: unknown): Promise<SubagentResult> {
    const pol = this.policy.subagents;
    const gov = parent.governor;
    const depth = (parent.sub?.scope.depth ?? 0) + 1;
    const reject = (reasons: string[]): never => {
      parent.audit.append('subagent.rejected', { spawnerRunId: parent.runId, depth, reasons: reasons.slice(0, 20).map((r) => r.slice(0, 300)) });
      throw new SubagentRejected(reasons);
    };
    const limitReasons = (): string[] => {
      const why: string[] = [];
      if (parent.spawned.total >= pol.maxTotalPerRun) why.push(`this run already started ${parent.spawned.total} sub-agents (subagents.maxTotalPerRun = ${pol.maxTotalPerRun})`);
      if (parent.spawned.live >= pol.maxConcurrent) why.push(`${parent.spawned.live} sub-agents are already running (subagents.maxConcurrent = ${pol.maxConcurrent})`);
      return why;
    };

    if (!pol.enabled) return reject(['sub-agents are disabled (policy subagents.enabled = false)']);
    const parsed = SpawnRequestSchema.safeParse(raw);
    if (!parsed.success) return reject(['malformed request: ' + parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')]);
    const req = parsed.data;
    const early = limitReasons();
    if (early.length) return reject(early);

    const attenuateNow = (): SubagentScope => {
      try {
        return attenuate(this.parentLimits(parent), req, pol);
      } catch (e) {
        if (e instanceof SubagentRejected) return reject(e.reasons);
        throw e;
      }
    };
    const approvedScope = attenuateNow();

    const childId = randomUUID();
    const chain = [...(parent.sub?.ref.chain ?? [parent.runId]), childId];
    const action: Action = {
      class: 'agent.spawn',
      target: `depth-${approvedScope.depth}`,
      summary: `Start a SUB-AGENT (depth ${approvedScope.depth}; chain ${chain.join(' > ')}; tools: ${approvedScope.tools.join(', ')}; spend ${approvedScope.spendCents}c; LLM ${approvedScope.llmCents}c): ${req.goal.replace(/\s+/g, ' ').slice(0, 150)}`.slice(0, 400),
      detail: JSON.stringify({ childId, parentRunId: parent.runId, chain, goal: req.goal, scope: scopeSummary(approvedScope) }, null, 2),
    };
    const d = await gov.authorize(action);
    if (!d.allowed) throw new GovernorDenied(d, action);

    // After the (possibly long) approval: the clock starts now, availability may have changed. Re-derive from the SAME request;
    // the result may be smaller than what was approved, never larger. Everything from here to the carve is synchronous, so
    // concurrent spawns cannot all pass the same check.
    const scope = attenuateNow();
    if (scope.llmCents > approvedScope.llmCents || (scope.maxActions ?? 0) > (approvedScope.maxActions ?? 0) || scope.spendCents !== approvedScope.spendCents || scope.tools.join() !== approvedScope.tools.join()) {
      return reject(['the request resolved to a different scope after approval; nothing was started']);
    }
    const late = limitReasons();
    if (late.length) return reject(late);
    let spendSlice: SpendSlice | undefined;
    let llmSlice: ReturnType<LlmBudget['carve']> | undefined;
    try {
      spendSlice = parent.pool.carve(scope.spendCents, Math.min(gov.policy.spend.maxPerActionCents, scope.spendCents));
      llmSlice = parent.budget.carve(scope.llmCents);
    } catch (e: any) {
      spendSlice?.close();
      return reject([String(e?.message ?? e)]);
    }
    parent.spawned.total++;
    parent.spawned.live++;

    // The spawn is on the record BEFORE the child exists.
    const ref: SubagentRef = { runId: childId, parentRunId: parent.runId, chain, depth: scope.depth, goal: req.goal.slice(0, 2000) };
    parent.audit.append('subagent.spawn', {
      childId,
      spawnerRunId: parent.runId,
      chain,
      depth: scope.depth,
      decisionId: d.id,
      goal: req.goal.slice(0, 2000),
      scope: scopeSummary(scope),
      scopeSha256: scopeSha256(scope),
      parentTainted: gov.taint.tainted,
      llmSliceCents: scope.llmCents,
      spendSliceCents: scope.spendCents,
      liveChildren: parent.spawned.live,
      totalChildren: parent.spawned.total,
    });

    const audit = scopedAudit(this.audit, { runId: childId, parentRunId: parent.runId, subagentDepth: scope.depth });
    const taint = new TaintTracker((s) => audit.append('taint.mark', { kind: s.kind, ref: s.ref }));
    taint.inherit(gov.taint.provenance());
    const childPolicy: Policy = structuredClone(gov.policy);
    childPolicy.spend = { ...childPolicy.spend, maxTotalCents: scope.spendCents, maxPerActionCents: Math.min(childPolicy.spend.maxPerActionCents, scope.spendCents) };
    childPolicy.llmBudget = { ...childPolicy.llmBudget, perRunCents: scope.llmCents };
    const childPool = new SpendPool(spendSlice, scope.spendCents);
    const cgov = new Governor({ policy: childPolicy, audit, taint, approver: this.approver, spendAuthority: childPool, rail: this.rail });
    const pctx = gov.runContext;
    cgov.setRunContext({ origin: pctx?.origin === 'scheduled' ? 'scheduled' : 'owner', jobId: pctx?.jobId, triggerAt: pctx?.triggerAt, deadlineAt: scope.deadlineAt, subagent: ref, scope });
    const child: RunCtx = { governor: cgov, broker: undefined as unknown as Broker, budget: llmSlice.budget, history: [], scheduled: parent.scheduled, runId: childId, pool: childPool, spawned: { total: 0, live: 0 }, audit, sub: { ref, scope } };
    child.broker = this.makeBroker(cgov, () => child, scope);

    let res: GoalResult;
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;
    try {
      const wait = Math.max(1, (scope.deadlineAt ?? Date.now()) - Date.now()) + 2000;
      res = await Promise.race([
        this.runGoal(child, req.goal, { origin: 'owner', originRef: `subagent:${childId}` }),
        new Promise<GoalResult>((resolve) => {
          timer = setTimeout(() => {
            timedOut = true;
            resolve({ success: false, kind: 'task', error: 'the sub-agent did not finish before its wall-clock deadline', tainted: cgov.taint.tainted, llmCostCentsCeil: llmSlice!.budget.runCentsCeil });
          }, wait);
          timer.unref?.();
        }),
      ]);
    } catch (e: any) {
      res = { success: false, kind: 'task', error: String(e?.message ?? e).slice(0, 500), tainted: cgov.taint.tainted, llmCostCentsCeil: llmSlice.budget.runCentsCeil };
    } finally {
      if (timer) clearTimeout(timer);
    }
    // Unspent budget goes back to the parent; a child that was abandoned mid-call is charged its whole LLM slice.
    const llmSpent = llmSlice.close(timedOut);
    const spend = spendSlice.close();
    parent.spawned.live--;

    const max = pol.maxResultChars;
    const resJson = JSON.stringify(res.result ?? null) ?? 'null';
    const resultTruncated = resJson.length > max;
    const out: SubagentResult = {
      untrusted: true,
      childId,
      ok: res.success,
      result: resultTruncated ? resJson.slice(0, max) : res.result ?? null,
      ...(resultTruncated ? { resultTruncated: true } : {}),
      stdout: (res.stdout ?? '').slice(0, max),
      error: res.error?.slice(0, 500),
      deniedBy: res.denied?.by,
      childTainted: res.tainted,
      llmCostCents: Math.ceil(llmSpent.spentMicro / 1_000_000),
      spentCents: spend.spentCents,
    };
    parent.audit.append('subagent.result', {
      childId,
      spawnerRunId: parent.runId,
      chain,
      ok: out.ok,
      error: out.error,
      deniedBy: out.deniedBy,
      timedOut,
      childTainted: out.childTainted,
      llmMicrocents: llmSpent.spentMicro,
      llmCostCents: out.llmCostCents,
      spentCents: spend.spentCents,
      returnedSpendCents: spend.returnedCents,
      resultSha256: sha256Hex(JSON.stringify(out.result ?? null) + '\n' + (out.stdout ?? '')),
      resultTruncated,
      liveChildren: parent.spawned.live,
    });
    // Whatever the child produced is data from a run that may have been steered by hostile content: it taints the parent,
    // clean child or not, so a hijacked child cannot hand its parent anything that skips the parent's own approvals.
    gov.taint.mark('subagent-result', childId);
    return out;
  }

  private async runGoal(ctx: RunCtx, goal: string, o: GoalOptions): Promise<GoalResult> {
    const log = (m: string) => (o.onLog ? o.onLog(m) : undefined);
    const gov = ctx.governor;
    const scheduled = !!ctx.scheduled;
    const sub = ctx.sub;
    if (!sub) {
      ctx.runId = randomUUID();
      ctx.spawned = { total: 0, live: 0 };
    }
    const agentDeadline = Date.now() + this.policy.agent.maxSeconds * 1000;
    gov.setRunContext({ ...(gov.runContext ?? { origin: 'owner' as const }), deadlineAt: Math.min(agentDeadline, gov.runContext?.deadlineAt ?? agentDeadline) });
    ctx.budget.newRun();
    const origin = o.origin ?? 'owner';
    if (origin !== 'owner') gov.taint.mark('non-owner-message', o.originRef ?? 'non-owner');
    ctx.audit.append('goal.received', { origin: scheduled ? 'scheduled' : origin, originRef: o.originRef, jobId: ctx.scheduled?.jobId, runId: ctx.runId, goal: goal.slice(0, 2000) });
    const fail = (kind: GoalResult['kind'], error: string, extra: Partial<GoalResult> = {}): GoalResult => {
      ctx.audit.append('goal.failed', { error: error.slice(0, 500), denied: extra.denied?.by, jobId: ctx.scheduled?.jobId });
      return { success: false, kind, error, tainted: gov.taint.tainted, llmCostCentsCeil: ctx.budget.runCentsCeil, ...extra };
    };
    try {
      ctx.history.push({ role: 'user', content: goal });
      // Unattended jobs are always tasks: a "conversation" reply would go nowhere.
      const intent = scheduled || sub ? 'task' : await this.llmCall(ctx, (options) => this.llm.classifyIntent(goal, options), 'classify');
      if (intent === 'conversation') {
        const reply = await this.llmCall(ctx, (options) => this.llm.converse(goal, ctx.history.slice(0, -1), options), 'converse');
        ctx.history.push({ role: 'assistant', content: reply });
        ctx.audit.append('goal.completed', { kind: 'conversation' });
        return { success: true, kind: 'conversation', reply, tainted: gov.taint.tainted, llmCostCentsCeil: ctx.budget.runCentsCeil };
      }

      // 1. Recall (verified). Tainted memories taint the session.
      // A sub-agent never reads the parent's memory (memories are the owner's, and may be tainted): it gets none.
      const memories = sub ? [] : this.memory.search(goal, 3);
      for (const m of memories) if (m.tainted) gov.taint.mark('tainted-memory', m.id);
      const memoryContext = memories.filter((m) => m.kind === 'note').map((m) => `- ${m.content}`).join('\n');

      // 2. Reuse a verified skill if one matches; otherwise generate.
      let code = '';
      let reusedId: string | undefined;
      const skillMem = memories.find((m) => m.kind === 'skill' && m.meta.goal === goal);
      if (skillMem) {
        try {
          code = this.skills.load(String(skillMem.meta.name), String(skillMem.meta.sha256));
          reusedId = skillMem.id;
          log(`Reusing verified skill ${skillMem.meta.name}`);
        } catch (e: any) {
          ctx.audit.append('skill.rejected', { name: skillMem.meta.name, error: e.message });
          log(`Skill rejected: ${e.message}`);
        }
      }
      if (!code) {
        code = await this.llmCall(ctx, (options) => this.llm.generateCode({ goal, memoryContext, history: ctx.history.slice(0, -1), tainted: gov.taint.tainted, subagent: sub && { depth: sub.scope.depth, tools: [...sub.scope.tools], domains: sub.scope.domains === 'any' ? 'any' : [...sub.scope.domains], readPaths: [...sub.scope.readPaths], writePaths: [...sub.scope.writePaths], spendCents: sub.scope.spendCents, maxActions: sub.scope.maxActions } }, options), 'codegen');
        code = await this.validateAndHeal(ctx, goal, code);
      }

      let codeHash = '';
      let run!: RunResult;
      let retries = 0;
      let usedSteps = 0;
      const deadline = gov.runContext!.deadlineAt!;
      const effects = new Map<string, { step: number; result: unknown }>();
      const deduplicate = new Set(['writeFile', 'editFile', 'applyPatch', 'spend', 'notifyOwner', 'scheduleCreate']);
      const observations: ChatTurn[] = [];
      const readOnly = new Set(['readFile', 'listDir', 'fetchUrl', 'search', 'browseReadText', 'browseReadLinks']);
      for (let step = 0; step < this.policy.agent.maxSteps; step++) {
        usedSteps++;
        if (Date.now() >= deadline) return fail('task', 'agent wall-clock limit exceeded');
        let attemptedEffect = false;
        let denied: Decision | undefined;
        const stepBroker = { handle: async (call: Parameters<Broker['handle']>[0]) => {
          if (Date.now() >= deadline) throw new Error('agent wall-clock limit exceeded');
          const effect = !readOnly.has(call.name);
          const key = effect ? sha256Hex(canonicalize(call)) : '';
          const previous = effects.get(key);
          if (effect && deduplicate.has(call.name) && previous && previous.step < step) return previous.result;
          if (effect) attemptedEffect = true;
          try {
            const result = await ctx.broker.handle(call);
            if (effect) effects.set(key, { step, result });
            return result;
          } catch (e) {
            if (e instanceof GovernorDenied) denied = e.decision;
            throw e;
          }
        }};
        // 3. Fail closed on the sandbox BEFORE asking a human to approve anything.
        await this.sandbox.ensureSafe();

        // 4. Approval to execute (decision is audited before the code runs).
        codeHash = sha256Hex(code);
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

        ctx.audit.append('exec.start', { decisionId: d.id, codeSha256: codeHash, tainted: gov.taint.tainted, jobId: ctx.scheduled?.jobId });
        run = await this.runSandbox(code, stepBroker, !!sub);
        ctx.audit.append('exec.result', {
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
        const continuation = run.ok && run.value && typeof run.value === 'object' && (run.value as any).__starclaw === 'continue';
        if (denied && (!run.ok || continuation)) return fail('task', run.error ?? `Denied (${denied.by}): ${denied.reason}`, { denied, stdout: run.stdout });
        if (run.ok && !continuation) break;
        if (!run.ok) {
          if (reusedId) this.memory.reportError(reusedId);
          // A failed side effect has an ambiguous outcome: never automatically replay it.
          if (attemptedEffect || run.timedOut || retries >= this.policy.agent.maxRuntimeRetries) return fail('task', run.error ?? 'execution failed', { stdout: run.stdout });
          retries++;
        }
        if (step + 1 >= this.policy.agent.maxSteps) return fail('task', 'agent step limit exceeded before completion', { stdout: run.stdout });
        // Any observation sent back into a model is untrusted, including errors.
        gov.taint.mark('tool-output', `agent-step:${step + 1}`);
        const observation = JSON.stringify({ ok: run.ok, result: run.value, error: run.error, stdout: run.stdout }).slice(0, 12000);
        observations.push({ role: 'assistant', content: code.slice(0, 16000) }, { role: 'user', content: `UNTRUSTED OBSERVATION from step ${step + 1}: ${observation}\nContinue the original goal from this progress. Do not repeat completed side effects. Verify the outcome before returning a final result.` });
        ctx.audit.append('agent.continue', { step: step + 1, runtimeRetry: !run.ok, observationSha256: sha256Hex(observation) });
        log(`Planning step ${step + 2} from observed results`);
        reusedId = undefined;
        code = await this.llmCall(ctx, (options) => this.llm.generateCode({ goal, memoryContext, history: [...ctx.history.slice(0, -1), ...observations], tainted: true, subagent: sub && { depth: sub.scope.depth, tools: [...sub.scope.tools], domains: sub.scope.domains === 'any' ? 'any' : [...sub.scope.domains], readPaths: [...sub.scope.readPaths], writePaths: [...sub.scope.writePaths], spendCents: sub.scope.spendCents, maxActions: sub.scope.maxActions } }, options), 'replan');
        code = await this.validateAndHeal(ctx, goal, code);
      }

      // 5. Persist what was learned (each write is itself governed; denial is not a failure of the goal).
      // (A sub-agent writes no memory and saves no skill: its answer goes to its parent, which decides what to keep.)
      if (!sub) {
        const content = `Completed: ${goal.slice(0, 300)}\nOutcome (untrusted data): ${JSON.stringify(run.value ?? null).slice(0, 2000)}`;
        const memAction: Action = { class: 'memory.write', target: 'memory.db', summary: `Remember: ${content}`, detail: content };
        const md = await gov.authorize(memAction);
        if (md.allowed) this.memory.remember(content, { tainted: gov.taint.tainted });
      }
      if (this.learnSkills && !reusedId && !scheduled && !sub && usedSteps === 1) await this.maybeSaveSkill(gov, goal, code, codeHash);

      ctx.history.push({ role: 'assistant', content: `Ran code (sha256 ${codeHash.slice(0, 12)}); result: ${JSON.stringify(run.value ?? null).slice(0, 300)}` });
      ctx.audit.append('goal.completed', { kind: 'task', tainted: gov.taint.tainted, jobId: ctx.scheduled?.jobId });
      return { success: true, kind: 'task', result: run.value, stdout: run.stdout, tainted: gov.taint.tainted, llmCostCentsCeil: ctx.budget.runCentsCeil };
    } catch (e: any) {
      if (e instanceof GovernorDenied) return fail('task', e.message, { denied: e.decision });
      if (e instanceof BudgetExceeded) return fail('task', `LLM budget: ${e.message}`);
      return fail('task', String(e?.message ?? e));
    }
  }

  /** Install a signed bundle from a local file. The owner's approval is requested through the Governor (class skill.install; no approver = deny). */
  installRegistrySkill(file: string, o: InstallOptions = {}): Promise<InstallResult> {
    return this.registry.install(file, o);
  }

  /**
   * Run an installed registry skill. It is re-verified in full on every run (signature, hashes, expiry, revocation) and then
   * runs ATTENUATED: its declared capabilities intersected with the current policy, never wider. Unsigned/agent-authored
   * skills (`this.skills`) are unaffected by this path and keep their existing semantics.
   */
  runRegistrySkill(id: string, o: GoalOptions = {}): Promise<GoalResult> {
    return this.enqueueOwner(() => this.runRegistrySkillNow(id, o));
  }

  private async runRegistrySkillNow(id: string, o: GoalOptions): Promise<GoalResult> {
    const gov = this.governor;
    gov.setRunContext({ origin: 'owner', deadlineAt: Date.now() + this.policy.agent.maxSeconds * 1000 });
    const fail = (error: string, extra: Partial<GoalResult> = {}): GoalResult => {
      this.audit.append('goal.failed', { error: error.slice(0, 500), skill: id });
      return { success: false, kind: 'task', error, tainted: gov.taint.tainted, llmCostCentsCeil: 0, ...extra };
    };
    try {
      const skill = this.registry.load(id);
      const { manifest } = skill;
      const unmet = unmetRequirements(this.policy, manifest.capabilities);
      if (unmet.length) {
        this.audit.append('skillreg.refused', { code: 'capability-not-granted', id, version: manifest.version, unmet });
        return fail(`skill ${id} requires capabilities the current policy does not grant: ${unmet.join('; ')}`);
      }
      const origin = o.origin ?? 'owner';
      if (origin !== 'owner') gov.taint.mark('non-owner-message', o.originRef ?? 'non-owner');
      await this.sandbox.ensureSafe();
      const ref = `${manifest.id}@${manifest.version}`;
      const agov = new AttenuatedGovernor(
        { policy: this.policy, audit: this.audit, taint: gov.taint, approver: this.approver, spendAuthority: this.spendAuthority, rail: this.rail },
        manifest.capabilities,
        { id: manifest.id, version: manifest.version },
        fs.realpathSync.native(this.workspaceDir),
      );
      agov.setRunContext(gov.runContext);
      const codeHash = sha256Hex(skill.code);
      const d = await agov.authorize({
        class: 'exec',
        target: `skill:${ref}`,
        summary: `Run signed registry skill ${ref} (publisher ${manifest.publisher}, bundle sha256 ${skill.bundleSha256.slice(0, 12)}) in the isolated sandbox, attenuated to its declared capabilities`,
        detail: `${manifest.description}
declared: tools=${manifest.capabilities.tools.join(',') || '-'} optional=${manifest.capabilities.optionalTools.join(',') || '-'} domains=${manifest.capabilities.domains.join(',') || '-'} paths=${manifest.capabilities.paths.join(',') || '-'} spendCents=${manifest.capabilities.spendCents}
--- code ---
${skill.code}`,
      });
      if (!d.allowed) return fail(`execution not permitted: ${d.reason}`, { denied: d });
      // The skill runs inside the owner's main run, but any sub-agent it spawns must inherit the ATTENUATED governor, never the owner's.
      const broker = this.makeBroker(agov, () => ({ ...this.main, governor: agov }));
      const handler = attenuatedHandler((call) => broker.handle(call), manifest.capabilities, { id: manifest.id, version: manifest.version }, this.audit);
      this.audit.append('exec.start', { decisionId: d.id, codeSha256: codeHash, skill: ref, bundleSha256: skill.bundleSha256, tainted: gov.taint.tainted });
      const run = await this.runSandbox(skill.code, { handle: handler });
      this.audit.append('exec.result', { decisionId: d.id, codeSha256: codeHash, skill: ref, ok: run.ok, error: run.error?.slice(0, 500), timedOut: run.timedOut, brokerCalls: run.brokerCalls, stdoutBytes: run.stdout.length, durationMs: run.durationMs, taintedAfter: gov.taint.tainted });
      // A revocation that landed while it ran is recorded; the run's effects were already governed call by call.
      if (!run.ok) return fail(run.error ?? 'execution failed', { stdout: run.stdout });
      return { success: true, kind: 'task', result: run.value, stdout: run.stdout, tainted: gov.taint.tainted, llmCostCentsCeil: 0 };
    } catch (e: any) {
      if (e instanceof GovernorDenied) return fail(e.message, { denied: e.decision });
      if (e instanceof SkillRefused) return fail(`skill refused: ${e.message}`);
      return fail(String(e?.message ?? e));
    }
  }

  private async maybeSaveSkill(gov: Governor, goal: string, code: string, codeHash: string) {
    const name = sanitizeSkillName(goal.slice(0, 40));
    const action: Action = { class: 'skill.save', target: name, summary: `Save the code that just ran as reusable skill "${name}" (sha256 ${codeHash.slice(0, 12)})`, detail: code };
    const d = await gov.authorize(action);
    if (!d.allowed) return;
    const saved = this.skills.save(name, code);
    this.memory.remember(`SKILL ${saved.name}: ${goal.slice(0, 300)}`, { kind: 'skill', meta: { name: saved.name, sha256: saved.sha256, goal }, tainted: gov.taint.tainted });
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
        current = await this.llmCall(ctx, (options) => this.llm.fixCode(goal, current, msg, options), 'fixCode');
      }
    }
  }
}
