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
import { MnemoPaySpendAuthority, NoPaymentRail, PaymentRail } from './governance/spend';
import { TaintTracker, TaintedFileStore } from './governance/taint';
import { Action, Approver, Decision, GovernorDenied } from './governance/types';
import type { ChatTurn, LLM, LlmResult } from './llm/types';
import { CognitiveMemory, MemoryVerifyReport } from './memory/CognitiveMemory';
import type { RunResult, Sandbox } from './sandbox/types';
import { SelectingSandbox } from './sandbox/select';
import type { ProbeReport } from './sandbox/probe';
import { SkillStore, sanitizeSkillName } from './skills/SkillStore';

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

export class StarClawEngine {
  readonly id: string;
  readonly governor: Governor;
  readonly audit: AuditLog;
  readonly memory: CognitiveMemory;
  readonly sandbox: Sandbox;
  readonly broker: Broker;
  readonly budget: LlmBudget;
  readonly skills: SkillStore;
  readonly policy: Policy;
  readonly stateDir: string;
  readonly workspaceDir: string;
  private history: ChatTurn[] = [];
  private readonly llm: LLM;
  private readonly learnSkills: boolean;

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
    const spendAuthority = new MnemoPaySpendAuthority(this.id, this.policy.spend, { ledgerFile: path.join(this.stateDir, 'spend-ledger.json') });
    this.governor = new Governor({ policy: this.policy, audit: this.audit, taint, approver: o.approver, spendAuthority, rail: o.rail ?? new NoPaymentRail() });
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
    this.broker = new Broker({ governor: this.governor, workspaceDir: this.workspaceDir, stateDir: this.stateDir, taintedFiles: new TaintedFileStore(path.join(this.stateDir, 'tainted-files.json')) });
    this.audit.append('engine.start', { id: this.id, node: process.version, platform: process.platform, learnSkills: this.learnSkills, approver: o.approver?.name ?? 'none' });
  }

  get tainted(): boolean {
    return this.governor.taint.tainted;
  }

  setApprover(a: Approver | undefined) {
    this.governor.setApprover(a);
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
    this.history = [];
    this.governor.taint.reset();
    this.audit.append('session.new', {});
  }

  private async llmCall<T>(fn: () => Promise<LlmResult<T>>, what: string): Promise<T> {
    this.budget.assertCanSpend();
    const r = await fn();
    const micro = costMicrocents(r.usage, r.price);
    this.budget.record(micro);
    this.audit.append('llm.usage', { what, inputTokens: r.usage.inputTokens, outputTokens: r.usage.outputTokens, microcents: micro, runCentsCeil: this.budget.runCentsCeil, dayCentsCeil: this.budget.dayCentsCeil });
    return r.value;
  }

  async executeGoal(goal: string, o: GoalOptions = {}): Promise<GoalResult> {
    const log = (m: string) => (o.onLog ? o.onLog(m) : undefined);
    this.budget.newRun();
    const origin = o.origin ?? 'owner';
    if (origin !== 'owner') this.governor.taint.mark('non-owner-message', o.originRef ?? 'non-owner');
    this.audit.append('goal.received', { origin, originRef: o.originRef, goal: goal.slice(0, 2000) });
    const fail = (kind: GoalResult['kind'], error: string, extra: Partial<GoalResult> = {}): GoalResult => {
      this.audit.append('goal.failed', { error: error.slice(0, 500), denied: extra.denied?.by });
      return { success: false, kind, error, tainted: this.tainted, llmCostCentsCeil: this.budget.runCentsCeil, ...extra };
    };
    try {
      this.history.push({ role: 'user', content: goal });
      const intent = await this.llmCall(() => this.llm.classifyIntent(goal), 'classify');
      if (intent === 'conversation') {
        const reply = await this.llmCall(() => this.llm.converse(goal, this.history.slice(0, -1)), 'converse');
        this.history.push({ role: 'assistant', content: reply });
        this.audit.append('goal.completed', { kind: 'conversation' });
        return { success: true, kind: 'conversation', reply, tainted: this.tainted, llmCostCentsCeil: this.budget.runCentsCeil };
      }

      // 1. Recall (verified). Tainted memories taint the session.
      const memories = this.memory.search(goal, 3);
      for (const m of memories) if (m.tainted) this.governor.taint.mark('tainted-memory', m.id);
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
        code = await this.llmCall(() => this.llm.generateCode({ goal, memoryContext, history: this.history.slice(0, -1), tainted: this.tainted }), 'codegen');
        code = await this.validateAndHeal(goal, code);
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
      const d = await this.governor.authorize(execAction);
      if (!d.allowed) {
        this.history.push({ role: 'assistant', content: `I was not permitted to run code for that goal (${d.reason}).` });
        return fail('task', `execution not permitted: ${d.reason}`, { denied: d });
      }

      this.audit.append('exec.start', { decisionId: d.id, codeSha256: codeHash, tainted: this.tainted });
      const run: RunResult = await this.sandbox.run(code, (call) => this.broker.handle(call));
      this.audit.append('exec.result', {
        decisionId: d.id,
        codeSha256: codeHash,
        ok: run.ok,
        error: run.error?.slice(0, 500),
        timedOut: run.timedOut,
        brokerCalls: run.brokerCalls,
        stdoutBytes: run.stdout.length,
        durationMs: run.durationMs,
        taintedAfter: this.tainted,
      });
      if (!run.ok) {
        if (reusedId) this.memory.reportError(reusedId);
        return fail('task', run.error ?? 'execution failed', { stdout: run.stdout });
      }

      // 5. Persist what was learned (each write is itself governed; denial is not a failure of the goal).
      const content = `Completed: ${goal.slice(0, 300)}`;
      const memAction: Action = { class: 'memory.write', target: 'memory.db', summary: `Remember: ${content}`, detail: content };
      const md = await this.governor.authorize(memAction);
      if (md.allowed) this.memory.remember(content, { tainted: this.tainted });
      if (this.learnSkills && !reusedId) await this.maybeSaveSkill(goal, code, codeHash);

      this.history.push({ role: 'assistant', content: `Ran code (sha256 ${codeHash.slice(0, 12)}); result: ${JSON.stringify(run.value ?? null).slice(0, 300)}` });
      this.audit.append('goal.completed', { kind: 'task', tainted: this.tainted });
      return { success: true, kind: 'task', result: run.value, stdout: run.stdout, tainted: this.tainted, llmCostCentsCeil: this.budget.runCentsCeil };
    } catch (e: any) {
      if (e instanceof GovernorDenied) return fail('task', e.message, { denied: e.decision });
      if (e instanceof BudgetExceeded) return fail('task', `LLM budget: ${e.message}`);
      return fail('task', String(e?.message ?? e));
    }
  }

  private async maybeSaveSkill(goal: string, code: string, codeHash: string) {
    const name = sanitizeSkillName(goal.slice(0, 40));
    const action: Action = { class: 'skill.save', target: name, summary: `Save the code that just ran as reusable skill "${name}" (sha256 ${codeHash.slice(0, 12)})`, detail: code };
    const d = await this.governor.authorize(action);
    if (!d.allowed) return;
    const saved = this.skills.save(name, code);
    this.memory.remember(`SKILL ${saved.name}: ${goal.slice(0, 300)}`, { kind: 'skill', meta: { name: saved.name, sha256: saved.sha256 }, tainted: this.tainted });
    this.audit.append('skill.saved', { name: saved.name, sha256: saved.sha256 });
  }

  /** Syntax-check generated code (parse only, never run) and ask the LLM to repair parse errors. */
  private async validateAndHeal(goal: string, code: string): Promise<string> {
    let current = code;
    for (let attempt = 0; ; attempt++) {
      try {
        new vm.Script('(function (module, exports, tools, require) {\n' + current + '\n})', { filename: 'generated.js' });
        return current;
      } catch (err: any) {
        if (attempt >= MAX_FIX_ATTEMPTS) throw new Error(`generated code does not parse after ${MAX_FIX_ATTEMPTS} repair attempts: ${err.message}`);
        const msg = String(err.message);
        current = await this.llmCall(() => this.llm.fixCode(goal, current, msg), 'fixCode');
      }
    }
  }
}
