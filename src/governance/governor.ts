import { randomUUID } from 'node:crypto';
import type { AuditSink } from './audit';
import { Policy, evaluatePolicy } from './policy';
import { SubagentScope, scopeClasses, scopeDenies } from './subagent';
import { PaymentRail, SpendAuthority, isValidCents, NoPaymentRail } from './spend';
import { TaintTracker } from './taint';
import {
  ALWAYS_ASK,
  Action,
  ApprovalAnswer,
  ActionClass,
  ApprovalRequest,
  Approver,
  Decision,
  DENIED_IN_SUBAGENT,
  DENIED_WHEN_SCHEDULED,
  GovernorDenied,
  NEVER_AUTO_WHEN_SCHEDULED,
  TAINT_SENSITIVE,
  SubagentRef,
  Verdict,
} from './types';

/** Who is driving the current run. Set by the engine around each goal; scheduled runs are unattended. */
export interface RunContext {
  origin: 'owner' | 'non-owner' | 'scheduled';
  jobId?: string;
  triggerAt?: string;
  /** Epoch ms after which every governed action in this run is denied (scheduled.maxRunSeconds). */
  deadlineAt?: number;
  /** Set for a sub-agent run: who it is, and the scope its parent granted. The scope can only remove authority. */
  subagent?: SubagentRef;
  scope?: SubagentScope;
}

export interface GovernorOptions {
  policy: Policy;
  audit: AuditSink;
  taint: TaintTracker;
  /** No approver = non-interactive: every `ask` becomes a deny. */
  approver?: Approver;
  spendAuthority?: SpendAuthority;
  rail?: PaymentRail;
}

/**
 * The single choke point. Every action that touches the outside world is described as an Action and passed to
 * authorize()/governed(). The decision is written to the audit log BEFORE the action runs; the result after.
 */
export class Governor {
  readonly policy: Policy;
  readonly audit: AuditSink;
  readonly taint: TaintTracker;
  private approver?: Approver;
  private readonly spendAuthority?: SpendAuthority;
  private readonly rail: PaymentRail;
  private ctx?: RunContext;
  private actionsAttempted = 0;
  private scopeClassSet?: Set<ActionClass>;

  constructor(opts: GovernorOptions) {
    this.policy = opts.policy;
    this.audit = opts.audit;
    this.taint = opts.taint;
    this.approver = opts.approver;
    this.spendAuthority = opts.spendAuthority;
    this.rail = opts.rail ?? new NoPaymentRail();
  }

  setApprover(a: Approver | undefined) {
    this.approver = a;
  }

  setRunContext(ctx: RunContext | undefined) {
    this.ctx = ctx;
    this.scopeClassSet = ctx?.scope ? scopeClasses(ctx.scope) : undefined;
    this.actionsAttempted = 0;
  }
  /** Governed actions a sub-agent run may still attempt (null = no limit). */
  get actionsRemaining(): number | null {
    const max = this.ctx?.scope?.maxActions;
    return max === undefined || max === null ? null : Math.max(0, max - this.actionsAttempted);
  }
  get runContext(): RunContext | undefined {
    return this.ctx;
  }

  /** Decide whether `action` may run. Never throws for a denial; returns the Decision. */
  async authorize(action: Action): Promise<Decision> {
    const id = randomUUID();
    const provenance = this.taint.provenance();
    const decide = (allowed: boolean, by: Decision['by'], reason: string, escalated: boolean): Decision => ({
      id,
      allowed,
      by,
      reason,
      escalatedByTaint: escalated,
      provenance,
    });

    // 0. Hard validation that no policy can relax.
    if (action.class === 'spend') {
      if (!isValidCents(action.cents)) {
        return this.finish(action, decide(false, 'hard-rule', 'spend amount must be a positive integer number of cents', false));
      }
    }

    // 1. Policy.
    const ev = evaluatePolicy(this.policy, action);
    let verdict: Verdict = ev.verdict;
    let escalated = false;
    const scheduled = this.ctx?.origin === 'scheduled';

    // 1b. Unattended runs may never use these classes at all, whatever the policy says.
    if (scheduled && DENIED_WHEN_SCHEDULED.has(action.class)) {
      this.audit.append('decision.request', this.auditAction(id, action, provenance, 'deny', false, ev));
      return this.finish(action, decide(false, 'scheduled-policy', `${action.class} is never allowed in a scheduled (unattended) run`, false));
    }

    if (scheduled && this.ctx?.deadlineAt !== undefined && Date.now() > this.ctx.deadlineAt) {
      this.audit.append('decision.request', this.auditAction(id, action, provenance, 'deny', false, ev));
      return this.finish(action, decide(false, 'scheduled-policy', 'the scheduled run exceeded its wall-clock limit (scheduled.maxRunSeconds)', false));
    }

    // 1c. Sub-agent runs: the scope its parent granted is checked FIRST and can only remove authority. Everything below
    //     (policy, taint, approval, spend authority) still applies, so the result is the INTERSECTION of both.
    const sub = this.ctx?.subagent;
    if (sub) {
      let why: string | undefined;
      if (DENIED_IN_SUBAGENT.has(action.class)) why = `${action.class} is never allowed inside a sub-agent`;
      else if (this.ctx?.deadlineAt !== undefined && Date.now() > this.ctx.deadlineAt) why = "the sub-agent exceeded its wall-clock deadline (shorter than its parent's)";
      else if (this.ctx?.scope) {
        why = scopeDenies(this.ctx.scope, action, this.scopeClassSet);
        if (!why && action.class !== 'exec') {
          if (this.ctx.scope.maxActions !== null && this.actionsAttempted >= this.ctx.scope.maxActions) why = `the sub-agent used its ${this.ctx.scope.maxActions} allowed governed actions`;
          else this.actionsAttempted++;
        }
      } else why = 'sub-agent run without a scope (refusing: fail closed)';
      if (why) {
        this.audit.append('decision.request', this.auditAction(id, action, provenance, 'deny', false, ev));
        return this.finish(action, decide(false, 'subagent-scope', why, false));
      }
    }

    // 2. Taint escalation: policy can never auto-allow a tainted sensitive action.
    if (verdict === 'allow' && provenance.tainted && TAINT_SENSITIVE.has(action.class)) {
      verdict = 'ask';
      escalated = true;
    }
    // 2b. Some classes are never auto-allowed at all (agent-created schedules), and an unattended run never gets
    //     an automatic spend/host command from a policy `allow`: a human must be asked.
    let forcedReason: string | undefined;
    if (verdict === 'allow' && ALWAYS_ASK.has(action.class)) {
      verdict = 'ask';
      forcedReason = `${action.class} always needs a human, whatever the policy says`;
    } else if (verdict === 'allow' && scheduled && NEVER_AUTO_WHEN_SCHEDULED.has(action.class)) {
      verdict = 'ask';
      forcedReason = `${action.class} is never auto-allowed in an unattended run`;
    }

    // 3. Spend: refuse impossible spends before bothering a human.
    if (action.class === 'spend' && verdict !== 'deny') {
      const pre = this.spendCheck(action);
      if (!pre.ok) {
        this.audit.append('decision.request', this.auditAction(id, action, provenance, ev.verdict, escalated));
        return this.finish(action, decide(false, 'spend-authority', pre.reason!, escalated));
      }
    }

    // Decision recorded BEFORE anything runs.
    this.audit.append('decision.request', this.auditAction(id, action, provenance, verdict, escalated, ev));

    if (verdict === 'deny') {
      return this.finish(action, decide(false, 'policy', `policy rule denies ${action.class}`, escalated));
    }
    // Legacy unsandboxed host commands: even an explicit policy `allow` needs a human present. With no approver
    // (non-interactive: --non-interactive, no TTY, a server without a channel) they are denied.
    if (verdict === 'allow' && action.class === 'host.exec' && !this.approver) {
      return this.finish(action, decide(false, 'no-approver', 'host.exec (unsandboxed host command) is denied when non-interactive, whatever the policy says', escalated));
    }
    if (verdict === 'allow') {
      return this.finish(action, decide(true, 'policy', 'allowed by policy', false));
    }

    // verdict === 'ask'
    let timeoutMs = this.policy.approvalTimeoutSeconds * 1000;
    let scheduledInfo: ApprovalRequest['scheduled'];
    if (scheduled) {
      // Nobody is at the terminal. Either deny at once, or ask the owner through an approver that reaches them elsewhere.
      if (this.policy.scheduled.defaultVerdictForAsk !== 'ask-async') {
        return this.finish(action, decide(false, 'scheduled-policy', 'approval would be required but this is an unattended scheduled run (scheduled.defaultVerdictForAsk = deny)', escalated));
      }
      if (!this.approver?.async) {
        return this.finish(action, decide(false, 'scheduled-policy', 'approval would be required but no asynchronous approver (e.g. Telegram) is configured for unattended runs', escalated));
      }
      timeoutMs = this.policy.scheduled.approvalTimeoutSeconds * 1000;
      if (this.ctx?.deadlineAt !== undefined) timeoutMs = Math.max(1, Math.min(timeoutMs, this.ctx.deadlineAt - Date.now()));
      scheduledInfo = { jobId: this.ctx!.jobId ?? 'unknown', triggerAt: this.ctx!.triggerAt ?? 'unknown' };
    }
    if (!this.approver) {
      return this.finish(action, decide(false, 'no-approver', 'approval required but no approver is configured (non-interactive mode denies)', escalated));
    }
    const req: ApprovalRequest = {
      id,
      action,
      provenance,
      reason: forcedReason ?? (ev.source === 'rule' ? `policy rule #${ev.ruleIndex} requires approval` : `policy default for ${action.class} is "ask"`),
      escalatedByTaint: escalated,
      expiresAt: Date.now() + timeoutMs,
      scheduled: scheduledInfo,
      subagent: sub,
    };
    const { answer, error, timedOut } = await this.askWithTimeout(req, timeoutMs);
    if (error) return this.finish(action, decide(false, 'approver-error', `approver failed: ${error}`, escalated));
    if (timedOut) return this.finish(action, decide(false, 'timeout', 'no answer before the approval timeout', escalated));
    if (answer !== 'approve') return this.finish(action, decide(false, 'human', 'denied by approver', escalated));

    // 4. A human 'yes' can never exceed the spend authority's caps: re-check after approval.
    if (action.class === 'spend') {
      const post = this.spendCheck(action);
      if (!post.ok) return this.finish(action, decide(false, 'spend-authority', `approved by human but ${post.reason}`, escalated));
    }
    return this.finish(action, decide(true, 'human', 'approved by human', escalated));
  }

  /** authorize + run + audit the result. Throws GovernorDenied when not allowed. */
  async governed<T>(action: Action, fn: () => Promise<T>, summarize: (r: T) => Record<string, unknown> = () => ({})): Promise<T> {
    const d = await this.authorize(action);
    if (!d.allowed) throw new GovernorDenied(d, action);
    try {
      const r = await fn();
      this.audit.append('action.result', { decisionId: d.id, class: action.class, target: action.target, ok: true, ...summarize(r) });
      return r;
    } catch (e: any) {
      this.audit.append('action.result', { decisionId: d.id, class: action.class, target: action.target, ok: false, error: String(e?.message ?? e).slice(0, 500) });
      throw e;
    }
  }

  /**
   * Move money. The ONLY code path that calls a payment rail. Order: validate -> policy/taint/approval ->
   * re-check caps -> reserve -> charge -> (release on failure).
   */
  async spend(req: { cents: number; payee: string; memo: string }): Promise<{ id: string; cents: number }> {
    const action: Action = {
      class: 'spend',
      target: req.payee,
      summary: `Pay ${req.cents} cents to ${req.payee} via ${this.rail.name}: ${req.memo}`.slice(0, 300),
      detail: `payee=${req.payee}\ncents=${req.cents}\nrail=${this.rail.name}\nmemo=${req.memo}`,
      cents: req.cents,
    };
    const d = await this.authorize(action);
    if (!d.allowed) throw new GovernorDenied(d, action);
    // Final synchronous re-check immediately before reserving (another spend may have landed while we awaited).
    const last = this.spendCheck(action);
    if (!last.ok) {
      const denied: Decision = { ...d, allowed: false, by: 'spend-authority', reason: last.reason! };
      this.audit.append('decision.result', { decisionId: d.id, class: 'spend', target: action.target, allowed: false, by: denied.by, reason: denied.reason, escalatedByTaint: d.escalatedByTaint });
      throw new GovernorDenied(denied, action);
    }
    const authority = this.spendAuthority!;
    authority.reserve(req.cents, req.payee);
    try {
      const out = await this.rail.charge({ cents: req.cents, payee: req.payee, memo: req.memo.slice(0, 200), idempotencyKey: d.id });
      this.audit.append('action.result', { decisionId: d.id, class: 'spend', target: req.payee, ok: true, cents: req.cents, railTx: out.id, totalReservedCents: authority.totalReservedCents });
      return { id: out.id, cents: req.cents };
    } catch (e: any) {
      authority.release(req.cents);
      this.audit.append('action.result', { decisionId: d.id, class: 'spend', target: req.payee, ok: false, cents: req.cents, error: String(e?.message ?? e).slice(0, 300) });
      throw e;
    }
  }

  // ---- internals -------------------------------------------------------------------------------------------

  private spendCheck(action: Action): { ok: boolean; reason?: string } {
    if (!this.spendAuthority) return { ok: false, reason: 'no spend authority configured: spending is disabled' };
    return this.spendAuthority.check(action.cents!, action.target);
  }

  private finish(action: Action, d: Decision): Decision {
    this.audit.append('decision.result', {
      decisionId: d.id,
      class: action.class,
      target: action.target,
      allowed: d.allowed,
      by: d.by,
      reason: d.reason,
      escalatedByTaint: d.escalatedByTaint,
    });
    return d;
  }

  private auditAction(id: string, a: Action, p: ReturnType<TaintTracker['provenance']>, verdict: Verdict, escalated: boolean, ev?: { source: string; ruleIndex?: number }) {
    return {
      decisionId: id,
      class: a.class,
      target: a.target,
      summary: a.summary,
      detail: a.detail ? (a.detail.length > 16000 ? a.detail.slice(0, 16000) + '...[truncated]' : a.detail) : undefined,
      cents: a.cents,
      inWorkspace: a.inWorkspace,
      verdictBeforeApproval: verdict,
      escalatedByTaint: escalated,
      policySource: ev?.source,
      policyRule: ev?.ruleIndex,
      tainted: p.tainted,
      taintSources: p.sources.map((s) => `${s.kind}:${s.ref}`),
      origin: this.ctx?.origin,
      subagent: this.ctx?.subagent ? { runId: this.ctx.subagent.runId, parentRunId: this.ctx.subagent.parentRunId, chain: this.ctx.subagent.chain, depth: this.ctx.subagent.depth } : undefined,
      jobId: this.ctx?.jobId,
      triggerAt: this.ctx?.triggerAt,
    };
  }

  private async askWithTimeout(req: ApprovalRequest, timeoutMs: number): Promise<{ answer?: ApprovalAnswer; error?: string; timedOut?: boolean }> {
    const ac = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<{ timedOut: true }>((res) => {
      timer = setTimeout(() => res({ timedOut: true }), timeoutMs);
    });
    try {
      const r = await Promise.race([
        this.approver!.request(req, ac.signal).then((answer) => ({ answer }), (e: any) => ({ error: String(e?.message ?? e) })),
        timeout,
      ]);
      if ('timedOut' in r) {
        ac.abort();
        return { timedOut: true };
      }
      if ('error' in r) return { error: r.error };
      // Anything other than the exact string 'approve' is a deny.
      return { answer: r.answer === 'approve' ? 'approve' : 'deny' };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
