import { randomUUID } from 'node:crypto';
import { AuditLog } from './audit';
import { Policy, evaluatePolicy } from './policy';
import { PaymentRail, SpendAuthority, isValidCents, NoPaymentRail } from './spend';
import { TaintTracker } from './taint';
import {
  Action,
  ApprovalAnswer,
  ApprovalRequest,
  Approver,
  Decision,
  GovernorDenied,
  TAINT_SENSITIVE,
  Verdict,
} from './types';

export interface GovernorOptions {
  policy: Policy;
  audit: AuditLog;
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
  readonly audit: AuditLog;
  readonly taint: TaintTracker;
  private approver?: Approver;
  private readonly spendAuthority?: SpendAuthority;
  private readonly rail: PaymentRail;

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

    // 2. Taint escalation: policy can never auto-allow a tainted sensitive action.
    if (verdict === 'allow' && provenance.tainted && TAINT_SENSITIVE.has(action.class)) {
      verdict = 'ask';
      escalated = true;
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
    if (verdict === 'allow') {
      return this.finish(action, decide(true, 'policy', 'allowed by policy', false));
    }

    // verdict === 'ask'
    if (!this.approver) {
      return this.finish(action, decide(false, 'no-approver', 'approval required but no approver is configured (non-interactive mode denies)', escalated));
    }
    const timeoutMs = this.policy.approvalTimeoutSeconds * 1000;
    const req: ApprovalRequest = {
      id,
      action,
      provenance,
      reason: ev.source === 'rule' ? `policy rule #${ev.ruleIndex} requires approval` : `policy default for ${action.class} is "ask"`,
      escalatedByTaint: escalated,
      expiresAt: Date.now() + timeoutMs,
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
