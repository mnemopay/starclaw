/**
 * Core vocabulary of the Governor. Everything the agent can do that touches the
 * outside world is expressed as an Action of one of these classes.
 */
export const ACTION_CLASSES = [
  'exec',
  'fs.read',
  'fs.write',
  'net.egress',
  'spend',
  'skill.save',
  'memory.write',
  /** Command inside the locked-down shell container (workspace copied in, changes copied back). */
  'shell.exec',
  /** LEGACY: command run directly on the host, unsandboxed (tools.runCommand). */
  'host.exec',
  /** An agent asking to create a scheduled job. Never auto-allowed. */
  'schedule.create',
  /** A proactive message to the configured owner. */
  'notify.owner',
  /** Opening the governed browser tab (MnemoPay Native Browser control API). A human always decides. */
  'browser.open',
  /** Navigating the open browser tab to another URL. */
  'browser.navigate',
  /** Reading text/links from, or closing, the open browser tab. */
  'browser.read',
  /** Clicking an element in the open browser tab (may run page handlers or start a same-site navigation). */
  'browser.click',
  /** Typing text into an element of the open browser tab: hands data to a website, i.e. an exfiltration path. */
  'browser.type',
  /** A run asking to start a sub-agent with a narrower capability set (tools.spawnAgent). */
  'agent.spawn',
  /** Installing (or replacing) a skill from the signed skills registry. A human ALWAYS decides; never in unattended runs. */
  'skill.install',
] as const;
export type ActionClass = (typeof ACTION_CLASSES)[number];

/** Action classes that can NEVER be auto-allowed while the session is tainted. */
export const TAINT_SENSITIVE: ReadonlySet<ActionClass> = new Set<ActionClass>([
  'exec',
  'net.egress',
  'spend',
  'skill.save',
  'shell.exec',
  'host.exec',
  'schedule.create',
  'notify.owner',
  'browser.open',
  'browser.navigate',
  'browser.click',
  'browser.type',
  'agent.spawn',
  'skill.install',
]);

/** Action classes that policy can never auto-allow, tainted or not: a human always decides (or the action is denied). */
export const ALWAYS_ASK: ReadonlySet<ActionClass> = new Set<ActionClass>(['schedule.create', 'browser.open', 'skill.install']);

/** Action classes that a scheduled (unattended) run can never have auto-allowed by a policy `allow`. */
export const NEVER_AUTO_WHEN_SCHEDULED: ReadonlySet<ActionClass> = new Set<ActionClass>(['spend', 'host.exec', 'schedule.create', 'browser.open', 'browser.type', 'agent.spawn', 'skill.install']);

/** Action classes that are refused outright for runs with origin `scheduled`, whatever the policy says. */
export const DENIED_WHEN_SCHEDULED: ReadonlySet<ActionClass> = new Set<ActionClass>(['host.exec', 'schedule.create', 'skill.install']);

/** Action classes that are refused outright inside a sub-agent run, whatever the policy and the capability request say. */
export const DENIED_IN_SUBAGENT: ReadonlySet<ActionClass> = new Set<ActionClass>(['host.exec', 'schedule.create']);

export type Verdict = 'allow' | 'ask' | 'deny';

export interface Action {
  class: ActionClass;
  /** What the action operates on: a path, a host, a command, a payee, ... */
  target: string;
  /** One human-readable line shown to the approver. */
  summary: string;
  /** Exact payload shown to the approver (code, full URL, command line, ...). Written to the audit log. */
  detail?: string;
  /**
   * Shown to the human approver and NEVER written to the audit log (the Governor's audit records list their fields
   * explicitly and leave this out). Used for text an agent is about to type into a web page: a human must see it, the
   * log keeps only its length and SHA-256.
   */
  approverOnly?: { label: string; text: string };
  /** Integer cents (spend only). */
  cents?: number;
  /** fs.*: resolved path is inside the workspace. */
  inWorkspace?: boolean;
  /** net.egress: hostname. */
  host?: string;
}

export type TaintKind = 'web' | 'non-owner-message' | 'tool-output' | 'tainted-memory' | 'tainted-file' | 'scheduled-job' | 'subagent-result';

export interface TaintSource {
  kind: TaintKind;
  ref: string;
  at: string;
}

export interface Provenance {
  tainted: boolean;
  sources: TaintSource[];
}

export interface Decision {
  id: string;
  allowed: boolean;
  /** Who/what made the final call. */
  by: 'policy' | 'scheduled-policy' | 'human' | 'default-deny' | 'hard-rule' | 'spend-authority' | 'no-approver' | 'timeout' | 'approver-error' | 'subagent-scope';
  reason: string;
  escalatedByTaint: boolean;
  provenance: Provenance;
}

export class GovernorDenied extends Error {
  constructor(public readonly decision: Decision, public readonly action: Action) {
    super(`Denied (${decision.by}): ${decision.reason} [${action.class} ${action.target}]`);
    this.name = 'GovernorDenied';
  }
}

export interface ApprovalRequest {
  id: string;
  action: Action;
  provenance: Provenance;
  /** Why a human is being asked. */
  reason: string;
  escalatedByTaint: boolean;
  /** Epoch ms after which the request is auto-denied. */
  expiresAt: number;
  /** Set for unattended runs: the job and trigger time the request belongs to. */
  scheduled?: { jobId: string; triggerAt: string };
  /** Set when the action comes from a sub-agent run: the full chain, root run first, this sub-agent last. */
  subagent?: SubagentRef;
}

/** Who a sub-agent is and where it came from. Shown to the approver and written into every audit record of the run. */
export interface SubagentRef {
  runId: string;
  parentRunId: string;
  /** Root run id first, this sub-agent's id last. */
  chain: string[];
  depth: number;
  goal: string;
}

export type ApprovalAnswer = 'approve' | 'deny';

/** An approver shows the exact request to a human and returns their answer. */
export interface Approver {
  readonly name: string;
  /** True only for approvers that reach a human who is NOT sitting at the terminal (e.g. Telegram). Scheduled runs use only these. */
  readonly async?: boolean;
  /** Must resolve; anything other than 'approve' is treated as deny. */
  request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer>;
}

/** Render a request as plain text. Used by every approver so they all show the same facts. */
export function describeRequest(req: ApprovalRequest): string {
  const a = req.action;
  const lines: string[] = [];
  lines.push(`APPROVAL REQUEST ${req.id}`);
  lines.push(`Action : ${a.class}`);
  lines.push(`Target : ${a.target}`);
  lines.push(`Summary: ${a.summary}`);
  // Early in the text: channel approvers cut long messages from the end, and this is what the human must read.
  if (a.approverOnly) lines.push(`--- ${a.approverOnly.label} (${[...a.approverOnly.text].length} chars; shown to you only, NOT written to the audit log) ---`, a.approverOnly.text, '--- end ---');
  if (req.subagent) {
    lines.push(`Origin : SUB-AGENT (depth ${req.subagent.depth}) - NOT the run you started. Chain: ${req.subagent.chain.join(' > ')}`);
    lines.push(`         Its goal, written by the parent run: ${req.subagent.goal.slice(0, 300)}`);
  }
  if (req.scheduled) lines.push(`Origin : SCHEDULED job ${req.scheduled.jobId}, triggered ${req.scheduled.triggerAt} (nobody is at the terminal)`);
  if (a.cents !== undefined) lines.push(`Cost   : ${a.cents} cents (${(a.cents / 100).toFixed(2)} in the rail's currency unit)`);
  if (req.provenance.tainted) {
    lines.push(`Provenance: TAINTED - untrusted content is in this session's context`);
    for (const s of req.provenance.sources.slice(0, 8)) lines.push(`  - ${s.kind}: ${s.ref}`);
    if (req.provenance.sources.length > 8) lines.push(`  - ... and ${req.provenance.sources.length - 8} more`);
  } else {
    lines.push(`Provenance: clean (no untrusted content seen this session)`);
  }
  lines.push(`Why asked: ${req.reason}${req.escalatedByTaint ? ' (policy would have allowed this; escalated because the session is tainted)' : ''}`);
  if (a.detail) {
    const d = a.detail.length > 3000 ? a.detail.slice(0, 3000) + `\n... [${a.detail.length - 3000} more chars not shown]` : a.detail;
    lines.push('--- exact payload ---', d, '--- end payload ---');
  }
  return lines.join('\n');
}
