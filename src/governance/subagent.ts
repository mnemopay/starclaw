import * as path from 'node:path';
import { z } from 'zod';
import { hostAllowed } from '../browser/guard';
import { canonicalize, sha256Hex } from './canonical';
import type { SubagentsPolicySchema } from './policy';
import type { SpendAuthority } from './spend';
import { Action, ActionClass } from './types';

type SubagentsPolicy = z.infer<typeof SubagentsPolicySchema>;

/** Tools a sub-agent can never hold, whatever its parent asks for: they are the legacy/unattended-risk classes. */
export const FORBIDDEN_FOR_SUBAGENTS: readonly string[] = ['runCommand', 'scheduleCreate'];

/** Which action classes each brokered tool can produce. A sub-agent may only perform classes its tool list implies. */
export const TOOL_CLASSES: Readonly<Record<string, readonly ActionClass[]>> = {
  readFile: ['fs.read'],
  listDir: ['fs.read'],
  writeFile: ['fs.write'],
  applyPatch: ['fs.read', 'fs.write'],
  editFile: ['fs.read', 'fs.write'],
  fetchUrl: ['net.egress'],
  search: ['net.egress'],
  shell: ['shell.exec'],
  notifyOwner: ['notify.owner'],
  spend: ['spend'],
  browseOpen: ['browser.open'],
  browseNavigate: ['browser.navigate'],
  browseReadText: ['browser.read'],
  browseReadLinks: ['browser.read'],
  browseClose: ['browser.read'],
  browseClick: ['browser.click'],
  browseType: ['browser.type'],
  mcpList: ['mcp.call'],
  mcpCall: ['mcp.call'],
  spawnAgent: ['agent.spawn'],
  runCommand: ['host.exec'],
  scheduleCreate: ['schedule.create'],
};

/**
 * What a run may do. The root run's scope is "everything the policy lets it try" (`domains: 'any'`, path '' = the whole
 * workspace, numbers = what is left right now). A child's scope is derived from its parent's by `attenuate()`: never wider.
 * Sandbox, policy rules, taint, approvals and spend authority all still apply on top: a scope can only REMOVE authority.
 */
export interface SubagentScope {
  /** Tool names the run may call. */
  tools: readonly string[];
  /** Host patterns (exact, or `*.sub.example.com` for subdomains only) for net.egress / browser.open / browser.navigate / browser.click / browser.type (the page host); 'any' = no scope restriction. */
  domains: readonly string[] | 'any';
  /** Workspace-relative directory prefixes ('' = the whole workspace), normalised POSIX, for reads and for writes. */
  readPaths: readonly string[];
  writePaths: readonly string[];
  /** Integer cents. For a child: the slice carved from the parent's remaining cap. */
  spendCents: number;
  /** Integer cents of LLM budget (the child's per-run cap). */
  llmCents: number;
  /** Epoch ms; every governed action and LLM call after it is refused. undefined = no deadline (root interactive run). */
  deadlineAt: number | undefined;
  /** Governed actions allowed (the run's own code execution is not counted). null = unlimited. */
  maxActions: number | null;
  /** 0 for the root run. */
  depth: number;
}

export class SubagentRejected extends Error {
  constructor(public readonly reasons: string[]) {
    super(`sub-agent request rejected: ${reasons.join('; ')}`);
    this.name = 'SubagentRejected';
  }
}

// ---- the request a parent run makes --------------------------------------------------------------------------------

/** One label of a domain; the pattern as a whole is checked by validDomainPattern(). */
export function validDomainPattern(p: string): boolean {
  if (p.length < 1 || p.length > 253 || p !== p.toLowerCase()) return false;
  const body = p.startsWith('*.') ? p.slice(2) : p;
  const labels = body.split('.');
  // A wildcard must sit above at least two labels: `*.com` would be a grant of "every .com host".
  if (p.startsWith('*.') && labels.length < 2) return false;
  return labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));
}

/** A workspace-relative directory. Normalised; no `..`, no absolute or drive paths, no backslashes, no NUL. Returns undefined if malformed. */
export function normalizeScopePath(p: string): string | undefined {
  if (p.includes('\0') || p.includes('\\') || p.startsWith('/') || /^[a-zA-Z]:/.test(p) || p.length > 500) return undefined;
  const n = path.posix.normalize(p === '' ? '.' : p);
  if (n === '..' || n.startsWith('../') || n.split('/').includes('..')) return undefined;
  const t = n === '.' ? '' : n.replace(/\/+$/, '');
  return t;
}

export const SpawnRequestSchema = z
  .object({
    goal: z.string().min(3).max(2000),
    capabilities: z
      .object({
        /** REQUIRED. The only tools the child can call. */
        tools: z.array(z.string().min(1).max(40)).min(1).max(30),
        /** Hosts the child may reach. Absent or empty = no network. */
        domains: z.array(z.string().min(1).max(253)).max(50).default([]),
        /** Workspace-relative directories the child may read / write. Absent or empty = none. */
        readPaths: z.array(z.string().max(500)).max(50).default([]),
        writePaths: z.array(z.string().max(500)).max(50).default([]),
        /** Integer cents carved from the parent's remaining spend cap. Default 0. */
        spendCents: z.number().int().nonnegative().max(1_000_000_000).default(0),
        /** Integer cents of LLM budget carved from the parent's remaining per-run budget. Default: the policy's maxLlmCentsPerChild (or what is left). */
        llmCents: z.number().int().min(1).max(1_000_000).optional(),
        /** Wall-clock life. Default and ceiling: subagents.maxSeconds and what is left of the parent's. */
        ttlSeconds: z.number().int().min(1).max(86_400).optional(),
        /** Governed actions. Default and ceiling: subagents.maxActionsPerChild and what is left of the parent's. */
        maxActions: z.number().int().min(1).max(100_000).optional(),
      })
      .strict(),
  })
  .strict();
export type SpawnRequest = z.infer<typeof SpawnRequestSchema>;

/** Does pattern `q` (a parent grant) cover pattern `p` (a child request)? Exact, or `*.x.y` covering `a.x.y` and `*.b.x.y`. */
export function domainCovers(q: string, p: string): boolean {
  if (q === p) return true;
  if (q.startsWith('*.')) return p.endsWith(q.slice(1)) && p.length > q.length - 1;
  return false;
}

export function pathCovers(parent: string, child: string): boolean {
  if (parent === '') return true;
  return child === parent || child.startsWith(parent + '/');
}

/** Everything the parent can hand down RIGHT NOW (the scope plus live availability, resolved by the engine at spawn time). */
export interface ParentLimits {
  scope: SubagentScope;
  /** Spend cents that can still be carved (cap minus reserved minus other children's unspent slices). */
  spendAvailableCents: number;
  /** LLM cents that can still be carved from the parent's per-run budget. */
  llmAvailableCents: number;
  /** Governed actions the parent has left (null = unlimited). */
  actionsRemaining: number | null;
  /** Epoch ms now (injected for tests). */
  now: number;
  /** Extra ceiling on a child's wall-clock life: a child runs inside its parent's sandbox call, so it cannot outlive the parent's sandbox timeout. */
  ttlCeilingSeconds?: number;
}

/**
 * The only way a child scope comes into being. A request that tries to widen ANY dimension is REJECTED whole (every reason
 * collected); it is never silently clipped. Throws SubagentRejected, or returns a scope that is <= the parent's in every dimension.
 */
export function attenuate(parent: ParentLimits, req: SpawnRequest, pol: SubagentsPolicy): SubagentScope {
  const why: string[] = [];
  const c = req.capabilities;
  const ps = parent.scope;

  const tools = [...new Set(c.tools)];
  for (const t of tools) {
    if (!(t in TOOL_CLASSES)) why.push(`unknown tool "${t}"`);
    else if (FORBIDDEN_FOR_SUBAGENTS.includes(t)) why.push(`tool "${t}" can never be held by a sub-agent`);
    else if (!ps.tools.includes(t)) why.push(`tool "${t}" is not held by the parent`);
  }
  if (tools.includes('spawnAgent') && ps.depth + 2 > pol.maxDepth) why.push(`spawnAgent would let the child spawn, but subagents.maxDepth is ${pol.maxDepth}`);

  let domains: string[] = [];
  for (const d of c.domains) {
    if (!validDomainPattern(d)) why.push(`malformed domain pattern ${JSON.stringify(d.slice(0, 80))}`);
    else if (ps.domains !== 'any' && !ps.domains.some((q) => domainCovers(q, d))) why.push(`domain ${d} is not covered by the parent's domains`);
    else domains.push(d);
  }
  domains = [...new Set(domains)];
  if (domains.length > 0 && !tools.some((t) => TOOL_CLASSES[t]?.some((k) => k === 'net.egress' || k === 'browser.open' || k === 'browser.navigate'))) {
    why.push('domains were requested but no tool that can use the network was');
  }

  const resolvePaths = (label: string, requested: string[], parentPaths: readonly string[]): string[] => {
    const out: string[] = [];
    for (const raw of requested) {
      const n = normalizeScopePath(raw);
      if (n === undefined) why.push(`malformed ${label} ${JSON.stringify(raw.slice(0, 80))}`);
      else if (!parentPaths.some((q) => pathCovers(q, n))) why.push(`${label} ${JSON.stringify(raw.slice(0, 80))} is not inside the parent's ${label}s`);
      else out.push(n);
    }
    return [...new Set(out)];
  };
  const readPaths = resolvePaths('readPath', c.readPaths, ps.readPaths);
  const writePaths = resolvePaths('writePath', c.writePaths, ps.writePaths);
  // tools.shell copies the WHOLE workspace into its container: it can only be granted with whole-workspace read access.
  if (tools.includes('shell') && !readPaths.includes('')) why.push('tool "shell" sees a copy of the whole workspace, so it needs readPaths to include "" (the whole workspace)');
  if (tools.includes('shell') && writePaths.length > 0 && !writePaths.includes('')) why.push('tool "shell" writes back anywhere in the workspace, so writePaths must be empty or include ""');

  const spendCents = c.spendCents;
  if (spendCents > 0 && !tools.includes('spend')) why.push('spendCents > 0 but the "spend" tool was not requested');
  if (spendCents > pol.maxSpendCentsPerChild) why.push(`spendCents ${spendCents} exceeds subagents.maxSpendCentsPerChild (${pol.maxSpendCentsPerChild})`);
  if (spendCents > Math.min(ps.spendCents, parent.spendAvailableCents)) why.push(`spendCents ${spendCents} exceeds what the parent can still give (${Math.max(0, Math.min(ps.spendCents, parent.spendAvailableCents))})`);

  const llmCap = Math.min(pol.maxLlmCentsPerChild, parent.llmAvailableCents);
  const llmCents = c.llmCents ?? llmCap;
  if (llmCents < 1) why.push('the parent has no LLM budget left to give');
  else if (llmCents > pol.maxLlmCentsPerChild) why.push(`llmCents ${llmCents} exceeds subagents.maxLlmCentsPerChild (${pol.maxLlmCentsPerChild})`);
  else if (llmCents > parent.llmAvailableCents) why.push(`llmCents ${llmCents} exceeds the parent's remaining LLM budget (${parent.llmAvailableCents})`);

  const parentLeftMs = ps.deadlineAt === undefined ? Number.POSITIVE_INFINITY : ps.deadlineAt - parent.now;
  if (parentLeftMs <= 0) why.push('the parent has no time left');
  const maxTtl = Math.min(pol.maxSeconds, parent.ttlCeilingSeconds ?? pol.maxSeconds, Number.isFinite(parentLeftMs) ? Math.floor(parentLeftMs / 1000) : pol.maxSeconds);
  const ttl = c.ttlSeconds ?? maxTtl;
  if (ttl < 1) why.push('the parent has less than a second left');
  else if (ttl > maxTtl) why.push(`ttlSeconds ${ttl} exceeds the allowed ${maxTtl}s (subagents.maxSeconds and the parent's own deadline)`);

  const actionCap = ps.maxActions === null ? pol.maxActionsPerChild : Math.min(pol.maxActionsPerChild, parent.actionsRemaining ?? 0);
  const maxActions = c.maxActions ?? actionCap;
  if (maxActions < 1) why.push('the parent has no governed actions left to give');
  else if (maxActions > actionCap) why.push(`maxActions ${maxActions} exceeds the allowed ${actionCap}`);

  if (ps.depth + 1 > pol.maxDepth) why.push(`subagents.maxDepth (${pol.maxDepth}) does not allow another level`);

  if (why.length > 0) throw new SubagentRejected(why);
  return { tools, domains, readPaths, writePaths, spendCents, llmCents, deadlineAt: parent.now + ttl * 1000, maxActions, depth: ps.depth + 1 };
}

/** The scope of the run a human starts. It can try anything the policy allows; children are cut down from it. */
export function rootScope(toolNames: readonly string[]): SubagentScope {
  return { tools: [...toolNames], domains: 'any', readPaths: [''], writePaths: [''], spendCents: Number.MAX_SAFE_INTEGER, llmCents: Number.MAX_SAFE_INTEGER, deadlineAt: undefined, maxActions: null, depth: 0 };
}

/** Is `child` no wider than `parent` in every dimension (limits compared as numbers; availability is separate)? Used by tests and as a runtime assertion. */
export function isNarrowerOrEqual(child: SubagentScope, parent: SubagentScope): boolean {
  if (!child.tools.every((t) => parent.tools.includes(t))) return false;
  if (parent.domains !== 'any') {
    if (child.domains === 'any') return false;
    if (!child.domains.every((d) => (parent.domains as readonly string[]).some((q) => domainCovers(q, d)))) return false;
  }
  if (!child.readPaths.every((p) => parent.readPaths.some((q) => pathCovers(q, p)))) return false;
  if (!child.writePaths.every((p) => parent.writePaths.some((q) => pathCovers(q, p)))) return false;
  if (child.spendCents > parent.spendCents || child.llmCents > parent.llmCents) return false;
  if (parent.deadlineAt !== undefined && (child.deadlineAt === undefined || child.deadlineAt > parent.deadlineAt)) return false;
  if (parent.maxActions !== null && (child.maxActions === null || child.maxActions > parent.maxActions)) return false;
  return child.depth > parent.depth;
}

/** Allowed action classes of a scope: the ones its tools can produce, plus the run executing its own code. */
export function scopeClasses(scope: SubagentScope): Set<ActionClass> {
  const s = new Set<ActionClass>(['exec']);
  for (const t of scope.tools) for (const k of TOOL_CLASSES[t] ?? []) s.add(k);
  return s;
}

/** Governor-side check (the broker enforces tool names and file paths itself). Pure; returns why not, or undefined when the scope permits. */
export function scopeDenies(scope: SubagentScope, action: Action, classes = scopeClasses(scope)): string | undefined {
  if (!classes.has(action.class)) return `${action.class} is outside this sub-agent's capabilities (tools: ${scope.tools.join(', ') || 'none'})`;
  if (scope.domains !== 'any' && (action.class === 'net.egress' || action.class === 'browser.open' || action.class === 'browser.navigate' || action.class === 'browser.click' || action.class === 'browser.type')) {
    if (!action.host || !hostAllowed(action.host, scope.domains)) return `host ${action.host ?? '(none)'} is outside this sub-agent's domains (${scope.domains.join(', ') || 'none'})`;
  }
  return undefined;
}

export function scopeSummary(scope: SubagentScope) {
  return {
    tools: [...scope.tools],
    domains: scope.domains,
    readPaths: [...scope.readPaths],
    writePaths: [...scope.writePaths],
    spendCents: scope.spendCents,
    llmCents: scope.llmCents,
    deadlineAt: scope.deadlineAt ? new Date(scope.deadlineAt).toISOString() : null,
    maxActions: scope.maxActions,
    depth: scope.depth,
  };
}
export const scopeSha256 = (scope: SubagentScope) => sha256Hex(canonicalize(scopeSummary(scope)));

// ---- spend: carving a child's slice out of the parent's remaining cap -------------------------------------------------

/**
 * Wraps a SpendAuthority and lets part of its remaining cap be CARVED into a slice for a child. While a slice is open, its
 * unspent part is unavailable to everyone else (the owner's run, other children), so reserved + carved <= cap always holds
 * and concurrent children cannot jointly exceed the parent. Spending through a slice reserves on the underlying authority
 * (so the daily ledger and the SDK counters see it exactly once). Closing a slice returns what it did not spend.
 */
export class SpendPool implements SpendAuthority {
  private carved = 0;
  constructor(private readonly inner: SpendAuthority, readonly capTotalCents: number) {}

  get totalReservedCents() {
    return this.inner.totalReservedCents;
  }
  /** What can still be spent or carved right now. */
  get availableCents(): number {
    return Math.max(0, this.capTotalCents - this.inner.totalReservedCents - this.carved);
  }
  get carvedCents() {
    return this.carved;
  }

  check(cents: number, payee: string) {
    const r = this.inner.check(cents, payee);
    if (!r.ok) return r;
    if (this.inner.totalReservedCents + this.carved + cents > this.capTotalCents) {
      return { ok: false, reason: `exceeds the spend still available (${this.availableCents} cents; the rest is held for sub-agents)` };
    }
    return r;
  }
  reserve(cents: number, payee: string) {
    this.inner.reserve(cents, payee);
  }
  release(cents: number) {
    this.inner.release(cents);
  }

  carve(cents: number, perActionCents: number): SpendSlice {
    if (!Number.isSafeInteger(cents) || cents < 0) throw new Error('invalid spend slice');
    if (cents > this.availableCents) throw new Error(`cannot carve ${cents} cents: only ${this.availableCents} are available`);
    this.carved += cents;
    return new SpendSlice(this.inner, cents, perActionCents, (delta) => (this.carved += delta));
  }
}

export class SpendSlice implements SpendAuthority {
  private used = 0;
  private closed = false;
  constructor(
    private readonly inner: SpendAuthority,
    readonly sliceCents: number,
    private readonly perActionCents: number,
    private readonly adjustCarved: (delta: number) => void,
  ) {}

  get totalReservedCents() {
    return this.used;
  }
  get remainingCents() {
    return this.closed ? 0 : this.sliceCents - this.used;
  }

  check(cents: number, payee: string) {
    if (this.closed) return { ok: false, reason: 'the sub-agent has finished: its spend slice is closed' };
    if (!Number.isSafeInteger(cents) || cents <= 0) return { ok: false, reason: 'amount must be a positive integer number of cents' };
    if (cents > this.perActionCents) return { ok: false, reason: `exceeds the sub-agent's per-action cap (${cents} > ${this.perActionCents} cents)` };
    if (this.used + cents > this.sliceCents) return { ok: false, reason: `exceeds the sub-agent's spend slice (${this.used + cents} > ${this.sliceCents} cents)` };
    return this.inner.check(cents, payee);
  }
  reserve(cents: number, payee: string) {
    if (this.closed || this.used + cents > this.sliceCents) throw new Error('sub-agent spend slice exceeded');
    this.inner.reserve(cents, payee);
    this.used += cents;
    this.adjustCarved(-cents); // moved from "held for the child" to "reserved on the authority"
  }
  release(cents: number) {
    this.inner.release(cents);
    this.used -= cents;
    if (!this.closed) this.adjustCarved(cents); // after close the unspent part was already returned; the freed cents just reopen the parent's cap
  }
  /** Returns the unspent part to the pool. Idempotent; the slice is unusable afterwards. */
  close(): { spentCents: number; returnedCents: number } {
    if (!this.closed) {
      this.closed = true;
      this.adjustCarved(-(this.sliceCents - this.used));
    }
    return { spentCents: this.used, returnedCents: this.sliceCents - this.used };
  }
}

/** The `starclaw doctor` line for sub-agents, plus warnings worth showing. */
export function subagentsStatus(policy: { subagents: SubagentsPolicy; defaults: Record<string, string>; spend: { maxTotalCents: number } }): { line: string; warnings: string[] } {
  const p = policy.subagents;
  if (!p.enabled) return { line: 'Sub-agents: disabled (policy subagents.enabled = false; tools.spawnAgent is refused)', warnings: [] };
  const warnings: string[] = [];
  if (policy.defaults['agent.spawn'] === 'allow') warnings.push('defaults["agent.spawn"] is "allow": the model can start children without asking you (an unattended run and a tainted session still must ask)');
  if (p.maxDepth > 1) warnings.push(`subagents.maxDepth is ${p.maxDepth}: children can start children (each level only ever holds less than its parent)`);
  if (p.maxSpendCentsPerChild > 0 && policy.spend.maxTotalCents === 0) warnings.push('subagents.maxSpendCentsPerChild > 0 but spend.maxTotalCents is 0: children can never spend');
  const line = `Sub-agents: ENABLED; depth <= ${p.maxDepth}, <= ${p.maxConcurrent} at once, <= ${p.maxTotalPerRun} per run, <= ${p.maxSeconds}s, <= ${p.maxActionsPerChild} actions, LLM <= ${p.maxLlmCentsPerChild}c, spend <= ${p.maxSpendCentsPerChild}c each; spawning is "${policy.defaults['agent.spawn']}"; host.exec and schedule.create are never available to a child`;
  return { line, warnings };
}
