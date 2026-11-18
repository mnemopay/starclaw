import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import { Governor, GovernorOptions } from '../../governance/governor';
import { Policy, evaluatePolicy, globToRegExp } from '../../governance/policy';
import type { BrokerCall } from '../../sandbox/ProcessSandbox';
import type { Action, ActionClass, Decision } from '../../governance/types';
import type { Capabilities } from './bundle';

/** Which action classes each tool produces (used to probe the CURRENT policy for required tools). */
export const TOOL_CLASSES: Record<string, ActionClass[]> = {
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
};

/** Classes a registry skill can never trigger, whatever it declares. */
const NEVER_FOR_SKILLS: ReadonlySet<ActionClass> = new Set<ActionClass>(['agent.spawn', 'host.exec', 'schedule.create', 'skill.save', 'skill.install', 'memory.write']);

export function domainMatches(pattern: string, host: string): boolean {
  const h = host.toLowerCase();
  if (pattern.startsWith('*.')) return h.endsWith(pattern.slice(1)) && h.length > pattern.length - 1;
  return h === pattern.toLowerCase();
}

/**
 * A Governor that applies the skill's DECLARED capabilities first and then the normal policy/taint/approval pipeline.
 * Result = intersection: the skill can never do more than it declared, and never more than the policy allows.
 */
export class AttenuatedGovernor extends Governor {
  private spentThisRun = 0;
  constructor(opts: GovernorOptions, private readonly caps: Capabilities, private readonly skill: { id: string; version: string }, private readonly workspace: string) {
    super(opts);
  }

  private denyAttenuated(action: Action, reason: string): Decision {
    const id = randomUUID();
    this.audit.append('skillreg.attenuated.denied', { decisionId: id, skill: `${this.skill.id}@${this.skill.version}`, class: action.class, target: action.target.slice(0, 300), reason });
    return { id, allowed: false, by: 'hard-rule', reason: `skill ${this.skill.id} did not declare this capability: ${reason}`, escalatedByTaint: false, provenance: this.taint.provenance() };
  }

  private scopeViolation(a: Action): string | undefined {
    const c = this.caps;
    if (NEVER_FOR_SKILLS.has(a.class)) return `${a.class} is never available to registry skills`;
    if (a.class === 'shell.exec' && !c.paths.includes('**')) return 'shell requires whole-workspace path access (**)' ;
    switch (a.class) {
      case 'fs.read':
      case 'fs.write': {
        if (c.paths.length === 0) return 'no path scopes declared';
        if (!a.inWorkspace) return 'path is outside the workspace';
        const rel = path.relative(this.workspace, a.target).split(path.sep).join('/');
        if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return 'path is not inside the declared scopes';
        return c.paths.some((p) => globToRegExp(p).test(rel)) ? undefined : `path ${rel} is outside declared scopes [${c.paths.join(', ')}]`;
      }
      case 'net.egress':
      case 'browser.open':
      case 'browser.navigate':
      case 'browser.click':
      case 'browser.type': {
        const host = a.host ?? a.target;
        if (c.domains.length === 0) return 'no domains declared';
        return c.domains.some((d) => domainMatches(d, host)) ? undefined : `domain ${host} is outside declared domains [${c.domains.join(', ')}]`;
      }
      case 'spend': {
        if (c.spendCents === 0) return 'spend is 0 (the default)';
        const cents = a.cents ?? 0;
        if (this.spentThisRun + cents > c.spendCents) return `would exceed the declared per-run cap of ${c.spendCents} cents`;
        return undefined;
      }
      default:
        return undefined; // exec / shell.exec / notify.owner / browser.read: gated by the declared tool list + normal policy
    }
  }

  override async authorize(action: Action): Promise<Decision> {
    // The run itself (class exec, target skill:<id>@<ver>) is the one action that is not a declared capability.
    if (!(action.class === 'exec' && action.target.startsWith('skill:'))) {
      const v = this.scopeViolation(action);
      if (v) return this.denyAttenuated(action, v);
    }
    const d = await super.authorize(action);
    if (d.allowed && action.class === 'spend') this.spentThisRun += action.cents ?? 0;
    return d;
  }
}

/** Wrap a broker handler: only declared tools are callable. Everything else is refused and audited before the broker sees it. */
export function attenuatedHandler(
  handler: (call: BrokerCall) => Promise<unknown>,
  caps: Capabilities,
  skill: { id: string; version: string },
  audit: { append(type: string, data: Record<string, unknown>): unknown },
): (call: BrokerCall) => Promise<unknown> {
  const allowed = new Set([...caps.tools, ...caps.optionalTools]);
  return async (call) => {
    if (!allowed.has(call.name)) {
      audit.append('skillreg.attenuated.denied', { skill: `${skill.id}@${skill.version}`, tool: String(call.name).slice(0, 60), reason: 'tool not declared in the manifest' });
      throw new Error(`skill ${skill.id} did not declare tool ${String(call.name).slice(0, 40)}`);
    }
    return handler(call);
  };
}

/**
 * Before running: every REQUIRED tool must be obtainable under the current policy. A required tool whose class the policy
 * flatly denies (or `spend` with no policy allowance) means the skill cannot do its job: refuse rather than run half-blind.
 */
export function unmetRequirements(policy: Policy, caps: Capabilities): string[] {
  const unmet: string[] = [];
  for (const tool of caps.tools) {
    for (const cls of TOOL_CLASSES[tool] ?? []) {
      const probe: Action = {
        class: cls,
        target: cls === 'net.egress' || cls.startsWith('browser.') ? (caps.domains[0] ?? 'example.com').replace(/^\*\./, 'x.') : 'declared-scope',
        host: (caps.domains[0] ?? 'example.com').replace(/^\*\./, 'x.'),
        inWorkspace: true,
        cents: cls === 'spend' ? 1 : undefined,
        summary: 'capability probe',
      };
      if (evaluatePolicy(policy, probe).verdict === 'deny') unmet.push(`${tool}: policy denies ${cls}`);
    }
    if (tool === 'spend' && (caps.spendCents === 0 || policy.spend.maxPerActionCents === 0 || policy.spend.maxTotalCents === 0)) {
      unmet.push(caps.spendCents === 0 ? 'spend: declared as a tool but spendCents is 0' : 'spend: the policy spend caps are 0 (spending is impossible)');
    }
    if (tool.startsWith('browse') && !policy.browser.enabled) unmet.push(`${tool}: policy browser.enabled is false`);
    if (tool === 'browseType' && !policy.browser.allowInput) unmet.push('browseType: policy browser.allowInput is false');
    if (tool === 'fetchUrl' && caps.domains.length === 0) unmet.push('fetchUrl: no domains declared');
    if ((tool === 'readFile' || tool === 'listDir' || tool === 'writeFile' || tool === 'editFile' || tool === 'applyPatch') && caps.paths.length === 0) unmet.push(`${tool}: no path scopes declared`);
  }
  return [...new Set(unmet)];
}
