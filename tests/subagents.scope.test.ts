/**
 * Sub-agents, the parts that need no model and no sandbox: the policy block, attenuation (property-style), budget and
 * spend slicing, and the Governor / Broker enforcement of a scope. The engine-level behaviour (limits, taint, approvals,
 * audit order, files) is in subagents.engine.test.ts.
 */
import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Broker } from '../src/broker';
import { hostAllowed } from '../src/browser/guard';
import { AuditLog, scopedAudit, verifyAuditFile } from '../src/governance/audit';
import { BudgetExceeded, LlmBudget } from '../src/governance/budget';
import { Governor } from '../src/governance/governor';
import { SubagentsPolicySchema, defaultPolicy, parsePolicy } from '../src/governance/policy';
import { Ed25519Signer } from '../src/governance/signer';
import { MnemoPaySpendAuthority } from '../src/governance/spend';
import {
  FORBIDDEN_FOR_SUBAGENTS,
  ParentLimits,
  SpawnRequestSchema,
  SpendPool,
  SubagentRejected,
  SubagentScope,
  TOOL_CLASSES,
  attenuate,
  isNarrowerOrEqual,
  normalizeScopePath,
  rootScope,
  subagentsStatus,
  validDomainPattern,
} from '../src/governance/subagent';
import { TaintTracker, TaintedFileStore } from '../src/governance/taint';
import { ApprovalRequest, DENIED_IN_SUBAGENT, describeRequest } from '../src/governance/types';
import { TOOL_DOCS, codegenSystemPrompt } from '../src/llm/prompts';
import { DEFAULT_TOOL_NAMES } from '../src/sandbox/types';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

const POL = SubagentsPolicySchema.parse({ enabled: true, maxDepth: 3, maxConcurrent: 4, maxTotalPerRun: 10, maxSeconds: 120, maxActionsPerChild: 30, maxLlmCentsPerChild: 20, maxSpendCentsPerChild: 40 });
const NOW = 1_800_000_000_000;

/** Deterministic PRNG so a failing case can be replayed. */
function mulberry32(a: number) {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const base = (over: Partial<ParentLimits> = {}, scope: Partial<SubagentScope> = {}): ParentLimits => ({
  scope: { ...rootScope(DEFAULT_TOOL_NAMES), ...scope },
  spendAvailableCents: 100,
  llmAvailableCents: 40,
  actionsRemaining: null,
  now: NOW,
  ...over,
});
const request = (caps: Record<string, unknown> = {}, goal = 'summarise the notes') => SpawnRequestSchema.parse({ goal, capabilities: { tools: ['readFile'], readPaths: ['docs'], ...caps } });

describe('subagents policy block', () => {
  test('disabled by default, strict schema, bounded numbers, and spawning asks by default', () => {
    const p = defaultPolicy();
    assert.equal(p.subagents.enabled, false);
    assert.equal(p.subagents.maxDepth, 1, 'default depth 1: children cannot spawn');
    assert.equal(p.subagents.maxSpendCentsPerChild, 0, 'children can never spend unless the owner raises this');
    assert.equal(p.defaults['agent.spawn'], 'ask');
    for (const bad of [{ extra: 1 }, { maxDepth: 0 }, { maxDepth: 4 }, { maxConcurrent: 0 }, { maxConcurrent: 99 }, { maxTotalPerRun: 0 }, { maxSeconds: 1 }, { maxSpendCentsPerChild: -1 }, { maxLlmCentsPerChild: 0 }, { enabled: 'yes' }, { maxDepth: 1.5 }])
      assert.throws(() => parsePolicy(JSON.stringify({ version: 1, subagents: bad })), /./s, `accepted ${JSON.stringify(bad)}`);
    assert.equal(parsePolicy(JSON.stringify({ version: 1, subagents: { enabled: true, maxDepth: 2 } })).subagents.maxConcurrent, 2);
  });

  test('agent.spawn is a taint-sensitive, never-auto-when-unattended action class that no sub-agent may have denied away', () => {
    assert.ok(DENIED_IN_SUBAGENT.has('host.exec') && DENIED_IN_SUBAGENT.has('schedule.create'));
    for (const t of FORBIDDEN_FOR_SUBAGENTS) assert.ok(DEFAULT_TOOL_NAMES.includes(t));
    assert.ok(DEFAULT_TOOL_NAMES.includes('spawnAgent'));
    for (const t of DEFAULT_TOOL_NAMES) assert.ok(t in TOOL_CLASSES, `tool ${t} has no class mapping: a child could call it unchecked`);
  });

  test('doctor line states the state plainly and warns about the loosening settings', () => {
    assert.match(subagentsStatus(defaultPolicy()).line, /Sub-agents: disabled/);
    const on = subagentsStatus(parsePolicy(JSON.stringify({ version: 1, subagents: { enabled: true, maxDepth: 2 }, defaults: { 'agent.spawn': 'allow' } })));
    assert.match(on.line, /ENABLED; depth <= 2/);
    assert.match(on.line, /host\.exec and schedule\.create are never available to a child/);
    assert.ok(on.warnings.some((w) => /agent\.spawn.*allow/.test(w)));
    assert.ok(on.warnings.some((w) => /maxDepth/.test(w)));
  });

  test('the prompts document the tool, and a sub-agent prompt lists exactly what it holds', () => {
    assert.match(TOOL_DOCS, /tools\.spawnAgent/);
    assert.match(TOOL_DOCS, /UNTRUSTED/);
    assert.doesNotMatch(codegenSystemPrompt('', false), /SUB-AGENT/);
    const p = codegenSystemPrompt('', false, { depth: 1, tools: ['readFile'], domains: [], readPaths: ['docs'], writePaths: [], spendCents: 0, maxActions: 5 });
    assert.match(p, /SUB-AGENT/);
    assert.match(p, /ONLY these tools: readFile/);
    assert.match(p, /UNTRUSTED DATA/);
  });
});

describe('attenuation: a child can only ever hold less', () => {
  const ok = (req = request(), limits = base()) => attenuate(limits, req, POL);
  const rejects = (re: RegExp, req = request(), limits = base(), pol = POL) => assert.throws(() => attenuate(limits, req, pol), (e: unknown) => e instanceof SubagentRejected && re.test(e.message), `expected rejection ${re}`);

  test('a plain narrowing is accepted and produces exactly the requested scope (spend 0, shorter ttl, fewer actions)', () => {
    const s = ok();
    assert.deepEqual([...s.tools], ['readFile']);
    assert.deepEqual([...s.readPaths], ['docs']);
    assert.deepEqual([...s.writePaths], []);
    assert.deepEqual(s.domains, []);
    assert.equal(s.spendCents, 0, 'spend is 0 unless carved');
    assert.equal(s.llmCents, 20, 'defaults to subagents.maxLlmCentsPerChild');
    assert.equal(s.deadlineAt, NOW + 120_000);
    assert.equal(s.maxActions, 30);
    assert.equal(s.depth, 1);
  });

  test('every way of asking for MORE is rejected whole (never clipped)', () => {
    rejects(/not held by the parent/, request({ tools: ['readFile', 'writeFile'] }), base({}, { tools: ['readFile'] }));
    rejects(/can never be held/, request({ tools: ['runCommand'] }));
    rejects(/can never be held/, request({ tools: ['scheduleCreate'] }));
    rejects(/unknown tool/, request({ tools: ['formatDisk'] }));
    rejects(/maxDepth is 1/, request({ tools: ['spawnAgent'] }), base(), SubagentsPolicySchema.parse({ enabled: true }));
    rejects(/not covered by the parent's domains/, request({ tools: ['fetchUrl'], domains: ['evil.com'] }), base({}, { domains: ['docs.example.com', '*.wiki.example.org'] }));
    rejects(/not covered/, request({ tools: ['fetchUrl'], domains: ['wiki.example.org'] }), base({}, { domains: ['*.wiki.example.org'] }));
    rejects(/not covered/, request({ tools: ['fetchUrl'], domains: ['*.example.org'] }), base({}, { domains: ['*.wiki.example.org'] }));
    rejects(/not inside the parent's readPaths/, request({ readPaths: ['src'] }), base({}, { readPaths: ['docs'] }));
    rejects(/not inside the parent's readPaths/, request({ readPaths: [''] }), base({}, { readPaths: ['docs'] }));
    rejects(/not inside the parent's writePaths/, request({ tools: ['writeFile'], writePaths: ['docs'] }), base({}, { writePaths: [] }));
    rejects(/exceeds subagents.maxSpendCentsPerChild/, request({ tools: ['spend'], spendCents: 41 }));
    rejects(/exceeds what the parent can still give/, request({ tools: ['spend'], spendCents: 30 }), base({ spendAvailableCents: 10 }));
    rejects(/"spend" tool was not requested/, request({ spendCents: 5 }));
    rejects(/exceeds subagents.maxLlmCentsPerChild/, request({ llmCents: 21 }));
    rejects(/exceeds the parent's remaining LLM budget/, request({ llmCents: 6 }), base({ llmAvailableCents: 5 }));
    rejects(/no LLM budget left/, request(), base({ llmAvailableCents: 0 }));
    rejects(/ttlSeconds 121 exceeds/, request({ ttlSeconds: 121 }));
    rejects(/ttlSeconds 31 exceeds/, request({ ttlSeconds: 31 }), base({}, { deadlineAt: NOW + 30_000 }));
    rejects(/no time left/, request(), base({}, { deadlineAt: NOW - 1 }));
    rejects(/maxActions 31 exceeds/, request({ maxActions: 31 }));
    rejects(/maxActions 6 exceeds/, request({ maxActions: 6 }), base({ actionsRemaining: 5 }, { maxActions: 10 }));
    rejects(/no governed actions left/, request(), base({ actionsRemaining: 0 }, { maxActions: 10 }));
    rejects(/does not allow another level/, request(), base({}, { depth: 3 }));
  });

  test('a rejection lists every problem at once', () => {
    try {
      attenuate(base(), request({ tools: ['runCommand', 'nope'], readPaths: ['..'], ttlSeconds: 9999 }), POL);
      assert.fail('should have been rejected');
    } catch (e: any) {
      assert.ok(e instanceof SubagentRejected);
      assert.ok(e.reasons.length >= 4, e.message);
    }
  });

  test('narrowed child deadline is the SHORTER of the policy cap, the request, and what is left of the parent', () => {
    assert.equal(ok(request({ ttlSeconds: 10 })).deadlineAt, NOW + 10_000);
    assert.equal(ok(request(), base({}, { deadlineAt: NOW + 45_000 })).deadlineAt, NOW + 45_000);
    assert.equal(ok(request(), base({ ttlCeilingSeconds: 20 })).deadlineAt, NOW + 20_000, 'a child runs inside its parent sandbox call and cannot outlive it');
    rejects(/exceeds the allowed 20s/, request({ ttlSeconds: 21 }), base({ ttlCeilingSeconds: 20 }));
  });

  test('tools.shell sees the whole workspace, so it needs whole-workspace read access and cannot be paired with a narrow write scope', () => {
    rejects(/shell.*whole workspace/, request({ tools: ['shell'], readPaths: ['docs'] }));
    rejects(/shell.*writes back anywhere/, request({ tools: ['shell'], readPaths: [''], writePaths: ['out'] }));
    assert.deepEqual([...ok(request({ tools: ['shell'], readPaths: [''] })).readPaths], ['']);
  });

  test('fail closed on malformed capability requests: schema (strict) and path/domain syntax', () => {
    const bad = (caps: unknown, goal: unknown = 'do the thing') => assert.equal(SpawnRequestSchema.safeParse({ goal, capabilities: caps }).success, false, JSON.stringify(caps));
    bad({});
    bad({ tools: [] });
    bad({ tools: 'readFile' });
    bad({ tools: ['readFile'], extra: true });
    bad({ tools: ['readFile'], spendCents: -1 });
    bad({ tools: ['readFile'], spendCents: 1.5 });
    bad({ tools: ['readFile'], spendCents: Number.NaN });
    bad({ tools: ['readFile'], spendCents: Infinity });
    bad({ tools: ['readFile'], llmCents: 0 });
    bad({ tools: ['readFile'], ttlSeconds: 0 });
    bad({ tools: ['readFile'], domains: 'a.com' });
    bad({ tools: [42] });
    bad(undefined);
    bad({ tools: ['readFile'] }, 'x');
    assert.equal(SpawnRequestSchema.safeParse({ goal: 'ok goal', capabilities: { tools: ['readFile'] }, extra: 1 }).success, false);
    for (const p of ['..', '../x', 'a/../../x', '/etc', 'C:/Windows', 'c:x', 'a\\b', 'x\0y', 'a/b/../../..']) assert.equal(normalizeScopePath(p), undefined, p);
    assert.equal(normalizeScopePath(''), '');
    assert.equal(normalizeScopePath('.'), '');
    assert.equal(normalizeScopePath('docs//sub/'), 'docs/sub');
    assert.equal(normalizeScopePath('docs/../src'), 'src');
    for (const d of ['*', '*.com', 'EXAMPLE.com', 'a b.com', 'https://a.com', 'a.com/x', '-a.com', 'a..com', '', '*.']) assert.equal(validDomainPattern(d), false, d);
    for (const d of ['a.com', '*.a.com', 'localhost', '127.0.0.1', 'x-y.example.org']) assert.equal(validDomainPattern(d), true, d);
    rejects(/malformed domain/, request({ tools: ['fetchUrl'], domains: ['*.com'] }));
    rejects(/malformed readPath/, request({ readPaths: ['../secret'] }));
    rejects(/malformed readPath/, request({ readPaths: ['C:/Users'] }));
    rejects(/malformed writePath/, request({ tools: ['writeFile'], writePaths: ['/etc'] }), base());
    rejects(/no tool that can use the network/, request({ domains: ['a.com'] }));
  });

  test('PROPERTY: over thousands of random requests, an accepted child is never wider than its parent in ANY dimension; a widening request is never accepted', () => {
    const rnd = mulberry32(0x5eed);
    const pick = <T,>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)];
    const subset = <T,>(a: readonly T[], p = 0.5): T[] => a.filter(() => rnd() < p);
    const int = (lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));

    const TOOLS = ['readFile', 'listDir', 'writeFile', 'editFile', 'applyPatch', 'fetchUrl', 'search', 'spend', 'notifyOwner', 'browseOpen', 'browseNavigate', 'browseReadText', 'spawnAgent'];
    const REQ_TOOLS = [...TOOLS, 'runCommand', 'scheduleCreate', 'shell', 'bogus'];
    const DOMS = ['a.example.com', '*.example.com', '*.docs.example.org', 'example.net', 'x.y.example.com', 'b.example.com', '*.b.example.com'];
    const REQ_DOMS = [...DOMS, 'evil.com', '*.com', 'a.example.org', '*.y.example.com', 'Example.com', 'docs.example.org', 'q.docs.example.org'];
    const PATHS = ['', 'docs', 'docs/sub', 'src', 'out/x'];
    const REQ_PATHS = [...PATHS, 'docs/sub/deep', '..', '/etc', 'C:/x', 'docs\\x', 'other', 'docs/../src', 'out', 'docs/'];
    const PROBE_HOSTS = ['a.example.com', 'z.example.com', 'example.com', 'x.y.example.com', 'q.x.y.example.com', 'docs.example.org', 'q.docs.example.org', 'example.net', 'evil.com', 'b.example.com', 'c.b.example.com', 'com', 'a.example.org'];
    const PROBE_PATHS = ['', 'docs', 'docs/a.txt', 'docs/sub/deep/x', 'docs2/x', 'src/main.ts', 'out', 'out/x/y', 'other/z', 'sr', 'docs/sub'];
    const inPaths = (set: readonly string[], p: string) => set.some((q) => q === '' || p === q || p.startsWith(q + '/'));
    const coveredDomain = (set: readonly string[] | 'any', d: string) => set === 'any' || set.some((q) => q === d || (q.startsWith('*.') && d.length > q.length - 1 && d.endsWith(q.slice(1))));

    let accepted = 0;
    let rejected = 0;
    for (let i = 0; i < 4000; i++) {
      const pol = SubagentsPolicySchema.parse({ enabled: true, maxDepth: int(1, 3), maxSeconds: int(10, 300), maxActionsPerChild: int(1, 60), maxLlmCentsPerChild: int(1, 30), maxSpendCentsPerChild: int(0, 60) });
      const dl = rnd() < 0.5 ? undefined : NOW + int(1, 400) * 1000;
      const ma = rnd() < 0.5 ? null : int(0, 40);
      const parent: ParentLimits = {
        scope: {
          tools: subset(TOOLS, 0.7),
          domains: rnd() < 0.4 ? 'any' : subset(DOMS, 0.5),
          readPaths: subset(PATHS, 0.5),
          writePaths: subset(PATHS, 0.4),
          spendCents: int(0, 100),
          llmCents: int(1, 50),
          deadlineAt: dl,
          maxActions: ma,
          depth: int(0, 2),
        },
        spendAvailableCents: int(0, 100),
        llmAvailableCents: int(0, 40),
        actionsRemaining: ma === null ? null : int(0, ma),
        now: NOW,
        ttlCeilingSeconds: rnd() < 0.3 ? int(1, 100) : undefined,
      };
      const NET = ['fetchUrl', 'search', 'browseOpen', 'browseNavigate'];
      const derivedDomain = (q: string) => (q.startsWith('*.') ? pick([q, 'a' + q.slice(1), '*.b' + q.slice(1)]) : q);
      const derivedPath = (q: string) => pick([q, q === '' ? pick(['docs', 'src']) : `${q}/sub`]);
      let raw: { goal: string; capabilities: Record<string, unknown> };
      if (rnd() < 0.6 && parent.scope.tools.length > 0) {
        // Mostly-valid narrowing, so the accept side of the property is exercised often; some fields still go wrong.
        const t = parent.scope.tools.filter(() => rnd() < 0.5);
        const tl = t.length ? t : [parent.scope.tools[0]];
        const dom = parent.scope.domains === 'any' ? subset(DOMS, 0.3) : parent.scope.domains.filter(() => rnd() < 0.5).map(derivedDomain);
        const spendMax = Math.min(parent.scope.spendCents, parent.spendAvailableCents, pol.maxSpendCentsPerChild);
        const spendCents = tl.includes('spend') && spendMax > 0 ? int(0, spendMax) : 0;
        const llmMax = Math.min(parent.llmAvailableCents, pol.maxLlmCentsPerChild);
        raw = {
          goal: 'a random goal',
          capabilities: {
            tools: tl,
            domains: tl.some((x) => NET.includes(x)) ? dom : [],
            readPaths: parent.scope.readPaths.filter(() => rnd() < 0.6).map(derivedPath),
            writePaths: parent.scope.writePaths.filter(() => rnd() < 0.6).map(derivedPath),
            spendCents,
            ...(llmMax >= 1 && rnd() < 0.6 ? { llmCents: int(1, llmMax) } : {}),
            ...(rnd() < 0.5 ? { ttlSeconds: int(1, 60) } : {}),
            ...(rnd() < 0.5 ? { maxActions: int(1, 12) } : {}),
          },
        };
      } else {
        const tools = subset(REQ_TOOLS, 0.3);
        raw = {
          goal: 'a random goal',
          capabilities: {
            tools: tools.length ? tools : ['readFile'],
            domains: subset(REQ_DOMS, 0.25),
            readPaths: subset(REQ_PATHS, 0.25),
            writePaths: subset(REQ_PATHS, 0.2),
            spendCents: rnd() < 0.5 ? 0 : int(0, 120),
            ...(rnd() < 0.6 ? { llmCents: int(1, 40) } : {}),
            ...(rnd() < 0.5 ? { ttlSeconds: int(1, 400) } : {}),
            ...(rnd() < 0.5 ? { maxActions: int(1, 80) } : {}),
          },
        };
      }
      const parsed = SpawnRequestSchema.safeParse(raw);
      assert.ok(parsed.success, 'the generator produced a request the schema cannot even parse');
      const req = parsed.data;
      const c = req.capabilities;

      // ORACLE (independent of attenuate()): does this request widen anything?
      const reasonsWide: string[] = [];
      for (const t of c.tools) {
        if (!(t in TOOL_CLASSES) || FORBIDDEN_FOR_SUBAGENTS.includes(t) || !parent.scope.tools.includes(t)) reasonsWide.push('tool ' + t);
      }
      if (c.tools.includes('spawnAgent') && parent.scope.depth + 2 > pol.maxDepth) reasonsWide.push('spawn depth');
      if (parent.scope.depth + 1 > pol.maxDepth) reasonsWide.push('depth');
      for (const d of c.domains) if (!validDomainPattern(d) || !coveredDomain(parent.scope.domains, d)) reasonsWide.push('domain ' + d);
      for (const [label, list, par] of [['read', c.readPaths, parent.scope.readPaths], ['write', c.writePaths, parent.scope.writePaths]] as const) {
        for (const raw of list) {
          const n = normalizeScopePath(raw);
          if (n === undefined || !inPaths(par, n)) reasonsWide.push(`${label} path ${raw}`);
        }
      }
      if (c.spendCents > Math.min(parent.scope.spendCents, parent.spendAvailableCents) || c.spendCents > pol.maxSpendCentsPerChild) reasonsWide.push('spend');
      if (c.llmCents !== undefined && (c.llmCents > parent.llmAvailableCents || c.llmCents > pol.maxLlmCentsPerChild)) reasonsWide.push('llm');
      if (c.llmCents === undefined && Math.min(pol.maxLlmCentsPerChild, parent.llmAvailableCents) < 1) reasonsWide.push('no llm');
      const left = dl === undefined ? Infinity : dl - NOW;
      const ttlMax = Math.min(pol.maxSeconds, parent.ttlCeilingSeconds ?? Infinity, Math.floor(left / 1000));
      if (left <= 0 || (c.ttlSeconds ?? ttlMax) > ttlMax || (c.ttlSeconds ?? ttlMax) < 1) reasonsWide.push('ttl');
      const actCap = ma === null ? pol.maxActionsPerChild : Math.min(pol.maxActionsPerChild, parent.actionsRemaining ?? 0);
      if ((c.maxActions ?? actCap) > actCap || (c.maxActions ?? actCap) < 1) reasonsWide.push('actions');

      let child: SubagentScope | undefined;
      try {
        child = attenuate(parent, req, pol);
      } catch (e) {
        assert.ok(e instanceof SubagentRejected, 'only SubagentRejected may come out of attenuate: ' + String(e));
      }
      if (!child) {
        rejected++;
        continue; // (rejecting something the oracle thinks is fine is stricter, never wider; the other cases below pin what MUST be rejected)
      }
      accepted++;
      assert.deepEqual(reasonsWide, [], `ACCEPTED a widening request (iteration ${i}): ${JSON.stringify(raw)} against ${JSON.stringify(parent)}`);
      // The child is no wider than the parent, dimension by dimension.
      for (const t of child.tools) assert.ok(parent.scope.tools.includes(t), 'tool escalated: ' + t);
      assert.ok(!child.tools.some((t) => FORBIDDEN_FOR_SUBAGENTS.includes(t)));
      for (const h of PROBE_HOSTS) if (hostAllowed(h, child.domains as string[])) assert.ok(parent.scope.domains === 'any' || hostAllowed(h, parent.scope.domains as string[]), `host ${h} reachable by child but not by parent`);
      assert.notEqual(child.domains, 'any', 'a child never gets unrestricted network scope');
      for (const p of PROBE_PATHS) {
        if (inPaths(child.readPaths, p)) assert.ok(inPaths(parent.scope.readPaths, p), `read ${p} widened`);
        if (inPaths(child.writePaths, p)) assert.ok(inPaths(parent.scope.writePaths, p), `write ${p} widened`);
      }
      assert.ok(child.spendCents <= parent.scope.spendCents && child.spendCents <= parent.spendAvailableCents && child.spendCents <= pol.maxSpendCentsPerChild, 'spend cap widened');
      assert.ok(child.llmCents <= parent.llmAvailableCents && child.llmCents <= pol.maxLlmCentsPerChild && child.llmCents >= 1, 'llm widened');
      if (dl !== undefined) assert.ok(child.deadlineAt! <= dl, 'deadline widened');
      assert.ok(child.deadlineAt! <= NOW + pol.maxSeconds * 1000 && child.deadlineAt! > NOW);
      assert.ok(child.maxActions !== null && child.maxActions <= pol.maxActionsPerChild && (ma === null || child.maxActions <= (parent.actionsRemaining ?? 0)), 'action cap widened');
      assert.equal(child.depth, parent.scope.depth + 1);
      assert.ok(child.depth <= pol.maxDepth);
      assert.ok(isNarrowerOrEqual(child, { ...parent.scope, llmCents: Math.max(parent.scope.llmCents, parent.llmAvailableCents) }), 'isNarrowerOrEqual disagrees with the oracle');
    }
    assert.ok(accepted >= 150, `property test is vacuous: only ${accepted} accepted`);
    assert.ok(rejected >= 150, `property test is vacuous: only ${rejected} rejected`);
  });

  test('PROPERTY (mutation of a valid request): bumping any ONE field past the parent is always rejected', () => {
    const rnd = mulberry32(7);
    const parent = base({ spendAvailableCents: 30, llmAvailableCents: 8, actionsRemaining: 12 }, { tools: ['readFile', 'fetchUrl', 'spend'], domains: ['*.example.com'], readPaths: ['docs'], writePaths: ['docs/out'], deadlineAt: NOW + 60_000, maxActions: 20, spendCents: 50 });
    const good = { tools: ['readFile', 'fetchUrl', 'spend'], domains: ['a.example.com', '*.b.example.com'], readPaths: ['docs/x'], writePaths: ['docs/out/y'], spendCents: 30, llmCents: 8, ttlSeconds: 60, maxActions: 12 };
    assert.doesNotThrow(() => attenuate(parent, SpawnRequestSchema.parse({ goal: 'ok goal', capabilities: good }), POL), 'the baseline must be accepted or the mutations prove nothing');
    const mutations: Array<Record<string, unknown>> = [
      { tools: [...good.tools, 'writeFile'] },
      { tools: [...good.tools, 'spawnAgent'] },
      { tools: [...good.tools, 'runCommand'] },
      { domains: [...good.domains, 'example.com'] },
      { domains: ['*.example.com', 'x.com'] },
      { domains: ['b.example.org'] },
      { readPaths: ['docs', 'src'] },
      { readPaths: [''] },
      { readPaths: ['docs/../src'] },
      { writePaths: ['docs'] },
      { writePaths: ['docs/outside'] },
      { spendCents: 31 },
      { llmCents: 9 },
      { ttlSeconds: 61 },
      { maxActions: 13 },
    ];
    for (const m of mutations) assert.throws(() => attenuate(parent, SpawnRequestSchema.parse({ goal: 'ok goal', capabilities: { ...good, ...m } }), POL), SubagentRejected, JSON.stringify(m));
    // And random single-field bumps on the numeric dimensions.
    for (let i = 0; i < 200; i++) {
      const k = (['spendCents', 'llmCents', 'ttlSeconds', 'maxActions'] as const)[Math.floor(rnd() * 4)];
      const bumped = (good[k] as number) + 1 + Math.floor(rnd() * 50);
      assert.throws(() => attenuate(parent, SpawnRequestSchema.parse({ goal: 'ok goal', capabilities: { ...good, [k]: bumped } }), POL), SubagentRejected, `${k}=${bumped}`);
    }
  });

  test('attenuating twice only narrows again (monotone down a chain)', () => {
    const p1 = attenuate(base(), request({ tools: ['readFile', 'fetchUrl'], domains: ['*.example.com'], readPaths: ['docs'], ttlSeconds: 60 }), POL);
    assert.throws(() => attenuate({ ...base({ actionsRemaining: 30 }), scope: p1 }, request({ tools: ['readFile', 'writeFile'] }), POL), SubagentRejected);
    const p2 = attenuate({ ...base({ actionsRemaining: 30 }), scope: p1 }, request({ tools: ['readFile', 'fetchUrl'], domains: ['a.example.com'], readPaths: ['docs/x'], ttlSeconds: 30 }), POL);
    assert.ok(isNarrowerOrEqual(p2, p1));
    assert.ok(!isNarrowerOrEqual(p1, p2));
    assert.equal(p2.depth, 2);
    assert.throws(() => attenuate({ ...base({ actionsRemaining: 30 }), scope: p1 }, request({ tools: ['fetchUrl'], domains: ['example.com'] }), POL), /not covered/);
  });
});

describe('budget slicing', () => {
  let dir: string;
  beforeEach(() => (dir = tmpDir()));
  afterEach(() => rm(dir));

  test('LLM: a carved slice is held, charged exactly what the child spent, and the rest returns', () => {
    const b = new LlmBudget(10, 100, path.join(dir, 'b.json'));
    b.newRun();
    b.record(2_000_000); // 2 cents
    assert.equal(b.availableRunCents, 8);
    const s = b.carve(5);
    assert.equal(b.availableRunCents, 3, 'the slice is unavailable to the parent while the child lives');
    s.budget.record(1_500_000);
    assert.equal(b.runCentsCeil, 2, 'the parent is not charged until the slice closes');
    assert.deepEqual(s.close(), { spentMicro: 1_500_000 });
    assert.deepEqual(s.close(), { spentMicro: 1_500_000 }, 'idempotent');
    assert.equal(b.runCentsCeil, 4);
    assert.equal(b.availableRunCents, 6, 'unspent part returned: 10 - 2 - 1.5 = 6.5 -> 6 whole cents');
    assert.equal(b.dayCentsCeil, 4, 'the per-day total counts the child once (not twice)');
  });

  test('LLM: concurrent slices cannot jointly exceed the parent, and the slice caps the child', () => {
    const b = new LlmBudget(5, 100);
    b.newRun();
    const a = b.carve(3);
    assert.throws(() => b.carve(3), BudgetExceeded);
    const c = b.carve(2);
    assert.throws(() => b.carve(1), BudgetExceeded);
    assert.throws(() => b.assertCanSpend(), BudgetExceeded, 'a parent whose whole budget is held by children cannot call the model');
    a.budget.record(3_000_000);
    assert.throws(() => a.budget.assertCanSpend(), BudgetExceeded, 'a child cannot spend past its slice');
    a.close();
    c.close();
    assert.equal(b.runCentsCeil, 3);
    assert.doesNotThrow(() => b.assertCanSpend());
    for (const bad of [0, -1, 1.5, NaN]) assert.throws(() => b.carve(bad), /invalid/);
  });

  test('LLM: a child abandoned at its deadline is charged its WHOLE slice', () => {
    const b = new LlmBudget(10, 100);
    b.newRun();
    const s = b.carve(4);
    s.budget.record(500_000);
    assert.deepEqual(s.close(true), { spentMicro: 4_000_000 });
    assert.equal(b.runCentsCeil, 4);
  });

  test('spend: reserved + carved never exceeds the cap; a slice caps the child; unspent returns on close; a closed slice is dead', () => {
    const inner = new MnemoPaySpendAuthority('t', { maxPerActionCents: 100, maxTotalCents: 100, tokenMinutes: 5 }, {});
    const pool = new SpendPool(inner, 100);
    const a = pool.carve(60, 100);
    assert.equal(pool.availableCents, 40);
    assert.throws(() => pool.carve(50, 100), /only 40 are available/);
    const b = pool.carve(40, 100);
    assert.equal(pool.availableCents, 0);
    assert.equal(pool.check(1, 'x').ok, false, 'the parent itself cannot spend what its children hold');
    assert.equal(a.check(61, 'x').ok, false);
    assert.equal(a.check(0, 'x').ok, false);
    assert.equal(a.check(60, 'x').ok, true);
    a.reserve(45, 'x');
    assert.equal(inner.totalReservedCents, 45, 'child spending lands on the parent authority exactly once');
    assert.equal(a.check(16, 'x').ok, false);
    assert.equal(pool.availableCents, 0);
    assert.deepEqual(a.close(), { spentCents: 45, returnedCents: 15 });
    assert.equal(pool.availableCents, 15);
    assert.equal(a.check(1, 'x').ok, false, 'closed');
    assert.throws(() => a.reserve(1, 'x'), /exceeded/);
    assert.equal(pool.check(15, 'x').ok, true);
    assert.equal(pool.check(16, 'x').ok, false);
    b.close();
    assert.equal(pool.availableCents, 55);
    assert.ok(inner.totalReservedCents + pool.carvedCents <= 100);
  });

  test('spend: a per-action cap of 0 (the default) means the slice can never be used', () => {
    const inner = new MnemoPaySpendAuthority('t', { maxPerActionCents: 100, maxTotalCents: 100, tokenMinutes: 5 }, {});
    const s = new SpendPool(inner, 100).carve(0, 0);
    assert.equal(s.check(1, 'x').ok, false);
  });
});

describe('Governor and Broker enforce a scope', () => {
  let dir: string;
  let audit: AuditLog;
  let signer: Ed25519Signer;
  beforeEach(() => {
    dir = tmpDir();
    signer = Ed25519Signer.generate();
    audit = new AuditLog(path.join(dir, 'audit.jsonl'), signer);
  });
  afterEach(() => rm(dir));
  const lines = () => fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const scopeOf = (over: Partial<SubagentScope> = {}): SubagentScope => ({ tools: ['readFile'], domains: [], readPaths: ['docs'], writePaths: [], spendCents: 0, llmCents: 5, deadlineAt: Date.now() + 60_000, maxActions: 3, depth: 1, ...over });
  const childGov = (policyOver: Record<string, unknown>, scope: SubagentScope, approver?: ScriptedApprover, taint = new TaintTracker()) => {
    const gov = new Governor({ policy: policyWith(policyOver), audit: scopedAudit(audit, { runId: 'child-1', parentRunId: 'root-1' }), taint, approver });
    gov.setRunContext({ origin: 'owner', deadlineAt: scope.deadlineAt, subagent: { runId: 'child-1', parentRunId: 'root-1', chain: ['root-1', 'child-1'], depth: 1, goal: 'g' }, scope });
    return gov;
  };
  const read = { class: 'fs.read' as const, target: '/ws/docs/a.txt', summary: 'read', inWorkspace: true };

  test('INTERSECTION: policy allows a class but the scope does not -> denied; scope allows but policy denies -> denied; both allow -> allowed', async () => {
    const allowAll = { rules: [{ class: 'fs.read', verdict: 'allow' }, { class: 'fs.write', verdict: 'allow' }, { class: 'net.egress', verdict: 'allow' }] };
    const gov = childGov(allowAll, scopeOf());
    assert.equal((await gov.authorize(read)).allowed, true);
    const w = await gov.authorize({ class: 'fs.write', target: '/ws/docs/a.txt', summary: 'w', inWorkspace: true });
    assert.equal(w.allowed, false);
    assert.equal(w.by, 'subagent-scope');
    const n = await gov.authorize({ class: 'net.egress', target: 'a.com', host: 'a.com', summary: 'get' });
    assert.equal(n.by, 'subagent-scope');
    const denyRead = childGov({ rules: [{ class: 'fs.read', verdict: 'deny' }] }, scopeOf());
    const d = await denyRead.authorize(read);
    assert.equal(d.allowed, false);
    assert.equal(d.by, 'policy', 'the parent policy still applies on top of the scope');
  });

  test('legacy host.exec and schedule.create are denied inside a child even if its scope somehow lists them, policy allows them and an approver says yes', async () => {
    const approver = new ScriptedApprover(() => 'approve');
    const gov = childGov({ rules: [{ class: 'host.exec', verdict: 'allow' }, { class: 'schedule.create', verdict: 'allow' }] }, scopeOf({ tools: ['runCommand', 'scheduleCreate'] }), approver);
    for (const action of [
      { class: 'host.exec' as const, target: 'node', summary: 'run' },
      { class: 'schedule.create' as const, target: 'job', summary: 'sched' },
    ]) {
      const d = await gov.authorize(action);
      assert.equal(d.allowed, false, action.class);
      assert.equal(d.by, 'subagent-scope');
      assert.match(d.reason, /never allowed inside a sub-agent/);
    }
    assert.equal(approver.seen.length, 0, 'a human was never even asked');
  });

  test('domains: only listed hosts, exact or subdomain-only wildcard; redirects/lookalikes are other hosts', async () => {
    const gov = childGov({ rules: [{ class: 'net.egress', verdict: 'allow' }] }, scopeOf({ tools: ['fetchUrl'], domains: ['docs.example.com', '*.wiki.example.org'], maxActions: 20 }));
    const net = (host: string) => gov.authorize({ class: 'net.egress', target: host, host, summary: 'get ' + host });
    assert.equal((await net('docs.example.com')).allowed, true);
    assert.equal((await net('en.wiki.example.org')).allowed, true);
    for (const h of ['wiki.example.org', 'evil.com', 'docs.example.com.evil.com', 'x.docs.example.com', 'evilwiki.example.org']) assert.equal((await net(h)).by, 'subagent-scope', h);
  });

  test('maxActions: the Nth+1 governed action is denied; the run executing its own code is not counted', async () => {
    const gov = childGov({ rules: [{ class: 'fs.read', verdict: 'allow' }, { class: 'exec', verdict: 'allow' }] }, scopeOf({ maxActions: 2 }));
    assert.equal((await gov.authorize({ class: 'exec', target: 'sandbox:js', summary: 'run' })).allowed, true);
    assert.equal(gov.actionsRemaining, 2);
    assert.equal((await gov.authorize(read)).allowed, true);
    assert.equal((await gov.authorize(read)).allowed, true);
    const d = await gov.authorize(read);
    assert.equal(d.allowed, false);
    assert.match(d.reason, /used its 2 allowed governed actions/);
    assert.equal(gov.actionsRemaining, 0);
  });

  test('deadline: after it, every governed action is denied (interactive child, not just scheduled runs)', async () => {
    const gov = childGov({ rules: [{ class: 'fs.read', verdict: 'allow' }] }, scopeOf({ deadlineAt: Date.now() - 1 }));
    const d = await gov.authorize(read);
    assert.equal(d.allowed, false);
    assert.match(d.reason, /wall-clock deadline/);
  });

  test('a sub-agent run with no scope fails closed', async () => {
    const gov = new Governor({ policy: policyWith({ rules: [{ class: 'fs.read', verdict: 'allow' }] }), audit, taint: new TaintTracker() });
    gov.setRunContext({ origin: 'owner', subagent: { runId: 'c', parentRunId: 'p', chain: ['p', 'c'], depth: 1, goal: 'g' } });
    const d = await gov.authorize(read);
    assert.equal(d.allowed, false);
    assert.match(d.reason, /without a scope/);
  });

  test('approval requests from a child carry the full chain and say so in the text the human reads', async () => {
    const approver = new ScriptedApprover(() => 'deny');
    const gov = childGov({}, scopeOf());
    gov.setApprover(approver);
    const d = await gov.authorize({ ...read, inWorkspace: false });
    assert.equal(d.allowed, false);
    assert.equal(d.by, 'human');
    const req = approver.seen[0] as ApprovalRequest;
    assert.deepEqual(req.subagent?.chain, ['root-1', 'child-1']);
    const text = describeRequest(req);
    assert.match(text, /SUB-AGENT \(depth 1\)/);
    assert.match(text, /root-1 > child-1/);
    // CONTROL: a request from a normal run has no such line.
    assert.doesNotMatch(describeRequest({ ...req, subagent: undefined }), /SUB-AGENT/);
  });

  test('every audit record a child governor writes carries runId/parentRunId and stays in ONE verifiable chain', async () => {
    const gov = childGov({ rules: [{ class: 'fs.read', verdict: 'allow' }] }, scopeOf());
    await gov.authorize(read);
    await gov.authorize({ class: 'fs.write', target: 'x', summary: 'w' });
    audit.append('subagent.result', { childId: 'child-1' });
    const recs = lines().filter((r) => r.type === 'decision.request' || r.type === 'decision.result');
    assert.ok(recs.length >= 4);
    for (const r of recs) {
      assert.equal(r.data.runId, 'child-1');
      assert.equal(r.data.parentRunId, 'root-1');
    }
    const v = verifyAuditFile(path.join(dir, 'audit.jsonl'), { pinnedPublicKeyHex: signer.publicKeyHex });
    assert.equal(v.ok, true, JSON.stringify(v.errors));
    // `extra` cannot be overridden by the caller's own data (a child cannot claim to be someone else).
    const forged = scopedAudit(audit, { runId: 'real' });
    assert.equal(forged.append('x', { runId: 'fake' }).data.runId, 'real');
  });

  test('taint is inherited: a child of a tainted parent starts tainted (and each inherited source is audited under the child)', () => {
    const parent = new TaintTracker();
    parent.mark('web', 'http://evil.example/');
    parent.mark('non-owner-message', 'tg:1');
    const seen: string[] = [];
    const child = new TaintTracker((s) => seen.push(`${s.kind}:${s.ref}`));
    assert.equal(child.tainted, false);
    child.inherit(parent.provenance());
    assert.equal(child.tainted, true);
    assert.deepEqual(seen, ['web:http://evil.example/', 'non-owner-message:tg:1']);
    // The parent is not touched by what the child later sees.
    child.mark('tool-output', 'child-only');
    assert.equal(parent.provenance().sources.length, 2);
  });

  describe('Broker', () => {
    let ws: string;
    let state: string;
    beforeEach(() => {
      ws = path.join(dir, 'ws');
      state = path.join(dir, 'state');
      fs.mkdirSync(path.join(ws, 'docs', 'sub'), { recursive: true });
      fs.mkdirSync(path.join(ws, 'secret'), { recursive: true });
      fs.mkdirSync(path.join(ws, 'out'), { recursive: true });
      fs.mkdirSync(state, { recursive: true });
      fs.writeFileSync(path.join(ws, 'docs', 'a.txt'), 'doc A');
      fs.writeFileSync(path.join(ws, 'docs', 'sub', 'b.txt'), 'doc B');
      fs.writeFileSync(path.join(ws, 'secret', 's.txt'), 'TOP SECRET');
      fs.writeFileSync(path.join(ws, 'root.txt'), 'root file');
      fs.writeFileSync(path.join(state, 'memory.db'), 'pretend memory');
    });
    const mk = (scope: SubagentScope | undefined) => {
      const gov = new Governor({ policy: policyWith({ rules: [{ class: 'fs.read', verdict: 'allow' }, { class: 'fs.write', verdict: 'allow' }] }), audit, taint: new TaintTracker() });
      if (scope) gov.setRunContext({ origin: 'owner', scope, subagent: { runId: 'c', parentRunId: 'p', chain: ['p', 'c'], depth: 1, goal: 'g' } });
      return new Broker({ governor: gov, workspaceDir: ws, stateDir: state, taintedFiles: new TaintedFileStore(), scope });
    };

    test('a tool outside the allow-list is refused and audited, whatever the policy says', async () => {
      const b = mk(scopeOf({ tools: ['readFile'], readPaths: [''] }));
      await b.handle({ name: 'readFile', args: { path: 'root.txt' } });
      for (const name of ['writeFile', 'runCommand', 'scheduleCreate', 'spawnAgent', 'shell', 'fetchUrl', 'notifyOwner', 'spend', 'nothing']) {
        await assert.rejects(() => b.handle({ name, args: {} }), /not among this sub-agent's capabilities/, name);
      }
      assert.ok(lines().some((r) => r.type === 'subagent.tool-denied' && r.data.tool === 'runCommand'));
      // CONTROL: without a scope the same broker call is not refused for that reason.
      await assert.rejects(() => mk(undefined).handle({ name: 'spawnAgent', args: {} }), /not available/);
    });

    test('file scope: read only inside readPaths; write only inside writePaths; never the state dir; ../ and absolute paths do not escape', async () => {
      const b = mk(scopeOf({ tools: ['readFile', 'listDir', 'writeFile'], readPaths: ['docs'], writePaths: ['out'], maxActions: 50 }));
      assert.equal(((await b.handle({ name: 'readFile', args: { path: 'docs/a.txt' } })) as any).content, 'doc A');
      assert.equal(((await b.handle({ name: 'readFile', args: { path: 'docs/sub/b.txt' } })) as any).content, 'doc B');
      for (const p of ['secret/s.txt', 'root.txt', 'docs/../secret/s.txt', path.join(ws, 'secret', 's.txt'), path.join(state, 'memory.db'), '../state/memory.db', 'docs2/x'])
        await assert.rejects(() => b.handle({ name: 'readFile', args: { path: p } }), /denied by hard rule/, p);
      await assert.rejects(() => b.handle({ name: 'listDir', args: { path: '.' } }), /denied by hard rule/);
      await b.handle({ name: 'writeFile', args: { path: 'out/new.txt', content: 'x' } });
      assert.equal(fs.readFileSync(path.join(ws, 'out', 'new.txt'), 'utf8'), 'x');
      for (const p of ['docs/new.txt', 'root2.txt', 'secret/new.txt', '../escape.txt']) await assert.rejects(() => b.handle({ name: 'writeFile', args: { path: p, content: 'x' } }), /denied by hard rule/, p);
      assert.equal(fs.existsSync(path.join(ws, 'secret', 'new.txt')), false);
      // CONTROL: the same reads succeed for the run a human started (no scope).
      assert.equal(((await mk(undefined).handle({ name: 'readFile', args: { path: 'secret/s.txt' } })) as any).content, 'TOP SECRET');
    });

    test('a junction/symlink INSIDE a granted directory that points outside it does not widen the scope (real paths are compared)', async () => {
      const link = path.join(ws, 'docs', 'to-secret');
      try {
        fs.symlinkSync(path.join(ws, 'secret'), link, 'junction');
      } catch {
        return; // cannot create links here: nothing to prove, and nothing is claimed
      }
      const b = mk(scopeOf({ tools: ['readFile'], readPaths: ['docs'], maxActions: 50 }));
      await assert.rejects(() => b.handle({ name: 'readFile', args: { path: 'docs/to-secret/s.txt' } }), /denied by hard rule/);
    });
  });
});

void mulberry32;
