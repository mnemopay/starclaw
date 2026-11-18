import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { StarClawEngine } from '../src/engine';
import { TaintedFileStore } from '../src/governance/taint';
import { LlmBudget } from '../src/governance/budget';
import { CapabilitiesSchema } from '../src/skills/registry/bundle';
import { BackendLLM, type ChatBackend } from '../src/llm/BackendLLM';
import { FakeLLM, ScriptedApprover, code, policyWith, tmpDir, rm } from './helpers';

async function withEngine(fn: (e: StarClawEngine, llm: FakeLLM, dir: string) => Promise<void>, overrides: Record<string, unknown> = {}) {
  const dir = tmpDir();
  const llm = new FakeLLM();
  const e = new StarClawEngine({ llm, stateDir: path.join(dir, 'state'), workspaceDir: path.join(dir, 'ws'), policy: policyWith(overrides), approver: new ScriptedApprover(() => 'approve') });
  try { await fn(e, llm, dir); } finally { e.memory.close(); rm(dir); }
}

test('observations drive another model turn, preserve taint, and persist a useful final outcome', async () => {
  await withEngine(async (e, llm) => {
    llm.codeQueue.push(code('return {__starclaw:"continue", observation:{count:7}};'), code('return {verified:true, total:14};'));
    const result = await e.executeGoal('inspect then compute');
    assert.equal(result.success, true, result.error);
    assert.deepEqual(result.result, { verified: true, total: 14 });
    assert.equal(llm.calls.code, 2);
    assert.equal(llm.lastCodegen?.tainted, true);
    assert.match(JSON.stringify(llm.lastCodegen?.history), /count/);
    assert.match(e.memory.search('compute')[0].content, /total.*14/);
  });
});

test('runtime recovery is bounded and cannot replay an attempted side effect', async () => {
  await withEngine(async (e, llm, dir) => {
    llm.codeQueue.push(code('throw new Error("missing result");'), code('return 42;'));
    assert.equal((await e.executeGoal('calculate')).result, 42);
    llm.codeQueue.push(code('await tools.writeFile({path:"once.txt",content:"written"}); throw new Error("failure after write");'), code('return "must not run";'));
    const result = await e.executeGoal('write once');
    assert.equal(result.success, false);
    assert.equal(fs.readFileSync(path.join(dir, 'ws', 'once.txt'), 'utf8'), 'written');
    assert.equal(llm.codeQueue.length, 1);
  });
});

test('continuation deduplicates identical successful mutations within one goal', async () => {
  await withEngine(async (e, llm) => {
    const write = 'await tools.writeFile({path:"once.txt",content:"same"});';
    llm.codeQueue.push(code(write + 'return {__starclaw:"continue",observation:"written"};'), code(write + 'return "verified";'));
    const result = await e.executeGoal('write and verify');
    assert.equal(result.success, true, result.error);
    const records = fs.readFileSync(path.join(e.stateDir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map(x => JSON.parse(x));
    assert.equal(records.filter(r => r.type === 'action.result' && r.data?.class === 'fs.write').length, 1);
  });
});

test('endless continuations stop at the configured step limit', async () => {
  await withEngine(async (e, llm) => {
    llm.codeQueue.push(code('return {__starclaw:"continue",observation:"again"};'), code('return {__starclaw:"continue",observation:"again"};'));
    const result = await e.executeGoal('never finish');
    assert.equal(result.success, false);
    assert.match(result.error!, /step limit/);
    assert.equal(llm.calls.code, 2);
  }, { agent: { maxSteps: 2 } });
});

test('a denied action cannot be laundered into an automatic continuation', async () => {
  await withEngine(async (e, llm) => {
    e.setApprover(new ScriptedApprover(req => req.action.class === 'net.egress' ? 'deny' : 'approve'));
    llm.codeQueue.push(code('try { await tools.fetchUrl({url:"https://example.com"}); } catch {} return {__starclaw:"continue",observation:"try something else"};'), code('return "must not run";'));
    const result = await e.executeGoal('respect the owner decision');
    assert.equal(result.success, false);
    assert.equal(result.denied?.by, 'human');
    assert.equal(llm.calls.code, 1);
    assert.equal(llm.codeQueue.length, 1);
  });
});

test('a new session cannot clear provenance while owner work is active or queued', async () => {
  await withEngine(async (e, llm) => {
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const generate = llm.generateCode.bind(llm);
    llm.generateCode = async req => { await gate; return generate(req); };
    llm.codeQueue.push(code('return 1;'), code('return 2;'));
    e.governor.taint.mark('web', 'hostile page');
    const first = e.executeGoal('first');
    const second = e.executeGoal('second');
    assert.equal(e.newSession(), false);
    assert.equal(e.tainted, true);
    release();
    assert.equal((await first).result, 1);
    assert.equal((await second).result, 2);
    assert.equal(e.newSession(), true);
    assert.equal(e.tainted, false);
  });
});

test('unknown, externally edited, legacy and corrupt file provenance is untrusted', () => {
  const dir = tmpDir();
  try {
    const file = path.join(dir, 'note.txt'), storePath = path.join(dir, 'provenance.json');
    fs.writeFileSync(file, 'known');
    let store = new TaintedFileStore(storePath);
    assert.equal(store.has(file), true);
    store.remove(file);
    store = new TaintedFileStore(storePath);
    assert.equal(store.has(file), false);
    fs.writeFileSync(file, 'injected');
    assert.equal(store.has(file), true);
    fs.writeFileSync(storePath, 'broken');
    assert.equal(new TaintedFileStore(storePath).has(file), true);
    fs.writeFileSync(storePath, '[]');
    assert.equal(new TaintedFileStore(storePath).has(file), true);
  } finally { rm(dir); }
});

test('registry shell needs explicit whole-workspace consent; delegation is unavailable', () => {
  for (const tools of [['shell'], ['spawnAgent']]) assert.equal(CapabilitiesSchema.safeParse({ tools, paths: ['docs/**'] }).success, false);
  assert.equal(CapabilitiesSchema.safeParse({ tools: ['readFile'], optionalTools: ['shell'], paths: [] }).success, false);
  assert.equal(CapabilitiesSchema.safeParse({ tools: ['shell'], paths: ['**'] }).success, true);
});

test('an approval arriving after sandbox timeout cannot write into a new session', async () => {
  await withEngine(async (e, llm, dir) => {
    let approve!: (answer: 'approve') => void;
    let asked!: () => void;
    const waiting = new Promise<void>(resolve => { asked = resolve; });
    e.setApprover(new ScriptedApprover(req => {
      if (req.action.class !== 'fs.write') return 'approve';
      asked();
      return new Promise(resolve => { approve = resolve; });
    }));
    llm.codeQueue.push(code('await tools.writeFile({path:"late.txt",content:"should never appear"}); return true;'));
    const goal = e.executeGoal('wait for approval');
    await waiting;
    const result = await goal;
    assert.equal(result.success, false);
    assert.match(result.error!, /timed out/);
    assert.equal(e.newSession(), true);
    approve('approve');
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(fs.existsSync(path.join(dir, 'ws', 'late.txt')), false);
  }, { sandbox: { timeoutSeconds: 1 } });
});

test('approval-time junction swaps and hard-linked secret aliases cannot leak files', async () => {
  await withEngine(async (e, _llm, dir) => {
    const outside = path.join(dir, 'outside');
    const target = path.join(e.workspaceDir, 'target');
    fs.mkdirSync(outside);
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, 'note.txt'), 'approved');
    fs.writeFileSync(path.join(outside, 'note.txt'), 'secret');
    e.setApprover(new ScriptedApprover(() => {
      fs.renameSync(target, `${target}-old`);
      fs.symlinkSync(outside, target, process.platform === 'win32' ? 'junction' : 'dir');
      return 'approve';
    }));
    e.policy.defaults['fs.read'] = 'ask';
    e.policy.rules = [];
    await assert.rejects(() => e.broker.handle({ name: 'readFile', args: { path: 'target/note.txt' } }), /path changed/);
    const alias = path.join(e.workspaceDir, 'alias.txt');
    fs.linkSync(path.join(e.stateDir, 'audit.key'), alias);
    e.setApprover(new ScriptedApprover(() => 'approve'));
    await assert.rejects(() => e.broker.handle({ name: 'readFile', args: { path: 'alias.txt' } }), /links/);
    await assert.rejects(() => e.broker.handle({ name: 'editFile', args: { path: 'alias.txt', find: 'PRIVATE', replace: 'x' } }), /single-link/);
  });
});

test('writeFile refuses to overwrite a file edited while its approval is pending', async () => {
  await withEngine(async (e) => {
    const target = path.join(e.workspaceDir, 'draft.txt');
    fs.writeFileSync(target, 'before');
    e.setApprover(new ScriptedApprover(() => {
      fs.writeFileSync(target, 'human edit');
      return 'approve';
    }));
    await assert.rejects(() => e.broker.handle({ name: 'writeFile', args: { path: 'draft.txt', content: 'agent replacement' } }), /file changed/);
    assert.equal(fs.readFileSync(target, 'utf8'), 'human edit');
  });
});

test('daily reservations are shared, survive restart, reconcile once, and fail closed on corruption', () => {
  const dir = tmpDir();
  try {
    const file = path.join(dir, 'budget.json');
    const a = new LlmBudget(10, 1, file), b = new LlmBudget(10, 1, file);
    const reservation = a.reserve(800_000);
    assert.throws(() => b.reserve(300_000), /daily/);
    assert.equal(new LlmBudget(10, 1, file).availableMicro, 200_000);
    reservation.settle(100_000);
    assert.equal(b.availableMicro, 900_000);
    assert.throws(() => reservation.settle(0), /already settled/);
    fs.writeFileSync(file, 'corrupt');
    assert.throws(() => b.reserve(1), /corrupt/);
  } finally { rm(dir); }
});

test('a production backend reserves before dispatch and reduces output tokens to remaining funds', async () => {
  let calls = 0, maxTokens = 0;
  const backend: ChatBackend = { provider: 'test', complete: async req => { calls++; maxTokens = req.maxTokens; return { text: 'ok', usage: { inputTokens: 1, outputTokens: 1 } }; } };
  const llm = new BackendLLM(backend, { model: 'test', price: { inputCentsPerMTok: 100, outputCentsPerMTok: 3000 } });
  const budget = new LlmBudget(1, 1);
  const result = await llm.converse('hello', [], { budget });
  assert.equal(result.prepaid, true);
  assert.ok(maxTokens > 0 && maxTokens < 500);
  assert.equal(budget.runCentsCeil, 1);
  await assert.rejects(() => llm.converse('too expensive', [], { budget: new LlmBudget(0, 0) }), /budget/);
  assert.equal(calls, 1);
});

test('a failed provider request retains reserved cost instead of granting a free retry', async () => {
  const backend: ChatBackend = { provider: 'test', complete: async () => { throw new Error('connection lost after dispatch'); } };
  const llm = new BackendLLM(backend, { model: 'test', price: { inputCentsPerMTok: 100, outputCentsPerMTok: 3000 } });
  const budget = new LlmBudget(1, 1);
  await assert.rejects(() => llm.converse('hello', [], { budget }), /connection lost/);
  assert.ok(budget.availableMicro < 3000, 'the dispatched request retains the reservation');
  await assert.rejects(() => llm.converse('hello', [], { budget }), /remaining LLM budget/);
});
