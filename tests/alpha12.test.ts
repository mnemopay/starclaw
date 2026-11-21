import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { StarClawEngine, programReportedFailure } from '../src/engine';
import { parsePolicy } from '../src/governance/policy';
import { codegenSystemPrompt } from '../src/llm/prompts';
import type { CodegenRequest } from '../src/llm/types';
import { FakeLLM, ScriptedApprover, code, policyWith, tmpDir, rm } from './helpers';

async function withEngine(
  fn: (e: StarClawEngine, llm: FakeLLM, ws: string, approver: ScriptedApprover) => Promise<void>,
  overrides: Record<string, unknown> = {},
  decide: ConstructorParameters<typeof ScriptedApprover>[0] = () => 'approve',
  llm: FakeLLM = new FakeLLM(),
) {
  const dir = tmpDir();
  const ws = path.join(dir, 'ws');
  const approver = new ScriptedApprover(decide);
  const e = new StarClawEngine({ llm, stateDir: path.join(dir, 'state'), workspaceDir: ws, policy: policyWith(overrides), approver });
  fs.mkdirSync(ws, { recursive: true });
  try { await fn(e, llm, ws, approver); } finally { e.memory.close(); rm(dir); }
}

const audit = (e: StarClawEngine) => fs.readFileSync(path.join(e.stateDir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map((x) => JSON.parse(x));
const memoryWrites = (a: ReturnType<typeof ApprovalLog>) => a.filter((r) => r.action.class === 'memory.write');
const ApprovalLog = (approver: ScriptedApprover) => approver.seen;

test('programReportedFailure reads success:false and nothing else (not ok:false, which tool results carry)', () => {
  assert.equal(programReportedFailure({ success: false, error: 'tests failed' }), 'tests failed');
  assert.equal(programReportedFailure({ ok: false, err: 'child refused' }), undefined);
  assert.equal(programReportedFailure({ success: false }), 'success: false');
  assert.equal(programReportedFailure({ success: true }), undefined);
  assert.equal(programReportedFailure({ total: 3 }), undefined);
  assert.equal(programReportedFailure(null), undefined);
  assert.equal(programReportedFailure([{ success: false }]), undefined);
});

test('a program that returns { success: false } fails the job and proposes no "Completed:" memory', async () => {
  await withEngine(async (e, llm, _ws, approver) => {
    llm.codeQueue.push(code('return { success: false, error: "the tests still fail" };'));
    const r = await e.executeGoal('fix the bug');
    assert.equal(r.success, false);
    assert.match(r.error!, /program reported failure: the tests still fail/);
    assert.deepEqual(r.result, { success: false, error: 'the tests still fail' });
    assert.equal(memoryWrites(ApprovalLog(approver)).length, 0, 'no memory note is proposed for a failed run');
    assert.equal(e.memory.search('fix the bug').filter((m) => /^Completed:/.test(m.content)).length, 0);
    assert.ok(audit(e).some((x) => x.type === 'goal.failed'));
    assert.ok(!audit(e).some((x) => x.type === 'goal.completed'));
  });
});

test('a successful run still proposes its "Completed:" memory', async () => {
  await withEngine(async (e, llm, _ws, approver) => {
    llm.codeQueue.push(code('return { success: true, total: 14 };'));
    const r = await e.executeGoal('compute the total');
    assert.equal(r.success, true, r.error);
    assert.equal(memoryWrites(ApprovalLog(approver)).length, 1);
    assert.match(e.memory.search('compute the total')[0].content, /^Completed:/);
  });
});

test('a step with a denied action never reports success, even if the program caught the denial and returned', async () => {
  await withEngine(
    async (e, llm, _ws, approver) => {
      llm.codeQueue.push(code('try { await tools.fetchUrl({url:"https://example.com"}); } catch {} return "looks done";'));
      const r = await e.executeGoal('fetch it');
      assert.equal(r.success, false);
      assert.equal(r.denied?.by, 'human');
      assert.equal(memoryWrites(ApprovalLog(approver)).length, 0);
    },
    {},
    (req) => (req.action.class === 'net.egress' ? 'deny' : 'approve'),
  );
});

test('read-before-edit: editing an existing unread file is refused without writing or asking; reading first lets it through', async () => {
  await withEngine(async (e, llm, ws, approver) => {
    fs.writeFileSync(path.join(ws, 'a.txt'), 'original');
    llm.codeQueue.push(
      code('await tools.writeFile({path:"a.txt",content:"guessed"}); return "done";'),
      code('const f = await tools.readFile({path:"a.txt"}); await tools.writeFile({path:"a.txt",content: f.content + "+edit"}); return "done";'),
    );
    const r = await e.executeGoal('edit a.txt');
    assert.equal(r.success, true, r.error);
    assert.equal(fs.readFileSync(path.join(ws, 'a.txt'), 'utf8'), 'original+edit');
    const recs = audit(e);
    assert.equal(recs.filter((x) => x.type === 'agent.edit-unread').length, 1);
    assert.match(JSON.stringify(llm.lastCodegen?.history), /has not been read in this job/);
    // The refused write was never shown to a human.
    assert.equal(ApprovalLog(approver).filter((q) => q.action.class === 'fs.write').length, 1);
  });
});

test('read-before-edit does not apply to new files, and a read in an earlier step counts', async () => {
  await withEngine(async (e, llm, ws) => {
    fs.writeFileSync(path.join(ws, 'b.txt'), 'b0');
    llm.codeQueue.push(
      code('await tools.writeFile({path:"new.txt",content:"fresh"}); const f = await tools.readFile({path:"b.txt"}); return {__starclaw:"continue", observation:{content:f.content}};'),
      code('await tools.editFile({path:"b.txt",find:"b0",replace:"b1"}); return "done";'),
    );
    const r = await e.executeGoal('write new, then edit b');
    assert.equal(r.success, true, r.error);
    assert.equal(fs.readFileSync(path.join(ws, 'new.txt'), 'utf8'), 'fresh');
    assert.equal(fs.readFileSync(path.join(ws, 'b.txt'), 'utf8'), 'b1');
    assert.equal(audit(e).filter((x) => x.type === 'agent.edit-unread').length, 0);
  });
});

test('read-before-edit can be switched off by policy', async () => {
  await withEngine(async (e, llm, ws) => {
    fs.writeFileSync(path.join(ws, 'c.txt'), 'c0');
    llm.codeQueue.push(code('await tools.writeFile({path:"c.txt",content:"c1"}); return "done";'));
    const r = await e.executeGoal('overwrite c');
    assert.equal(r.success, true, r.error);
    assert.equal(fs.readFileSync(path.join(ws, 'c.txt'), 'utf8'), 'c1');
  }, { agent: { requireReadBeforeEdit: false } });
});

test('continueAfterDeny is OFF by default and parses as an opt-in flag', () => {
  const p = parsePolicy(JSON.stringify({ version: 1 }));
  assert.equal(p.agent.continueAfterDeny, false);
  assert.equal(p.agent.requireReadBeforeEdit, true);
  assert.equal(parsePolicy(JSON.stringify({ version: 1, agent: { continueAfterDeny: true } })).agent.continueAfterDeny, true);
});

test('continueAfterDeny: a denied action goes back to the model, is never asked again, and the job can finish another way', async () => {
  await withEngine(
    async (e, llm, _ws, approver) => {
      llm.codeQueue.push(
        code('try { await tools.fetchUrl({url:"https://example.com/x"}); } catch {} return {__starclaw:"continue", observation:"fetch failed"};'),
        code('let again; try { await tools.fetchUrl({url:"https://example.com/x"}); } catch (err) { again = String(err.message); } await tools.writeFile({path:"note.txt",content:"offline plan"}); return { done: true, again };'),
      );
      const r = await e.executeGoal('get the page or make a plan');
      assert.equal(r.success, true, r.error);
      assert.match(String((r.result as any).again), /already denied in this job/);
      assert.equal(ApprovalLog(approver).filter((q) => q.action.class === 'net.egress').length, 1, 'the identical denied action is not shown to a human twice');
      const recs = audit(e);
      assert.equal(recs.filter((x) => x.type === 'agent.denied-replan').length, 1);
      assert.equal(recs.filter((x) => x.type === 'agent.denied-repeat').length, 1);
      assert.match(JSON.stringify(llm.lastCodegen?.history), /DENIED and will not be allowed/);
    },
    { agent: { continueAfterDeny: true } },
    (req) => (req.action.class === 'net.egress' ? 'deny' : 'approve'),
  );
});

test('continueAfterDeny: a denied program is replanned once, and re-proposing the same program ends the job', async () => {
  let execs = 0;
  await withEngine(
    async (e, llm) => {
      llm.codeQueue.push(code('return "first";'), code('return "second";'));
      const r = await e.executeGoal('try twice');
      assert.equal(r.success, true, r.error);
      assert.equal(r.result, 'second');
      assert.equal(audit(e).filter((x) => x.type === 'agent.denied-replan').length, 1);
    },
    { agent: { continueAfterDeny: true } },
    (req) => (req.action.class === 'exec' && execs++ === 0 ? 'deny' : 'approve'),
  );
  let n = 0;
  await withEngine(
    async (e, llm) => {
      llm.codeQueue.push(code('return "same";'), code('return "same";'));
      const r = await e.executeGoal('same program twice');
      assert.equal(r.success, false);
      assert.match(r.error!, /re-proposed a program that was already denied/);
    },
    { agent: { continueAfterDeny: true } },
    (req) => (req.action.class === 'exec' && n++ === 0 ? 'deny' : 'approve'),
  );
});

test('without continueAfterDeny a denied program still ends the job immediately', async () => {
  await withEngine(
    async (e, llm) => {
      llm.codeQueue.push(code('return "first";'), code('return "second";'));
      const r = await e.executeGoal('denied');
      assert.equal(r.success, false);
      assert.equal(llm.calls.code, 1);
    },
    {},
    (req) => (req.action.class === 'exec' ? 'deny' : 'approve'),
  );
});

class RetryingLLM extends FakeLLM {
  override async generateCode(req: CodegenRequest) {
    const r = await super.generateCode(req);
    return { ...r, retries: [{ kind: 'tool_use_failed' as const }, { kind: 'rate-limit' as const, waitSeconds: 3 }] };
  }
}

test('provider retries inside an LLM call are visible in the audit log as llm.retry', async () => {
  await withEngine(async (e, llm) => {
    llm.codeQueue.push(code('return 1;'));
    const r = await e.executeGoal('anything');
    assert.equal(r.success, true, r.error);
    const retries = audit(e).filter((x) => x.type === 'llm.retry');
    assert.deepEqual(retries.map((x) => [x.data.what, x.data.kind, x.data.waitSeconds]), [['codegen', 'tool_use_failed', undefined], ['codegen', 'rate-limit', 3]]);
  }, {}, () => 'approve', new RetryingLLM());
});

test('the code-generation prompt requires reading a file before editing it', () => {
  assert.match(codegenSystemPrompt('', false), /READ BEFORE YOU EDIT/);
  assert.match(codegenSystemPrompt('', false), /refuses edits to existing files you have\s+not read/);
});
