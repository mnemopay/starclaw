/** Phase 2 (no Docker): cron + job store + scheduler, unattended runs, async approvals, notifyOwner, legacy host.exec. */
import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { StarClawEngine } from '../src/engine';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintTracker } from '../src/governance/taint';
import type { ApprovalAnswer, ApprovalRequest, Approver } from '../src/governance/types';
import { MemoryNotifier } from '../src/notify/Notifier';
import { minGapSeconds, nextFire, parseSchedule } from '../src/scheduler/cron';
import { JobError, JobStore } from '../src/scheduler/JobStore';
import { Scheduler } from '../src/scheduler/Scheduler';
import { FakeLLM, HangingApprover, ScriptedApprover, code, policyWith, rm, tmpDir } from './helpers';

/** Reaches the owner away from the terminal (like Telegram). */
class AsyncApprover extends ScriptedApprover {
  readonly async = true;
}

describe('cron', () => {
  test('parses lists, ranges, steps and @every; rejects everything else', () => {
    assert.equal(minGapSeconds(parseSchedule('*/15 * * * *')), 900);
    assert.equal(minGapSeconds(parseSchedule('0 9 * * 1-5')) >= 86_400, true);
    assert.equal(minGapSeconds(parseSchedule('@every 30m')), 1800);
    for (const bad of ['', '* * * *', '60 * * * *', '* 24 * * *', '* * 0 * *', '* * * 13 *', '*/0 * * * *', 'MON * * * *', '* * * * * *', '0 0 31 2 *', '5-1 * * * *', '@every 0s', '@daily'])
      assert.throws(() => parseSchedule(bad), Error, `accepted: ${JSON.stringify(bad)}`);
  });
  test('next fire respects the timezone', () => {
    const after = Date.UTC(2026, 0, 15, 0, 0, 0); // 2026-01-15 00:00 UTC
    const utc = nextFire(parseSchedule('0 9 * * *', 'UTC'), after, 'UTC')!;
    assert.equal(new Date(utc).toISOString(), '2026-01-15T09:00:00.000Z');
    const lagos = nextFire(parseSchedule('0 9 * * *', 'Africa/Lagos'), after, 'Africa/Lagos')!; // UTC+1
    assert.equal(new Date(lagos).toISOString(), '2026-01-15T08:00:00.000Z');
    assert.equal(new Date(nextFire(parseSchedule('@every 90s'), after)!).toISOString(), '2026-01-15T00:01:30.000Z');
  });
});

describe('JobStore', () => {
  let dir: string;
  beforeEach(() => (dir = tmpDir()));
  afterEach(() => rm(dir));
  const mk = (over: Record<string, unknown> = {}) => new JobStore(path.join(dir, 's.json'), () => policyWith({ scheduled: over }).scheduled);

  test('enforces minimum interval, job count and name/goal sanity; survives a restart', () => {
    const s = mk({ minIntervalSeconds: 300, maxJobsTotal: 2 });
    assert.throws(() => s.add({ name: 'fast', schedule: '@every 60s', goal: 'do it', createdBy: 'owner-cli' }), JobError);
    assert.throws(() => s.add({ name: 'fast', schedule: '* * * * *', goal: 'do it', createdBy: 'owner-cli' }), /minIntervalSeconds/);
    assert.throws(() => s.add({ name: '', schedule: '@every 10m', goal: 'do it', createdBy: 'owner-cli' }), JobError);
    assert.throws(() => s.add({ name: 'x', schedule: '@every 10m', goal: 'ab', createdBy: 'owner-cli' }), JobError);
    const a = s.add({ name: 'a', schedule: '@every 10m', goal: 'check things', createdBy: 'owner-cli' });
    s.add({ name: 'b', schedule: '*/10 * * * *', goal: 'check more', createdBy: 'owner-cli', kind: 'heartbeat' });
    assert.throws(() => s.add({ name: 'c', schedule: '@every 10m', goal: 'one too many', createdBy: 'owner-cli' }), /job limit/);
    const again = mk({ maxJobsTotal: 2 });
    assert.equal(again.list().length, 2);
    assert.equal(again.get(a.id)?.name, 'a');
    assert.equal(again.list().find((j) => j.name === 'b')!.notify, 'agent', 'heartbeats only message through tools.notifyOwner by default');
  });

  test('a corrupt state file runs nothing', () => {
    fs.writeFileSync(path.join(dir, 's.json'), '{not json');
    assert.deepEqual(mk().list(), []);
  });
});

describe('Scheduler', () => {
  let dir: string;
  let audit: AuditLog;
  beforeEach(() => {
    dir = tmpDir();
    audit = new AuditLog(path.join(dir, 'audit.jsonl'), Ed25519Signer.generate());
  });
  afterEach(() => rm(dir));
  const types = () => fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l).type as string);

  const mk = (over: Record<string, unknown>, run: (job: any) => Promise<any>, onPaused?: (j: any, r: string) => void) => {
    const policy = policyWith({ scheduled: over }).scheduled;
    const store = new JobStore(path.join(dir, 's.json'), () => policy);
    const calls: string[] = [];
    const sched = new Scheduler({ store, audit, policy, runner: { runScheduled: async (job, o) => { calls.push(job.id); return run(Object.assign({}, job, o)); } }, onPaused });
    return { store, sched, calls };
  };
  const ok = { success: true, kind: 'task', tainted: false, llmCostCentsCeil: 1 };
  const bad = { success: false, kind: 'task', error: 'boom', tainted: false, llmCostCentsCeil: 0 };

  test('runs a due job once, writes the start record BEFORE the run, and schedules the next slot', async () => {
    let typesAtRun: string[] = [];
    const { store, sched, calls } = mk({}, async () => { typesAtRun = types(); return ok; });
    const j = store.add({ name: 'j', schedule: '@every 10m', goal: 'do it', createdBy: 'owner-cli' });
    const t = Date.now() + 600_000;
    store.update(j.id, { nextRunAt: t });
    assert.deepEqual((await sched.tick(t - 1000)).ran, [], 'not due yet');
    assert.deepEqual((await sched.tick(t)).ran, [j.id]);
    assert.ok(typesAtRun.includes('scheduler.run.start'), 'run.start must be audited before the run');
    assert.ok(!typesAtRun.includes('scheduler.run.end'));
    assert.deepEqual((await sched.tick(t + 1)).ran, [], 'missed slots are coalesced: no replay');
    assert.equal(calls.length, 1);
    assert.ok(store.get(j.id)!.nextRunAt! > t);
    assert.equal(store.counters().llmCentsToday, 1);
  });

  test('daily limits: total runs per day and per job per day are enforced and audited', async () => {
    const { store, sched, calls } = mk({ maxRunsPerDay: 2, maxRunsPerJobPerDay: 1, minIntervalSeconds: 300 }, async () => ok);
    const past = Date.now() - 3_600_000;
    const a = store.add({ name: 'a', schedule: '@every 10m', goal: 'job a', createdBy: 'owner-cli' }, past);
    const b = store.add({ name: 'b', schedule: '@every 10m', goal: 'job b', createdBy: 'owner-cli' }, past);
    await sched.tick(Date.now());
    assert.equal(calls.length, 2);
    // Both are due again; a/b already used their per-job allowance and the global cap is reached.
    store.update(a.id, { nextRunAt: Date.now() - 1 });
    store.update(b.id, { nextRunAt: Date.now() - 1 });
    const rep = await sched.tick(Date.now());
    assert.equal(calls.length, 2);
    assert.equal(rep.skipped.length, 2);
    assert.ok(types().includes('scheduler.skipped'));
  });

  test('the LLM-spend cap for scheduled runs stops further runs', async () => {
    const { store, sched, calls } = mk({ maxLlmCentsPerDay: 1, maxRunsPerJobPerDay: 10 }, async () => ({ ...ok, llmCostCentsCeil: 2 }));
    const j = store.add({ name: 'a', schedule: '@every 10m', goal: 'job a', createdBy: 'owner-cli' }, Date.now() - 3_600_000);
    await sched.tick(Date.now());
    store.update(j.id, { nextRunAt: Date.now() - 1 });
    const rep = await sched.tick(Date.now());
    assert.equal(calls.length, 1);
    assert.match(rep.skipped[0].reason, /maxLlmCentsPerDay/);
  });

  test('failures back off, then the job is paused and the owner hook fires; a paused job never runs again', async () => {
    const paused: string[] = [];
    const { store, sched, calls } = mk({ maxConsecutiveFailures: 3, backoffBaseSeconds: 60, maxRunsPerDay: 100, maxRunsPerJobPerDay: 100 }, async () => bad, (j, r) => paused.push(r));
    const j = store.add({ name: 'flaky', schedule: '@every 10m', goal: 'always fails', createdBy: 'owner-cli' }, Date.now() - 3_600_000);
    for (let i = 0; i < 3; i++) {
      store.update(j.id, { nextRunAt: Date.now() - 1 });
      await sched.tick(Date.now());
    }
    const after = store.get(j.id)!;
    assert.equal(after.paused, true);
    assert.equal(after.consecutiveFailures, 3);
    assert.equal(paused.length, 1);
    assert.match(paused[0], /3 consecutive failures/);
    store.update(j.id, { nextRunAt: Date.now() - 1 });
    await sched.tick(Date.now());
    assert.equal(calls.length, 3, 'paused jobs are never run');
    assert.ok(types().includes('scheduler.job.paused'));
  });

  test('a run that throws is a failure, not a crash', async () => {
    const { store, sched } = mk({}, async () => { throw new Error('kaboom'); });
    const j = store.add({ name: 'x', schedule: '@every 10m', goal: 'explode', createdBy: 'owner-cli' }, Date.now() - 3_600_000);
    await sched.tick(Date.now());
    assert.match(store.get(j.id)!.lastStatus!, /kaboom/);
  });
});

describe('unattended runs through the engine', () => {
  let dir: string, ws: string, state: string, llm: FakeLLM;
  const engines: StarClawEngine[] = [];
  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    llm = new FakeLLM();
  });
  afterEach(() => {
    for (const e of engines.splice(0)) e.memory.close();
    rm(dir);
  });
  const make = (policy: Record<string, unknown>, approver?: Approver, extra: Record<string, unknown> = {}) => {
    const e = new StarClawEngine({ llm, policy: policyWith(policy), stateDir: state, workspaceDir: ws, approver, ...extra });
    engines.push(e);
    return e;
  };
  const addJob = (e: StarClawEngine, over: Record<string, unknown> = {}) => e.jobs.add({ name: 'job', schedule: '@every 10m', goal: 'do the thing', createdBy: 'owner-cli', ...over } as any);
  const run = (e: StarClawEngine, jobId: string, ms = 20_000) => e.runScheduled(e.jobs.get(jobId)!, { triggerAt: new Date().toISOString(), deadlineAt: Date.now() + ms });
  const auditText = () => fs.readFileSync(path.join(state, 'audit.jsonl'), 'utf8');

  test('DEFAULT: an unattended run that needs approval is DENIED at once, even with an interactive approver that would say yes', async () => {
    const approver = new ScriptedApprover(() => 'approve'); // a terminal approver: NOT async
    const e = make({}, approver);
    llm.codeQueue.push(code(`await tools.writeFile({ path: 'x.txt', content: 'x' }); return 1;`));
    const r = await run(e, addJob(e).id);
    assert.equal(r.success, false);
    assert.equal(r.denied?.by, 'scheduled-policy');
    assert.equal(approver.seen.length, 0, 'nobody may be asked at the terminal for an unattended run');
    assert.equal(fs.existsSync(path.join(ws, 'x.txt')), false);
    assert.match(auditText(), /"origin":"scheduled"/);
  });

  test('ask-async + an async approver (Telegram-like): the owner is asked WITH the job id; approve runs, deny does not', async () => {
    const approver = new AsyncApprover(() => 'approve');
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' } }, approver);
    llm.codeQueue.push(code(`return 7;`));
    const j = addJob(e);
    const r = await run(e, j.id);
    assert.equal(r.success, true, r.error);
    assert.equal(r.result, 7);
    assert.equal(approver.seen[0].action.class, 'exec');
    assert.equal(approver.seen[0].scheduled?.jobId, j.id);

    const denier = new AsyncApprover(() => 'deny');
    e.setApprover(denier);
    llm.codeQueue.push(code(`return 8;`));
    const r2 = await run(e, j.id);
    assert.equal(r2.success, false);
    assert.equal(r2.denied?.by, 'human');
  });

  test('ask-async but the approver is NOT async (terminal/HTTP): denied, never asked', async () => {
    const approver = new ScriptedApprover(() => 'approve');
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' } }, approver);
    llm.codeQueue.push(code(`return 1;`));
    const r = await run(e, addJob(e).id);
    assert.equal(r.denied?.by, 'scheduled-policy');
    assert.equal(approver.seen.length, 0);
  });

  test('ask-async with NO approver at all: denied', async () => {
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' } });
    llm.codeQueue.push(code(`return 1;`));
    assert.equal((await run(e, addJob(e).id)).denied?.by, 'scheduled-policy');
  });

  test('an approval nobody answers is a DENY at the run deadline (never an implicit approve)', async () => {
    class SlowAsync extends HangingApprover {
      readonly async = true;
    }
    const approver = new SlowAsync();
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async', approvalTimeoutSeconds: 900 } }, approver);
    llm.codeQueue.push(code(`return 1;`));
    const t0 = Date.now();
    const r = await run(e, addJob(e).id, 600);
    assert.equal(r.success, false);
    assert.equal(r.denied?.by, 'timeout');
    assert.ok(Date.now() - t0 < 5000);
    assert.equal(approver.aborted, true);
  });

  test('host.exec and schedule.create are refused in unattended runs whatever the policy and approver say', async () => {
    const approver = new AsyncApprover(() => 'approve');
    const e = make({ rules: [{ class: 'exec', verdict: 'allow' }, { class: 'host.exec', verdict: 'allow' }, { class: 'schedule.create', verdict: 'allow' }], scheduled: { defaultVerdictForAsk: 'ask-async' } }, approver);
    llm.codeQueue.push(code(`const out = {};
      try { await tools.runCommand({ file: process.execPath, args: ['-e', '1'] }); out.host = 'RAN'; } catch (err) { out.host = String(err.message).slice(0, 120); }
      try { await tools.scheduleCreate({ name: 'evil', schedule: '@every 10m', goal: 'persist myself' }); out.sched = 'CREATED'; } catch (err) { out.sched = String(err.message).slice(0, 120); }
      return out;`));
    const r = await run(e, addJob(e).id);
    // alpha.12: the denied actions mean the run is not reported as a success; the program's result is kept.
    assert.equal(r.success, false);
    assert.equal(r.denied?.by, 'scheduled-policy');
    const out = r.result as any;
    assert.match(out.host, /never allowed in a scheduled/);
    assert.match(out.sched, /never allowed in a scheduled/);
    assert.equal(e.jobs.list().length, 1, 'a scheduled run created a job');
    assert.deepEqual(approver.seen.map((s) => s.action.class), [], 'exec was allowed by policy; the host.exec and schedule.create attempts never reached the owner (and a failed run proposes no memory)');
  });

  test('a job created in a tainted session starts every run tainted, and the owner session is neither tainted nor affected by a scheduled run', async () => {
    const approver = new AsyncApprover(() => 'approve');
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' }, rules: [{ class: 'exec', verdict: 'allow' }] }, approver);
    llm.codeQueue.push(code(`await tools.writeFile({ path: 'n.txt', content: 'z' }); return 1;`));
    const j = addJob(e, { createdTainted: true });
    const r = await run(e, j.id);
    assert.equal(r.success, true, r.error);
    assert.equal(r.tainted, true);
    assert.ok(approver.seen.some((s) => s.action.class === 'exec' && s.escalatedByTaint), 'taint must escalate the policy-allowed exec to the owner');
    assert.equal(e.tainted, false, 'the owner session must be unaffected');
  });

  test('job notify=summary sends one rate-limited message; failures are reported too', async () => {
    const n = new MemoryNotifier();
    const approver = new AsyncApprover(() => 'approve');
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' } }, approver, { notifier: n });
    llm.codeQueue.push(code(`return 'all good';`));
    await run(e, addJob(e, { notify: 'summary' }).id);
    assert.equal(n.sent.length, 1);
    assert.match(n.sent[0], /job: all good/);
  });

  test('HEARTBEAT "message you first": the agent decides to speak via tools.notifyOwner; the message reaches ONLY the configured owner channel', async () => {
    const n = new MemoryNotifier();
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' } }, new AsyncApprover(() => 'approve'), { notifier: n });
    llm.codeQueue.push(code(`const r = await tools.notifyOwner({ text: 'Disk is 95% full' }); return r;`));
    const j = addJob(e, { kind: 'heartbeat', goal: 'check disk space' });
    const r = await run(e, j.id);
    assert.equal(r.success, true, r.error);
    assert.equal(n.sent.length, 1);
    assert.match(n.sent[0], /Disk is 95% full/);
    assert.match(llm.lastCodegen!.goal, /HEARTBEAT/);
    assert.match(auditText(), /"type":"decision.request"[^\n]*"class":"notify.owner"/);
  });

  test('a heartbeat that has nothing to say sends nothing', async () => {
    const n = new MemoryNotifier();
    const e = make({ scheduled: { defaultVerdictForAsk: 'ask-async' } }, new AsyncApprover(() => 'approve'), { notifier: n });
    llm.codeQueue.push(code(`return 'nothing to report';`));
    await run(e, addJob(e, { kind: 'heartbeat', goal: 'check' }).id);
    assert.equal(n.sent.length, 0);
  });
});

describe('notifyOwner (interactive runs)', () => {
  let dir: string, ws: string, state: string, llm: FakeLLM;
  const engines: StarClawEngine[] = [];
  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    llm = new FakeLLM();
  });
  afterEach(() => {
    for (const e of engines.splice(0)) e.memory.close();
    rm(dir);
  });
  const make = (policy: Record<string, unknown>, approver?: Approver, extra: Record<string, unknown> = {}) => {
    const e = new StarClawEngine({ llm, policy: policyWith(policy), stateDir: state, workspaceDir: ws, approver, ...extra });
    engines.push(e);
    return e;
  };
  const exec = { class: 'exec', verdict: 'allow' };

  test('unavailable without an owner channel; the tool has no recipient parameter', async () => {
    const e = make({ rules: [exec] });
    await assert.rejects(() => e.broker.handle({ name: 'notifyOwner', args: { text: 'hi' } }), /not available/);
    const n = new MemoryNotifier();
    const e2 = make({ rules: [exec] }, undefined, { notifier: n });
    await assert.rejects(() => e2.broker.handle({ name: 'notifyOwner', args: { text: 'hi', chat_id: 12345 } }), /unrecognized|Unrecognized/i);
    assert.equal(n.sent.length, 0);
  });

  test('allowed by default for a clean session; capped in length; rate-limited per hour (persisted across engines)', async () => {
    const n = new MemoryNotifier();
    const e = make({ notify: { maxPerHour: 2, maxChars: 50 } }, undefined, { notifier: n });
    await e.broker.handle({ name: 'notifyOwner', args: { text: 'x'.repeat(500) } });
    await e.broker.handle({ name: 'notifyOwner', args: { text: 'second' } });
    assert.ok(n.sent[0].length <= 50 + '[StarClaw] '.length);
    await assert.rejects(() => e.broker.handle({ name: 'notifyOwner', args: { text: 'third' } }), /rate limit/);
    const e2 = make({ notify: { maxPerHour: 2, maxChars: 50 } }, undefined, { notifier: n });
    await assert.rejects(() => e2.broker.handle({ name: 'notifyOwner', args: { text: 'after restart' } }), /rate limit/);
    assert.equal(n.sent.length, 2);
    assert.match(fs.readFileSync(path.join(state, 'audit.jsonl'), 'utf8'), /notify\.rate-limited/);
  });

  test('a TAINTED session cannot message the owner without approval (phishing/exfil vector)', async () => {
    const n = new MemoryNotifier();
    const approver = new ScriptedApprover(() => 'deny');
    const e = make({}, approver, { notifier: n });
    e.governor.taint.mark('web', 'http://evil.example/');
    await assert.rejects(() => e.broker.handle({ name: 'notifyOwner', args: { text: 'click http://evil.example' } }));
    assert.equal(n.sent.length, 0);
    assert.equal(approver.seen[0].escalatedByTaint, true);
  });

  test('system notices (job paused) use the same channel and limits, and are audited before the send', async () => {
    const n = new MemoryNotifier();
    const e = make({ notify: { maxPerHour: 1 } }, undefined, { notifier: n });
    assert.equal(await e.notifySystem('job "x" was paused'), true);
    assert.equal(await e.notifySystem('again'), false);
    assert.equal(n.sent.length, 1);
    assert.match(fs.readFileSync(path.join(state, 'audit.jsonl'), 'utf8'), /notify\.system/);
  });
});

describe('legacy host.exec and agent-created schedules', () => {
  let dir: string, ws: string, state: string, llm: FakeLLM;
  const engines: StarClawEngine[] = [];
  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    llm = new FakeLLM();
  });
  afterEach(() => {
    for (const e of engines.splice(0)) e.memory.close();
    rm(dir);
  });
  const make = (policy: Record<string, unknown>, approver?: Approver) => {
    const e = new StarClawEngine({ llm, policy: policyWith(policy), stateDir: state, workspaceDir: ws, approver });
    engines.push(e);
    return e;
  };
  const runCmd = { name: 'runCommand', args: { file: process.execPath, args: ['-e', 'console.log(1)'] } };

  test('non-interactive (no approver): denied even when the policy explicitly allows host.exec; the class is distinct from sandboxed exec', async () => {
    const e = make({ rules: [{ class: 'host.exec', verdict: 'allow' }] });
    await assert.rejects(() => e.broker.handle(runCmd), /host\.exec \(unsandboxed host command\) is denied when non-interactive/);
    // CONTROL: with an interactive approver present, the same explicit allow works.
    const e2 = new StarClawEngine({ llm, policy: policyWith({ rules: [{ class: 'host.exec', verdict: 'allow' }] }), stateDir: path.join(dir, 's2'), workspaceDir: ws, approver: new ScriptedApprover(() => 'deny') });
    engines.push(e2);
    const r: any = await e2.broker.handle(runCmd);
    assert.equal(r.code, 0);
  });

  test('default policy: asks a present human; a rule for class exec does not open host.exec', async () => {
    const approver = new ScriptedApprover(() => 'deny');
    const e = make({ rules: [{ class: 'exec', verdict: 'allow' }] }, approver);
    await assert.rejects(() => e.broker.handle(runCmd));
    assert.equal(approver.seen[0].action.class, 'host.exec');
  });

  test('schedule.create ALWAYS asks, even when the policy says allow; a denial creates nothing; an approval records who made it', async () => {
    const args = { name: 'nightly', schedule: '0 3 * * *', goal: 'summarise the workspace' };
    const denier = new ScriptedApprover(() => 'deny');
    const e = make({ rules: [{ class: 'schedule.create', verdict: 'allow' }] }, denier);
    await assert.rejects(() => e.broker.handle({ name: 'scheduleCreate', args }));
    assert.equal(denier.seen[0].action.class, 'schedule.create');
    assert.match(denier.seen[0].reason, /always needs a human/);
    assert.equal(e.jobs.list().length, 0);
    e.setApprover(new ScriptedApprover(() => 'approve'));
    const r: any = await e.broker.handle({ name: 'scheduleCreate', args });
    assert.ok(r.id);
    const job = e.jobs.list()[0];
    assert.equal(job.createdBy, 'agent-approved');
    assert.equal(job.createdTainted, false);
    // And with no approver at all: denied.
    const e3 = new StarClawEngine({ llm, policy: policyWith({ rules: [{ class: 'schedule.create', verdict: 'allow' }] }), stateDir: path.join(dir, 's3'), workspaceDir: ws });
    engines.push(e3);
    await assert.rejects(() => e3.broker.handle({ name: 'scheduleCreate', args }));
    assert.equal(e3.jobs.list().length, 0);
  });

  test('an invalid schedule is rejected BEFORE a human is asked; a job from a tainted session is flagged', async () => {
    const approver = new ScriptedApprover(() => 'approve');
    const e = make({}, approver);
    await assert.rejects(() => e.broker.handle({ name: 'scheduleCreate', args: { name: 'spam', schedule: '* * * * *', goal: 'every minute forever' } }), /minIntervalSeconds/);
    assert.equal(approver.seen.length, 0);
    e.governor.taint.mark('web', 'http://x/');
    await e.broker.handle({ name: 'scheduleCreate', args: { name: 'ok', schedule: '@every 1h', goal: 'check the page' } });
    assert.equal(approver.seen[0].escalatedByTaint || approver.seen[0].provenance.tainted, true);
    assert.equal(e.jobs.list()[0].createdTainted, true);
  });
});

describe('Governor: run deadline', () => {
  test('after the deadline every governed action in a scheduled run is denied', async () => {
    const dir = tmpDir();
    try {
      const audit = new AuditLog(path.join(dir, 'a.jsonl'), Ed25519Signer.generate());
      const gov = new Governor({ policy: policyWith({ rules: [{ class: 'fs.read', verdict: 'allow' }] }), audit, taint: new TaintTracker() });
      gov.setRunContext({ origin: 'scheduled', jobId: 'j', triggerAt: 'now', deadlineAt: Date.now() - 1 });
      const d = await gov.authorize({ class: 'fs.read', target: 'x', summary: 'read x', inWorkspace: true });
      assert.equal(d.allowed, false);
      assert.equal(d.by, 'scheduled-policy');
      gov.setRunContext(undefined);
      assert.equal((await gov.authorize({ class: 'fs.read', target: 'x', summary: 'read x', inWorkspace: true })).allowed, true);
    } finally {
      rm(dir);
    }
  });
});

void ({} as ApprovalAnswer);
void ({} as ApprovalRequest);

describe('real TelegramApprover as the asynchronous approver (fake Bot API)', () => {
  test('a scheduled job asks the owner with the job id; only the owner can approve; the answer arrives later; an expired request is a deny', async () => {
    const { TelegramApprover } = await import('../src/channels/telegram');
    const sent: any[] = [];
    const api = { call: async (m: string, p: any) => { sent.push({ m, p }); return { message_id: 7 }; } };
    const dir = tmpDir();
    try {
      const tg = new TelegramApprover(api, 4242);
      assert.equal(tg.async, true);
      const audit = new AuditLog(path.join(dir, 'a.jsonl'), Ed25519Signer.generate());
      const gov = new Governor({ policy: policyWith({ scheduled: { defaultVerdictForAsk: 'ask-async', approvalTimeoutSeconds: 30 } }), audit, taint: new TaintTracker(), approver: tg });
      gov.setRunContext({ origin: 'scheduled', jobId: 'job-123', triggerAt: '2026-11-16T09:00:00Z' });
      const act = { class: 'fs.write' as const, target: 'x', summary: 'write x', inWorkspace: true };
      const p = gov.authorize(act);
      await new Promise((r) => setTimeout(r, 50));
      const msg = sent.find((s) => s.m === 'sendMessage');
      assert.match(msg.p.text, /SCHEDULED job job-123/);
      const id = /sc:a:([0-9a-f-]{36})/.exec(JSON.stringify(msg.p.reply_markup))![1];
      // A stranger's tap does not resolve the request.
      await tg.handleUpdate({ update_id: 1, callback_query: { id: 'c1', from: { id: 999 }, data: `sc:a:${id}`, message: { message_id: 7, chat: { id: 999 } } } });
      assert.equal(tg.pendingCount, 1);
      // The owner approves (arbitrarily later).
      await tg.handleUpdate({ update_id: 2, callback_query: { id: 'c2', from: { id: 4242 }, data: `sc:a:${id}`, message: { message_id: 7, chat: { id: 4242 } } } });
      const d = await p;
      assert.equal(d.allowed, true);
      assert.equal(d.by, 'human');
      // A second tap on the same request (replay) changes nothing.
      await tg.handleUpdate({ update_id: 3, callback_query: { id: 'c3', from: { id: 4242 }, data: `sc:a:${id}`, message: { message_id: 7, chat: { id: 4242 } } } });
      assert.equal(tg.pendingCount, 0);
      // After the deadline a request is denied without a human answer.
      gov.setRunContext({ origin: 'scheduled', jobId: 'job-123', triggerAt: 'x', deadlineAt: Date.now() + 300 });
      const d2 = await gov.authorize(act);
      assert.equal(d2.allowed, false);
      assert.equal(d2.by, 'timeout');
      assert.equal(tg.pendingCount, 0);
    } finally {
      rm(dir);
    }
  });
});
