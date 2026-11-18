import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import { HttpApprover } from '../src/channels/http';
import { isSessionId, Transcript } from '../src/channels/transcript';
import { createGateway, replyText } from '../src/server';
import { rm, tmpDir } from './helpers';

const KEY = 'console-key-0123456789abcdef';
const H = { authorization: `Bearer ${KEY}`, 'content-type': 'application/json' };

/** Reads an authenticated event stream and collects { event, data } frames. */
async function openStream(base: string) {
  const res = await fetch(`${base}/api/stream`, { headers: { authorization: `Bearer ${KEY}` } });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  const events: Array<{ event: string; data: any }> = [];
  let buf = '';
  let stopped = false;
  (async () => {
    while (!stopped) {
      const { done, value } = await reader.read().catch(() => ({ done: true, value: undefined }));
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const ev = /^event: (.+)$/m.exec(frame);
        const data = /^data: (.*)$/m.exec(frame);
        if (ev && data) events.push({ event: ev[1], data: JSON.parse(data[1]) });
      }
    }
  })();
  const waitFor = async (pred: (e: Array<{ event: string; data: any }>) => boolean, ms = 5000) => {
    const t0 = Date.now();
    while (!pred(events)) {
      if (Date.now() - t0 > ms) throw new Error(`timed out; events so far: ${JSON.stringify(events.map((e) => e.event))}`);
      await new Promise((r) => setTimeout(r, 20));
    }
  };
  return { events, waitFor, close: () => { stopped = true; reader.cancel().catch(() => {}); } };
}

function fakeEngine(approver?: HttpApprover) {
  return {
    tainted: false,
    audit: { length: 0 },
    newSession: () => true,
    executeGoal: async (goal: string, o: any) => {
      o.onLog('planning');
      if (goal === 'needs approval' && approver) {
        const answer = await approver.request(
          { id: 'a1', action: { class: 'net.egress', target: 'example.com', summary: 'GET https://example.com/' }, provenance: { tainted: false, sources: [] }, reason: 'policy', escalatedByTaint: false, expiresAt: Date.now() + 60_000 } as any,
          new AbortController().signal,
        );
        return { success: answer === 'approve', kind: 'task', reply: `answer: ${answer}`, tainted: false, llmCostCentsCeil: 0 };
      }
      o.onLog('ran code');
      return { success: true, kind: 'task', reply: `done: ${goal}`, tainted: true, llmCostCentsCeil: 0 };
    },
  } as any;
}

describe('chat console', () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => rm(dir));

  test('transcript: append/read, rotate keeps the old session, ids are validated, a torn line is skipped', () => {
    let n = 0;
    const t = new Transcript(dir, () => new Date(Date.UTC(2026, 10, 18, 12, 0, n++)));
    const first = t.sessionId;
    assert.ok(isSessionId(first));
    t.append('user', 'hello');
    t.append('agent', 'hi', { tainted: true });
    assert.deepEqual(t.read().map((e) => [e.kind, e.text, e.tainted]), [['user', 'hello', undefined], ['agent', 'hi', true]]);
    fs.appendFileSync(path.join(dir, `${first}.jsonl`), '{"broken');
    assert.equal(t.read().length, 2);
    t.rotate();
    assert.notEqual(t.sessionId, first);
    assert.deepEqual(t.read(), []);
    assert.deepEqual(t.sessions().map((s) => [s.id, s.preview]), [[first, 'hello']]);
    for (const bad of ['../x', 'x', '20261118T120000Z-zzzzzzzz', `${first}/..`]) assert.throws(() => t.read(bad), /bad session id/);
    if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(dir, `${first}.jsonl`)).mode & 0o077, 0);
  });

  test('replyText: reply/stdout/result joined; failures and denials are labelled', () => {
    assert.deepEqual(replyText({ success: true, kind: 'task', reply: 'r', stdout: 'out\n', result: { a: 1 }, tainted: false, llmCostCentsCeil: 0 }, []), { kind: 'agent', text: 'r\n\nout\n\n{\n  "a": 1\n}' });
    assert.deepEqual(replyText({ success: false, kind: 'task', error: 'boom', tainted: false, llmCostCentsCeil: 0 }, []), { kind: 'error', text: 'Failed: boom' });
    assert.equal(replyText({ success: false, kind: 'task', denied: { verdict: 'deny' } as any, error: 'net.egress denied', tainted: false, llmCostCentsCeil: 0 }, []).kind, 'denied');
    assert.equal(replyText(undefined, ['error: crashed']).text, 'error: crashed');
  });

  test('live: the stream carries the user message, progress, the reply and status; the transcript keeps the conversation', async () => {
    const tdir = path.join(dir, 'console');
    const gw = createGateway(fakeEngine(), new HttpApprover(), KEY, { transcriptDir: tdir });
    const srv = gw.listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      assert.equal((await fetch(`${base}/api/stream`)).status, 401, 'the stream needs the key');
      const s = await openStream(base);
      await s.waitFor((e) => e.some((x) => x.event === 'status'));
      await fetch(`${base}/api/goal`, { method: 'POST', headers: H, body: JSON.stringify({ goal: 'do it' }) });
      await s.waitFor((e) => e.some((x) => x.event === 'message' && x.data.kind === 'agent'));
      const seq = s.events.filter((x) => ['message', 'log'].includes(x.event)).map((x) => (x.event === 'log' ? `log:${x.data.line}` : `${x.data.kind}:${x.data.text}`));
      assert.deepEqual(seq, ['user:do it', 'log:planning', 'log:ran code', 'agent:done: do it']);
      const agentMsg = s.events.find((x) => x.event === 'message' && x.data.kind === 'agent')!.data;
      assert.equal(agentMsg.tainted, true, 'a reply built from untrusted content is marked');
      s.close();

      const tr = await (await fetch(`${base}/api/transcript`, { headers: H })).json();
      assert.deepEqual(tr.entries.map((e: any) => e.kind), ['user', 'agent']);
      const firstSession = tr.sessionId;

      assert.equal((await fetch(`${base}/api/session/new`, { method: 'POST', headers: H, body: '{}' })).status, 200);
      assert.deepEqual((await (await fetch(`${base}/api/transcript`, { headers: H })).json()).entries, [], 'new session starts empty');
      const sessions = (await (await fetch(`${base}/api/sessions`, { headers: H })).json()).sessions;
      assert.deepEqual(sessions.map((x: any) => [x.id, x.preview]), [[firstSession, 'do it']]);
      const old = await (await fetch(`${base}/api/sessions/${firstSession}`, { headers: H })).json();
      assert.equal(old.readOnly, true);
      assert.deepEqual(old.entries.map((e: any) => e.text), ['do it', 'done: do it']);
      assert.equal((await fetch(`${base}/api/sessions/..%2F..%2Fetc`, { headers: H })).status, 404);
      assert.equal((await fetch(`${base}/api/sessions`)).status, 401);
    } finally {
      srv.close();
    }
  });

  test('approvals appear on the stream as soon as they are requested, and clear when decided', async () => {
    const approver = new HttpApprover();
    const gw = createGateway(fakeEngine(approver), approver, KEY, { transcriptDir: path.join(dir, 'console') });
    const srv = gw.listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      const s = await openStream(base);
      await fetch(`${base}/api/goal`, { method: 'POST', headers: H, body: JSON.stringify({ goal: 'needs approval' }) });
      await s.waitFor((e) => e.some((x) => x.event === 'approvals' && x.data.length === 1));
      const pending = s.events.filter((x) => x.event === 'approvals').at(-1)!.data[0];
      assert.equal(pending.summary, 'GET https://example.com/');
      assert.equal((await fetch(`${base}/api/approvals/a1`, { method: 'POST', headers: H, body: JSON.stringify({ decision: 'approve' }) })).status, 200);
      await s.waitFor((e) => e.some((x) => x.event === 'message' && x.data.text === 'answer: approve'));
      assert.deepEqual(s.events.filter((x) => x.event === 'approvals').at(-1)!.data, [], 'cleared after the decision');
      s.close();
    } finally {
      srv.close();
    }
  });

  test('without a transcript dir (library use) the gateway still works and writes nothing', async () => {
    const gw = createGateway(fakeEngine(), new HttpApprover(), KEY);
    const srv = gw.listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      assert.deepEqual(await (await fetch(`${base}/api/transcript`, { headers: H })).json(), { sessionId: null, entries: [] });
      assert.deepEqual(fs.readdirSync(dir), []);
    } finally {
      srv.close();
    }
  });
});
