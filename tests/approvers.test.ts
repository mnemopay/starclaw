import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { CliApprover } from '../src/governance/approvers';
import { ApprovalRequest } from '../src/governance/types';
import { ConfigError, HttpApprover, approvalRouter, bearerAuth, safeEqual } from '../src/channels/http';
import { TelegramApi, TelegramApprover, TelegramUpdate } from '../src/channels/telegram';
import { createGateway } from '../src/server';

const REQ = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  id: '11111111-2222-3333-4444-555555555555',
  action: { class: 'net.egress', target: 'evil.example', summary: 'GET http://evil.example/?x=1', detail: 'http://evil.example/?x=1' },
  provenance: { tainted: true, sources: [{ kind: 'web', ref: 'http://page/x', at: '' }] },
  reason: 'policy default',
  escalatedByTaint: true,
  expiresAt: Date.now() + 60_000,
  ...over,
});

describe('CliApprover', () => {
  const answer = async (a: string | Error) => {
    const out: string[] = [];
    const ap = new CliApprover(async () => { if (a instanceof Error) throw a; return a; }, (s) => out.push(s));
    return { r: await ap.request(REQ(), new AbortController().signal), out: out.join('\n') };
  };
  test('y / yes approve; everything else denies', async () => {
    assert.equal((await answer('y')).r, 'approve');
    assert.equal((await answer(' YES ')).r, 'approve');
    for (const no of ['', 'n', 'no', 'ok', 'approve', 'yy', '1']) assert.equal((await answer(no)).r, 'deny', JSON.stringify(no));
    assert.equal((await answer(new Error('closed'))).r, 'deny');
  });
  test('shows the exact action, target and provenance', async () => {
    const { out } = await answer('n');
    for (const s of ['net.egress', 'evil.example', 'http://evil.example/?x=1', 'TAINTED', 'http://page/x', 'escalated']) assert.ok(out.includes(s), s);
  });
});

class FakeTelegram implements TelegramApi {
  sent: Array<{ method: string; params: any }> = [];
  async call(method: string, params: Record<string, unknown>) {
    this.sent.push({ method, params });
    return method === 'sendMessage' ? { message_id: 77 } : true;
  }
}
const OWNER = 4242;
const cb = (data: string, fromId: number, chatId: number): TelegramUpdate => ({ update_id: 1, callback_query: { id: 'cq', from: { id: fromId }, data, message: { message_id: 77, chat: { id: chatId } } } });

describe('TelegramApprover', () => {
  test('refuses to be constructed without a numeric owner id (fail closed)', () => {
    assert.throws(() => new TelegramApprover(new FakeTelegram(), 0), /owner chat id/);
    assert.throws(() => new TelegramApprover(new FakeTelegram(), NaN), /owner chat id/);
  });

  test('sends the full request with Approve/Deny buttons to the owner chat only', async () => {
    const api = new FakeTelegram();
    const ap = new TelegramApprover(api, OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await new Promise((r) => setTimeout(r, 10));
    const m = api.sent.find((s) => s.method === 'sendMessage')!;
    assert.equal(m.params.chat_id, OWNER);
    assert.match(m.params.text, /evil\.example/);
    assert.match(m.params.text, /TAINTED/);
    assert.equal(m.params.reply_markup.inline_keyboard[0].length, 2);
    ac.abort();
    assert.equal(await p, 'deny');
  });

  test('owner approves via button', async () => {
    const api = new FakeTelegram();
    const ap = new TelegramApprover(api, OWNER);
    const p = ap.request(REQ(), new AbortController().signal);
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(await ap.handleUpdate(cb(`sc:a:${REQ().id}`, OWNER, OWNER)), true);
    assert.equal(await p, 'approve');
    assert.equal(ap.pendingCount, 0);
  });

  test('owner denies via button', async () => {
    const ap = new TelegramApprover(new FakeTelegram(), OWNER);
    const p = ap.request(REQ(), new AbortController().signal);
    await new Promise((r) => setTimeout(r, 10));
    await ap.handleUpdate(cb(`sc:d:${REQ().id}`, OWNER, OWNER));
    assert.equal(await p, 'deny');
  });

  test('a NON-owner pressing Approve (even in the owner chat, or from another chat) does nothing', async () => {
    const api = new FakeTelegram();
    const ap = new TelegramApprover(api, OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await new Promise((r) => setTimeout(r, 10));
    await ap.handleUpdate(cb(`sc:a:${REQ().id}`, 666, OWNER)); // right chat, wrong user
    await ap.handleUpdate(cb(`sc:a:${REQ().id}`, OWNER, 666)); // right user, wrong chat
    await ap.handleUpdate(cb(`sc:a:${REQ().id}`, 666, 666));
    assert.equal(ap.pendingCount, 1, 'still pending');
    assert.ok(api.sent.filter((s) => s.method === 'answerCallbackQuery').every((s) => /Not authorised/.test(s.params.text)));
    ac.abort(); // timeout
    assert.equal(await p, 'deny');
  });

  test('malformed or foreign callback data is ignored; a replay after resolution is rejected', async () => {
    const ap = new TelegramApprover(new FakeTelegram(), OWNER);
    assert.equal(await ap.handleUpdate(cb('garbage', OWNER, OWNER)), false);
    assert.equal(await ap.handleUpdate(cb('sc:a:not-a-uuid', OWNER, OWNER)), false);
    const p = ap.request(REQ(), new AbortController().signal);
    await new Promise((r) => setTimeout(r, 10));
    await ap.handleUpdate(cb(`sc:a:${REQ().id}`, OWNER, OWNER));
    assert.equal(await p, 'approve');
    await ap.handleUpdate(cb(`sc:a:${REQ().id}`, OWNER, OWNER)); // replay: nothing pending, no effect
    assert.equal(ap.pendingCount, 0);
  });

  test('timeout (abort) resolves deny and marks the message expired', async () => {
    const api = new FakeTelegram();
    const ap = new TelegramApprover(api, OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await new Promise((r) => setTimeout(r, 10));
    ac.abort();
    assert.equal(await p, 'deny');
    assert.ok(api.sent.some((s) => s.method === 'editMessageText' && /DENIED \(timeout\)/.test(s.params.text)));
  });
});

async function listen(app: express.Express) {
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

describe('HTTP approvals + gateway auth', () => {
  const KEY = 'k'.repeat(32);

  test('fails closed: no key, empty key or short key refuses to construct auth and the gateway', () => {
    for (const bad of [undefined, '', 'short']) {
      assert.throws(() => bearerAuth(bad), ConfigError);
      assert.throws(() => createGateway({} as any, new HttpApprover(), bad), ConfigError);
    }
  });

  test('safeEqual compares correctly regardless of length', () => {
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
    assert.equal(safeEqual('abc', 'abcd'), false);
    assert.equal(safeEqual('', 'a'), false);
  });

  test('every /api route needs the bearer key; the approval flow works end to end over HTTP', async () => {
    const approver = new HttpApprover();
    const app = express();
    const api = express.Router();
    api.use(bearerAuth(KEY));
    api.use(approvalRouter(approver));
    app.use('/api', api);
    const srv = await listen(app);
    try {
      const pending = approver.request(REQ(), new AbortController().signal);
      const H = (k?: string): RequestInit => ({ headers: k ? { Authorization: `Bearer ${k}` } : ({} as Record<string, string>) });
      assert.equal((await fetch(`${srv.base}/api/approvals`)).status, 401);
      assert.equal((await fetch(`${srv.base}/api/approvals`, H('wrong'.repeat(8)))).status, 401);
      assert.equal((await fetch(`${srv.base}/api/approvals`, { headers: { Authorization: `Basic ${KEY}` } })).status, 401);
      const post = (k: string | undefined, body: unknown) => fetch(`${srv.base}/api/approvals/${REQ().id}`, { method: 'POST', headers: { 'content-type': 'application/json', ...(k ? { Authorization: `Bearer ${k}` } : {}) }, body: JSON.stringify(body) });
      assert.equal((await post(undefined, { decision: 'approve' })).status, 401);
      assert.equal(approver.pendingCount, 1, 'an unauthenticated approve must not resolve anything');
      const list: any = await (await fetch(`${srv.base}/api/approvals`, H(KEY))).json();
      assert.equal(list.approvals.length, 1);
      assert.match(list.approvals[0].description, /evil\.example/);
      assert.equal(list.approvals[0].tainted, true);
      assert.equal((await post(KEY, { decision: 'sure' })).status, 400);
      assert.equal((await post(KEY, { decision: 'approve' })).status, 200);
      assert.equal(await pending, 'approve');
      assert.equal((await post(KEY, { decision: 'approve' })).status, 404, 'cannot answer twice');
    } finally {
      await srv.close();
    }
  });

  test('abort (timeout) removes the request and denies', async () => {
    const a = new HttpApprover();
    const ac = new AbortController();
    const p = a.request(REQ(), ac.signal);
    ac.abort();
    assert.equal(await p, 'deny');
    assert.equal(a.pendingCount, 0);
  });

  test('the full gateway: /api/status needs auth, the static page does not', async () => {
    const gw = createGateway({ tainted: false, audit: { length: 1 } } as any, new HttpApprover(), KEY);
    const srv = await listen(gw);
    try {
      assert.equal((await fetch(`${srv.base}/api/status`)).status, 401);
      assert.equal((await fetch(`${srv.base}/api/goal`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"goal":"x"}' })).status, 401);
      const ok = await fetch(`${srv.base}/api/status`, { headers: { Authorization: `Bearer ${KEY}` } });
      assert.equal(ok.status, 200);
      assert.equal((await fetch(`${srv.base}/`)).status, 200);
      assert.match((await fetch(`${srv.base}/`)).headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
    } finally {
      await srv.close();
    }
  });
});
