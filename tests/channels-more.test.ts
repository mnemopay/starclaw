import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { CodeApprover, CODE_RE, newApprovalCode } from '../src/channels/codeApproval';
import { ChannelConfigError, resolveEmailConfig, resolveSignalConfig, resolveWhatsAppConfig } from '../src/channels/config';
import { EmailGateway, isOwnerMail, providerVerdict, replyText, type Mail, type MailClient } from '../src/channels/email';
import { GoalQueue } from '../src/channels/queue';
import { ChannelRuntime } from '../src/channels/runtime';
import { SignalGateway, type SignalApi } from '../src/channels/signal';
import { verifyMetaSignature, WhatsAppApprover, WhatsAppGateway, whatsappRoutes, type WhatsAppApi } from '../src/channels/whatsapp';
import { parsePolicy } from '../src/governance/policy';
import type { ApprovalRequest } from '../src/governance/types';

const REQ = (id = '11111111-2222-3333-4444-555555555555'): ApprovalRequest => ({
  id, action: { class: 'net.egress', target: 'example.com', summary: 'GET https://example.com/' }, provenance: { tainted: false, sources: [] }, reason: 'policy', escalatedByTaint: false, expiresAt: Date.now() + 60_000,
});
function fakeEngine() {
  const calls: Array<{ goal: string; origin: string }> = [];
  return { calls, engine: { newSession: () => true, audit: { append() {} }, executeGoal: async (goal: string, o: any) => { calls.push({ goal, origin: o.origin }); return { success: true, kind: 'task', reply: `done: ${goal}`, tainted: false, llmCostCentsCeil: 0 }; } } as any };
}
const tick = () => new Promise((r) => setTimeout(r, 20));

describe('code approvals (Signal, email)', () => {
  test('a code is sent only through the channel; "yes CODE" from the owner approves once; others are ignored', async () => {
    const sent: string[] = [];
    const a = new CodeApprover('t', async (t) => { sent.push(t); });
    const p = a.request(REQ(), new AbortController().signal);
    await tick();
    const code = /yes ([A-Z2-9]{6})/.exec(sent[0])![1];
    assert.equal(a.handleReply(`yes ${code}`, false), 'ignored', 'not the owner');
    assert.equal(a.handleReply(`approve`, true), 'ignored', 'no code');
    assert.equal(a.handleReply(`yes ${code.toLowerCase()}`, true), 'answered');
    assert.equal(await p, 'approve');
    assert.equal(a.handleReply(`yes ${code}`, true), 'not-pending', 'a code works once');
  });
  test('"no CODE" denies; abort denies; a send failure denies; codes avoid look-alike characters', async () => {
    const sent: string[] = [];
    const a = new CodeApprover('t', async (t) => { sent.push(t); });
    const p = a.request(REQ(), new AbortController().signal);
    await tick();
    a.handleReply(`no ${/yes ([A-Z2-9]{6})/.exec(sent[0])![1]}`, true);
    assert.equal(await p, 'deny');
    const ac = new AbortController();
    const p2 = a.request(REQ(), ac.signal);
    ac.abort();
    assert.equal(await p2, 'deny');
    assert.equal(await new CodeApprover('t', async () => { throw new Error('down'); }).request(REQ(), new AbortController().signal), 'deny');
    for (let i = 0; i < 200; i++) assert.match(newApprovalCode(), /^[A-HJKMNP-Z2-9]{6}$/);
    assert.ok(CODE_RE.test('  YES abc234 ') && !CODE_RE.test('yes abc234 please'));
  });
});

describe('WhatsApp', () => {
  const SECRET = 'app-secret-0123456789abcdef';
  const OWNER = '15551234567';
  const sign = (body: string) => 'sha256=' + createHmac('sha256', SECRET).update(body).digest('hex');
  function setup(allowPublic = false) {
    const out: Array<{ to: string; text: string; buttons?: string[] }> = [];
    const api: WhatsAppApi = { sendText: async (to, text) => { out.push({ to, text }); }, sendButtons: async (to, text, b) => { out.push({ to, text, buttons: b.map((x) => x.id) }); } };
    const { engine, calls } = fakeEngine();
    const approver = new WhatsAppApprover(api, OWNER);
    const gateway = new WhatsAppGateway({ engine, api, approver, owner: OWNER, allowPublic, queue: new GoalQueue(), toleranceSec: 300 });
    const [route] = whatsappRoutes({ gateway, appSecret: SECRET, verifyToken: 'verify-token-0123456789' });
    return { out, calls, approver, route };
  }
  const payload = (msgs: any[]) => JSON.stringify({ object: 'whatsapp_business_account', entry: [{ changes: [{ field: 'messages', value: { messages: msgs } }] }] });
  const text = (from: string, body: string, id = 'wamid.' + Math.random(), ts = Math.floor(Date.now() / 1000)) => ({ from, id, timestamp: String(ts), type: 'text', text: { body } });

  test('signature: right secret passes; wrong secret, tampered body, malformed header fail', () => {
    const b = Buffer.from('{"a":1}');
    assert.equal(verifyMetaSignature(SECRET, sign('{"a":1}'), b), true);
    assert.equal(verifyMetaSignature('other-secret-0123456789', sign('{"a":1}'), b), false);
    assert.equal(verifyMetaSignature(SECRET, sign('{"a":2}'), b), false);
    assert.equal(verifyMetaSignature(SECRET, 'sha1=abc', b), false);
    assert.equal(verifyMetaSignature('', sign('{"a":1}'), b), false);
  });

  test('webhook verification: only the right verify token echoes the challenge', async () => {
    const { route } = setup();
    assert.deepEqual(await route.get!(new URLSearchParams('hub.mode=subscribe&hub.verify_token=verify-token-0123456789&hub.challenge=12345')), { status: 200, body: '12345' });
    assert.equal((await route.get!(new URLSearchParams('hub.mode=subscribe&hub.verify_token=wrong-token-0123456789&hub.challenge=1'))).status, 403);
    assert.equal((await route.get!(new URLSearchParams('hub.mode=subscribe&hub.verify_token=verify-token-0123456789&hub.challenge=<script>'))).status, 403);
  });

  test('owner text runs as an owner goal; unsigned/replayed requests, non-owners, stale and duplicate messages do not', async () => {
    const { route, calls, out } = setup();
    const ownerMsg = text(OWNER, 'check the weather', 'wamid.1');
    const body = payload([ownerMsg]);
    assert.equal((await route.handle({ rawBody: Buffer.from(body), headers: {} })).status, 401, 'unsigned');
    assert.equal((await route.handle({ rawBody: Buffer.from(body), headers: { 'x-hub-signature-256': sign(body + ' ') } })).status, 401, 'wrong signature');
    assert.equal((await route.handle({ rawBody: Buffer.from(body), headers: { 'x-hub-signature-256': sign(body) } })).status, 200);
    assert.equal((await route.handle({ rawBody: Buffer.from(body), headers: { 'x-hub-signature-256': sign(body) } })).status, 401, 'replayed signature');
    const others = payload([text('15559999999', 'spend my money'), text(OWNER, 'old', 'wamid.old', Math.floor(Date.now() / 1000) - 3600), { ...ownerMsg }]);
    await route.handle({ rawBody: Buffer.from(others), headers: { 'x-hub-signature-256': sign(others) } });
    await tick();
    assert.deepEqual(calls, [{ goal: 'check the weather', origin: 'owner' }]);
    assert.ok(out.some((m) => m.to === OWNER && m.text === 'done: check the weather'));
  });

  test('allowPublic: a stranger runs as a non-owner (tainted) goal', async () => {
    const { route, calls } = setup(true);
    const body = payload([text('15559999999', 'hello')]);
    await route.handle({ rawBody: Buffer.from(body), headers: { 'x-hub-signature-256': sign(body) } });
    await tick();
    assert.deepEqual(calls, [{ goal: 'hello', origin: 'non-owner' }]);
  });

  test('approval buttons: only the owner pressing on a pending request resolves it', async () => {
    const { approver, out } = setup();
    const p = approver.request(REQ(), new AbortController().signal);
    await tick();
    const btn = out.find((m) => m.buttons)!.buttons!;
    assert.deepEqual(btn, ['sc:a:11111111-2222-3333-4444-555555555555', 'sc:d:11111111-2222-3333-4444-555555555555']);
    assert.equal(approver.handleButton('15559999999', btn[0]), true);
    assert.equal(approver.pendingCount, 1, 'a stranger pressing Approve does nothing');
    approver.handleButton(OWNER, btn[0]);
    assert.equal(await p, 'approve');
  });
});

describe('Signal', () => {
  const OWNER = '+15551234567';
  test('owner messages are goals; approval codes from the owner resolve; strangers are ignored; duplicates once', async () => {
    const out: Array<{ to: string; text: string }> = [];
    const api: SignalApi = { receive: async () => [], send: async (to, text) => { out.push({ to, text }); } };
    const { engine, calls } = fakeEngine();
    const approver = new CodeApprover('signal', (t) => api.send(OWNER, t));
    const g = new SignalGateway({ engine, api, approver, owner: OWNER, allowPublic: false, queue: new GoalQueue() });
    const env = (from: string, message: string, ts: number) => ({ sourceNumber: from, timestamp: ts, dataMessage: { message, timestamp: ts } });
    await g.onEnvelope(env(OWNER, 'summarise my notes', 1));
    await g.onEnvelope(env(OWNER, 'summarise my notes', 1)); // redelivered
    await g.onEnvelope(env('+15559999999', 'spend', 2));
    assert.deepEqual(calls, [{ goal: 'summarise my notes', origin: 'owner' }]);
    const p = approver.request(REQ(), new AbortController().signal);
    await tick();
    const code = /yes ([A-Z2-9]{6})/.exec(out.filter((m) => m.to === OWNER).at(-1)!.text)![1];
    await g.onEnvelope(env('+15559999999', `yes ${code}`, 3));
    assert.equal(approver.pendingCount, 1, 'a stranger with the right code cannot approve');
    await g.onEnvelope(env(OWNER, `yes ${code}`, 4));
    assert.equal(await p, 'approve');
    assert.equal(calls.length, 1, 'an approval reply is not also run as a goal');
  });
});

describe('email', () => {
  const OWNER = 'me@example.com';
  const AUTH = 'mx.provider.test';
  const mail = (over: Partial<Mail> = {}, auth = `Authentication-Results: ${AUTH}; dkim=pass header.i=@example.com; spf=pass; dmarc=pass (p=REJECT) header.from=example.com`): Mail => ({
    uid: 1, messageId: '<m' + Math.random() + '@x>', from: OWNER, subject: 'task', text: 'list my files', headerLines: auth ? [{ key: 'authentication-results', line: auth }] : [], ...over,
  });

  test('only the TOPMOST provider verdict counts; a header the sender added lower down is ignored', () => {
    const forged = { key: 'authentication-results', line: `Authentication-Results: ${AUTH}; dmarc=pass header.from=example.com` };
    const real = { key: 'authentication-results', line: `Authentication-Results: ${AUTH}; dmarc=fail header.from=example.com` };
    assert.equal(providerVerdict([real, forged], AUTH)?.dmarc, 'fail');
    assert.equal(providerVerdict([{ key: 'authentication-results', line: 'Authentication-Results: evil.example; dmarc=pass header.from=example.com' }], AUTH), undefined);
  });

  test('owner mail needs the address AND dmarc=pass for the owner domain from the provider', () => {
    assert.equal(isOwnerMail(mail(), OWNER, AUTH), true);
    assert.equal(isOwnerMail(mail({}, ''), OWNER, AUTH), false, 'no authentication results');
    assert.equal(isOwnerMail(mail({}, `Authentication-Results: ${AUTH}; dmarc=pass header.from=attacker.example`), OWNER, AUTH), false, 'DMARC for another domain');
    assert.equal(isOwnerMail(mail({ from: 'ME@EXAMPLE.COM' }), OWNER, AUTH), true, 'case-insensitive');
    assert.equal(isOwnerMail(mail({ from: 'other@example.com' }), OWNER, AUTH), false);
  });

  test('reply text stops at the quoted message', () => {
    assert.equal(replyText('yes ABC234\n\nOn Tue, Nov 18, 2026 at 5 PM StarClaw <bot@x> wrote:\n> Reply "yes ABC234"'), 'yes ABC234');
    assert.equal(replyText('do this\r\n> old'), 'do this');
  });

  test('gateway: an authenticated owner goal runs; a forged From is ignored and cannot approve even with the right code', async () => {
    const sent: Array<{ to: string; text: string }> = [];
    const client: MailClient = { fetchUnseen: async () => [], send: async (to, _s, text) => { sent.push({ to, text }); }, close: async () => {} };
    const { engine, calls } = fakeEngine();
    const approver = new CodeApprover('email', (t, s) => client.send(OWNER, s, t));
    const logs: string[] = [];
    const g = new EmailGateway({ engine, client, approver, owner: OWNER, authservId: AUTH, allowPublic: false, queue: new GoalQueue(), log: (s) => logs.push(s) });
    await g.onMail(mail({ text: 'list my files\n\n> quoted' }));
    await g.onMail(mail({ text: 'forged goal' }, ''));
    assert.deepEqual(calls, [{ goal: 'list my files', origin: 'owner' }]);
    assert.ok(logs.some((l) => /failed the provider DMARC check/.test(l)));
    const p = approver.request(REQ(), new AbortController().signal);
    await tick();
    const code = /yes ([A-Z2-9]{6})/.exec(sent.at(-1)!.text)![1];
    await g.onMail(mail({ text: `yes ${code}` }, ''));
    assert.equal(approver.pendingCount, 1, 'a forged owner address with the right code does not approve');
    await g.onMail(mail({ text: `yes ${code}\n\n> earlier message` }));
    assert.equal(await p, 'approve');
  });
});

describe('channel config and runtime', () => {
  const base = { version: 1 };
  test('enabled channels fail closed with errors that name variables, never values', () => {
    const wa = parsePolicy(JSON.stringify({ ...base, whatsapp: { enabled: true } }));
    assert.throws(() => resolveWhatsAppConfig(wa, {}), (e: any) => e instanceof ChannelConfigError && /WHATSAPP_TOKEN/.test(e.message));
    const secretEnv = { WHATSAPP_TOKEN: 'EAAG-very-secret-token-value-1234', WHATSAPP_APP_SECRET: 'short', WHATSAPP_VERIFY_TOKEN: 'verify-token-0123456789', WHATSAPP_PHONE_NUMBER_ID: '123456789', WHATSAPP_OWNER_NUMBER: '+15551234567' };
    assert.throws(() => resolveWhatsAppConfig(wa, secretEnv), (e: any) => /WHATSAPP_APP_SECRET/.test(e.message) && !e.message.includes('EAAG-very-secret'));
    const sg = parsePolicy(JSON.stringify({ ...base, signal: { enabled: true, bridgeUrl: 'http://10.0.0.5:8080' } }));
    assert.throws(() => resolveSignalConfig(sg, { SIGNAL_ACCOUNT: '+15550000001', SIGNAL_OWNER_NUMBER: '+15550000002' }), /on this PC/);
    assert.throws(() => parsePolicy(JSON.stringify({ ...base, email: { enabled: true } })), /imapHost is required/);
    const em = parsePolicy(JSON.stringify({ ...base, email: { enabled: true, imapHost: 'imap.example.com', smtpHost: 'smtp.example.com', authservId: 'mx.example.com' } }));
    assert.throws(() => resolveEmailConfig(em, { EMAIL_USER: 'a@example.com', EMAIL_PASSWORD: 'pw', EMAIL_OWNER_ADDRESS: 'a@example.com' }), /must be different/);
    assert.throws(() => parsePolicy(JSON.stringify({ ...base, channels: { ownerChannel: 'signal' } })), /signal.enabled is false/);
  });

  test('the owner channel picks the matching approver/notifier', () => {
    const env = { SIGNAL_ACCOUNT: '+15550000001', SIGNAL_OWNER_NUMBER: '+15550000002' };
    const p = parsePolicy(JSON.stringify({ ...base, signal: { enabled: true }, channels: { ownerChannel: 'signal' } }));
    const rt = new ChannelRuntime(p, env, { signalApi: { receive: async () => [], send: async () => {} } });
    assert.equal(rt.ownerApprover?.name, 'signal');
    assert.equal(rt.ownerNotifier?.name, 'signal');
    assert.equal(rt.ownerApprover?.async, true, 'usable by unattended runs');
  });
});
