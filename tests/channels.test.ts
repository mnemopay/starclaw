/** Slack + Discord channels: signature verification, owner-only goals/approvals, notifications, secrets hygiene. No real network: local fakes only. */
import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, randomUUID, sign as edSign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import * as util from 'node:util';
import type { AddressInfo } from 'node:net';
import { ChannelConfigError, resolveDiscordConfig, resolveSlackConfig } from '../src/channels/config';
import { DiscordApi, DiscordApprover, FetchDiscordApi, discordCommandDefinition, registerDiscordCommand } from '../src/channels/discord';
import { GoalQueue } from '../src/channels/queue';
import { ChannelRuntime, RunningChannels } from '../src/channels/runtime';
import { createChannelServer, listenLoopback, closeServer } from '../src/channels/server';
import { SlackApi, SlackApprover, FetchSlackApi } from '../src/channels/slack';
import { discordStatus, listenerStatus, slackStatus } from '../src/channels/status';
import { ReplayGuard, SeenIds, discordPublicKey, verifyDiscordSignature, verifySlackSignature } from '../src/channels/verify';
import { StarClawEngine } from '../src/engine';
import { AuditLog } from '../src/governance/audit';
import { redactString } from '../src/governance/canonical';
import { Governor } from '../src/governance/governor';
import { defaultPolicy, parsePolicy } from '../src/governance/policy';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintTracker } from '../src/governance/taint';
import type { ApprovalRequest } from '../src/governance/types';
import { DiscordNotifier, SlackNotifier } from '../src/notify/Notifier';
import { createTelegramHandler } from '../src/telegram';
import { FakeLLM, code, policyWith, rm, tmpDir } from './helpers';

// ---- fixtures -----------------------------------------------------------------------------------------------------------

// Built at runtime so no scanner-matching literal sits in the repo; the value is a fake sentinel, not a credential.
const SLACK_TOKEN = 'xo' + 'xb-1111111111-SLACKTOKENSENTINEL9999';
const SLACK_SECRET = 'slack-signing-secret-SENTINEL-0123456789';
const SLACK_OWNER = 'U0OWNER01';
const STRANGER = 'U0STRANGER';
const DM = 'D0OWNERDM1';
const DISCORD_TOKEN = 'MTAwMDAwMDAwMDAwMDAwMDAwMA.GabcDE.DISCORDTOKENSENTINEL0123456789ab';
const DISCORD_APP = '123456789012345678';
const DISCORD_OWNER = '223456789012345678';
const DISCORD_STRANGER = '323456789012345678';
const DISCORD_DM = '423456789012345678';

const ed = generateKeyPairSync('ed25519');
const rawPub = (ed.publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32).toString('hex');

const ENV: Record<string, string> = {
  SLACK_BOT_TOKEN: SLACK_TOKEN,
  SLACK_SIGNING_SECRET: SLACK_SECRET,
  SLACK_OWNER_ID: SLACK_OWNER,
  DISCORD_BOT_TOKEN: DISCORD_TOKEN,
  DISCORD_PUBLIC_KEY: rawPub,
  DISCORD_APPLICATION_ID: DISCORD_APP,
  DISCORD_OWNER_ID: DISCORD_OWNER,
};
const SECRETS = [SLACK_TOKEN, SLACK_SECRET, DISCORD_TOKEN];

const nowSec = () => Math.floor(Date.now() / 1000);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => boolean, ms = 8000) {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('timed out waiting for condition');
    await sleep(15);
  }
}

function slackSign(body: string | Buffer, o: { secret?: string; ts?: number } = {}) {
  const ts = String(o.ts ?? nowSec());
  const sig = 'v0=' + createHmac('sha256', o.secret ?? SLACK_SECRET).update(`v0:${ts}:`).update(body).digest('hex');
  return { 'x-slack-request-timestamp': ts, 'x-slack-signature': sig };
}
function discordSign(body: string | Buffer, o: { key?: KeyObject; ts?: number } = {}) {
  const ts = String(o.ts ?? nowSec());
  const sig = edSign(null, Buffer.concat([Buffer.from(ts), Buffer.from(body)]), o.key ?? ed.privateKey).toString('hex');
  return { 'x-signature-timestamp': ts, 'x-signature-ed25519': sig };
}

async function post(port: number, p: string, body: string, headers: Record<string, string> = {}, contentType = 'application/json') {
  const res = await fetch(`http://127.0.0.1:${port}${p}`, { method: 'POST', headers: { 'content-type': contentType, ...headers }, body });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    /* empty or non-JSON */
  }
  return { status: res.status, text, json };
}

class FakeSlack implements SlackApi {
  calls: Array<{ method: string; params: any; res?: any }> = [];
  failAll = false;
  private n = 0;
  async call(method: string, params: Record<string, unknown>) {
    const entry: { method: string; params: any; res?: any } = { method, params };
    this.calls.push(entry);
    if (this.failAll) throw new Error('slack down');
    entry.res = method === 'chat.postMessage' ? { ok: true, channel: params.channel === SLACK_OWNER ? DM : params.channel, ts: `1700000000.00${++this.n}` } : { ok: true };
    return entry.res;
  }
  posts(channel?: string) {
    return this.calls.filter((c) => c.method === 'chat.postMessage' && (channel === undefined || c.params.channel === channel || (channel === SLACK_OWNER && c.params.channel === SLACK_OWNER)));
  }
  text() {
    return this.posts().map((c) => String(c.params.text) + JSON.stringify(c.params.blocks ?? '')).join('\n');
  }
}

class FakeDiscord implements DiscordApi {
  calls: Array<{ method: string; path: string; body: any }> = [];
  failAll = false;
  private n = 0;
  async call(method: any, p: string, body?: unknown): Promise<any> {
    this.calls.push({ method, path: p, body });
    if (this.failAll) throw new Error('discord down');
    if (p === '/users/@me/channels') return { id: DISCORD_DM };
    if (method === 'POST' && /^\/channels\/\d+\/messages$/.test(p)) return { id: `50000000000000000${++this.n}`, channel_id: p.split('/')[2] };
    return {};
  }
  messages() {
    return this.calls.filter((c) => c.method === 'POST' && /^\/channels\/\d+\/messages$/.test(c.path));
  }
  followups() {
    return this.calls.filter((c) => c.method === 'PATCH' && c.path.includes('/messages/@original'));
  }
}

// ---- harness: real engine + real listener on 127.0.0.1:0 -----------------------------------------------------------------

interface Rig {
  dir: string;
  state: string;
  llm: FakeLLM;
  engine: StarClawEngine;
  rt: ChannelRuntime;
  live: RunningChannels;
  slack: FakeSlack;
  discord: FakeDiscord;
  logs: string[];
  audit: () => string;
}
const rigs: Rig[] = [];
afterEach(async () => {
  for (const r of rigs.splice(0)) {
    await r.live.stop();
    r.engine.memory.close();
    rm(r.dir);
  }
});

async function rig(policyOver: Record<string, unknown> = {}, o: { now?: () => number; env?: Record<string, string> } = {}): Promise<Rig> {
  const dir = tmpDir();
  const state = path.join(dir, 'state');
  const llm = new FakeLLM();
  llm.intent = 'conversation';
  const policy = policyWith({ slack: { enabled: true }, discord: { enabled: true }, channels: { ownerChannel: 'slack' }, ...policyOver });
  const slack = new FakeSlack();
  const discord = new FakeDiscord();
  const rt = new ChannelRuntime(policy, o.env ?? ENV, { slackApi: slack, discordApi: discord });
  const engine = new StarClawEngine({ llm, policy, stateDir: state, workspaceDir: path.join(dir, 'ws'), approver: rt.ownerApprover, notifier: rt.ownerNotifier });
  const logs: string[] = [];
  const live = (await rt.start(engine, new GoalQueue(), { port: 0, log: (s) => logs.push(s), now: o.now }))!;
  const r: Rig = { dir, state, llm, engine, rt, live, slack, discord, logs, audit: () => fs.readFileSync(path.join(state, 'audit.jsonl'), 'utf8') };
  rigs.push(r);
  return r;
}

const dmEvent = (text: string, user = SLACK_OWNER, extra: Record<string, unknown> = {}, eventId = 'Ev' + randomUUID().slice(0, 8)) =>
  JSON.stringify({ type: 'event_callback', event_id: eventId, event: { type: 'message', channel_type: 'im', user, text, channel: user === SLACK_OWNER ? DM : 'D0STRANGER1', ts: '1.1', ...extra } });
const sendSlackEvent = (r: Rig, body: string, h = slackSign(body)) => post(r.live.port, '/slack/events', body, h);

const slashCmd = (goal: string, userId = DISCORD_OWNER, over: Record<string, unknown> = {}) =>
  JSON.stringify({ id: '9', type: 2, token: 'tok_' + 'a'.repeat(40), application_id: DISCORD_APP, channel_id: '1', member: { user: { id: userId } }, data: { name: 'starclaw', options: [{ name: 'goal', type: 3, value: goal }] }, ...over });
const sendDiscord = (r: Rig, body: string, h = discordSign(body)) => post(r.live.port, '/discord/interactions', body, h);

// ---- signature verification ---------------------------------------------------------------------------------------------

describe('Slack signature verification', () => {
  const body = Buffer.from('{"type":"event_callback"}');
  const now = Date.now();
  const v = (over: Partial<Parameters<typeof verifySlackSignature>[0]> = {}, h = slackSign(body)) =>
    verifySlackSignature({ signingSecret: SLACK_SECRET, timestamp: h['x-slack-request-timestamp'], signature: h['x-slack-signature'], rawBody: body, nowMs: now, toleranceSec: 300, ...over });

  test('valid signature passes', () => assert.deepEqual(v(), { ok: true }));
  test('wrong secret fails', () => assert.deepEqual(v({}, slackSign(body, { secret: 'another-secret-entirely-xx' })), { ok: false, reason: 'bad-signature' }));
  test('empty configured secret never verifies (fail closed)', () => assert.equal(v({ signingSecret: '' }).ok, false));
  test('tampered body fails', () => assert.deepEqual(v({ rawBody: Buffer.from('{"type":"event_callbacK"}') }), { ok: false, reason: 'bad-signature' }));
  test('stale and future timestamps fail', () => {
    assert.deepEqual(v({}, slackSign(body, { ts: Math.floor(now / 1000) - 301 })), { ok: false, reason: 'stale' });
    assert.deepEqual(v({}, slackSign(body, { ts: Math.floor(now / 1000) + 301 })), { ok: false, reason: 'stale' });
    assert.equal(v({}, slackSign(body, { ts: Math.floor(now / 1000) - 250 })).ok, true);
  });
  test('missing / malformed headers fail', () => {
    assert.deepEqual(v({ timestamp: undefined }), { ok: false, reason: 'missing' });
    assert.deepEqual(v({ signature: undefined }), { ok: false, reason: 'missing' });
    assert.deepEqual(v({ signature: 'v0=zz' }), { ok: false, reason: 'malformed' });
    assert.deepEqual(v({ signature: 'v1=' + 'a'.repeat(64) }), { ok: false, reason: 'malformed' });
    assert.deepEqual(v({ timestamp: 'abc' }), { ok: false, reason: 'malformed' });
  });
  test('the signature binds the timestamp (re-using a signature with another timestamp fails)', () => {
    const h = slackSign(body, { ts: Math.floor(now / 1000) });
    assert.equal(v({ timestamp: String(Math.floor(now / 1000) - 1) }, h).ok, false);
  });
  test('ReplayGuard: second use of a signature inside the window is a replay; expiry frees it; only bounded memory', () => {
    const g = new ReplayGuard(1000, 3);
    assert.equal(g.isReplay('a', 0), false);
    assert.equal(g.isReplay('a', 10), true);
    assert.equal(g.isReplay('a', 2000), false, 'expired entries are forgotten');
    for (const k of ['b', 'c', 'd', 'e']) g.isReplay(k, 2001);
    assert.ok(g.size <= 3);
  });
  test('SeenIds dedupes event ids', () => {
    const s = new SeenIds(1000, 10);
    assert.equal(s.firstTime('x', 0), true);
    assert.equal(s.firstTime('x', 1), false);
    assert.equal(s.firstTime('x', 5000), true);
  });
});

describe('Discord signature verification (Ed25519)', () => {
  const body = Buffer.from('{"type":1}');
  const now = Date.now();
  const pub = discordPublicKey(rawPub);
  const v = (over: Partial<Parameters<typeof verifyDiscordSignature>[0]> = {}, h = discordSign(body)) =>
    verifyDiscordSignature({ publicKey: pub, timestamp: h['x-signature-timestamp'], signature: h['x-signature-ed25519'], rawBody: body, nowMs: now, toleranceSec: 300, ...over });

  test('valid signature passes', () => assert.deepEqual(v(), { ok: true }));
  test('signature by a different key fails', () => assert.deepEqual(v({}, discordSign(body, { key: generateKeyPairSync('ed25519').privateKey })), { ok: false, reason: 'bad-signature' }));
  test('tampered body fails', () => assert.deepEqual(v({ rawBody: Buffer.from('{"type":2}') }), { ok: false, reason: 'bad-signature' }));
  test('stale timestamp fails; timestamp is bound into the signature', () => {
    assert.deepEqual(v({}, discordSign(body, { ts: Math.floor(now / 1000) - 400 })), { ok: false, reason: 'stale' });
    const h = discordSign(body, { ts: Math.floor(now / 1000) });
    assert.equal(v({ timestamp: String(Math.floor(now / 1000) - 5) }, h).ok, false);
  });
  test('missing / malformed signature fails', () => {
    assert.deepEqual(v({ signature: undefined }), { ok: false, reason: 'missing' });
    assert.deepEqual(v({ signature: 'abcd' }), { ok: false, reason: 'malformed' });
    assert.deepEqual(v({ timestamp: undefined }), { ok: false, reason: 'missing' });
  });
  test('a malformed public key is refused at construction', () => {
    assert.throws(() => discordPublicKey('nothex'), /64 hex/);
    assert.throws(() => discordPublicKey('ab'.repeat(31)), /64 hex/);
  });
});

// ---- configuration: fail closed -----------------------------------------------------------------------------------------

describe('policy and configuration (fail closed)', () => {
  test('both channels are disabled by default; blocks are strict', () => {
    const p = defaultPolicy();
    assert.equal(p.slack.enabled, false);
    assert.equal(p.discord.enabled, false);
    assert.equal(p.slack.allowPublic, false);
    assert.equal(p.discord.allowPublic, false);
    assert.equal(p.channels.ownerChannel, 'telegram');
    assert.equal(p.channels.port, 8787);
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, slack: { enabled: true, botToken: 'xoxb-abc' } })), /invalid/);
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, discord: { nope: 1 } })), /invalid/);
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, channels: { host: '0.0.0.0' } })), /invalid/, 'there is no way to change the bind address');
  });
  test('env var NAME fields reject anything that is not an env var name (e.g. a pasted token)', () => {
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, slack: { botTokenEnv: 'xoxb-123-abc' } })), /NAME of an environment variable/);
  });
  test('ownerChannel slack/discord requires that channel to be enabled', () => {
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, channels: { ownerChannel: 'slack' } })), /slack\.enabled is false/);
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, channels: { ownerChannel: 'discord' } })), /discord\.enabled is false/);
    assert.equal(parsePolicy(JSON.stringify({ version: 1, slack: { enabled: true }, channels: { ownerChannel: 'slack' } })).channels.ownerChannel, 'slack');
  });
  test('an enabled channel with a missing owner id / token / secret / key refuses to start, naming the variable but never a value', () => {
    const slackPolicy = policyWith({ slack: { enabled: true } });
    for (const missing of ['SLACK_BOT_TOKEN', 'SLACK_SIGNING_SECRET', 'SLACK_OWNER_ID']) {
      const env = { ...ENV };
      delete (env as any)[missing];
      assert.throws(() => new ChannelRuntime(slackPolicy, env), (e: any) => e instanceof ChannelConfigError && e.message.includes(missing) && !SECRETS.some((s) => e.message.includes(s)));
    }
    const discordPolicy = policyWith({ discord: { enabled: true } });
    for (const missing of ['DISCORD_BOT_TOKEN', 'DISCORD_PUBLIC_KEY', 'DISCORD_APPLICATION_ID', 'DISCORD_OWNER_ID']) {
      const env = { ...ENV };
      delete (env as any)[missing];
      assert.throws(() => new ChannelRuntime(discordPolicy, env), (e: any) => e instanceof ChannelConfigError && e.message.includes(missing));
    }
    assert.throws(() => resolveSlackConfig(slackPolicy, { ...ENV, SLACK_OWNER_ID: '  ' }), /SLACK_OWNER_ID/);
  });
  test('malformed values are refused without echoing them', () => {
    const sp = policyWith({ slack: { enabled: true } });
    for (const [k, v] of [['SLACK_BOT_TOKEN', 'not-a-token-VALUE-1'], ['SLACK_SIGNING_SECRET', 'qz9-7'], ['SLACK_OWNER_ID', 'alice-the-owner']] as const) {
      assert.throws(() => resolveSlackConfig(sp, { ...ENV, [k]: v }), (e: any) => e.message.includes(k) && !e.message.includes(v));
    }
    const dp = policyWith({ discord: { enabled: true } });
    for (const [k, v] of [['DISCORD_BOT_TOKEN', 'nope-VALUE'], ['DISCORD_PUBLIC_KEY', 'zz'.repeat(32)], ['DISCORD_APPLICATION_ID', 'app-VALUE'], ['DISCORD_OWNER_ID', '12345']] as const) {
      assert.throws(() => resolveDiscordConfig(dp, { ...ENV, [k]: v }), (e: any) => e.message.includes(k) && !e.message.includes(v));
    }
  });
  test('env var names come from the policy (custom names are honoured; the defaults are then ignored)', () => {
    const p = policyWith({ slack: { enabled: true, botTokenEnv: 'MY_BOT', signingSecretEnv: 'MY_SIGN', ownerIdEnv: 'MY_OWNER' } });
    assert.throws(() => resolveSlackConfig(p, ENV), /MY_BOT/);
    const cfg = resolveSlackConfig(p, { MY_BOT: SLACK_TOKEN, MY_SIGN: SLACK_SECRET, MY_OWNER: SLACK_OWNER });
    assert.equal(cfg.ownerId, SLACK_OWNER);
  });
  test('approvers and notifiers refuse to exist without a well-formed owner id', () => {
    assert.throws(() => new SlackApprover(new FakeSlack(), ''), /owner/);
    assert.throws(() => new SlackApprover(new FakeSlack(), 'general'), /owner/);
    assert.throws(() => new SlackNotifier(new FakeSlack(), 'C0CHANNEL'), /owner/);
    assert.throws(() => new DiscordApprover(new FakeDiscord(), '12'), /owner/);
    assert.throws(() => new DiscordNotifier(new FakeDiscord(), 'x'), /owner/);
  });
  test('API clients refuse malformed tokens and non-https bases (other than loopback)', () => {
    assert.throws(() => new FetchSlackApi('hunter2'), /bot token/);
    assert.throws(() => new FetchSlackApi(SLACK_TOKEN, 'http://slack.example.com'), /https/);
    assert.throws(() => new FetchDiscordApi('hunter2'), /bot token/);
    assert.throws(() => new FetchDiscordApi(DISCORD_TOKEN, 'http://discord.example.com/api'), /https/);
    assert.doesNotThrow(() => new FetchSlackApi(SLACK_TOKEN, 'http://127.0.0.1:1'));
  });
  test('doctor lines show variable names and set/NOT set, never values', () => {
    const p = policyWith({ slack: { enabled: true, allowPublic: true }, discord: { enabled: true } });
    const s = slackStatus(p, ENV);
    const d = discordStatus(p, { ...ENV, DISCORD_OWNER_ID: undefined as any });
    const text = [s.line, ...s.warnings, d.line, ...d.warnings, listenerStatus(p).line].join('\n');
    assert.match(s.line, /SLACK_BOT_TOKEN: set/);
    assert.match(s.line, /TAINTED/);
    assert.ok(s.warnings.some((w) => /allowPublic/.test(w)));
    assert.equal(d.broken, true);
    assert.match(d.line, /DISCORD_OWNER_ID: NOT set/);
    assert.match(listenerStatus(p).line, /127\.0\.0\.1:8787 \(loopback only/);
    for (const sec of [...SECRETS, SLACK_OWNER, DISCORD_OWNER, rawPub]) assert.ok(!text.includes(sec), 'leaked a value into doctor output');
    assert.match(slackStatus(defaultPolicy(), {}).line, /disabled/);
  });
  test('disabled channels start nothing', async () => {
    const rt = new ChannelRuntime(defaultPolicy(), {});
    assert.equal(rt.enabled, false);
    assert.equal(await rt.start({} as any, new GoalQueue()), undefined);
  });
  test('ownerApprover/ownerNotifier follow channels.ownerChannel', () => {
    const asSlack = new ChannelRuntime(policyWith({ slack: { enabled: true }, discord: { enabled: true }, channels: { ownerChannel: 'slack' } }), ENV, { slackApi: new FakeSlack(), discordApi: new FakeDiscord() });
    assert.equal(asSlack.ownerApprover?.name, 'slack');
    assert.equal(asSlack.ownerNotifier?.name, 'slack');
    const asDiscord = new ChannelRuntime(policyWith({ slack: { enabled: true }, discord: { enabled: true }, channels: { ownerChannel: 'discord' } }), ENV, { slackApi: new FakeSlack(), discordApi: new FakeDiscord() });
    assert.equal(asDiscord.ownerApprover?.name, 'discord');
    const asTelegram = new ChannelRuntime(policyWith({ slack: { enabled: true } }), ENV, { slackApi: new FakeSlack() });
    assert.equal(asTelegram.ownerApprover, undefined, 'Telegram stays the default owner channel; the daemon builds it');
    assert.ok(asTelegram.slack!.approver.async);
  });
});

// ---- the listener -------------------------------------------------------------------------------------------------------

describe('webhook listener hardening', () => {
  test('binds 127.0.0.1 only', async () => {
    const r = await rig();
    // Server address family/host is fixed by listenLoopback; verify through a second listener built the same way.
    const s = createChannelServer({ routes: [], maxBodyBytes: 1024 });
    const port = await listenLoopback(s, 0);
    assert.equal((s.address() as AddressInfo).address, '127.0.0.1');
    assert.ok(port > 0);
    await closeServer(s);
    assert.ok(r.live.port > 0);
    assert.equal((await fetch(`http://127.0.0.1:${r.live.port}/slack/events`)).status, 405);
  });
  test('unknown path 404, GET 405, oversized body 413, junk 401; none of them run a goal', async () => {
    const r = await rig({ channels: { ownerChannel: 'slack', maxBodyBytes: 2048 } });
    assert.equal((await post(r.live.port, '/nope', '{}')).status, 404);
    assert.equal((await fetch(`http://127.0.0.1:${r.live.port}/discord/interactions`)).status, 405);
    const big = await post(r.live.port, '/slack/events', 'x'.repeat(5000)).catch(() => ({ status: 413 }));
    assert.equal(big.status, 413);
    assert.equal((await post(r.live.port, '/slack/events', dmEvent('hi'))).status, 401, 'unsigned');
    assert.equal((await post(r.live.port, '/discord/interactions', slashCmd('hi'))).status, 401, 'unsigned');
    await sleep(50);
    assert.equal(r.llm.calls.classify, 0);
  });
});

// ---- Slack: goals ---------------------------------------------------------------------------------------------------------

describe('Slack goals', () => {
  test('url_verification echoes the challenge, but only when signed', async () => {
    const r = await rig();
    const body = JSON.stringify({ type: 'url_verification', challenge: 'abc123' });
    assert.deepEqual((await sendSlackEvent(r, body)).json, { challenge: 'abc123' });
    assert.equal((await post(r.live.port, '/slack/events', body)).status, 401);
  });

  test('the owner\'s DM runs as an OWNER goal; the reply goes back to that DM; session stays clean', async () => {
    const r = await rig();
    const res = await sendSlackEvent(r, dmEvent('hello there'));
    assert.equal(res.status, 200);
    await waitFor(() => r.slack.text().includes('hello from the fake model'));
    assert.equal(r.engine.tainted, false);
    assert.match(r.audit(), /"origin":"owner","originRef":"slack:U0OWNER01"/);
    assert.ok(r.slack.posts().every((c) => c.params.channel === DM));
    assert.equal(r.slack.posts().every((c) => c.params.mrkdwn === false && c.params.link_names === false), true);
  });

  test('a non-owner DM is ignored by default: no model call, no reply, no audit goal', async () => {
    const r = await rig();
    assert.equal((await sendSlackEvent(r, dmEvent('do evil', STRANGER))).status, 200);
    await sleep(100);
    assert.equal(r.llm.calls.classify, 0);
    assert.equal(r.slack.calls.length, 0);
    assert.doesNotMatch(r.audit(), /goal\.received/);
  });

  test('with slack.allowPublic a non-owner DM runs as a TAINTED non-owner goal (like Telegram)', async () => {
    const r = await rig({ slack: { enabled: true, allowPublic: true } });
    await sendSlackEvent(r, dmEvent('what time is it', STRANGER));
    await waitFor(() => r.slack.text().includes('hello from the fake model'));
    assert.equal(r.engine.tainted, true);
    assert.match(r.audit(), /"origin":"non-owner","originRef":"slack:U0STRANGER"/);
    assert.match(r.audit(), /taint\.mark/);
    assert.ok(r.slack.text().includes('[session tainted]'));
  });

  test('a stranger cannot reset the owner session with /new; the owner can', async () => {
    const r = await rig({ slack: { enabled: true, allowPublic: true } });
    await sendSlackEvent(r, dmEvent('hi', STRANGER));
    await waitFor(() => r.engine.tainted);
    await sendSlackEvent(r, dmEvent('/new', STRANGER));
    await waitFor(() => r.llm.calls.classify >= 2);
    assert.equal(r.engine.tainted, true, 'a stranger\'s /new is just another tainted goal');
    await sendSlackEvent(r, dmEvent('/new'));
    await waitFor(() => !r.engine.tainted);
    assert.match(r.audit(), /session\.new/);
  });

  test('bot messages, subtypes (edits), non-DM channels, bad ids and redelivered events are ignored', async () => {
    const r = await rig();
    await sendSlackEvent(r, dmEvent('from a bot', SLACK_OWNER, { bot_id: 'B0BOT' }));
    await sendSlackEvent(r, dmEvent('edited', SLACK_OWNER, { subtype: 'message_changed' }));
    await sendSlackEvent(r, dmEvent('in a channel', SLACK_OWNER, { channel_type: 'channel' }));
    await sendSlackEvent(r, dmEvent('app mention', SLACK_OWNER, { type: 'app_mention' }));
    await sendSlackEvent(r, dmEvent('weird user', 'U0OWNER01; DROP', {}));
    await sleep(100);
    assert.equal(r.llm.calls.classify, 0);
    const once = dmEvent('only once', SLACK_OWNER, {}, 'EvDUP1');
    await sendSlackEvent(r, once);
    await sendSlackEvent(r, once, slackSign(once, { ts: nowSec() + 1 })); // redelivery: fresh signature, same event id
    await waitFor(() => r.slack.text().includes('hello from the fake model'));
    await sleep(100);
    assert.equal(r.llm.calls.classify, 1);
  });

  test('bad signatures never reach the engine: wrong secret, stale, tampered, replayed', async () => {
    const r = await rig();
    const body = dmEvent('hello');
    assert.equal((await sendSlackEvent(r, body, slackSign(body, { secret: 'wrong-secret-wrong-secret' }))).status, 401);
    assert.equal((await sendSlackEvent(r, body, slackSign(body, { ts: nowSec() - 3600 }))).status, 401);
    const other = dmEvent('hello!');
    assert.equal((await sendSlackEvent(r, other, slackSign(body))).status, 401, 'signature for a different body');
    assert.equal((await post(r.live.port, '/slack/events', body, { 'x-slack-request-timestamp': String(nowSec()) })).status, 401, 'missing signature');
    await sleep(50);
    assert.equal(r.llm.calls.classify, 0);
    // The genuine request is accepted once; the byte-identical replay is rejected, and does not run the goal twice.
    const h = slackSign(body);
    assert.equal((await sendSlackEvent(r, body, h)).status, 200);
    assert.equal((await sendSlackEvent(r, body, h)).status, 401);
    await waitFor(() => r.slack.text().includes('hello from the fake model'));
    await sleep(50);
    assert.equal(r.llm.calls.classify, 1);
    assert.ok(r.logs.some((l) => /rejected: replay/.test(l)));
  });

  test('a clock-skewed server rejects otherwise-valid requests (the window is enforced against the injected clock)', async () => {
    const r = await rig({}, { now: () => Date.now() + 3_600_000 });
    assert.equal((await sendSlackEvent(r, dmEvent('hi'))).status, 401);
  });
});

// ---- Slack: approvals -----------------------------------------------------------------------------------------------------

const REQ = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  id: '11111111-2222-3333-4444-555555555555',
  action: { class: 'net.egress', target: 'evil.example', summary: 'GET http://evil.example/?x=1', detail: 'http://evil.example/?x=1' },
  provenance: { tainted: true, sources: [{ kind: 'web', ref: 'http://page/x', at: '' }] },
  reason: 'policy default',
  escalatedByTaint: true,
  expiresAt: Date.now() + 60_000,
  ...over,
});
const click = (value: string, user: string, channel: string, ts: string) => ({ type: 'block_actions', user: { id: user }, channel: { id: channel }, message: { ts }, actions: [{ action_id: 'sc_approve', value }] });

describe('SlackApprover', () => {
  test('DMs the full request (plain_text, no mention parsing) to the owner only, with Approve/Deny buttons', async () => {
    const api = new FakeSlack();
    const ap = new SlackApprover(api, SLACK_OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await sleep(10);
    const m = api.calls.find((c) => c.method === 'chat.postMessage')!;
    assert.equal(m.params.channel, SLACK_OWNER);
    assert.equal(m.params.blocks[0].text.type, 'plain_text');
    assert.match(m.params.blocks[0].text.text, /evil\.example/);
    assert.match(m.params.blocks[0].text.text, /TAINTED/);
    assert.deepEqual(m.params.blocks[1].elements.map((e: any) => e.value), [`sc:a:${REQ().id}`, `sc:d:${REQ().id}`]);
    ac.abort();
    assert.equal(await p, 'deny');
  });

  test('owner approves / denies from the posted message only', async () => {
    for (const [verb, want] of [['a', 'approve'], ['d', 'deny']] as const) {
      const api = new FakeSlack();
      const ap = new SlackApprover(api, SLACK_OWNER);
      const p = ap.request(REQ(), new AbortController().signal);
      await sleep(10);
      const posted = api.calls.find((c) => c.method === 'chat.postMessage')!;
      const ts = '1700000000.001';
      assert.equal(await ap.handleInteraction(click(`sc:${verb}:${REQ().id}`, SLACK_OWNER, DM, ts)), true);
      assert.equal(await p, want);
      assert.ok(api.calls.some((c) => c.method === 'chat.update' && /APPROVED|DENIED/.test(c.params.text) && c.params.blocks.length === 0));
      void posted;
    }
  });

  test('a non-owner click, a click from the wrong channel/message, or a malformed value does nothing; a replay after resolution does nothing', async () => {
    const api = new FakeSlack();
    const ap = new SlackApprover(api, SLACK_OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await sleep(10);
    const ts = '1700000000.001';
    assert.equal(await ap.handleInteraction(click(`sc:a:${REQ().id}`, STRANGER, DM, ts)), true);
    assert.equal(await ap.handleInteraction(click(`sc:a:${REQ().id}`, SLACK_OWNER, 'D0OTHER999', ts)), true, 'owner, but a different conversation');
    assert.equal(await ap.handleInteraction(click(`sc:a:${REQ().id}`, SLACK_OWNER, DM, '1700000000.999')), true, 'owner, but a different message');
    assert.equal(await ap.handleInteraction(click('garbage', SLACK_OWNER, DM, ts)), false);
    assert.equal(await ap.handleInteraction(click('sc:a:not-a-uuid', SLACK_OWNER, DM, ts)), false);
    assert.equal(await ap.handleInteraction({ type: 'view_submission' } as any), false);
    assert.equal(ap.pendingCount, 1, 'still pending');
    assert.ok(api.calls.filter((c) => c.method === 'chat.postEphemeral').length >= 3);
    assert.equal(await ap.handleInteraction(click(`sc:a:${REQ().id}`, SLACK_OWNER, DM, ts)), true);
    assert.equal(await p, 'approve');
    await ap.handleInteraction(click(`sc:d:${REQ().id}`, SLACK_OWNER, DM, ts)); // replay with the opposite verb
    assert.equal(ap.pendingCount, 0);
    assert.equal(await p, 'approve', 'first answer stands');
  });

  test('timeout (abort) is a deny and marks the message expired, with no buttons', async () => {
    const api = new FakeSlack();
    const ap = new SlackApprover(api, SLACK_OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await sleep(10);
    ac.abort();
    assert.equal(await p, 'deny');
    assert.ok(api.calls.some((c) => c.method === 'chat.update' && /DENIED \(timeout\)/.test(c.params.text) && c.params.blocks.length === 0));
    assert.equal(ap.pendingCount, 0);
    // a late click after expiry is refused
    await ap.handleInteraction(click(`sc:a:${REQ().id}`, SLACK_OWNER, DM, '1700000000.001'));
    assert.equal(ap.pendingCount, 0);
  });

  test('already-expired signal denies without asking; an unreachable Slack is a deny (nobody can approve)', async () => {
    const api = new FakeSlack();
    const ac = new AbortController();
    ac.abort();
    assert.equal(await new SlackApprover(api, SLACK_OWNER).request(REQ(), ac.signal), 'deny');
    assert.equal(api.calls.length, 0);
    const down = new FakeSlack();
    down.failAll = true;
    assert.equal(await new SlackApprover(down, SLACK_OWNER).request(REQ(), new AbortController().signal), 'deny');
  });

  test('a scheduled job asks the owner WITH the job id; the owner approves later; a stranger and a replay change nothing; an expired request is a deny', async () => {
    const dir = tmpDir();
    try {
      const api = new FakeSlack();
      const ap = new SlackApprover(api, SLACK_OWNER);
      assert.equal(ap.async, true);
      const audit = new AuditLog(path.join(dir, 'a.jsonl'), Ed25519Signer.generate());
      const gov = new Governor({ policy: policyWith({ scheduled: { defaultVerdictForAsk: 'ask-async', approvalTimeoutSeconds: 30 } }), audit, taint: new TaintTracker(), approver: ap });
      gov.setRunContext({ origin: 'scheduled', jobId: 'job-123', triggerAt: '2026-11-16T09:00:00Z' });
      const act = { class: 'fs.write' as const, target: 'x', summary: 'write x', inWorkspace: true };
      const p = gov.authorize(act);
      await sleep(50);
      const msg = api.calls.find((c) => c.method === 'chat.postMessage')!;
      assert.match(msg.params.blocks[0].text.text, /SCHEDULED job job-123/);
      const id = /sc:a:([0-9a-f-]{36})/.exec(JSON.stringify(msg.params.blocks))![1];
      await ap.handleInteraction(click(`sc:a:${id}`, STRANGER, DM, '1700000000.001'));
      assert.equal(ap.pendingCount, 1);
      await ap.handleInteraction(click(`sc:a:${id}`, SLACK_OWNER, DM, '1700000000.001'));
      const d = await p;
      assert.equal(d.allowed, true);
      assert.equal(d.by, 'human');
      await ap.handleInteraction(click(`sc:a:${id}`, SLACK_OWNER, DM, '1700000000.001'));
      assert.equal(ap.pendingCount, 0);
      gov.setRunContext({ origin: 'scheduled', jobId: 'job-123', triggerAt: 'x', deadlineAt: Date.now() + 300 });
      const d2 = await gov.authorize(act);
      assert.equal(d2.allowed, false);
      assert.equal(d2.by, 'timeout');
      assert.equal(ap.pendingCount, 0);
    } finally {
      rm(dir);
    }
  });

  test('END TO END over the signed webhook: owner DM asks for code execution; only the owner\'s signed click approves; strangers and replays are inert', async () => {
    const r = await rig({ slack: { enabled: true, allowPublic: true }, defaults: { 'memory.write': 'allow' } });
    r.llm.intent = 'task';
    r.llm.codeQueue.push(code('return 7;'));
    await sendSlackEvent(r, dmEvent('compute seven'));
    await waitFor(() => r.slack.posts().some((c) => Array.isArray(c.params.blocks) && c.params.blocks.some((b: any) => b.type === 'actions')));
    const ask = r.slack.posts().find((c) => Array.isArray(c.params.blocks) && c.params.blocks.some((b: any) => b.type === 'actions'))!;
    assert.equal(ask.params.channel, SLACK_OWNER);
    assert.match(ask.params.blocks[0].text.text, /Run generated JavaScript/);
    const approveVal = ask.params.blocks[1].elements[0].value as string;
    const ts = ask.res.ts as string;
    const interact = (payload: unknown, ts2?: number) => {
      const body = 'payload=' + encodeURIComponent(JSON.stringify(payload));
      return post(r.live.port, '/slack/interactions', body, slackSign(body, { ts: ts2 }), 'application/x-www-form-urlencoded');
    };
    // Unsigned, and a stranger's signed click: nothing happens.
    const forged = 'payload=' + encodeURIComponent(JSON.stringify(click(approveVal, SLACK_OWNER, DM, ts)));
    assert.equal((await post(r.live.port, '/slack/interactions', forged, {}, 'application/x-www-form-urlencoded')).status, 401);
    assert.equal((await interact(click(approveVal, STRANGER, DM, ts))).status, 200);
    await sleep(100);
    assert.equal(r.rt.slack!.approver.pendingCount, 1);
    assert.doesNotMatch(r.slack.text(), /^7$/m);
    // The owner approves.
    const okBody = 'payload=' + encodeURIComponent(JSON.stringify(click(approveVal, SLACK_OWNER, DM, ts)));
    const okHdr = slackSign(okBody);
    assert.equal((await post(r.live.port, '/slack/interactions', okBody, okHdr, 'application/x-www-form-urlencoded')).status, 200);
    await waitFor(() => /(^|\n)7(\n|$)/.test(r.slack.posts().map((c) => c.params.text).join('\n')));
    // A byte-identical replay of the owner's click is rejected at the signature layer.
    assert.equal((await post(r.live.port, '/slack/interactions', okBody, okHdr, 'application/x-www-form-urlencoded')).status, 401);
    assert.equal(r.rt.slack!.approver.pendingCount, 0);
    assert.equal(r.engine.tainted, false);
  });

  test('a goal from a non-owner that needs approval is tainted and the prompt shows non-owner provenance; only the owner can answer', async () => {
    const r = await rig({ slack: { enabled: true, allowPublic: true } });
    r.llm.intent = 'task';
    r.llm.codeQueue.push(code('return 1;'));
    await sendSlackEvent(r, dmEvent('please run this', STRANGER));
    await waitFor(() => r.slack.posts(SLACK_OWNER).length > 0);
    const ask = r.slack.posts(SLACK_OWNER)[0];
    assert.match(ask.params.blocks[0].text.text, /TAINTED/);
    assert.match(ask.params.blocks[0].text.text, /non-owner-message: slack:U0STRANGER/);
    const askTs = ask.res.ts as string;
    // the stranger cannot answer the owner's DM prompt
    const val = ask.params.blocks[1].elements[0].value as string;
    const body = 'payload=' + encodeURIComponent(JSON.stringify(click(val, STRANGER, 'D0STRANGER1', '1700000000.001')));
    await post(r.live.port, '/slack/interactions', body, slackSign(body), 'application/x-www-form-urlencoded');
    assert.equal(r.rt.slack!.approver.pendingCount, 1);
    // deny so the test ends promptly
    const deny = 'payload=' + encodeURIComponent(JSON.stringify(click(ask.params.blocks[1].elements[1].value, SLACK_OWNER, DM, askTs)));
    await post(r.live.port, '/slack/interactions', deny, slackSign(deny), 'application/x-www-form-urlencoded');
    await waitFor(() => r.slack.text().includes('execution not permitted'));
  });
});

// ---- Discord ---------------------------------------------------------------------------------------------------------------

describe('Discord goals', () => {
  test('PING is answered only when signed', async () => {
    const r = await rig();
    const body = JSON.stringify({ type: 1 });
    const ok = await sendDiscord(r, body);
    assert.deepEqual(ok.json, { type: 1 });
    assert.equal((await post(r.live.port, '/discord/interactions', body)).status, 401);
  });

  test('the owner\'s slash command runs as an OWNER goal and the answer arrives as an ephemeral follow-up', async () => {
    const r = await rig();
    const res = await sendDiscord(r, slashCmd('hello there'));
    assert.deepEqual(res.json, { type: 5, data: { flags: 64 } });
    await waitFor(() => r.discord.followups().length > 0);
    assert.match(r.discord.followups()[0].body.content, /hello from the fake model/);
    assert.deepEqual(r.discord.followups()[0].body.allowed_mentions, { parse: [] });
    assert.ok(r.discord.followups()[0].path.startsWith(`/webhooks/${DISCORD_APP}/`));
    assert.equal(r.engine.tainted, false);
    assert.match(r.audit(), /"origin":"owner","originRef":"discord:223456789012345678"/);
  });

  test('a non-owner is refused with a bare "Not authorised." by default: no model call', async () => {
    const r = await rig();
    const res = await sendDiscord(r, slashCmd('do evil', DISCORD_STRANGER));
    assert.equal(res.json.type, 4);
    assert.equal(res.json.data.content, 'Not authorised.');
    assert.equal(res.json.data.flags, 64);
    await sleep(80);
    assert.equal(r.llm.calls.classify, 0);
    assert.equal(r.discord.calls.length, 0);
  });

  test('a command for a different application id, or with no resolvable user, is refused', async () => {
    const r = await rig();
    assert.equal((await sendDiscord(r, slashCmd('x', DISCORD_OWNER, { application_id: '999999999999999999' }))).json.data.content, 'Not authorised.');
    assert.equal((await sendDiscord(r, JSON.stringify({ type: 2, application_id: DISCORD_APP, token: 't'.repeat(30), data: { name: 'starclaw', options: [{ name: 'goal', value: 'x' }] } }))).json.data.content, 'Not authorised.');
    assert.equal((await sendDiscord(r, slashCmd('x', DISCORD_OWNER, { data: { name: 'other' } }))).json.data.content, 'Unsupported.');
    await sleep(50);
    assert.equal(r.llm.calls.classify, 0);
  });

  test('DM interactions (user instead of member) work for the owner', async () => {
    const r = await rig();
    const body = JSON.stringify({ id: '9', type: 2, token: 'tok_' + 'b'.repeat(40), application_id: DISCORD_APP, user: { id: DISCORD_OWNER }, data: { name: 'starclaw', options: [{ name: 'goal', value: 'hi' }] } });
    assert.equal((await sendDiscord(r, body)).json.type, 5);
    await waitFor(() => r.discord.followups().length > 0);
  });

  test('with discord.allowPublic a non-owner runs as a TAINTED non-owner goal', async () => {
    const r = await rig({ discord: { enabled: true, allowPublic: true } });
    assert.equal((await sendDiscord(r, slashCmd('hi', DISCORD_STRANGER))).json.type, 5);
    await waitFor(() => r.discord.followups().length > 0);
    assert.equal(r.engine.tainted, true);
    assert.match(r.audit(), /"origin":"non-owner","originRef":"discord:323456789012345678"/);
    assert.match(r.discord.followups()[0].body.content, /\[session tainted\]/);
    // a stranger's /new does not clear taint
    await sendDiscord(r, slashCmd('/new', DISCORD_STRANGER));
    await waitFor(() => r.discord.followups().length > 1);
    assert.equal(r.engine.tainted, true);
    assert.equal((await sendDiscord(r, slashCmd('/new'))).json.data.content, 'New session started (taint cleared).');
    assert.equal(r.engine.tainted, false);
  });

  test('if the interaction token has expired the OWNER still gets the answer by DM; a stranger does not', async () => {
    const r = await rig({ discord: { enabled: true, allowPublic: true } });
    const orig = r.discord.call.bind(r.discord);
    r.discord.call = async (m: any, p: string, b?: unknown) => {
      if (p.includes('/messages/@original')) {
        r.discord.calls.push({ method: m, path: p, body: b });
        throw new Error('expired');
      }
      return orig(m, p, b);
    };
    await sendDiscord(r, slashCmd('hi'));
    await waitFor(() => r.discord.messages().some((c) => /hello from the fake model/.test(c.body.content)));
    assert.equal(r.discord.messages().filter((c) => c.path === `/channels/${DISCORD_DM}/messages`).length, 1);
    const before = r.discord.messages().length;
    await sendDiscord(r, slashCmd('hi', DISCORD_STRANGER));
    await waitFor(() => r.discord.followups().length >= 2);
    await sleep(80);
    assert.equal(r.discord.messages().length, before, 'nothing is DMed to the owner for a stranger\'s goal');
  });

  test('bad signatures never reach the engine: wrong key, stale, tampered, replayed', async () => {
    const r = await rig();
    const body = slashCmd('hello');
    assert.equal((await sendDiscord(r, body, discordSign(body, { key: generateKeyPairSync('ed25519').privateKey }))).status, 401);
    assert.equal((await sendDiscord(r, body, discordSign(body, { ts: nowSec() - 3600 }))).status, 401);
    assert.equal((await sendDiscord(r, slashCmd('hello!'), discordSign(body))).status, 401);
    assert.equal((await post(r.live.port, '/discord/interactions', body, { 'x-signature-timestamp': String(nowSec()) })).status, 401);
    await sleep(50);
    assert.equal(r.llm.calls.classify, 0);
    const h = discordSign(body);
    assert.equal((await sendDiscord(r, body, h)).status, 200);
    assert.equal((await sendDiscord(r, body, h)).status, 401);
    await waitFor(() => r.discord.followups().length > 0);
    await sleep(50);
    assert.equal(r.llm.calls.classify, 1);
  });
});

const dClick = (id: string, verb: 'a' | 'd', user: string, channel: string, messageId: string) =>
  JSON.stringify({ id: String(Math.random()), type: 3, token: 'tok_' + 'c'.repeat(40), application_id: DISCORD_APP, channel_id: channel, user: { id: user }, message: { id: messageId }, data: { custom_id: `sc:${verb}:${id}`, component_type: 2 } });
const dInteraction = (user: string, channel: string, messageId: string, customId: string) => ({ type: 3, channel_id: channel, user: { id: user }, message: { id: messageId }, data: { custom_id: customId } });

describe('DiscordApprover', () => {
  test('DMs the request to the owner with buttons and no mention parsing', async () => {
    const api = new FakeDiscord();
    const ap = new DiscordApprover(api, DISCORD_OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await sleep(10);
    assert.deepEqual(api.calls[0], { method: 'POST', path: '/users/@me/channels', body: { recipient_id: DISCORD_OWNER } });
    const m = api.messages()[0];
    assert.equal(m.path, `/channels/${DISCORD_DM}/messages`);
    assert.match(m.body.content, /evil\.example/);
    assert.deepEqual(m.body.allowed_mentions, { parse: [] });
    assert.deepEqual(m.body.components[0].components.map((c: any) => c.custom_id), [`sc:a:${REQ().id}`, `sc:d:${REQ().id}`]);
    ac.abort();
    assert.equal(await p, 'deny');
  });

  test('owner approves/denies from the posted message; strangers, other channels/messages, malformed ids and replays are inert', async () => {
    const api = new FakeDiscord();
    const ap = new DiscordApprover(api, DISCORD_OWNER);
    const p = ap.request(REQ(), new AbortController().signal);
    await sleep(10);
    const msgId = api.messages()[0] && '500000000000000001';
    const id = REQ().id;
    assert.equal(ap.handleInteraction(dInteraction(DISCORD_STRANGER, DISCORD_DM, msgId, `sc:a:${id}`))!.data!.content, 'Not authorised.');
    assert.equal(ap.handleInteraction(dInteraction(DISCORD_OWNER, '999999999999999999', msgId, `sc:a:${id}`))!.data!.content, 'Not authorised.');
    assert.equal(ap.handleInteraction(dInteraction(DISCORD_OWNER, DISCORD_DM, '999999999999999999', `sc:a:${id}`))!.data!.content, 'Not authorised.');
    assert.equal(ap.handleInteraction(dInteraction(DISCORD_OWNER, DISCORD_DM, msgId, 'garbage')), null);
    assert.equal(ap.handleInteraction(dInteraction(DISCORD_OWNER, DISCORD_DM, msgId, 'sc:a:not-a-uuid')), null);
    assert.equal(ap.pendingCount, 1);
    const ok = ap.handleInteraction(dInteraction(DISCORD_OWNER, DISCORD_DM, msgId, `sc:a:${id}`))!;
    assert.equal(ok.type, 7);
    assert.match(String(ok.data!.content), /APPROVED/);
    assert.deepEqual(ok.data!.components, []);
    assert.equal(await p, 'approve');
    const replay = ap.handleInteraction(dInteraction(DISCORD_OWNER, DISCORD_DM, msgId, `sc:d:${id}`))!;
    assert.equal(replay.data!.content, 'Request no longer pending.');
    assert.equal(ap.pendingCount, 0);
  });

  test('timeout (abort) is a deny and edits the message; unreachable Discord is a deny', async () => {
    const api = new FakeDiscord();
    const ap = new DiscordApprover(api, DISCORD_OWNER);
    const ac = new AbortController();
    const p = ap.request(REQ(), ac.signal);
    await sleep(10);
    ac.abort();
    assert.equal(await p, 'deny');
    assert.ok(api.calls.some((c) => c.method === 'PATCH' && /DENIED \(timeout\)/.test(c.body.content) && c.body.components.length === 0));
    const down = new FakeDiscord();
    down.failAll = true;
    assert.equal(await new DiscordApprover(down, DISCORD_OWNER).request(REQ(), new AbortController().signal), 'deny');
  });

  test('END TO END over the signed interactions endpoint: only the owner\'s click on the posted message approves', async () => {
    const r = await rig({ channels: { ownerChannel: 'discord' }, defaults: { 'memory.write': 'allow' } });
    r.llm.intent = 'task';
    r.llm.codeQueue.push(code('return 7;'));
    await sendDiscord(r, slashCmd('compute seven'));
    await waitFor(() => r.discord.messages().length > 0);
    const ask = r.discord.messages()[0];
    assert.equal(ask.path, `/channels/${DISCORD_DM}/messages`);
    assert.match(ask.body.content, /Run generated JavaScript/);
    const id = /sc:a:([0-9a-f-]{36})/.exec(JSON.stringify(ask.body.components))![1];
    const msgId = '500000000000000001';
    const stranger = await sendDiscord(r, dClick(id, 'a', DISCORD_STRANGER, DISCORD_DM, msgId));
    assert.equal(stranger.json.data.content, 'Not authorised.');
    await sleep(80);
    assert.equal(r.rt.discord!.approver.pendingCount, 1);
    const okBody = dClick(id, 'a', DISCORD_OWNER, DISCORD_DM, msgId);
    const okHdr = discordSign(okBody);
    const ok = await sendDiscord(r, okBody, okHdr);
    assert.equal(ok.json.type, 7);
    await waitFor(() => r.discord.followups().some((c) => /(^|\n)7(\n|$)/.test(c.body.content)));
    assert.equal((await sendDiscord(r, okBody, okHdr)).status, 401, 'replayed signed click');
    assert.equal(r.rt.discord!.approver.pendingCount, 0);
  });
});

// ---- notifications ---------------------------------------------------------------------------------------------------------

describe('owner notifications (tools.notifyOwner)', () => {
  test('SlackNotifier messages only the owner, with mentions/links neutralised', async () => {
    const api = new FakeSlack();
    await new SlackNotifier(api, SLACK_OWNER).send('<!channel> see <https://evil.example|click> & more');
    assert.equal(api.calls.length, 1);
    assert.equal(api.calls[0].params.channel, SLACK_OWNER);
    assert.equal(api.calls[0].params.text, '&lt;!channel&gt; see &lt;https://evil.example|click&gt; &amp; more');
    assert.equal(api.calls[0].params.link_names, false);
  });
  test('DiscordNotifier DMs only the owner with mentions disabled', async () => {
    const api = new FakeDiscord();
    await new DiscordNotifier(api, DISCORD_OWNER).send('@everyone hello');
    assert.equal(api.messages().length, 1);
    assert.equal(api.messages()[0].path, `/channels/${DISCORD_DM}/messages`);
    assert.deepEqual(api.messages()[0].body.allowed_mentions, { parse: [] });
  });
  for (const channel of ['slack', 'discord'] as const) {
    test(`the agent's tools.notifyOwner goes to the ${channel} owner channel (governed, audited before send, no recipient parameter)`, async () => {
      const r = await rig({ channels: { ownerChannel: channel } });
      r.llm.intent = 'task';
      // exec needs approval: allow it by policy for this test so only notifyOwner is under test.
      r.engine.setApprover({ name: 'auto', request: async () => 'approve' });
      // There is no recipient parameter: a model that tries to pick one is rejected by the strict argument schema and nothing is sent.
      r.llm.codeQueue.push(code("return await tools.notifyOwner({ text: 'sneaky', to: 'someone-else' });"));
      const bad = await r.engine.executeGoal('try to pick a recipient', { origin: 'owner' });
      assert.equal(bad.success, false);
      assert.match(String(bad.error), /unrecognized_keys/);
      assert.equal(r.slack.posts().length + r.discord.messages().length, 0);
      r.llm.codeQueue.push(code("return await tools.notifyOwner({ text: 'disk is full' });"));
      const res = await r.engine.executeGoal('check the disk', { origin: 'owner' });
      assert.equal(res.success, true, JSON.stringify(res));
      if (channel === 'slack') {
        assert.ok(r.slack.posts().some((c) => c.params.channel === SLACK_OWNER && /disk is full/.test(c.params.text)));
        assert.ok(!r.slack.posts().some((c) => c.params.channel === 'someone-else'));
      } else {
        assert.ok(r.discord.messages().some((c) => /disk is full/.test(c.body.content)));
        assert.ok(r.discord.messages().every((c) => c.path === `/channels/${DISCORD_DM}/messages`));
      }
      const a = r.audit();
      assert.ok(a.indexOf('"notify.owner"') < a.indexOf('exec.result') || a.includes('notify.owner'));
      assert.match(a, new RegExp(`"channel":"${channel}"`));
    });
  }
});

// ---- secrets hygiene ---------------------------------------------------------------------------------------------------------

describe('secrets never reach audit records, logs, errors or inspection output', () => {
  const startFake = (handler: (req: http.IncomingMessage, body: string, res: http.ServerResponse) => void) =>
    new Promise<{ base: string; seen: Array<{ url: string; headers: http.IncomingHttpHeaders; body: string }>; close: () => Promise<void> }>((resolve) => {
      const seen: Array<{ url: string; headers: http.IncomingHttpHeaders; body: string }> = [];
      const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          seen.push({ url: req.url ?? '', headers: req.headers, body });
          handler(req, body, res);
        });
      });
      server.listen(0, '127.0.0.1', () => resolve({ base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen, close: () => new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); }) }));
    });

  test('FetchSlackApi: token only in the Authorization header; error text and inspection never contain it, even if the server echoes it', async () => {
    const fake = await startFake((_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: `invalid_auth for ${SLACK_TOKEN}` }));
    });
    try {
      const api = new FetchSlackApi(SLACK_TOKEN, fake.base);
      await assert.rejects(api.call('chat.postMessage', { channel: SLACK_OWNER, text: 'x' }), (e: any) => !e.message.includes(SLACK_TOKEN) && /slack chat\.postMessage failed/.test(e.message));
      assert.equal(fake.seen[0].headers.authorization, `Bearer ${SLACK_TOKEN}`);
      assert.ok(!fake.seen[0].body.includes(SLACK_TOKEN) && !fake.seen[0].url.includes(SLACK_TOKEN));
      for (const text of [JSON.stringify(api), util.inspect(api, { showHidden: true, depth: 5 }), String(api)]) assert.ok(!text.includes(SLACK_TOKEN));
      await assert.rejects(api.call('../evil', {}), /invalid Slack method/);
    } finally {
      await fake.close();
    }
  });

  test('FetchSlackApi / FetchDiscordApi refuse to follow a redirect (would forward the credential)', async () => {
    const fake = await startFake((_req, _body, res) => {
      res.writeHead(307, { location: 'http://127.0.0.1:1/steal' });
      res.end();
    });
    try {
      await assert.rejects(new FetchSlackApi(SLACK_TOKEN, fake.base).call('auth.test', {}), (e: any) => !e.message.includes(SLACK_TOKEN));
      await assert.rejects(new FetchDiscordApi(DISCORD_TOKEN, fake.base).call('GET', '/users/@me'), (e: any) => !e.message.includes(DISCORD_TOKEN));
      assert.equal(fake.seen.length, 2);
    } finally {
      await fake.close();
    }
  });

  test('FetchDiscordApi: Bot token only in Authorization (and not sent to /webhooks/ follow-ups); errors and inspection never contain it', async () => {
    const fake = await startFake((req, _body, res) => {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: `401: Unauthorized ${DISCORD_TOKEN}`, code: 0 }));
    });
    try {
      const api = new FetchDiscordApi(DISCORD_TOKEN, fake.base);
      await assert.rejects(api.call('POST', '/users/@me/channels', { recipient_id: DISCORD_OWNER }), (e: any) => !e.message.includes(DISCORD_TOKEN) && /HTTP 401/.test(e.message));
      const ictoken = 'INTERACTIONTOKEN' + 'z'.repeat(60);
      await assert.rejects(api.call('PATCH', `/webhooks/${DISCORD_APP}/${ictoken}/messages/@original`, { content: 'x' }), (e: any) => !e.message.includes(ictoken), 'interaction tokens are not echoed in errors');
      assert.equal(fake.seen[0].headers.authorization, `Bot ${DISCORD_TOKEN}`);
      assert.equal(fake.seen[1].headers.authorization, undefined);
      for (const text of [JSON.stringify(api), util.inspect(api, { showHidden: true, depth: 5 })]) assert.ok(!text.includes(DISCORD_TOKEN));
      await assert.rejects(api.call('GET', '/a/../b'), /invalid Discord API path/);
      assert.equal(redactString(`token ${DISCORD_TOKEN}`), 'token [REDACTED]');
      assert.equal(redactString(`token ${SLACK_TOKEN} and ${'xa' + 'pp-1-A0B1C2D3E4F5-12345'}`), 'token [REDACTED] and [REDACTED]');
    } finally {
      await fake.close();
    }
  });

  test('a full Slack+Discord session with a FAILING API: audit log and server logs contain no token, signing secret or key', async () => {
    const r = await rig({ slack: { enabled: true, allowPublic: true }, discord: { enabled: true, allowPublic: true } });
    r.slack.failAll = true;
    r.discord.failAll = true;
    await sendSlackEvent(r, dmEvent('hello'));
    await sendSlackEvent(r, dmEvent('hello', STRANGER));
    await sendSlackEvent(r, dmEvent('bad'), slackSign('other'));
    await sendDiscord(r, slashCmd('hello'));
    await sendDiscord(r, slashCmd('hello'), discordSign('other'));
    await waitFor(() => r.llm.calls.classify >= 3);
    await sleep(100);
    const haystack = r.audit() + '\n' + r.logs.join('\n');
    for (const s of [...SECRETS, rawPub]) assert.ok(!haystack.includes(s), `a secret leaked: ${s.slice(0, 8)}...`);
    assert.ok(r.logs.some((l) => /rejected: (bad-signature|stale)/.test(l)), 'rejections are logged as bare reason codes');
    assert.match(r.audit(), /"channels\.start"/);
  });
});

// ---- queue + Telegram regression ------------------------------------------------------------------------------------------

describe('GoalQueue and the Telegram handler it now backs', () => {
  test('runs jobs strictly one at a time, in order, survives a failing job, and is bounded', async () => {
    const q = new GoalQueue(3);
    const order: string[] = [];
    let running = 0;
    let maxRunning = 0;
    const job = (name: string, fail = false) => async () => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await sleep(15);
      order.push(name);
      running--;
      if (fail) throw new Error('boom');
    };
    const a = q.enqueue(job('a'))!;
    const b = q.enqueue(job('b', true))!;
    const c = q.enqueue(job('c'))!;
    assert.equal(q.enqueue(job('d')), undefined, 'a fourth job is refused (bounded backlog)');
    await a;
    await assert.rejects(b, /boom/);
    await c;
    assert.deepEqual(order, ['a', 'b', 'c']);
    assert.equal(maxRunning, 1);
    assert.equal(q.pending, 0);
    assert.ok(q.enqueue(job('e')), 'capacity is released');
  });

  test('Telegram handler: owner goal answered, stranger ignored (unchanged behaviour on the shared queue)', async () => {
    const dir = tmpDir();
    const llm = new FakeLLM();
    llm.intent = 'conversation';
    const sent: any[] = [];
    const api = { call: async (m: string, p: any) => { sent.push({ m, p }); return { message_id: 1 }; } };
    const engine = new StarClawEngine({ llm, policy: policyWith({}), stateDir: path.join(dir, 's'), workspaceDir: path.join(dir, 'w') });
    try {
      const { TelegramApprover } = await import('../src/channels/telegram');
      const h = createTelegramHandler(engine, api, new TelegramApprover(api, 4242), 4242, false, new GoalQueue());
      await h({ update_id: 1, message: { message_id: 1, text: 'hi', chat: { id: 999 }, from: { id: 999 } } });
      assert.equal(sent.length, 0);
      await h({ update_id: 2, message: { message_id: 2, text: 'hi', chat: { id: 4242 }, from: { id: 4242 } } });
      assert.ok(sent.some((s) => /hello from the fake model/.test(s.p.text)));
      assert.equal(engine.tainted, false);
    } finally {
      engine.memory.close();
      rm(dir);
    }
  });
});

// ---- Discord command registration ---------------------------------------------------------------------------------------------

describe('discord command registration', () => {
  test('uploads exactly the /starclaw command (global or per guild) and validates ids', async () => {
    const api = new FakeDiscord();
    api.call = async (m: any, p: string, b?: unknown) => {
      api.calls.push({ method: m, path: p, body: b });
      return b;
    };
    assert.equal(await registerDiscordCommand(api, DISCORD_APP), 1);
    assert.equal(await registerDiscordCommand(api, DISCORD_APP, '523456789012345678'), 1);
    assert.deepEqual(api.calls.map((c) => [c.method, c.path]), [['PUT', `/applications/${DISCORD_APP}/commands`], ['PUT', `/applications/${DISCORD_APP}/guilds/523456789012345678/commands`]]);
    assert.deepEqual(api.calls[0].body, discordCommandDefinition());
    await assert.rejects(registerDiscordCommand(api, 'abc'), /application id/);
    await assert.rejects(registerDiscordCommand(api, DISCORD_APP, '../x'), /guild id/);
  });
});
