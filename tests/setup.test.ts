import { test, describe, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import * as dotenv from 'dotenv';
import { HttpApprover } from '../src/channels/http';
import { parsePolicy } from '../src/governance/policy';
import { startApp } from '../src/app';
import { detect, listModels, PRESETS, recommendPreset, saveSetup, setEnvVar, testModel, type Preset, type PresetId } from '../src/setup';
import { rm, tmpDir } from './helpers';

const GOOD = 'sk-test-good-key-123456';
const CONSOLE_KEY = 'console-key-0123456789abcdef';

// A fake OpenAI-compatible server (what Ollama, LM Studio, OpenAI and OpenRouter look like to us).
let fake: http.Server;
let base = '';
const seen: Array<{ url: string; auth?: string }> = [];
before(async () => {
  fake = http.createServer((req, res) => {
    seen.push({ url: req.url!, auth: req.headers.authorization });
    const authed = req.headers.authorization === `Bearer ${GOOD}` || !req.headers.authorization;
    if (!authed) {
      res.writeHead(401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: `invalid key ${req.headers.authorization}` })); // echoes the key back
    }
    if (req.method === 'GET' && req.url === '/v1/models') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ data: [{ id: 'zeta-model' }, { id: 'alpha:7b' }, { id: 'bad id with spaces' }, { id: 'alpha:7b' }] }));
    }
    if (req.method === 'POST' && req.url === '/v1/chat/completions') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ choices: [{ message: { content: 'OK' } }], usage: { prompt_tokens: 12, completion_tokens: 1 } }));
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => fake.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(fake.address() as AddressInfo).port}/v1`;
});
after(() => new Promise<void>((r) => fake.close(() => r())));

const presets = (): Record<PresetId, Preset> => ({
  ...PRESETS,
  openai: { ...PRESETS.openai, baseUrl: base },
  ollama: { ...PRESETS.ollama, baseUrl: base },
  lmstudio: { ...PRESETS.lmstudio, baseUrl: 'http://127.0.0.1:9/v1' }, // nothing listens there
});

describe('guided model setup', () => {
  let home: string;
  beforeEach(() => { home = tmpDir(); seen.length = 0; });
  afterEach(() => rm(home));

  test('models come from the provider, sorted, deduplicated, invalid ids dropped; the key is sent', async () => {
    assert.deepEqual(await listModels('openai', GOOD, { presets: presets() }), ['alpha:7b', 'zeta-model']);
    assert.equal(seen[0].auth, `Bearer ${GOOD}`);
    assert.deepEqual(await listModels('groq', GOOD, { presets: presets() }), ['openai/gpt-oss-120b'], 'groq model is built in');
  });

  test('detect: a running local server is offered with its models, a dead one is not; keys are reported by name only', async () => {
    const d = await detect({ OPENROUTER_API_KEY: 'x', GROQ_API_KEY: '' } as any, { presets: presets() });
    assert.deepEqual(d.local.map((l) => [l.id, l.models.length]), [['ollama', 2]]);
    assert.deepEqual(d.keysPresent, ['openrouter']);
  });

  test('CONTROL: a working model passes the test call; a rejected key fails with the key scrubbed from the message', async () => {
    const ok = await testModel('openai', GOOD, 'alpha:7b', { presets: presets() });
    assert.equal(ok.ok, true, ok.error);
    assert.equal(ok.reply, 'OK');
    const bad = await testModel('openai', 'sk-wrong-key-9999999', 'alpha:7b', { presets: presets() });
    assert.equal(bad.ok, false);
    assert.match(bad.error!, /HTTP 401/);
    assert.ok(!bad.error!.includes('sk-wrong-key-9999999'), bad.error);
  });

  test('save: valid policy written (other fields kept), key in .env (other lines kept, same var replaced), local models priced at 0', () => {
    fs.writeFileSync(path.join(home, '.env'), 'STARCLAW_API_KEY=keepme-0123456789abcdef\nOPENAI_API_KEY=old-key-000000\n');
    fs.writeFileSync(path.join(home, 'starclaw.policy.json'), JSON.stringify({ version: 1, workspace: 'mywork' }));
    saveSetup(home, 'openai', GOOD, 'alpha:7b', presets());
    const env = dotenv.parse(fs.readFileSync(path.join(home, '.env'), 'utf8'));
    assert.equal(env.STARCLAW_API_KEY, 'keepme-0123456789abcdef');
    assert.equal(env.OPENAI_API_KEY, GOOD);
    const pol = parsePolicy(fs.readFileSync(path.join(home, 'starclaw.policy.json'), 'utf8'));
    assert.equal(pol.workspace, 'mywork');
    assert.deepEqual([pol.llm.provider, pol.llm.model, pol.llm.baseUrl], ['openai-compat', 'alpha:7b', base]);
    saveSetup(home, 'ollama', undefined, 'alpha:7b', presets());
    assert.deepEqual(parsePolicy(fs.readFileSync(path.join(home, 'starclaw.policy.json'), 'utf8')).llm.prices, { inputCentsPerMTok: 0, outputCentsPerMTok: 0 });
  });

  test('save refuses an invalid key or a bad model id and writes nothing', () => {
    assert.throws(() => saveSetup(home, 'openai', 'has space in it', 'alpha:7b', presets()), /valid API key/);
    assert.throws(() => saveSetup(home, 'openai', GOOD, 'bad id', presets()), /choose a model/);
    assert.throws(() => setEnvVar(path.join(home, '.env'), 'OPENAI_API_KEY', 'line\nINJECTED=1'), /invalid env entry/);
    assert.equal(fs.existsSync(path.join(home, '.env')), false);
    assert.equal(fs.existsSync(path.join(home, 'starclaw.policy.json')), false);
  });

  test('app in setup mode: API needs the console key; a failing model is not saved; a tested one is saved and the agent starts on the same port', async () => {
    const env: NodeJS.ProcessEnv = {};
    let booted = 0;
    const engine = { tainted: false, audit: { length: 1 } } as any;
    const a = await startApp({
      apiKey: CONSOLE_KEY, open: false,
      setup: { home, env, deps: { presets: presets() }, boot: async () => { booted++; return { engine, approver: new HttpApprover() }; } },
    });
    const url = (p: string) => `http://127.0.0.1:${a.port}${p}`;
    const H = { authorization: `Bearer ${CONSOLE_KEY}`, 'content-type': 'application/json' };
    const post = (p: string, body: unknown) => fetch(url(p), { method: 'POST', headers: H, body: JSON.stringify(body) });
    try {
      assert.equal(a.mode(), 'setup');
      assert.match(await (await fetch(url('/'))).text(), /StarClaw Setup/);
      assert.equal((await fetch(url('/api/setup/status'))).status, 401);
      const st = await (await fetch(url('/api/setup/status'), { headers: H })).json();
      assert.ok(st.presets.some((p: any) => p.id === 'ollama'));
      assert.equal((await post('/api/setup/models', { preset: 'nope' })).status, 400, 'unknown preset');
      assert.equal((await post('/api/setup/models', { preset: 'openai', baseUrl: 'http://evil' , key: GOOD })).status, 200, 'extra fields (a URL) are ignored');
      assert.ok(!seen.some((s) => s.url.includes('evil')));

      const failed = await post('/api/setup/save', { preset: 'openai', key: 'sk-wrong-key-9999999', model: 'alpha:7b' });
      assert.equal(failed.status, 400);
      assert.equal(fs.existsSync(path.join(home, 'starclaw.policy.json')), false, 'nothing saved when the model does not answer');
      assert.equal(booted, 0);

      const saved = await post('/api/setup/save', { preset: 'openai', key: GOOD, model: 'alpha:7b' });
      assert.equal(saved.status, 200, await saved.clone().text());
      assert.equal(booted, 1);
      assert.equal(env.OPENAI_API_KEY, GOOD, 'the running process gets the key without a restart');
      assert.equal(a.mode(), 'agent');
      const status = await fetch(url('/api/status'), { headers: H });
      assert.deepEqual(await status.json(), { tainted: false, auditRecords: 1, pendingApprovals: 0 });
      assert.match(await (await fetch(url('/'))).text(), /StarClaw Console/);
    } finally {
      await a.close();
    }
  });
});


describe('setup prefers what you already have; Groq is only the free fallback (alpha.11)', () => {
  const none = { local: [], keysPresent: [] as PresetId[] };
  const ollama = { id: 'ollama' as PresetId, label: 'Ollama (on this PC)', models: ['qwen2.5-coder:7b'] };
  test('order: Anthropic > OpenRouter > OpenAI keys > running local model > existing Groq key > suggested Groq', () => {
    assert.deepEqual(recommendPreset({ local: [ollama], keysPresent: ['groq', 'openai', 'openrouter', 'anthropic'] }).id, 'anthropic');
    assert.equal(recommendPreset({ local: [ollama], keysPresent: ['groq', 'openai', 'openrouter'] }).id, 'openrouter');
    assert.equal(recommendPreset({ local: [ollama], keysPresent: ['groq', 'openai'] }).id, 'openai');
    assert.equal(recommendPreset({ local: [ollama], keysPresent: ['groq'] }).id, 'ollama');
    const g = recommendPreset({ local: [], keysPresent: ['groq'] });
    assert.deepEqual([g.id, g.preselect], ['groq', true]);
  });
  test('nothing found: Groq is SUGGESTED (free), never preselected', () => {
    const r = recommendPreset(none);
    assert.equal(r.id, 'groq');
    assert.equal(r.preselect, false);
    assert.match(r.reason, /free/);
  });
  test('keys saved in the StarClaw home .env count the same as environment keys', () => {
    assert.equal(recommendPreset(none, ['anthropic']).id, 'anthropic');
    assert.equal(recommendPreset(none, ['openrouter']).preselect, true);
  });
  test('a local server with no models is not recommended', () => {
    assert.equal(recommendPreset({ local: [{ ...ollama, models: [] }], keysPresent: [] }).preselect, false);
  });
  test('the policy schema default is still provider "groq" (existing policies keep working)', () => {
    assert.equal(parsePolicy('{}').llm.provider, 'groq');
  });
});
