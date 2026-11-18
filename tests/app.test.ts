import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import * as dotenv from 'dotenv';
import { defaultAppHome, prepareAppHome, startApp } from '../src/app';
import { HttpApprover } from '../src/channels/http';
import { rm, tmpDir } from './helpers';

const CLI = path.join(__dirname, '..', 'src', 'cli.ts');
// Resolved here: the child runs in a temp dir, where a bare `--import tsx` would not be found.
const TSX = pathToFileURL(require.resolve('tsx')).href;
const fakeEngine = { tainted: false, audit: { length: 3 } } as any;

describe('starclaw app', () => {
  let dir: string;
  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => rm(dir));

  test('app home: STARCLAW_HOME wins, then %LOCALAPPDATA%\\StarClaw on Windows, else ~/.starclaw-app', () => {
    assert.equal(defaultAppHome({ STARCLAW_HOME: dir, LOCALAPPDATA: 'C:\\x' }, 'win32'), path.resolve(dir));
    assert.equal(defaultAppHome({ LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local' }, 'win32'), path.join('C:\\Users\\u\\AppData\\Local', 'StarClaw'));
    assert.equal(defaultAppHome({}, 'linux'), path.join(os.homedir(), '.starclaw-app'));
  });

  test('first run writes a strong console key; later runs reuse it; existing lines are kept', () => {
    const home = path.join(dir, 'home');
    fs.mkdirSync(home);
    fs.writeFileSync(path.join(home, '.env'), 'GROQ_API_KEY=abc'); // no trailing newline
    const a = prepareAppHome(home);
    assert.equal(a.created, true);
    assert.ok(a.apiKey.length >= 43 && /^[A-Za-z0-9_-]+$/.test(a.apiKey));
    const parsed = dotenv.parse(fs.readFileSync(a.envFile, 'utf8'));
    assert.equal(parsed.GROQ_API_KEY, 'abc');
    assert.equal(parsed.STARCLAW_API_KEY, a.apiKey);
    const b = prepareAppHome(home);
    assert.deepEqual([b.created, b.apiKey], [false, a.apiKey]);
    assert.notEqual(prepareAppHome(path.join(dir, 'other')).apiKey, a.apiKey, 'each home gets its own random key');
    if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(dir, 'other', '.env')).mode & 0o077, 0);
  });

  test('a short key already in .env is refused, not silently replaced', () => {
    fs.writeFileSync(path.join(dir, '.env'), 'STARCLAW_API_KEY=short\n');
    assert.throws(() => prepareAppHome(dir), /shorter than 16/);
    assert.equal(fs.readFileSync(path.join(dir, '.env'), 'utf8'), 'STARCLAW_API_KEY=short\n');
  });

  test('console: 127.0.0.1 only, key only in the fragment, API still needs it, page strips it', async () => {
    const { apiKey } = prepareAppHome(dir);
    let opened = '';
    const a = await startApp({ apiKey, engine: fakeEngine, approver: new HttpApprover(), open: (u) => { opened = u; } });
    try {
      const u = new URL(opened);
      assert.equal(u.hostname, '127.0.0.1');
      assert.equal(u.search, '');
      assert.equal(u.hash, `#key=${apiKey}`);
      const page = await fetch(`http://127.0.0.1:${a.port}/`);
      assert.equal(page.status, 200);
      const html = await page.text();
      assert.match(html, /location\.hash/);
      assert.match(html, /history\.replaceState/);
      assert.equal((await fetch(`http://127.0.0.1:${a.port}/api/status`)).status, 401);
      const ok = await fetch(`http://127.0.0.1:${a.port}/api/status`, { headers: { Authorization: `Bearer ${apiKey}` } });
      assert.deepEqual(await ok.json(), { tainted: false, auditRecords: 3, pendingApprovals: 0 });
    } finally {
      await a.close();
    }
  });

  test('CLI without a model key: opens guided setup (key-protected) instead of exiting', async () => {
    const home = path.join(dir, 'home');
    const env: NodeJS.ProcessEnv = { ...process.env, STARCLAW_HOME: home };
    for (const k of ['GROQ_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OPENROUTER_API_KEY', 'STARCLAW_POLICY', 'STARCLAW_API_KEY']) delete env[k];
    const child = spawn(process.execPath, ['--import', TSX, CLI, 'app', '--no-open'], { env, cwd: dir });
    try {
      let out = '';
      child.stderr.on('data', (d) => { out += d; });
      const port = await new Promise<number>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`no setup line in 60s:\n${out}`)), 60_000);
        child.stdout.on('data', (d) => {
          out += d;
          const m = /setup: http:\/\/127\.0\.0\.1:(\d+)\//.exec(out);
          if (m && out.includes('Ctrl+C stops it.')) { clearTimeout(t); resolve(Number(m[1])); }
        });
        child.on('exit', (c) => { clearTimeout(t); reject(new Error(`exited ${c}:\n${out}`)); });
      });
      assert.match(out, /No usable AI model yet \(GROQ_API_KEY is not set/);
      assert.match(await (await fetch(`http://127.0.0.1:${port}/`)).text(), /StarClaw Setup/);
      assert.equal((await fetch(`http://127.0.0.1:${port}/api/setup/status`)).status, 401);
      const key = dotenv.parse(fs.readFileSync(path.join(home, '.env'), 'utf8')).STARCLAW_API_KEY;
      const st = await fetch(`http://127.0.0.1:${port}/api/setup/status`, { headers: { Authorization: `Bearer ${key}` } });
      assert.equal(st.status, 200);
      assert.ok((await st.json()).presets.length >= 4);
    } finally {
      child.kill();
    }
  });

  test('CLI: a broken policy file is an error, not a reason to open setup', () => {
    const home = path.join(dir, 'home');
    fs.mkdirSync(home, { recursive: true });
    fs.writeFileSync(path.join(home, 'starclaw.policy.json'), '{"llm": {"provider": "nonsense"}}');
    const env: NodeJS.ProcessEnv = { ...process.env, STARCLAW_HOME: home };
    for (const k of ['STARCLAW_POLICY', 'STARCLAW_API_KEY']) delete env[k];
    const r = spawnSync(process.execPath, ['--import', TSX, CLI, 'app', '--no-open'], { encoding: 'utf8', env, cwd: dir, timeout: 60_000 });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.doesNotMatch(r.stdout, /guided setup/);
  });

  test('CLI end to end: boots in the app home, serves the console, API answers with the key from <home>/.env', async () => {
    const home = path.join(dir, 'home');
    const env: NodeJS.ProcessEnv = { ...process.env, STARCLAW_HOME: home, GROQ_API_KEY: 'gsk_not_a_real_key_never_called' };
    for (const k of ['STARCLAW_POLICY', 'STARCLAW_API_KEY', 'STARCLAW_STATE_DIR']) delete env[k];
    const child = spawn(process.execPath, ['--import', TSX, CLI, 'app', '--no-open', '--sandbox', 'process'], { env, cwd: dir });
    try {
      let out = '';
      child.stderr.on('data', (d) => { out += d; });
      const port = await new Promise<number>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`no console line in 120s:\n${out}`)), 120_000);
        child.stdout.on('data', (d) => {
          out += d;
          const m = /console: http:\/\/127\.0\.0\.1:(\d+)\//.exec(out);
          if (m && out.includes('Ctrl+C stops it.')) { clearTimeout(t); resolve(Number(m[1])); } // last line printed
        });
        child.on('exit', (c) => { clearTimeout(t); reject(new Error(`exited ${c}:\n${out}`)); });
      });
      const key = dotenv.parse(fs.readFileSync(path.join(home, '.env'), 'utf8')).STARCLAW_API_KEY;
      assert.ok(out.includes(`#key=${key}`), 'with --no-open the keyed address is printed');
      const ok = await fetch(`http://127.0.0.1:${port}/api/status`, { headers: { Authorization: `Bearer ${key}` } });
      assert.equal(ok.status, 200);
      assert.equal((await ok.json()).tainted, false);
      assert.ok(fs.existsSync(path.join(home, '.starclaw', 'audit.jsonl')), 'state lives in the app home, not the cwd');
      assert.equal(fs.existsSync(path.join(dir, '.starclaw')), false);
    } finally {
      child.kill();
    }
  });
});
