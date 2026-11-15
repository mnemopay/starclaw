import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { ProcessSandbox, SandboxUnavailable } from '../src/sandbox/ProcessSandbox';
import { code, rm, tmpDir } from './helpers';

const noBroker = async () => {
  throw new Error('no broker in this test');
};

describe('ProcessSandbox: probe (fail-closed)', () => {
  let dir: string;
  before(() => {
    dir = tmpDir();
  });
  after(() => rm(dir));

  test('the probe passes on this Node build and covers every forbidden class', async () => {
    const sb = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws') });
    const rep = await sb.ensureSafe();
    assert.equal(rep.ok, true, JSON.stringify(rep.failures));
    const names = rep.results.map((r) => r.name).join('\n');
    for (const needle of ['child_process.execFileSync', 'child_process.import()', 'worker_threads', 'native addon', 'wasi', 'net.connect', 'fetch', 'dns.lookup', 'dgram', 'fs.read outside', 'fs.write outside', 'process.kill(victim)', 'process.binding', 'inspector', 'env scrubbed', 'broker roundtrip', 'tcp listener saw no connection', 'victim process still alive']) {
      assert.ok(names.includes(needle), `probe is missing check: ${needle}`);
    }
    assert.ok(rep.results.length >= 30, `only ${rep.results.length} checks`);
  });

  test('CONTROL: without the permission model the probe FAILS and run() refuses to execute', async () => {
    const sb = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws-weak'), _unsafeDisablePermissionModel: true });
    await assert.rejects(() => sb.ensureSafe(), SandboxUnavailable);
    const failed = sb.lastProbe!.failures.map((f) => f.name);
    for (const must of ['child_process.execFileSync', 'worker_threads', 'net.connect tcp', 'fs.read outside workspace', 'fs.write outside workspace']) {
      assert.ok(failed.includes(must), `control should have failed on ${must}; failed on: ${failed.join(', ')}`);
    }
    // Real side effects happened in the control: proof the checks can fail.
    assert.ok(failed.some((f) => f.startsWith('side effect:')));
    const marker = path.join(dir, 'should-not-exist.txt');
    await assert.rejects(() => sb.run(code(`require('fs').writeFileSync(${JSON.stringify(marker)}, 'x')`), noBroker), SandboxUnavailable);
    assert.equal(fs.existsSync(marker), false, 'fail-closed: code must not run when the probe failed');
  });

  test('CONTROL: skipping the process.kill hardening lets generated code kill another process', async () => {
    const sb = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws-kill'), _unsafeSkipHardening: true });
    await assert.rejects(() => sb.ensureSafe(), SandboxUnavailable);
    const failed = sb.lastProbe!.failures.map((f) => f.name);
    assert.ok(failed.includes('process.kill(victim)'), failed.join(', '));
    assert.ok(failed.includes('side effect: victim process still alive'), failed.join(', '));
    assert.ok(failed.includes('process._debugProcess(victim)'), 'without hardening, generated code can switch on another process inspector: ' + failed.join(', '));
  });

  test('FINDING: granting direct workspace access is unsafe because a junction/symlink escapes it (so it is not a supported mode)', async () => {
    const sb = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws-direct'), _unsafeDirectWorkspaceAccess: true });
    await assert.rejects(() => sb.ensureSafe(), SandboxUnavailable);
    const failed = sb.lastProbe!.failures.map((f) => f.name);
    assert.ok(failed.some((f) => f.includes('through junction')), failed.join(', '));
  });
});

describe('ProcessSandbox: adversarial generated code', () => {
  let dir: string;
  let sb: ProcessSandbox;
  let outsideFile: string;
  before(() => {
    dir = tmpDir();
    sb = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws'), timeoutMs: 8000, maxOutputBytes: 2000 });
    outsideFile = path.join(dir, 'outside-secret.txt');
    fs.writeFileSync(outsideFile, 'secret');
  });
  after(() => rm(dir));

  const attempts: Record<string, string> = {
    'child_process.exec': `try { require('child_process').execSync('echo pwned > ${'x'}'); return 'RAN'; } catch (e) { return e.code; }`,
    'child_process via import()': `try { const m = await import('node:child_process'); m.execSync('echo hi'); return 'RAN'; } catch (e) { return e.code; }`,
    'worker_threads': `try { new (require('worker_threads').Worker)('1', { eval: true }); return 'RAN'; } catch (e) { return e.code; }`,
    'process.binding': `try { process.binding('fs'); return 'RAN'; } catch (e) { return e.code; }`,
    'native addon': `try { process.dlopen({ exports: {} }, process.execPath); return 'RAN'; } catch (e) { return e.code; }`,
    'wasi': `try { new (require('wasi').WASI)({ version: 'preview1' }); return 'RAN'; } catch (e) { return e.code; }`,
    'raw socket': `try { await new Promise((res, rej) => { const s = require('net').connect(9, '127.0.0.1'); s.on('error', rej); s.on('connect', res); }); return 'RAN'; } catch (e) { return e.code; }`,
    'fetch': `try { await fetch('http://127.0.0.1:59999/'); return 'RAN'; } catch (e) { return e.cause && e.cause.code; }`,
    'dns': `try { await new Promise((res, rej) => require('dns').lookup('example.com', (e, a) => e ? rej(e) : res(a))); return 'RAN'; } catch (e) { return e.code; }`,
    'read file outside workspace': `try { return require('fs').readFileSync(${JSON.stringify('OUTSIDE')}, 'utf8'); } catch (e) { return e.code; }`,
    'write file outside workspace': `try { require('fs').writeFileSync(${JSON.stringify('OUTSIDE2')}, 'x'); return 'RAN'; } catch (e) { return e.code; }`,
    'read the workspace directly (brokered only)': `try { return require('fs').readdirSync('.'); } catch (e) { return e.code; }`,
    'eval + Function reaching child_process': `try { return eval("new Function('return process.mainModule.require(\\"child_process\\").execSync(\\"echo hi\\")')()"); } catch (e) { return e.code; }`,
    'process._debugProcess (ungated by Node itself)': `try { process._debugProcess(process.pid + 1); return 'RAN'; } catch (e) { return e.code; }`,
    'process.kill': `try { process.kill(process.pid + 1); return 'RAN'; } catch (e) { return e.code; }`,
  };
  for (const [name, body] of Object.entries(attempts)) {
    test(`blocked: ${name}`, async () => {
      const marker = path.join(dir, `marker-${name.replace(/\W+/g, '_')}.txt`);
      const src = body.replace('OUTSIDE2', marker.replace(/\\/g, '\\\\')).replace('OUTSIDE', outsideFile.replace(/\\/g, '\\\\'));
      const r = await sb.run(code(src), noBroker);
      assert.equal(r.ok, true, r.error);
      assert.match(String(r.value), /^(ERR_ACCESS_DENIED|ERR_DLOPEN_DISABLED|ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING)$/, `got ${JSON.stringify(r.value)}`);
      assert.equal(fs.existsSync(marker), false);
    });
  }

  test('brokered calls reach the handler and errors come back as exceptions', async () => {
    const seen: string[] = [];
    const r = await sb.run(
      code(`const a = await tools.readFile({ path: 'x' }); let denied = null; try { await tools.fetchUrl({ url: 'http://e' }); } catch (e) { denied = e.code + ':' + e.message; } return { a, denied };`),
      async (c) => {
        seen.push(c.name);
        if (c.name === 'readFile') return 'content';
        throw Object.assign(new Error('nope'), { name: 'GovernorDenied' });
      },
    );
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.value, { a: 'content', denied: 'ERR_GOVERNOR_DENIED:nope' });
    assert.deepEqual(seen, ['readFile', 'fetchUrl']);
  });

  test('unknown tool names are refused by the parent', async () => {
    const r = await sb.run(code(`await tools.hackTheGibson({}); return 'RAN';`), noBroker);
    assert.equal(r.ok, false); // tools.hackTheGibson is undefined in the child
  });

  test('environment is scrubbed (no inherited secrets)', async () => {
    process.env.STARCLAW_TEST_SECRET_TOKEN = 'leak-me';
    try {
      const r = await sb.run(code(`return Object.keys(process.env).filter(k => /SECRET|TOKEN|KEY/i.test(k));`), noBroker);
      assert.deepEqual(r.value, []);
    } finally {
      delete process.env.STARCLAW_TEST_SECRET_TOKEN;
    }
  });

  test('wall-clock timeout kills the child (by handle)', async () => {
    const quick = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws2'), timeoutMs: 1500 });
    const r = await quick.run(code(`await new Promise(() => {}); `), noBroker);
    assert.equal(r.ok, false);
    assert.equal(r.timedOut, true);
  });

  test('output is capped', async () => {
    const r = await sb.run(code(`for (let i = 0; i < 2000; i++) console.log('x'.repeat(100)); return 1;`), noBroker);
    assert.equal(r.outputTruncated, true);
    assert.ok(r.stdout.length <= 2000);
  });

  test('broker call limit is enforced', async () => {
    const limited = new ProcessSandbox({ workspaceDir: path.join(dir, 'ws3'), maxBrokerCalls: 3 });
    const r = await limited.run(code(`let n = 0; try { for (let i = 0; i < 10; i++) { await tools.readFile({ path: 'a' }); n++; } } catch (e) { return { n, code: e.code }; } return { n };`), async () => 'x');
    assert.deepEqual(r.value, { n: 3, code: 'ERR_BROKER_LIMIT' });
  });

  test('a killed victim stays alive: sandboxed code cannot signal our test process tree', async () => {
    const victim = spawn(process.execPath, ['-e', 'setTimeout(()=>{},20000)'], { stdio: 'ignore' });
    try {
      await new Promise((r) => setTimeout(r, 150));
      const r = await sb.run(code(`try { process.kill(${victim.pid}); return 'KILLED'; } catch (e) { return e.code; }`), noBroker);
      assert.equal(r.value, 'ERR_ACCESS_DENIED');
      process.kill(victim.pid!, 0); // throws if dead
    } finally {
      victim.kill();
    }
  });
});
