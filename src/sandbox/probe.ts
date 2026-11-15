import * as dgram from 'node:dgram';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import type { ProcessSandbox, SandboxOptions } from './ProcessSandbox';

export interface ProbeItem {
  name: string;
  denied: boolean;
  detail: string;
}
export interface ProbeReport {
  ok: boolean;
  nodeVersion: string;
  platform: string;
  durationMs: number;
  results: ProbeItem[];
  failures: ProbeItem[];
  skipped: string[];
  /** Properties of the environment the probe observed, shown by `starclaw doctor`. */
  notes: string[];
}

const cache = new Map<string, Promise<ProbeReport>>();

/**
 * Fail-closed capability probe. It runs a program that attempts every forbidden operation THROUGH THE SAME
 * ProcessSandbox code path that generated code uses, then checks both the error the child saw and the
 * side effects the parent can observe independently (marker files, listener hits, a live victim process).
 * If any attempt is not denied, or if the sandbox cannot even do the allowed work, the report is not ok and
 * the sandbox refuses to execute generated code.
 */
export function probeSandbox(make: (o: Partial<SandboxOptions>) => ProcessSandbox, base: SandboxOptions): Promise<ProbeReport> {
  const key = [process.version, process.execPath, !!base._unsafeDirectWorkspaceAccess, !!base._unsafeDisablePermissionModel, !!base._unsafeSkipHardening, base.memoryMb ?? 256].join('|');
  let p = cache.get(key);
  if (!p) {
    p = runProbe(make);
    cache.set(key, p);
  }
  return p;
}

async function runProbe(make: (o: Partial<SandboxOptions>) => ProcessSandbox): Promise<ProbeReport> {
  const started = Date.now();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'starclaw-probe-'));
  const ws = path.join(tmp, 'ws');
  const outside = path.join(tmp, 'outside');
  fs.mkdirSync(ws);
  fs.mkdirSync(outside);
  const secretPath = path.join(outside, 'secret.txt');
  fs.writeFileSync(secretPath, 'TOP-SECRET-CANARY');
  fs.writeFileSync(path.join(ws, 'inside.txt'), 'inside');
  const skipped: string[] = [];
  const notes: string[] = [];
  const results: ProbeItem[] = [];

  let junctionOk = false;
  try {
    fs.symlinkSync(outside, path.join(ws, 'jn'), 'junction');
    junctionOk = true;
  } catch (e: any) {
    skipped.push(`symlink/junction traversal not testable here: ${e.code ?? e.message}`);
  }

  // Independent observers of network side effects.
  let tcpHits = 0;
  let udpHits = 0;
  const tcp = net.createServer((s) => {
    tcpHits++;
    s.destroy();
  });
  const udp = dgram.createSocket('udp4');
  udp.on('message', () => udpHits++);
  await new Promise<void>((r) => tcp.listen(0, '127.0.0.1', r));
  await new Promise<void>((r) => udp.bind(0, '127.0.0.1', r));
  const tcpPort = (tcp.address() as net.AddressInfo).port;
  const udpPort = udp.address().port;

  // A live victim process the child must not be able to signal.
  // The victim also reports (via a marker file) if anything switches on its inspector, which process._debugProcess() can do.
  const inspectorMarker = path.join(tmp, 'marker-inspector.txt');
  const victim = spawn(
    process.execPath,
    ['-e', `setTimeout(()=>process.exit(0),120000); setInterval(()=>{ if (require('inspector').url()) { require('fs').writeFileSync(${JSON.stringify(inspectorMarker)}, 'x'); process.exit(0); } }, 50)`],
    { stdio: 'ignore', windowsHide: true },
  );
  await new Promise((r) => setTimeout(r, 150));

  const prevCanary = process.env.STARCLAW_PROBE_ENV_CANARY;
  process.env.STARCLAW_PROBE_ENV_CANARY = 'must-not-leak';

  const P = (s: string) => JSON.stringify(s);
  const markers = {
    cp: path.join(tmp, 'marker-cp.txt'),
    cpImport: path.join(tmp, 'marker-cp-import.txt'),
    cpFn: path.join(tmp, 'marker-cp-fn.txt'),
    cpEval: path.join(tmp, 'marker-cp-eval.txt'),
    worker: path.join(tmp, 'marker-worker.txt'),
    inspectorOnVictim: inspectorMarker,
    outWrite: path.join(outside, 'pwned.txt'),
    outWriteRel: path.join(tmp, 'pwned-rel.txt'),
    jnWrite: path.join(outside, 'pwned-via-junction.txt'),
  };
  const writer = (m: string) => `require('fs').writeFileSync(${P(m)},'x')`;

  const program = `
const DENIED = new Set(['ERR_ACCESS_DENIED','ERR_DLOPEN_DISABLED']);
const results = {};
async function att(name, fn, alsoOk) {
  try { const r = await fn(); results[name] = { outcome: 'allowed', detail: String(r).slice(0, 100) }; }
  catch (e) {
    const code = String((e && (e.code || (e.cause && e.cause.code))) || (e && e.name));
    results[name] = { outcome: (DENIED.has(code) || (alsoOk || []).includes(code)) ? 'denied' : 'other', detail: code + ': ' + String(e && e.message).slice(0, 140) };
  }
}
const sink = (res, rej) => ({ res, rej });
async function execute() {
  const fs = require('fs'), path = require('path');
  await att('child_process.execFileSync', () => require('child_process').execFileSync(process.execPath, ['-e', ${P(writer(markers.cp))}]));
  await att('child_process.spawn', () => new Promise((res, rej) => { const c = require('child_process').spawn(process.execPath, ['-e', ${P(writer(markers.cp))}]); c.on('error', rej); c.on('exit', () => res('spawned')); }));
  await att('child_process.import()', async () => { const m = await import('node:child_process'); return m.execFileSync(process.execPath, ['-e', ${P(writer(markers.cpImport))}]); }, ['ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING']);
  await att('child_process.via Function+mainModule', () => new Function("return process.mainModule.require('child_process').execFileSync(process.execPath, ['-e', " + JSON.stringify(${P(writer(markers.cpFn))}) + "])")());
  await att('child_process.via eval', () => eval("require('child_process').execFileSync(process.execPath, ['-e', " + JSON.stringify(${P(writer(markers.cpEval))}) + "])"));
  await att('process.binding(spawn_sync)', () => process.binding('spawn_sync'));
  await att('worker_threads', () => new Promise((res, rej) => { const { Worker } = require('worker_threads'); const w = new Worker(${P(writer(markers.worker))}, { eval: true }); w.on('error', rej); w.on('exit', () => res('worker ran')); }));
  await att('native addon (process.dlopen)', () => process.dlopen({ exports: {} }, path.join(process.execPath)));
  await att('wasi', () => { const { WASI } = require('wasi'); return new WASI({ version: 'preview1' }) && 'constructed'; });
  await att('net.connect tcp', () => new Promise((res, rej) => { const s = require('net').connect(${tcpPort}, '127.0.0.1'); s.on('error', rej); s.on('connect', () => { s.destroy(); res('connected'); }); setTimeout(() => res('no error within 2s'), 2000); }));
  await att('http.get', () => new Promise((res, rej) => { const r = require('http').get('http://127.0.0.1:${tcpPort}/', () => res('response')); r.on('error', rej); setTimeout(() => res('no error within 2s'), 2000); }));
  await att('fetch', async () => { const r = await fetch('http://127.0.0.1:${tcpPort}/'); return r.status; });
  await att('dns.lookup', () => new Promise((res, rej) => require('dns').lookup('localhost', (e, a) => e ? rej(e) : res(a))));
  await att('dgram.send', () => new Promise((res, rej) => { const s = require('dgram').createSocket('udp4'); s.on('error', rej); s.send('x', ${udpPort}, '127.0.0.1', (e) => e ? rej(e) : res('sent')); setTimeout(() => res('no error within 2s'), 2000); }));
  await att('fs.read outside workspace', () => fs.readFileSync(${P(secretPath)}, 'utf8'));
  await att('fs.read via ../ traversal', () => fs.readFileSync(path.join(process.cwd(), '..', 'outside', 'secret.txt'), 'utf8'));
  await att('fs.write outside workspace', () => fs.writeFileSync(${P(markers.outWrite)}, 'x'));
  await att('fs.write via ../ traversal', () => fs.writeFileSync(path.join(process.cwd(), '..', 'pwned-rel.txt'), 'x'));
  await att('fs.read C:\\\\ system file / /etc/hostname', () => fs.readFileSync(process.platform === 'win32' ? 'C:\\\\Windows\\\\win.ini' : '/etc/hostname', 'utf8'));
  await att('fs.symlink creation', () => fs.symlinkSync(${P(outside)}, path.join(process.cwd(), 'newlink'), 'junction'));
${junctionOk ? `  await att('fs.read through junction to outside', () => fs.readFileSync(path.join(process.cwd(), 'jn', 'secret.txt'), 'utf8'));
  await att('fs.write through junction to outside', () => fs.writeFileSync(path.join(process.cwd(), 'jn', 'pwned-via-junction.txt'), 'x'));` : ''}
  await att('process.kill(victim)', () => process.kill(${victim.pid}));
  await att('process._kill(victim)', () => process._kill(${victim.pid}, 15));
  await att('process._debugProcess(victim)', () => process._debugProcess(${victim.pid}));
  await att('inspector.open', () => require('inspector').open(0));
  const envKeys = Object.keys(process.env);
  results['env scrubbed'] = { outcome: envKeys.some((k) => k === 'STARCLAW_PROBE_ENV_CANARY' || /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(k)) ? 'allowed' : 'denied', detail: 'env keys: ' + envKeys.join(',') };
  const pong = await tools.readFile({ path: 'ping' });
  results['broker roundtrip works'] = { outcome: pong === 'pong' ? 'denied' : 'allowed', detail: String(pong) };
  return results;
}
module.exports = { execute };
`;

  let report: ProbeReport;
  try {
    const sb = make({ workspaceDir: ws, timeoutMs: 45_000, maxBrokerCalls: 5, maxOutputBytes: 64_000, toolNames: ['readFile'] });
    const run = await sb.runUnchecked(program, async (c) => (c.name === 'readFile' ? 'pong' : undefined));
    // Only meaningful if the sandbox actually produced a result.
    if (!run.ok || typeof run.value !== 'object' || run.value === null) {
      results.push({ name: 'probe program ran', denied: false, detail: `probe program failed: ${run.error ?? 'no result'} | stderr: ${run.stderr.slice(0, 300)}` });
    } else {
      for (const [name, v] of Object.entries(run.value as Record<string, { outcome: string; detail: string }>)) {
        results.push({ name, denied: v.outcome === 'denied', detail: `${v.outcome}: ${v.detail}` });
      }
    }
    // Independent side-effect checks (the parent trusts these more than the child's own report).
    const side = (name: string, bad: boolean, detail: string) => results.push({ name: `side effect: ${name}`, denied: !bad, detail });
    for (const [k, p] of Object.entries(markers)) side(`${k} file not created`, fs.existsSync(p), fs.existsSync(p) ? `CREATED ${p}` : 'absent');
    side('outside secret unchanged', fs.readFileSync(secretPath, 'utf8') !== 'TOP-SECRET-CANARY', 'checked contents');
    side('no new link created', fs.existsSync(path.join(ws, 'newlink')), 'checked');
    side('tcp listener saw no connection', tcpHits > 0, `hits=${tcpHits}`);
    side('udp listener saw no datagram', udpHits > 0, `hits=${udpHits}`);
    let alive = true;
    try {
      process.kill(victim.pid!, 0);
    } catch {
      alive = false;
    }
    side('victim process still alive', !alive, alive ? 'alive' : 'KILLED by sandboxed code');

    const failures = results.filter((r) => !r.denied);
    notes.push(`runner argv: node ${sbArgs(sb)}`);
    report = {
      ok: failures.length === 0,
      nodeVersion: process.version,
      platform: `${process.platform}-${process.arch}`,
      durationMs: Date.now() - started,
      results,
      failures,
      skipped,
      notes,
    };
  } catch (e: any) {
    const f = { name: 'probe infrastructure', denied: false, detail: String(e?.message ?? e) };
    report = { ok: false, nodeVersion: process.version, platform: `${process.platform}-${process.arch}`, durationMs: Date.now() - started, results: [f], failures: [f], skipped, notes };
  } finally {
    if (prevCanary === undefined) delete process.env.STARCLAW_PROBE_ENV_CANARY;
    else process.env.STARCLAW_PROBE_ENV_CANARY = prevCanary;
    try {
      victim.kill();
    } catch {
      /* already gone */
    }
    tcp.close();
    udp.close();
    try {
      const jn = path.join(ws, 'jn');
      if (fs.existsSync(jn)) {
        try {
          fs.unlinkSync(jn);
        } catch {
          fs.rmdirSync(jn);
        }
      } // removes the junction itself, never its target
    } catch {
      /* ignore */
    }
    try {
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
  return report;
}

function sbArgs(sb: ProcessSandbox): string {
  return sb.buildArgs().map((a) => (a.length > 80 ? '...' + a.slice(-60) : a)).join(' ');
}
