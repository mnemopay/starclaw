import * as dgram from 'node:dgram';
import * as fs from 'node:fs';
import * as net from 'node:net';
import type { ContainerOptions, ContainerSandbox } from './ContainerSandbox';
import { dockerExec, sha256File } from './ContainerSandbox';
import { NAME_PREFIX } from './containerArgs';
import type { ProbeItem, ProbeReport } from './probe';

const cache = new Map<string, Promise<ProbeReport>>();

/**
 * Fail-closed probe of the CONTAINER layer. Two kinds of evidence:
 *  - the child's own report of what it can/cannot do (container-layer-only run: Node's permission model and the
 *    JS hardening are switched OFF so the container is the only barrier being measured), and
 *  - side effects observed from the host: a TCP and a UDP listener that must see nothing, no leftover
 *    labelled containers, and the exit status of deliberately abusive runs (memory bomb, fork bomb).
 * A second run through the normal path (container + permission model) checks that the layers stack.
 */
export type ProbePart = 'layer' | 'memory' | 'pids' | 'stack';
export const ALL_PARTS: ProbePart[] = ['layer', 'memory', 'pids', 'stack'];

export function probeContainer(sb: ContainerSandbox, parts: ProbePart[] = ALL_PARTS): Promise<ProbeReport> {
  const o = sb.options;
  const key = JSON.stringify([o.image, o.memoryMb, o.pidsLimit, o.runtime, o._unsafe, !!o._unsafeNoNonce, sb.docker, safeHash(sb.runnerPath), parts]);
  let p = cache.get(key);
  if (!p) {
    p = runProbe(sb, parts);
    cache.set(key, p);
  }
  return p;
}

function safeHash(p: string): string {
  try {
    return sha256File(p);
  } catch {
    return 'missing';
  }
}

const PROGRAM_LAYER = String.raw`
const fs = require('fs'), cp = require('child_process'), os = require('os'), net = require('net'), dns = require('dns'), dgram = require('dgram');
const R = {};
const rec = (n, ok, d) => { R[n] = { ok: !!ok, detail: String(d).slice(0, 220) }; };
const tryf = (f) => { try { return { v: f() }; } catch (e) { return { e }; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function execute() {
  const status = fs.readFileSync('/proc/self/status', 'utf8');
  const g = (k) => ((new RegExp('^' + k + ':\\s*(.*)$', 'm')).exec(status) || [])[1];
  rec('uid and gid are 65534 (not root)', process.getuid() === 65534 && process.getgid() === 65534, process.getuid() + ':' + process.getgid());
  for (const k of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) rec('capabilities: ' + k + ' is all zero', /^0+$/.test(g(k) || 'x'), k + '=' + g(k));
  rec('NoNewPrivs is 1', g('NoNewPrivs') === '1', 'NoNewPrivs=' + g('NoNewPrivs'));
  rec('seccomp filter active (Seccomp: 2)', g('Seccomp') === '2', 'Seccomp=' + g('Seccomp'));

  const mi = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').filter(Boolean).map((l) => { const p = l.split(' '); return { mp: p[4], opts: p[5].split(',') }; });
  const root = mi.find((m) => m.mp === '/');
  rec('root filesystem is mounted read-only', root && root.opts.includes('ro'), JSON.stringify(root));
  const tmp = mi.find((m) => m.mp === '/tmp');
  rec('/tmp is a tmpfs mounted noexec,nosuid', tmp && tmp.opts.includes('noexec') && tmp.opts.includes('nosuid'), JSON.stringify(tmp));
  for (const p of ['/probe-write', '/etc/probe-write', '/usr/probe-write', '/sandbox/probe-write', '/sandbox/runner.cjs']) {
    const r = tryf(() => fs.writeFileSync(p, 'x'));
    rec('cannot write ' + p, !!r.e, r.e ? r.e.code : 'WROTE');
  }
  const ex = tryf(() => { fs.writeFileSync('/tmp/x.sh', '#!/bin/sh\necho EXECUTED\n', { mode: 0o755 }); return cp.execFileSync('/tmp/x.sh', { encoding: 'utf8' }); });
  rec('cannot execute a file from /tmp (noexec)', !(ex.v && String(ex.v).includes('EXECUTED')), ex.e ? ex.e.code || ex.e.message : 'EXECUTED');
  const big = tryf(() => fs.writeFileSync('/tmp/big', Buffer.alloc(20 << 20)));
  rec('/tmp is size-limited (16 MB)', !!big.e && big.e.code === 'ENOSPC', big.e ? big.e.code : 'WROTE 20MB');

  rec('only the loopback interface exists', Object.keys(os.networkInterfaces()).every((k) => k === 'lo'), Object.keys(os.networkInterfaces()).join(','));
  const hosts = ['host.docker.internal', '172.17.0.1', '10.0.2.2', '192.168.65.254', 'gateway.docker.internal'];
  const conn = (h, p) => new Promise((res) => { const s = net.connect({ host: h, port: p, timeout: 2500 }); s.on('connect', () => { s.destroy(); res('CONNECTED'); }); s.on('error', (e) => res(e.code || e.message)); s.on('timeout', () => { s.destroy(); res('TIMEOUT'); }); });
  const outs = await Promise.all(hosts.map((h) => conn(h, __TCP__)));
  rec('cannot connect to the host TCP listener', outs.every((o) => o !== 'CONNECTED'), hosts.map((h, i) => h + '=' + outs[i]).join(' '));
  const net1 = await conn('1.1.1.1', 443);
  rec('cannot reach the internet by IP', net1 !== 'CONNECTED', '1.1.1.1:443=' + net1);
  for (const h of ['example.com', 'host.docker.internal']) {
    const r = await new Promise((res) => dns.lookup(h, (e, a) => res(e ? e.code : 'RESOLVED ' + a)));
    rec('DNS cannot resolve ' + h, String(r).startsWith('E'), r);
  }
  const udp = await new Promise((res) => { const s = dgram.createSocket('udp4'); s.on('error', (e) => res(e.code)); s.send('x', __UDP__, 'host.docker.internal', (e) => { s.close(); res(e ? e.code : 'SENT'); }); setTimeout(() => res('TIMEOUT'), 2500); });
  rec('cannot send UDP to the host', udp !== 'SENT', 'udp=' + udp);

  rec('no host drive visible (/mnt/c, /mnt/wsl, /host)', !['/mnt/c', '/mnt/wsl', '/host', '/Users', '/c'].some((p) => fs.existsSync(p)), 'checked');
  rec('no docker socket visible', !['/var/run/docker.sock', '/run/docker.sock'].some((p) => fs.existsSync(p)), 'checked');
  const envKeys = Object.keys(process.env);
  rec('no host environment passed through', !envKeys.some((k) => k === 'STARCLAW_PROBE_ENV_CANARY' || /KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL/i.test(k)), envKeys.join(','));

  const k1 = tryf(() => process.kill(1, 'SIGKILL'));
  await sleep(300);
  rec('process.kill(1) does not stop or escape the container', true, k1.e ? k1.e.code : 'signal sent; still running');

  const nr = process.arch === 'arm64' ? { mount: 40, unshare: 97, ptrace: 117 } : { mount: 165, unshare: 272, ptrace: 101 };
  const sys = (label, code) => {
    const r = tryf(() => cp.execFileSync('perl', ['-e', code], { encoding: 'utf8' }));
    rec(label, r.v !== undefined && String(r.v).startsWith('ERR'), r.v !== undefined ? r.v : 'perl failed: ' + r.e.message);
  };
  sys('mount(2) is denied', 'my ($a, $b, $c) = ("none", "/tmp", "tmpfs"); my $r = syscall(' + nr.mount + ', $a, $b, $c, 0, 0); print(($r == -1) ? "ERR " . ($!+0) : "OK $r")');
  sys('unshare(CLONE_NEWUSER) is denied', 'my $r = syscall(' + nr.unshare + ', 0x10000000); print(($r == -1) ? "ERR " . ($!+0) : "OK $r")');
  sys('ptrace(ATTACH, pid 1) is denied', 'my $r = syscall(' + nr.ptrace + ', 16, 1, 0, 0); print(($r == -1) ? "ERR " . ($!+0) : "OK $r")');
  return R;
}
module.exports = { execute };
`;

const PROGRAM_MEMORY = String.raw`
async function execute() {
  const hold = []; let mb = 0;
  while (mb < 400) { hold.push(Buffer.alloc(8 << 20, 1)); mb += 8; }
  return 'SURVIVED ' + mb + 'MB';
}
module.exports = { execute };
`;

const PROGRAM_PIDS = String.raw`
const cp = require('child_process');
async function execute() {
  let ok = 0, failed = 0;
  for (let i = 0; i < 160; i++) {
    const c = cp.spawn('sleep', ['5'], { stdio: 'ignore' });
    c.on('error', () => {});
    await new Promise((r) => setImmediate(r));
    if (c.pid) ok++; else failed++;
  }
  return { ok, failed };
}
module.exports = { execute };
`;

const PROGRAM_STACK = String.raw`
const R = {};
async function att(name, fn) {
  try { const r = await fn(); R[name] = { ok: false, detail: 'ALLOWED ' + String(r).slice(0, 80) }; }
  catch (e) { const c = String(e && (e.code || (e.cause && e.cause.code)) || e.name); R[name] = { ok: c === 'ERR_ACCESS_DENIED', detail: c }; }
}
async function execute() {
  await att('stack: child_process denied by the permission model', () => require('child_process').execFileSync('/bin/echo', ['x']));
  await att('stack: raw socket denied by the permission model', () => new Promise((res, rej) => { const s = require('net').connect(80, '1.1.1.1'); s.on('error', rej); s.on('connect', res); }));
  await att('stack: fs read denied by the permission model', () => require('fs').readFileSync('/etc/passwd', 'utf8'));
  await att('stack: fs write denied by the permission model', () => require('fs').writeFileSync('/tmp/stack-write', 'x'));
  await att('stack: process.kill(1) disabled by runner hardening', () => process.kill(1));
  const pong = await tools.readFile({ path: 'ping' });
  R['stack: broker round trip works over stdio'] = { ok: pong === 'pong', detail: String(pong) };
  return R;
}
module.exports = { execute };
`;

async function runProbe(sb: ContainerSandbox, parts: ProbePart[]): Promise<ProbeReport> {
  const started = Date.now();
  const o = sb.options;
  const results: ProbeItem[] = [];
  const notes: string[] = [];
  const add = (name: string, ok: boolean, detail: string) => results.push({ name, denied: ok, detail });
  const finish = (): ProbeReport => {
    const failures = results.filter((r) => !r.denied);
    return { ok: failures.length === 0, nodeVersion: process.version, platform: `${process.platform}-${process.arch}`, durationMs: Date.now() - started, results, failures, skipped: [], notes, layer: 'container' };
  };

  // 0. Docker reachable, image present and matching this package's runner.
  const ver = await dockerExec(sb.docker, ['version', '--format', '{{.Server.Version}}'], 15_000);
  if (ver.code !== 0) {
    add('docker daemon reachable', false, `docker not usable: ${(ver.stderr || ver.stdout).trim().slice(0, 200) || 'no output'}`);
    return finish();
  }
  notes.push(`docker server ${ver.stdout.trim()}`);
  add('docker daemon reachable', true, ver.stdout.trim());
  const img = await dockerExec(sb.docker, ['image', 'inspect', '--format', '{{.Id}}|{{ index .Config.Labels "starclaw.runner.sha256" }}', o.image], 15_000);
  if (img.code !== 0) {
    add('sandbox image present', false, `image ${o.image} not found: run "starclaw sandbox build"`);
    return finish();
  }
  const [imageId, label] = img.stdout.trim().split('|');
  const want = safeHash(sb.runnerPath);
  add('sandbox image matches this package\'s runner (sha256 label)', label === want, `image ${imageId.slice(0, 19)} label=${(label || '').slice(0, 12)} runner=${want.slice(0, 12)}`);
  if (label !== want) return finish();

  // Host-side observers.
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
  const prev = process.env.STARCLAW_PROBE_ENV_CANARY;
  process.env.STARCLAW_PROBE_ENV_CANARY = 'must-not-leak';

  const variant = (extra: Partial<ContainerOptions>) => new (sb.constructor as new (o: ContainerOptions) => ContainerSandbox)({ ...o, ...extra, timeoutMs: 40_000, maxBrokerCalls: 5, maxOutputBytes: 64_000, toolNames: ['readFile'] });
  const importResults = (r: Record<string, { ok: boolean; detail: string }>) => {
    for (const [name, v] of Object.entries(r)) add(name, v.ok, v.detail);
  };
  try {
    // A. container layer alone
    const layer = variant({ _layerOnly: true });
    notes.push(`container args: docker ${layer.buildArgs('NAME').join(' ')}`);
    if (parts.includes('layer')) {
    const a = await layer.runUnchecked(PROGRAM_LAYER.replace('__TCP__', String(tcpPort)).replace('__UDP__', String(udpPort)), async () => undefined);
    if (!a.ok || typeof a.value !== 'object' || a.value === null) add('container-layer probe program ran', false, `${a.error ?? 'no result'} | stderr: ${a.stderr.slice(0, 300)}`);
    else importResults(a.value as any);
    add('host TCP listener saw no connection from the container', tcpHits === 0, `hits=${tcpHits}`);
    add('host UDP listener saw no datagram from the container', udpHits === 0, `hits=${udpHits}`);
    }

    // B. memory bomb: must be killed by the cgroup limit, host unaffected
    if (parts.includes('memory')) {
    const b = await variant({ _layerOnly: true }).runUnchecked(PROGRAM_MEMORY, async () => undefined);
    add(`memory limit enforced (${o._unsafe?.memoryMb ?? o.memoryMb ?? 256} MB): allocation bomb is OOM-killed`, !b.ok && b.exitCode === 137, b.ok ? `SURVIVED: ${JSON.stringify(b.value)}` : `exit=${b.exitCode} ${b.error ?? ''}`.slice(0, 160));

    }
    // C. fork bomb: capped by --pids-limit
    if (parts.includes('pids')) {
    const c = await variant({ _layerOnly: true }).runUnchecked(PROGRAM_PIDS, async () => undefined);
    const cv = c.value as { ok: number; failed: number } | undefined;
    add('pids limit enforced: fork bomb is capped', !!cv && cv.failed > 0 && cv.ok < 100, cv ? `spawned ${cv.ok}, refused ${cv.failed}` : `no result: ${c.error}`);

    }
    // D. normal stack
    // (container + permission model + hardening, through the real stdio frame protocol)
    if (parts.includes('stack')) {
    const d = await variant({}).runUnchecked(PROGRAM_STACK, async (call) => (call.name === 'readFile' ? 'pong' : undefined));
    if (!d.ok || typeof d.value !== 'object' || d.value === null) add('full-stack probe program ran', false, `${d.error ?? 'no result'} | stderr: ${d.stderr.slice(0, 300)}`);
    else importResults(d.value as any);
    }

    // Host-side: nothing left behind, host process fine.
    const left = await dockerExec(sb.docker, ['ps', '-a', '-q', '--filter', 'label=starclaw.sandbox=1', '--filter', `name=${NAME_PREFIX}`], 15_000);
    add('no sandbox containers left running or stopped on the host', left.code === 0 && left.stdout.trim() === '', left.stdout.trim() || 'none');
  } catch (e: any) {
    add('probe infrastructure', false, String(e?.message ?? e));
  } finally {
    if (prev === undefined) delete process.env.STARCLAW_PROBE_ENV_CANARY;
    else process.env.STARCLAW_PROBE_ENV_CANARY = prev;
    tcp.close();
    udp.close();
  }
  return finish();
}

export function summarizeProbe(r: ProbeReport): string {
  return `${r.results.length - r.failures.length}/${r.results.length} checks passed in ${r.durationMs} ms`;
}

// Silence unused import in builds that tree-shake: fs is used by safeHash via sha256File.
void fs;
