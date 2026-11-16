/**
 * Shell container tests (tools.shell) and the bind-mount/junction experiment that decided the design.
 * They need a running Docker daemon, the shell image (starclaw shell build) and alpine:3.20 (for the experiment);
 * without them they SKIP with an explicit message. One container at a time. Only containers created here are
 * touched: the shell runner's own (label starclaw.shell=1, name starclaw-sh-*) and the experiment's
 * (--rm, label starclaw.test=1, name starclaw-test-*).
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Broker } from '../src/broker';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { GovernorDenied } from '../src/governance/types';
import { dockerExec } from '../src/sandbox/ContainerSandbox';
import { findForbiddenDockerFlags } from '../src/sandbox/containerArgs';
import { ShellRunner } from '../src/shell/ShellRunner';
import type { UnsafeShellSwitches } from '../src/shell/shellArgs';
import { buildShellImage, cleanShellContainers, listShellContainers, shellImageStatus } from '../src/shell/shellImage';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

function dockerUsable(): string | undefined {
  try {
    execFileSync('docker', ['version', '--format', '{{.Server.Version}}'], { stdio: 'pipe', timeout: 20_000 });
    return undefined;
  } catch (e: any) {
    return `docker is not usable (${String(e.message).split('\n')[0]})`;
  }
}
const skipReason = dockerUsable();
if (skipReason) console.log(`SKIPPING shell container tests: ${skipReason}`);

const hasImage = (ref: string) => {
  try {
    execFileSync('docker', ['image', 'inspect', ref], { stdio: 'pipe', timeout: 20_000 });
    return true;
  } catch {
    return false;
  }
};

/** A junction (Windows) or directory symlink (elsewhere) at `link` pointing to `target`. */
function makeDirLink(target: string, link: string) {
  fs.symlinkSync(target, link, 'junction');
}

describe('bind mount vs. junction/symlink (the experiment behind the copy-in/copy-out design)', { skip: skipReason ?? (hasImage('alpine:3.20') ? undefined : 'alpine:3.20 is not present locally') }, () => {
  let dir: string, ws: string, outside: string;
  before(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    outside = path.join(dir, 'outside');
    fs.mkdirSync(ws, { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'SECRET-OUTSIDE-WORKSPACE');
    fs.writeFileSync(path.join(ws, 'ok.txt'), 'inside');
    fs.mkdirSync(path.join(ws, '.git'));
    makeDirLink(outside, path.join(ws, 'jct'));
  });
  after(() => rm(dir));

  const runAlpine = (script: string) =>
    dockerExec('docker', ['run', '--rm', '--label', 'starclaw.test=1', '--name', `starclaw-test-${Date.now()}`, '--network', 'none', '--pull', 'never', '-v', `${ws}:/ws`, 'alpine:3.20', 'sh', '-c', script], 60_000);

  test('CONTROL: the bind mount works (the container reads a plain workspace file), so the negative results below are meaningful', async () => {
    const r = await runAlpine('cat /ws/ok.txt');
    assert.equal(r.stdout.trim(), 'inside', r.stderr);
  });

  test('FINDING 1 (Docker Desktop/WSL2, observed): a host junction/symlink inside the mount is NOT followable from the container', async () => {
    const r = await runAlpine('ls /ws/jct/ 2>&1; cat /ws/jct/secret.txt 2>&1; echo rc=$?');
    assert.ok(!r.stdout.includes('SECRET-OUTSIDE-WORKSPACE'), `a junction leaked a file outside the workspace through the bind mount: ${r.stdout}`);
    // Informational: the link is exposed to the container as a symlink with a translated path.
    const listing = (await runAlpine('ls -l /ws/jct')).stdout;
    assert.match(listing, /jct ->|^l/m, `junction not listed as a link: ${listing}`);
  });

  test('FINDING 2: even so, a bind mount is unsafe: the container writes .env and .git directly (no broker, no hard rules) and plants symlinks that appear on the HOST', async () => {
    const r = await runAlpine('echo pwn > /ws/.env; echo pwn > /ws/.git/hook; ln -s /etc/passwd /ws/evil; echo done');
    assert.equal(r.code, 0, r.stderr);
    assert.equal(fs.existsSync(path.join(ws, '.env')), true, 'container could not write .env (unexpected: re-check the design note)');
    assert.equal(fs.existsSync(path.join(ws, '.git', 'hook')), true);
    // The link appears in the host directory. On Windows it is a WSL-style reparse point that Node cannot even lstat (EACCES):
    // an entry the host cannot classify, which is exactly what the copy-in staging skips ("cannot be inspected").
    let lstat = 'ok';
    let isLink = false;
    try {
      isLink = fs.lstatSync(path.join(ws, 'evil')).isSymbolicLink();
    } catch (e: any) {
      lstat = e.code;
    }
    assert.ok(fs.readdirSync(ws).includes('evil'), 'a symlink created in the container did not appear on the host');
    assert.ok(isLink || lstat === 'EACCES', 'unexpected lstat result: ' + lstat);
    for (const f of ['.env', 'evil']) {
      try {
        fs.rmSync(path.join(ws, f), { force: true });
      } catch {
        /* best effort */
      }
    }
    fs.rmSync(path.join(ws, '.git', 'hook'), { force: true });
  });
});

describe('shell container (tools.shell)', { skip: skipReason }, () => {
  let dir: string, ws: string, state: string, outside: string;
  let approver: ScriptedApprover;
  let imageProblem: string | undefined;

  before(async () => {
    const st = await shellImageStatus();
    if (!st.imagePresent || !st.matches) {
      const rc = await buildShellImage();
      assert.equal(rc, 0, 'docker build of the shell image failed');
    }
    imageProblem = (await shellImageStatus()).matches ? undefined : 'shell image missing or stale';
    assert.equal(imageProblem, undefined);
  });
  after(async () => {
    assert.deepEqual(await listShellContainers(), [], 'tests left shell containers behind');
  });

  const setup = (policyOver: Record<string, unknown> = {}, unsafe?: UnsafeShellSwitches) => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    outside = path.join(dir, 'outside');
    for (const d of [ws, state, outside]) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'SECRET-OUTSIDE-WORKSPACE');
    approver = new ScriptedApprover(() => 'approve');
    const policy = policyWith({ rules: [{ class: 'shell.exec', verdict: 'allow' }, { class: 'fs.read', inWorkspace: true, verdict: 'allow' }], ...policyOver });
    const taint = new TaintTracker();
    const audit = new AuditLog(path.join(dir, 'audit.jsonl'), Ed25519Signer.generate());
    const gov = new Governor({ policy, audit, taint, approver });
    const wsReal = fs.realpathSync.native(ws);
    const stReal = fs.realpathSync.native(state);
    const shell = new ShellRunner({ workspace: wsReal, stateDir: stReal, policy: policy.shell, _unsafe: unsafe });
    const broker = new Broker({ governor: gov, workspaceDir: ws, stateDir: state, taintedFiles: new TaintedFileStore(path.join(state, 'tf.json')), shell });
    return { broker, gov, taint, shell, audit, policy, wsReal };
  };
  const sh = (b: Broker, command: string): Promise<any> => b.handle({ name: 'shell', args: { command } });
  const cleanup = async () => {
    assert.deepEqual(await listShellContainers(), [], 'a shell container outlived its command');
    rm(dir);
  };

  test('the docker argv carries every protection and no forbidden flag', () => {
    const { shell } = setup();
    const args = shell.buildArgs();
    assert.deepEqual(findForbiddenDockerFlags(args), []);
    assert.ok(!args.includes('-v') && !args.includes('--mount'), 'the shell container must never get a host mount');
    assert.ok(args.includes('--label') && args.includes('starclaw.shell=1'));
    rm(dir);
  });

  test('runs a command in the container, writes a new file back to the host, taints the session, and audits the plan BEFORE applying it', async () => {
    const { broker, taint, wsReal } = setup();
    fs.writeFileSync(path.join(ws, 'in.txt'), 'hello');
    const r = await sh(broker, 'cat in.txt && echo made > out.txt && mkdir sub && echo x > sub/y.txt && uname -s && id -u');
    assert.equal(r.exitCode, 0, r.stderr);
    assert.match(r.stdout, /hello/);
    assert.match(r.stdout, /Linux/);
    assert.match(r.stdout, /65534/, 'must run as the unprivileged uid');
    assert.equal(fs.readFileSync(path.join(wsReal, 'out.txt'), 'utf8').trim(), 'made');
    assert.equal(fs.readFileSync(path.join(wsReal, 'sub', 'y.txt'), 'utf8').trim(), 'x');
    assert.deepEqual(r.changes.written.sort(), ['out.txt', 'sub/y.txt']);
    assert.equal(taint.tainted, true, 'container output must taint the session');
    // Audit ordering: decision.request < shell.writeback.plan < action.result.
    const kinds = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l).type ?? JSON.parse(l).event ?? JSON.parse(l).kind);
    const iReq = kinds.indexOf('decision.request');
    const iPlan = kinds.indexOf('shell.writeback.plan');
    const iRes = kinds.indexOf('action.result');
    assert.ok(iReq >= 0 && iPlan > iReq && iRes > iPlan, `audit order wrong: ${kinds.join(',')}`);
    await cleanup();
  });

  test('no network, no host environment, read-only root, no mounts, no docker socket', async () => {
    process.env.SC_SENTINEL_SECRET = 'HOST-ENV-SENTINEL-12345';
    try {
      const { broker } = setup();
      const r = await sh(
        broker,
        [
          'ls /sys/class/net | tr "\\n" " "; echo',
          'env | grep -c SENTINEL || true',
          'python3 -c "import socket; socket.create_connection((\'1.1.1.1\', 53), 3)" >/dev/null 2>&1 && echo NET-OPEN || echo NET-CLOSED',
          'touch /etc/probe 2>/dev/null && echo ROOT-WRITABLE || echo ROOT-RO',
          'ls /var/run/docker.sock 2>/dev/null && echo SOCK || echo NOSOCK',
          'ls /host-mnt /mnt/host 2>/dev/null && echo MOUNT || echo NOMOUNT',
          'grep -E "^(CapEff|NoNewPrivs)" /proc/self/status',
        ].join('; '),
      );
      assert.match(r.stdout, /^lo\s*$/m, `unexpected interfaces: ${r.stdout}`);
      assert.match(r.stdout, /^0$/m, 'the host environment leaked into the container');
      assert.match(r.stdout, /NET-CLOSED/);
      assert.match(r.stdout, /ROOT-RO/);
      assert.match(r.stdout, /NOSOCK/);
      assert.match(r.stdout, /NOMOUNT/);
      assert.match(r.stdout, /CapEff:\s+0+$/m);
      assert.match(r.stdout, /NoNewPrivs:\s+1/);
      await cleanup();
    } finally {
      delete process.env.SC_SENTINEL_SECRET;
    }
  });

  test('a junction/symlink in the workspace is never copied or followed: the outside secret is unreachable, and the link is reported as skipped', async () => {
    const { broker } = setup();
    makeDirLink(outside, path.join(ws, 'jct'));
    fs.writeFileSync(path.join(ws, 'plain.txt'), 'p');
    const r = await sh(broker, 'ls -a; cat jct/secret.txt 2>&1; echo rc=$?; cat /mnt/host/c/secret.txt 2>&1 | head -1');
    assert.ok(!r.stdout.includes('SECRET-OUTSIDE-WORKSPACE'), `escape through a junction: ${r.stdout}`);
    assert.doesNotMatch(r.stdout, /^jct$/m, 'the link must not exist inside the container copy');
    assert.match(r.stdout, /plain\.txt/);
    assert.ok(r.skippedOnCopyIn >= 1);
    assert.equal(fs.existsSync(path.join(outside, 'secret.txt')), true, 'outside file must be untouched');
    await cleanup();
  });

  test('write-back refusals: symlinks, .env, .git and the state directory are never written to the host', async () => {
    const { broker, wsReal } = setup();
    fs.mkdirSync(path.join(ws, '.git'));
    const r = await sh(
      broker,
      'ln -s /etc/passwd evil; ln -s ../outside/secret.txt evil2; echo pwn > .env; echo pwn > .env.local; echo pwn > .git/config; mkdir -p .git/hooks && echo x > .git/hooks/pre-commit; echo ok > fine.txt',
    );
    assert.equal(r.exitCode, 0, r.stderr);
    for (const f of ['evil', 'evil2', '.env', '.env.local', '.git/config', '.git/hooks/pre-commit']) assert.equal(fs.existsSync(path.join(wsReal, ...f.split('/'))), false, `${f} reached the host`);
    assert.equal(fs.readFileSync(path.join(wsReal, 'fine.txt'), 'utf8').trim(), 'ok', 'a legitimate change in the same run must still apply');
    const refused = r.changes.refused.map((x: any) => x.path).sort();
    for (const f of ['evil', 'evil2']) assert.ok(refused.includes(f), `${f} not reported as refused: ${refused}`);
    assert.ok(refused.some((p: string) => p.startsWith('.env')), `.env not refused: ${refused}`);
    assert.ok(refused.some((p: string) => p.startsWith('.git')), `.git not refused: ${refused}`);
    await cleanup();
  });

  test('environment files and the state directory are not copied into the container', async () => {
    const { broker } = setup();
    fs.writeFileSync(path.join(ws, '.env'), 'API_KEY=very-secret');
    fs.mkdirSync(path.join(ws, 'nested'));
    fs.writeFileSync(path.join(ws, 'nested', '.env.production'), 'X=very-secret');
    const r = await sh(broker, 'ls -a; ls -a nested; grep -r very-secret . ; echo grep-rc=$?');
    assert.ok(!r.stdout.includes('very-secret'));
    assert.match(r.stdout, /grep-rc=1/);
    await cleanup();
  });

  test('a command that runs too long is killed, the container is destroyed and NOTHING is written back', async () => {
    const { broker, wsReal } = setup({ shell: { timeoutSeconds: 3 } });
    const r = await sh(broker, 'echo partial > partial.txt; sleep 60');
    assert.equal(r.timedOut, true);
    assert.equal(fs.existsSync(path.join(wsReal, 'partial.txt')), false);
    await cleanup();
  });

  test('output is capped', async () => {
    const { broker } = setup({ shell: { maxOutputBytes: 2048 } });
    const r = await sh(broker, 'yes AAAAAAAAAA | head -c 200000');
    assert.ok(r.stdout.length <= 2048);
    assert.equal(r.outputTruncated, true);
    await cleanup();
  });

  test('a host file edited while the command ran is a CONFLICT, not overwritten', async () => {
    const { broker, wsReal } = setup();
    fs.writeFileSync(path.join(ws, 'f.txt'), 'v1');
    // The command takes a moment; the host edit lands during it (the staging hash was taken before).
    const p = sh(broker, 'sleep 2; echo container > f.txt');
    await new Promise((r) => setTimeout(r, 1200));
    fs.writeFileSync(path.join(wsReal, 'f.txt'), 'host-edit');
    const r = await p;
    assert.equal(fs.readFileSync(path.join(wsReal, 'f.txt'), 'utf8'), 'host-edit');
    assert.deepEqual(r.changes.conflicts.map((c: any) => c.path), ['f.txt']);
    await cleanup();
  });

  test('a path that is a link on the host at write-back time is refused (race: a directory swapped for a junction)', async () => {
    const { broker, wsReal } = setup();
    fs.mkdirSync(path.join(ws, 'd'));
    // While the command runs, the host replaces the (empty) directory `d` with a junction to the outside.
    const p = sh(broker, 'sleep 2; echo gotcha > d/new.txt');
    await new Promise((r) => setTimeout(r, 1200));
    fs.rmSync(path.join(wsReal, 'd'), { recursive: true });
    makeDirLink(outside, path.join(wsReal, 'd'));
    const r = await p;
    assert.equal(fs.existsSync(path.join(outside, 'new.txt')), false, 'write-back followed a junction out of the workspace');
    assert.ok(r.changes.refused.some((x: any) => x.path === 'd/new.txt'), JSON.stringify(r.changes));
    await cleanup();
  });

  test('policy still applies: with shell.exec at ask and a denying human, no container is ever started', async () => {
    const { broker } = setup({ rules: [] });
    approver = new ScriptedApprover(() => 'deny');
    // rebuild with the deny approver
    const gov = (broker as any).o.governor as Governor;
    gov.setApprover(approver);
    await assert.rejects(() => sh(broker, 'echo hi > nope.txt'), GovernorDenied);
    assert.equal(fs.existsSync(path.join(ws, 'nope.txt')), false);
    assert.deepEqual(await listShellContainers(), []);
    rm(dir);
  });

  // CONTROLS: removing a protection must make the matching observation change, so the checks above can fail.
  test('CONTROL: with a host bind mount added, the command DOES read an outside file (proves the "no mounts" assertion can fail)', async () => {
    const s = setup();
    const unsafe = new ShellRunner({ workspace: s.wsReal, stateDir: fs.realpathSync.native(state), policy: s.policy.shell, _unsafe: { hostMount: outside } });
    const b = new Broker({ governor: s.gov, workspaceDir: ws, stateDir: state, taintedFiles: new TaintedFileStore(path.join(state, 'tf2.json')), shell: unsafe });
    const r = await sh(b, 'cat /host-mnt/secret.txt');
    assert.match(r.stdout, /SECRET-OUTSIDE-WORKSPACE/);
    assert.ok(findForbiddenDockerFlags(unsafe.buildArgs()).some((f) => f.reason === 'host mounts'), 'the forbidden-flag scan must flag the unsafe argv');
    await cleanup();
  });

  test('CONTROL: as root the command sees uid 0, and with the network switch it is no longer isolated (the checks above notice)', async () => {
    const s = setup({}, { root: true });
    const r = await sh(s.broker, 'id -u');
    assert.match(r.stdout, /^0$/m);
    await cleanup();
    const n = setup({}, { network: true });
    const r2 = await sh(n.broker, 'ls /sys/class/net | tr "\\n" " "');
    assert.ok(/eth0/.test(r2.stdout), `expected a non-loopback interface with the network switch, got: ${r2.stdout}`);
    await cleanup();
  });

  test('clean removes only labelled starclaw-sh- containers (nothing to remove when none exist)', async () => {
    assert.deepEqual(await cleanShellContainers(), []);
  });
});
