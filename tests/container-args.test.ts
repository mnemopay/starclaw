import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ContainerSandbox } from '../src/sandbox/ContainerSandbox';
import { buildDockerArgs, findForbiddenDockerFlags, UnsafeContainerSwitches } from '../src/sandbox/containerArgs';

const base = (unsafe?: UnsafeContainerSwitches, extra: Record<string, unknown> = {}) =>
  buildDockerArgs({ name: 'starclaw-sbx-test', image: 'starclaw-sandbox:x', memoryMb: 256, pidsLimit: 64, timeoutMs: 60_000, usePermissionModel: true, unsafe, ...extra } as any);

describe('docker argument builder', () => {
  test('contains every required protection, in the required form', () => {
    const a = base();
    const has = (...seq: string[]) => a.some((_, i) => seq.every((s, j) => a[i + j] === s));
    for (const seq of [
      ['--rm'], ['-i'], ['--init'], ['--read-only'], ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges'], ['--network', 'none'],
      ['--pids-limit', '64'], ['--memory', '256m'], ['--memory-swap', '256m'], ['--cpus', '1'], ['--user', '65534:65534'], ['--ipc', 'none'],
      ['--tmpfs', '/tmp:rw,noexec,nosuid,size=16m'], ['--label', 'starclaw.sandbox=1'], ['--name', 'starclaw-sbx-test'], ['--pull', 'never'],
    ]) assert.ok(has(...seq), `missing ${seq.join(' ')}`);
    assert.ok(a.includes('--permission'), 'Node permission model is kept inside the container as defence in depth');
    assert.equal(a.filter((x) => x === '--tmpfs').length, 1);
  });

  test('the default argument list is clean under the forbidden-flag scan', () => {
    assert.deepEqual(findForbiddenDockerFlags(base()), []);
    assert.deepEqual(findForbiddenDockerFlags(new ContainerSandbox({ image: 'x:y' }).buildArgs()), []);
  });

  test('no mounts, no env passthrough, no published ports, no host namespaces anywhere in the real argument list', () => {
    const a = base().join(' ');
    for (const bad of [/(^| )-v( |=)/, /--volume/, /--mount/, /(^| )-e( |=)/, /--env/, /--publish|(^| )-p( |=)/, /--pid( |=)/, /--privileged/, /--cap-add/, /--device/, /docker\.sock/, /--network host/, /--userns/, /--uts/]) assert.doesNotMatch(a, bad);
  });

  test('the container name is unique per run and the kill target is exactly that name', () => {
    const sb = new ContainerSandbox({ image: 'x:y' });
    const names = new Set([1, 2, 3, 4].map(() => sb.buildArgs().join(' ')));
    assert.equal(names.size, 1, 'buildArgs() is deterministic for a given name');
    const src = require('node:fs').readFileSync(require.resolve('../src/sandbox/ContainerSandbox.ts'), 'utf8');
    assert.match(src, /\['kill', name\]/);
    assert.doesNotMatch(src, /taskkill|pkill|killall|docker.*kill.*--filter|ancestor=/);
  });

  test('the timeout wrapper inside the container exceeds the host timeout (self-destruct if the host dies)', () => {
    const a = base(undefined, { timeoutMs: 30_000 });
    const i = a.indexOf('timeout');
    assert.deepEqual(a.slice(i, i + 4), ['timeout', '-s', 'KILL', '40']);
  });

  test('runtime passthrough is passed to docker verbatim when set (not claimed tested)', () => {
    const a = base(undefined, { runtime: 'runsc' });
    assert.deepEqual(a.slice(a.indexOf('--runtime'), a.indexOf('--runtime') + 2), ['--runtime', 'runsc']);
    assert.equal(base().includes('--runtime'), false);
  });
});

describe('forbidden-flag scanner', () => {
  const inject = (...extra: string[]) => {
    const a = base();
    a.splice(a.indexOf('starclaw-sandbox:x'), 0, ...extra);
    return findForbiddenDockerFlags(a);
  };

  test('CONTROL: the scanner catches every forbidden flag when it is injected', () => {
    const cases: Array<[string[], RegExp]> = [
      [['--privileged'], /privileged/],
      [['-v', 'C:\\Users:/host'], /host mounts/],
      [['--volume=/a:/b'], /host mounts/],
      [['--mount', 'type=bind,src=/a,dst=/b'], /host mounts/],
      [['--pid', 'host'], /pid namespace/],
      [['--pid=host'], /pid namespace/],
      [['--cap-add', 'SYS_ADMIN'], /capability/],
      [['--cap-add=NET_ADMIN'], /capability/],
      [['--security-opt', 'seccomp=unconfined'], /seccomp disabled/],
      [['--security-opt', 'apparmor=unconfined'], /apparmor/],
      [['--security-opt', 'no-new-privileges=false'], /privilege/],
      [['--device', '/dev/sda'], /host device/],
      [['-e', 'SECRET=1'], /environment/],
      [['--env-file', '.env'], /environment/],
      [['-p', '80:80'], /published/],
      [['--userns', 'host'], /user namespace/],
      [['--uts', 'host'], /uts/],
      [['--volumes-from', 'x'], /volumes/],
      [['-v', '/var/run/docker.sock:/var/run/docker.sock'], /docker socket|host mounts/],
      [['--sysctl', 'net.ipv4.ip_forward=1'], /sysctl/],
    ];
    for (const [flags, re] of cases) {
      const found = inject(...flags);
      assert.ok(found.length > 0 && found.some((f) => re.test(f.reason)), `not caught: ${flags.join(' ')} -> ${JSON.stringify(found)}`);
    }
  });

  test('CONTROL: network other than none, shared ipc, root user and removed protections are caught', () => {
    for (const net of ['host', 'bridge', 'container:abc']) {
      const a = base();
      a[a.indexOf('--network') + 1] = net;
      assert.ok(findForbiddenDockerFlags(a).some((f) => /network/.test(f.reason)), net);
    }
    const a = base();
    a[a.indexOf('--ipc') + 1] = 'host';
    assert.ok(findForbiddenDockerFlags(a).some((f) => /ipc/.test(f.reason)));
    const r = base();
    r[r.indexOf('--user') + 1] = '0:0';
    assert.ok(findForbiddenDockerFlags(r).some((f) => /root/.test(f.reason)));
    const noCap = base().filter((x, i, arr) => !(x === '--cap-drop' || arr[i - 1] === '--cap-drop'));
    assert.ok(findForbiddenDockerFlags(noCap).some((f) => /missing --cap-drop/.test(f.flag)));
    const partial = base();
    partial[partial.indexOf('--cap-drop') + 1] = 'NET_RAW';
    assert.ok(findForbiddenDockerFlags(partial).some((f) => /all capabilities/.test(f.reason)));
  });

  test('CONTROL: each test-only unsafe switch that removes a flag is flagged by the scanner', () => {
    const flagged: Array<[UnsafeContainerSwitches, RegExp]> = [
      [{ network: true }, /network|--network/],
      [{ writableRoot: true }, /read-only/],
      [{ keepCaps: true }, /cap-drop/],
      [{ root: true }, /root|--user/],
      [{ allowNewPrivs: true }, /privilege|no-new-privileges/],
      [{ noPidsLimit: true }, /pids-limit/],
      [{ noSeccomp: true }, /seccomp/],
    ];
    for (const [u, re] of flagged) {
      const f = findForbiddenDockerFlags(base(u));
      assert.ok(f.some((x) => re.test(x.flag) || re.test(x.reason)), `${JSON.stringify(u)} -> ${JSON.stringify(f)}`);
    }
  });
});
