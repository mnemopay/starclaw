/**
 * Builds the `docker run` argument list for the sandbox container and scans argument lists for flags that
 * must never appear. Pure functions: unit-testable without Docker.
 */

export const SANDBOX_LABEL = 'starclaw.sandbox=1';
export const NAME_PREFIX = 'starclaw-sbx-';
export const RUNNER_IN_IMAGE = '/sandbox/runner.cjs';

/** TEST-ONLY: each switch removes exactly one protection so a control can prove the matching check fails. */
export interface UnsafeContainerSwitches {
  network?: boolean; // drop --network none (default bridge)
  writableRoot?: boolean; // drop --read-only
  keepCaps?: boolean; // drop --cap-drop ALL
  root?: boolean; // run as root instead of 65534
  allowNewPrivs?: boolean; // drop no-new-privileges
  noPidsLimit?: boolean;
  memoryMb?: number; // larger memory limit than configured
  execTmp?: boolean; // tmpfs /tmp without noexec
  noSeccomp?: boolean; // seccomp=unconfined (also flagged by the forbidden-flag scanner, by design)
}

export interface ContainerArgOptions {
  name: string;
  image: string;
  memoryMb: number;
  pidsLimit: number;
  timeoutMs: number;
  runtime?: string;
  /** Node flags inside the container, e.g. keep `--permission` as defence in depth. */
  usePermissionModel: boolean;
  unsafe?: UnsafeContainerSwitches;
}

export function buildDockerArgs(o: ContainerArgOptions): string[] {
  const u = o.unsafe ?? {};
  const mem = `${u.memoryMb ?? o.memoryMb}m`;
  const args: string[] = ['run', '--rm', '-i', '--pull', 'never', '--name', o.name, '--label', SANDBOX_LABEL];
  if (o.runtime) args.push('--runtime', o.runtime);
  if (!u.network) args.push('--network', 'none');
  if (!u.writableRoot) args.push('--read-only');
  if (!u.keepCaps) args.push('--cap-drop', 'ALL');
  args.push('--security-opt', u.allowNewPrivs ? 'no-new-privileges=false' : 'no-new-privileges');
  if (u.noSeccomp) args.push('--security-opt', 'seccomp=unconfined');
  if (!u.noPidsLimit) args.push('--pids-limit', String(o.pidsLimit));
  args.push('--memory', mem, '--memory-swap', mem, '--cpus', '1');
  args.push('--user', u.root ? '0:0' : '65534:65534');
  args.push('--tmpfs', u.execTmp ? '/tmp:rw,exec,nosuid,size=16m' : '/tmp:rw,noexec,nosuid,size=16m');
  args.push('--ipc', 'none', '--init', '--log-driver', 'none', '--ulimit', 'nofile=256:256', '--ulimit', 'core=0');
  args.push(o.image);
  // `timeout` in the image kills node even if the host process dies; slightly longer than the host-side timeout.
  const secs = Math.ceil(o.timeoutMs / 1000) + 10;
  args.push('timeout', '-s', 'KILL', String(secs), 'node', `--max-old-space-size=${Math.min(o.memoryMb, 192)}`, '--disable-proto=delete');
  if (o.usePermissionModel) args.push('--permission', `--allow-fs-read=${RUNNER_IN_IMAGE}`);
  args.push(RUNNER_IN_IMAGE);
  return args;
}

export interface ForbiddenFinding {
  flag: string;
  reason: string;
}

const EXACT: Array<[RegExp, string]> = [
  [/^--privileged(=.*)?$/, 'privileged container'],
  [/^(-v|--volume|--mount)(=.*)?$/, 'host mounts'],
  [/^--volumes-from(=.*)?$/, 'inherits volumes'],
  [/^--pid(=.*)?$/, 'shares a pid namespace'],
  [/^--uts(=.*)?$/, 'shares uts namespace'],
  [/^--userns(=.*)?$/, 'user namespace override'],
  [/^--cap-add(=.*)?$/, 'adds a capability'],
  [/^--device(=.*)?$/, 'host device'],
  [/^--device-cgroup-rule(=.*)?$/, 'device cgroup rule'],
  [/^(-e|--env|--env-file)(=.*)?$/, 'environment passthrough'],
  [/^(-p|--publish|-P|--publish-all)(=.*)?$/, 'published ports'],
  [/^--cgroupns(=.*)?$/, 'cgroup namespace override'],
  [/^--sysctl(=.*)?$/, 'sysctl override'],
];

/** Returns every forbidden construct found in a `docker run` argument list. Empty = clean. */
export function findForbiddenDockerFlags(args: string[]): ForbiddenFinding[] {
  const out: ForbiddenFinding[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const next = args[i + 1] ?? '';
    for (const [re, reason] of EXACT) if (re.test(a)) out.push({ flag: a, reason });
    if (/docker\.sock/.test(a)) out.push({ flag: a, reason: 'docker socket' });
    if (a === '--network' || a === '--net') {
      if (next !== 'none') out.push({ flag: `${a} ${next}`, reason: 'network other than none' });
    } else if (/^--(network|net)=/.test(a) && !/=none$/.test(a)) out.push({ flag: a, reason: 'network other than none' });
    if (a === '--ipc' && next !== 'none') out.push({ flag: `${a} ${next}`, reason: 'ipc namespace shared' });
    if (a === '--security-opt' || /^--security-opt=/.test(a)) {
      const v = a === '--security-opt' ? next : a.split('=').slice(1).join('=');
      if (/seccomp[=:]unconfined/.test(v)) out.push({ flag: `--security-opt ${v}`, reason: 'seccomp disabled' });
      if (/apparmor[=:]unconfined/.test(v)) out.push({ flag: `--security-opt ${v}`, reason: 'apparmor disabled' });
      if (/no-new-privileges=false/.test(v)) out.push({ flag: `--security-opt ${v}`, reason: 'allows privilege gain' });
      if (/^(label|systempaths)[=:]/.test(v)) out.push({ flag: `--security-opt ${v}`, reason: 'weakens confinement' });
    }
    if (a === '--user' && (next === '0' || next.startsWith('0:') || next === 'root')) out.push({ flag: `--user ${next}`, reason: 'runs as root' });
  }
  const need = ['--read-only', '--cap-drop', '--pids-limit', '--memory', '--memory-swap', '--init'];
  for (const n of need) if (!args.includes(n)) out.push({ flag: `(missing ${n})`, reason: 'required protection absent' });
  if (!args.includes('--network')) out.push({ flag: '(missing --network none)', reason: 'required protection absent' });
  if (!args.some((a, i) => a === '--security-opt' && args[i + 1] === 'no-new-privileges')) out.push({ flag: '(missing no-new-privileges)', reason: 'required protection absent' });
  const capIdx = args.indexOf('--cap-drop');
  if (capIdx >= 0 && args[capIdx + 1] !== 'ALL') out.push({ flag: `--cap-drop ${args[capIdx + 1]}`, reason: 'does not drop all capabilities' });
  return out;
}
