import type { UnsafeContainerSwitches } from '../sandbox/containerArgs';

/** Containers started for the shell tool carry this label and name prefix (and ONLY these are ever cleaned up). */
export const SHELL_LABEL = 'starclaw.shell=1';
export const SHELL_NAME_PREFIX = 'starclaw-sh-';
/** Where the workspace copy lives inside the container (a size-capped tmpfs, never a host mount). */
export const WORK_DIR = '/work';

/** TEST-ONLY switches (each removes exactly one protection so a control can prove the probe notices). */
export interface UnsafeShellSwitches extends UnsafeContainerSwitches {
  /** Bind-mount this host directory at /host-mnt (what the design deliberately does NOT do). */
  hostMount?: string;
  /** Pass this variable into the container environment. */
  envPassthrough?: string;
}

export interface ShellArgOptions {
  name: string;
  image: string;
  memoryMb: number;
  pidsLimit: number;
  /** The container's own lifetime: it self-destructs after this many seconds even if the host process dies. */
  lifetimeSec: number;
  /** Size cap of the /work tmpfs, in MB (counts against the memory limit). */
  workTmpfsMb: number;
  runtime?: string;
  unsafe?: UnsafeShellSwitches;
}

/**
 * `docker run` argv (after `docker`) for the long-lived-but-short shell container. Pure function.
 * No mounts, no network, no env passthrough, no docker socket, no published ports; non-root, read-only root,
 * all capabilities dropped, no-new-privileges, seccomp default, pids/memory/cpu limits, tmpfs scratch.
 */
export function buildShellRunArgs(o: ShellArgOptions): string[] {
  const u = o.unsafe ?? {};
  const mem = `${u.memoryMb ?? o.memoryMb}m`;
  const a: string[] = ['run', '-d', '--rm', '--pull', 'never', '--name', o.name, '--label', SHELL_LABEL];
  if (o.runtime) a.push('--runtime', o.runtime);
  if (!u.network) a.push('--network', 'none');
  if (!u.writableRoot) a.push('--read-only');
  if (!u.keepCaps) a.push('--cap-drop', 'ALL');
  a.push('--security-opt', u.allowNewPrivs ? 'no-new-privileges=false' : 'no-new-privileges');
  if (u.noSeccomp) a.push('--security-opt', 'seccomp=unconfined');
  if (!u.noPidsLimit) a.push('--pids-limit', String(o.pidsLimit));
  a.push('--memory', mem, '--memory-swap', mem, '--cpus', '1');
  a.push('--user', u.root ? '0:0' : '65534:65534');
  a.push('--tmpfs', u.execTmp ? '/tmp:rw,exec,nosuid,nodev,size=16m' : '/tmp:rw,noexec,nosuid,nodev,size=16m');
  a.push('--tmpfs', `${WORK_DIR}:rw,noexec,nosuid,nodev,size=${o.workTmpfsMb}m,uid=65534,gid=65534,mode=0755`);
  a.push('--ipc', 'none', '--init', '--log-driver', 'none', '--ulimit', 'nofile=1024:1024', '--ulimit', 'core=0');
  if (u.hostMount) a.push('-v', `${u.hostMount}:/host-mnt`);
  if (u.envPassthrough) a.push('-e', u.envPassthrough);
  a.push(o.image, 'timeout', '-s', 'KILL', String(o.lifetimeSec), 'sleep', String(o.lifetimeSec));
  return a;
}
