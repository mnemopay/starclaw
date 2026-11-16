import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { dockerExec, sha256File } from '../sandbox/ContainerSandbox';
import { packageRoot, packageVersion } from '../sandbox/dockerImage';
import { SHELL_NAME_PREFIX } from './shellArgs';

export function defaultShellImageTag(): string {
  return `starclaw-shell:${packageVersion().replace(/[^a-zA-Z0-9_.-]/g, '-')}`;
}

export function packagedShellDockerfile(): string {
  return path.join(packageRoot(), 'docker', 'shell', 'Dockerfile');
}

/** Build the shell image. The BUILD may use the network (apt); the running container never does. Returns docker's exit code. */
export async function buildShellImage(opts: { docker?: string; tag?: string; onLog?: (s: string) => void } = {}): Promise<number> {
  const docker = opts.docker ?? 'docker';
  const tag = opts.tag ?? defaultShellImageTag();
  const dockerfile = packagedShellDockerfile();
  if (!fs.existsSync(dockerfile)) throw new Error(`packaged shell Dockerfile not found at ${dockerfile}`);
  const ctx = fs.mkdtempSync(path.join(os.tmpdir(), 'starclaw-shell-build-'));
  try {
    fs.copyFileSync(dockerfile, path.join(ctx, 'Dockerfile'));
    const hash = sha256File(dockerfile);
    return await new Promise<number>((resolve, reject) => {
      const c = spawn(docker, ['build', '--pull=false', '--build-arg', `DOCKERFILE_SHA256=${hash}`, '-t', tag, ctx], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      c.stdout.on('data', (d) => opts.onLog?.(String(d)));
      c.stderr.on('data', (d) => opts.onLog?.(String(d)));
      c.on('error', reject);
      c.on('close', (code) => resolve(code ?? 1));
    });
  } finally {
    fs.rmSync(ctx, { recursive: true, force: true });
  }
}

export interface ShellImageStatus {
  dockerOk: boolean;
  imagePresent: boolean;
  imageId?: string;
  matches: boolean;
  tag: string;
  detail: string;
}

export async function shellImageStatus(opts: { docker?: string; tag?: string } = {}): Promise<ShellImageStatus> {
  const docker = opts.docker ?? 'docker';
  const tag = opts.tag ?? defaultShellImageTag();
  const v = await dockerExec(docker, ['version', '--format', '{{.Server.Version}}'], 15_000);
  if (v.code !== 0) return { dockerOk: false, imagePresent: false, matches: false, tag, detail: `docker not usable: ${(v.stderr || v.stdout).trim().slice(0, 160) || 'no output'}` };
  const i = await dockerExec(docker, ['image', 'inspect', '--format', '{{.Id}}|{{ index .Config.Labels "starclaw.shell.dockerfile.sha256" }}', tag], 15_000);
  if (i.code !== 0) return { dockerOk: true, imagePresent: false, matches: false, tag, detail: `image ${tag} not found: run "starclaw shell build"` };
  const [id, label] = i.stdout.trim().split('|');
  const match = label === sha256File(packagedShellDockerfile());
  return { dockerOk: true, imagePresent: true, imageId: id, matches: match, tag, detail: match ? 'image present and built from this package\'s Dockerfile' : 'image is STALE: it was built from a different Dockerfile; run "starclaw shell build"' };
}

/** Containers started by the shell tool: label starclaw.shell=1 AND the starclaw-sh- name prefix. */
export async function listShellContainers(docker = 'docker'): Promise<string[]> {
  const r = await dockerExec(docker, ['ps', '-a', '--filter', 'label=starclaw.shell=1', '--filter', `name=${SHELL_NAME_PREFIX}`, '--format', '{{.ID}} {{.Names}}'], 15_000);
  if (r.code !== 0) return [];
  return r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
}

/** Remove only containers carrying our label and name prefix. Returns the names removed. */
export async function cleanShellContainers(docker = 'docker'): Promise<string[]> {
  const removed: string[] = [];
  for (const line of await listShellContainers(docker)) {
    const [id, name] = line.split(' ');
    if (!name?.startsWith(SHELL_NAME_PREFIX)) continue;
    const r = await dockerExec(docker, ['rm', '-f', id], 30_000);
    if (r.code === 0) removed.push(name);
  }
  return removed;
}
