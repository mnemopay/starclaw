import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { dockerExec, sha256File } from './ContainerSandbox';
import { NAME_PREFIX } from './containerArgs';

export function packageRoot(): string {
  return path.resolve(__dirname, '..', '..');
}

export function packageVersion(): string {
  try {
    return JSON.parse(fs.readFileSync(path.join(packageRoot(), 'package.json'), 'utf8')).version;
  } catch {
    return 'dev';
  }
}

export function defaultImageTag(): string {
  return `starclaw-sandbox:${packageVersion().replace(/[^a-zA-Z0-9_.-]/g, '-')}`;
}

export function packagedRunner(): string {
  return path.join(__dirname, 'runner.cjs');
}

export function packagedDockerfile(): string {
  return path.join(packageRoot(), 'docker', 'sandbox', 'Dockerfile');
}

/** Build the sandbox image from the packaged Dockerfile plus the packaged runner.cjs. Returns the docker exit code. */
export async function buildImage(opts: { docker?: string; tag?: string; onLog?: (s: string) => void } = {}): Promise<number> {
  const docker = opts.docker ?? 'docker';
  const tag = opts.tag ?? defaultImageTag();
  const dockerfile = packagedDockerfile();
  if (!fs.existsSync(dockerfile)) throw new Error(`packaged Dockerfile not found at ${dockerfile}`);
  const ctx = fs.mkdtempSync(path.join(os.tmpdir(), 'starclaw-sbx-build-'));
  try {
    fs.copyFileSync(dockerfile, path.join(ctx, 'Dockerfile'));
    fs.copyFileSync(packagedRunner(), path.join(ctx, 'runner.cjs'));
    const hash = sha256File(packagedRunner());
    return await new Promise<number>((resolve, reject) => {
      const c = spawn(docker, ['build', '--pull=false', '--build-arg', `RUNNER_SHA256=${hash}`, '-t', tag, ctx], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      c.stdout.on('data', (d) => opts.onLog?.(String(d)));
      c.stderr.on('data', (d) => opts.onLog?.(String(d)));
      c.on('error', reject);
      c.on('close', (code) => resolve(code ?? 1));
    });
  } finally {
    fs.rmSync(ctx, { recursive: true, force: true });
  }
}

export interface ImageStatus {
  dockerOk: boolean;
  dockerVersion?: string;
  imagePresent: boolean;
  imageId?: string;
  runnerMatches: boolean;
  tag: string;
  detail: string;
}

export async function imageStatus(opts: { docker?: string; tag?: string } = {}): Promise<ImageStatus> {
  const docker = opts.docker ?? 'docker';
  const tag = opts.tag ?? defaultImageTag();
  const v = await dockerExec(docker, ['version', '--format', '{{.Server.Version}}'], 15_000);
  if (v.code !== 0) return { dockerOk: false, imagePresent: false, runnerMatches: false, tag, detail: `docker not usable: ${(v.stderr || v.stdout).trim().slice(0, 160) || 'no output'}` };
  const i = await dockerExec(docker, ['image', 'inspect', '--format', '{{.Id}}|{{ index .Config.Labels "starclaw.runner.sha256" }}', tag], 15_000);
  if (i.code !== 0) return { dockerOk: true, dockerVersion: v.stdout.trim(), imagePresent: false, runnerMatches: false, tag, detail: `image ${tag} not found: run "starclaw sandbox build"` };
  const [id, label] = i.stdout.trim().split('|');
  const match = label === sha256File(packagedRunner());
  return { dockerOk: true, dockerVersion: v.stdout.trim(), imagePresent: true, imageId: id, runnerMatches: match, tag, detail: match ? 'image present and its runner hash matches this package' : 'image is STALE: its runner differs from this package; run "starclaw sandbox build"' };
}

/** Containers started by this tool: label starclaw.sandbox=1 AND the starclaw-sbx- name prefix. */
export async function listSandboxContainers(docker = 'docker'): Promise<string[]> {
  const r = await dockerExec(docker, ['ps', '-a', '--filter', 'label=starclaw.sandbox=1', '--filter', `name=${NAME_PREFIX}`, '--format', '{{.ID}} {{.Names}}'], 15_000);
  if (r.code !== 0) return [];
  return r.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
}

/** Remove only containers carrying our label and name prefix. Returns the names removed. */
export async function cleanContainers(docker = 'docker'): Promise<string[]> {
  const removed: string[] = [];
  for (const line of await listSandboxContainers(docker)) {
    const [id, name] = line.split(' ');
    if (!name?.startsWith(NAME_PREFIX)) continue;
    const r = await dockerExec(docker, ['rm', '-f', id], 30_000);
    if (r.code === 0) removed.push(name);
  }
  return removed;
}
