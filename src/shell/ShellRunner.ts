import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import { dockerExec } from '../sandbox/ContainerSandbox';
import type { Policy } from '../governance/policy';
import { buildShellRunArgs, SHELL_NAME_PREFIX, UnsafeShellSwitches, WORK_DIR } from './shellArgs';
import { defaultShellImageTag, shellImageStatus } from './shellImage';
import { readTar } from './tar';
import { applyPlan, ApplyReport, ChangePlan, planChanges, stageWorkspace, StageError } from './workspaceSync';

export type ShellPolicy = Policy['shell'];

export interface ShellRunnerOptions {
  /** Real (symlink-resolved) workspace directory. */
  workspace: string;
  /** Real state directory (never copied in). */
  stateDir: string;
  policy: ShellPolicy;
  docker?: string;
  runtime?: string;
  /** TEST-ONLY: removes one container protection so a control can prove a probe notices. */
  _unsafe?: UnsafeShellSwitches;
}

export interface ShellHooks {
  /** The broker's write-path hard rules for the HOST path (throws if not allowed). */
  guard: (abs: string) => void;
  /** Called with the full change plan BEFORE anything is written to the host (the broker audits it here). */
  beforeApply?: (plan: ChangePlan, staged: { files: number; bytes: number; skipped: number }) => void;
}

export interface ShellResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  outputTruncated: boolean;
  durationMs: number;
  staged: { files: number; bytes: number; skipped: Array<{ path: string; reason: string }> };
  /** undefined when the command timed out or was killed (the container's tree is discarded, nothing is written back). */
  changes?: ApplyReport;
  note?: string;
}

class Capture {
  private chunks: Buffer[] = [];
  size = 0;
  truncated = false;
  constructor(private readonly cap: number) {}
  push(b: Buffer) {
    if (this.size >= this.cap) {
      this.truncated = true;
      return;
    }
    const room = this.cap - this.size;
    if (b.length > room) {
      this.chunks.push(b.subarray(0, room));
      this.size += room;
      this.truncated = true;
    } else {
      this.chunks.push(b);
      this.size += b.length;
    }
  }
  get buffer() {
    return Buffer.concat(this.chunks);
  }
  get text() {
    return this.buffer.toString('utf8');
  }
}

/**
 * Runs a shell command in a throwaway, locked-down container against a COPY of the workspace.
 *
 * Why a copy and not a bind mount: see SECURITY.md "Shell container". In short, a bind mount lets the container
 * (a) write straight into the workspace without passing the broker's hard rules (.git, .env, the state directory),
 * (b) create symlinks on the host that the host later follows. The copy-in / copy-out design makes the broker the
 * only thing that ever touches the host tree.
 *
 * One command at a time (serialised): one container exists at any moment.
 */
export class ShellRunner {
  readonly docker: string;
  readonly image: string;
  private lock: Promise<unknown> = Promise.resolve();
  private imageChecked = false;

  constructor(private readonly o: ShellRunnerOptions) {
    this.docker = o.docker ?? 'docker';
    this.image = o.policy.image ?? defaultShellImageTag();
    // The workspace must already be a real directory.
    if (!fs.statSync(o.workspace).isDirectory()) throw new Error('shell workspace is not a directory');
  }

  describe(): string {
    const p = this.o.policy;
    return `shell container: image ${this.image}, no network, read-only root, all caps dropped, uid 65534, ${p.memoryMb} MB, ${p.timeoutSeconds}s limit, workspace COPIED in/out (no host mount)`;
  }

  /** The exact `docker run` argv (after `docker`). Exposed for tests and the forbidden-flag scan. */
  buildArgs(name = `${SHELL_NAME_PREFIX}example`): string[] {
    return this.argsFor(name);
  }

  private argsFor(name: string): string[] {
    const p = this.o.policy;
    return buildShellRunArgs({
      name,
      image: this.image,
      memoryMb: p.memoryMb,
      pidsLimit: p.pidsLimit,
      lifetimeSec: p.timeoutSeconds + 60,
      workTmpfsMb: Math.max(8, Math.min(Math.ceil((p.workspace.maxBytes * 2) / 1_000_000) + 8, Math.floor(p.memoryMb / 2))),
      runtime: this.o.runtime,
      unsafe: this.o._unsafe,
    });
  }

  run(command: string, hooks: ShellHooks): Promise<ShellResult> {
    const next = this.lock.then(() => this.runLocked(command, hooks));
    this.lock = next.catch(() => {});
    return next;
  }

  private async ensureImage() {
    if (this.imageChecked) return;
    const st = await shellImageStatus({ docker: this.docker, tag: this.image });
    if (!st.dockerOk || !st.imagePresent || !st.matches) throw new Error(`shell container unavailable: ${st.detail}`);
    this.imageChecked = true;
  }

  private async runLocked(command: string, hooks: ShellHooks): Promise<ShellResult> {
    const p = this.o.policy;
    const started = Date.now();
    await this.ensureImage();
    // 1. Stage the workspace (fails closed over the caps; never follows links; skips .env and the state dir).
    const snap = stageWorkspace(this.o.workspace, this.o.stateDir, p.workspace);
    const staged = { files: snap.files.size, bytes: snap.totalBytes, skipped: snap.skipped };
    const name = `${SHELL_NAME_PREFIX}${randomBytes(6).toString('hex')}`;
    const run = await dockerExec(this.docker, this.argsFor(name), 60_000);
    if (run.code !== 0) {
      await this.remove(name);
      throw new Error(`could not start the shell container: ${(run.stderr || run.stdout).trim().slice(0, 300)}`);
    }
    try {
      // 2. Copy in.
      const cin = await this.pipe(['exec', '-i', name, 'tar', '-x', '-C', WORK_DIR], snap.tar, 60_000, 1_000_000);
      if (cin.code !== 0) throw new Error(`copying the workspace into the container failed: ${cin.stderr.trim().slice(0, 300)}`);

      // 3. Run the command (no environment passed in; no stdin).
      const out = new Capture(p.maxOutputBytes);
      const err = new Capture(p.maxOutputBytes);
      const hostLimitMs = (p.timeoutSeconds + 8) * 1000;
      const ex = await this.stream(
        ['exec', '-w', WORK_DIR, name, 'timeout', '-k', '2', String(p.timeoutSeconds), 'sh', '-c', command],
        hostLimitMs,
        out,
        err,
        name,
      );
      const timedOut = ex.code === 124 || ex.killed;
      const base = {
        exitCode: ex.killed ? null : ex.code,
        stdout: out.text,
        stderr: err.text,
        timedOut,
        outputTruncated: out.truncated || err.truncated,
        durationMs: Date.now() - started,
        staged,
      };
      if (ex.killed) return { ...base, note: 'the command exceeded the host-side limit; the container was destroyed and nothing was written back' };
      if (timedOut) return { ...base, note: 'the command timed out; nothing was written back' };

      // 4. Copy out, parse defensively, plan, audit the plan, then apply through the broker's hard rules.
      const maxTar = p.workspace.maxBytes + (p.workspace.maxFiles + 64) * 2048 + 1_000_000;
      const tarOut = new Capture(maxTar);
      const co = await this.stream(['exec', name, 'tar', '--format=pax', '-c', '-C', WORK_DIR, '.'], 60_000, tarOut, new Capture(8192), name);
      if (co.killed || co.code !== 0 || tarOut.truncated) return { ...base, note: `write-back skipped: could not read the container's workspace back (${tarOut.truncated ? 'archive over the size cap' : 'tar failed'}); nothing was written` };
      try {
        const parsed = readTar(tarOut.buffer, { maxEntries: p.workspace.maxFiles * 2 + 4096, maxTotalBytes: p.workspace.maxBytes * 2, maxFileBytes: p.workspace.maxFileBytes });
        const plan = planChanges(parsed, snap, p.workspace);
        hooks.beforeApply?.(plan, { files: staged.files, bytes: staged.bytes, skipped: staged.skipped.length });
        const changes = applyPlan(plan, snap, this.o.workspace, hooks.guard);
        return { ...base, durationMs: Date.now() - started, changes };
      } catch (e: any) {
        if (e instanceof StageError) return { ...base, note: e.message };
        throw e;
      }
    } finally {
      await this.remove(name);
    }
  }

  /** Remove a container this runner created (name carries our prefix; nothing else is ever touched). */
  private async remove(name: string) {
    if (!name.startsWith(SHELL_NAME_PREFIX)) return;
    await dockerExec(this.docker, ['rm', '-f', name], 30_000);
  }

  private pipe(args: string[], input: Buffer, timeoutMs: number, errCap: number): Promise<{ code: number; stderr: string }> {
    return new Promise((resolve) => {
      const c = spawn(this.docker, args, { stdio: ['pipe', 'ignore', 'pipe'], windowsHide: true });
      const err = new Capture(errCap);
      const timer = setTimeout(() => c.kill(), timeoutMs);
      c.stderr!.on('data', (d) => err.push(d));
      c.stdin!.on('error', () => {});
      c.on('error', (e) => {
        clearTimeout(timer);
        resolve({ code: 127, stderr: String(e.message) });
      });
      c.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code: code ?? 1, stderr: err.text });
      });
      c.stdin!.end(input);
    });
  }

  /** Run a docker exec, capturing capped output. On the host-side timer the whole container is removed (killed:true). */
  private stream(args: string[], limitMs: number, out: Capture, err: Capture, containerName: string): Promise<{ code: number | null; killed: boolean }> {
    return new Promise((resolve) => {
      const c = spawn(this.docker, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      let killed = false;
      const timer = setTimeout(() => {
        killed = true;
        void this.remove(containerName);
        c.kill();
      }, limitMs);
      c.stdout!.on('data', (d) => out.push(d));
      c.stderr!.on('data', (d) => err.push(d));
      c.on('error', () => {
        clearTimeout(timer);
        resolve({ code: 127, killed });
      });
      c.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code, killed });
      });
    });
  }
}
