import { ChildProcess, execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildDockerArgs, NAME_PREFIX, SANDBOX_LABEL, UnsafeContainerSwitches } from './containerArgs';
import { FrameParser } from './frames';
import { ALL_PARTS, probeContainer, ProbePart } from './containerProbe';
import type { ProbeReport } from './probe';
import { BrokerHandler, DEFAULT_TOOL_NAMES, RunResult, Sandbox, SandboxUnavailable } from './types';

export interface ContainerOptions {
  /** Image built by `starclaw sandbox build`. */
  image: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  memoryMb?: number;
  pidsLimit?: number;
  maxBrokerCalls?: number;
  /** Max size of one protocol frame / output line, bytes. */
  maxFrameBytes?: number;
  toolNames?: string[];
  /** Optional OCI runtime passthrough (e.g. "runsc"). NOT tested by this project. */
  runtime?: string;
  dockerPath?: string;
  runnerPath?: string;
  /** TEST-ONLY controls (each removes one protection). Never set by the engine, CLI or server. */
  _unsafe?: UnsafeContainerSwitches;
  /** TEST-ONLY control: parent accepts frames without checking the nonce. */
  _unsafeNoNonce?: boolean;
  /** Internal to the probe: run WITHOUT Node's permission model and JS hardening so the container is the only barrier. */
  _layerOnly?: boolean;
}

export function sha256File(p: string): string {
  return createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

export function dockerExec(docker: string, args: string[], timeoutMs = 20_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(docker, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 8_000_000 }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof (err as any).code === 'number' ? (err as any).code : 127) : 0, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

/**
 * Runs generated JavaScript inside a locked-down Docker container (OS-level isolation underneath the Node
 * permission model). The container has no mounts, no network, a read-only root, no capabilities and runs as an
 * unprivileged uid; all file/network/spend access goes through the broker over a stdio frame protocol.
 *
 * Shared-kernel caveat: containers share the host kernel (on Docker Desktop: the WSL2 VM's kernel). This is not
 * a VM boundary. See SECURITY.md.
 */
export class ContainerSandbox implements Sandbox {
  readonly kind = 'container' as const;
  private probeReport?: ProbeReport;
  private probing?: Promise<ProbeReport>;
  readonly runnerPath: string;
  readonly docker: string;

  constructor(private readonly opts: ContainerOptions) {
    this.docker = opts.dockerPath ?? 'docker';
    this.runnerPath = path.resolve(opts.runnerPath ?? path.join(__dirname, 'runner.cjs'));
  }

  get options(): ContainerOptions {
    return this.opts;
  }
  get lastProbe() {
    return this.probeReport;
  }
  describe(): string {
    return `container: image ${this.opts.image}, no network, read-only root, all caps dropped, uid 65534, ${this.opts.memoryMb ?? 256} MB, then Node permission model inside${this.opts.runtime ? `, runtime ${this.opts.runtime} (untested)` : ''}`;
  }

  /** The exact argv (after `docker`) for a run. Exposed for tests and the forbidden-flag scan. */
  buildArgs(name = `${NAME_PREFIX}example`): string[] {
    return buildDockerArgs({
      name,
      image: this.opts.image,
      memoryMb: this.opts.memoryMb ?? 256,
      pidsLimit: this.opts.pidsLimit ?? 64,
      timeoutMs: this.opts.timeoutMs ?? 60_000,
      runtime: this.opts.runtime,
      usePermissionModel: !this.opts._layerOnly,
      unsafe: this.opts._unsafe,
    });
  }

  async ensureSafe(): Promise<ProbeReport> {
    if (!this.probing) this.probing = this.doProbe();
    this.probeReport = await this.probing;
    if (!this.probeReport.ok) {
      throw new SandboxUnavailable(
        `Refusing to run generated code in the container layer: probe failed (${this.probeReport.failures.map((f) => `${f.name}: ${f.detail}`).join(' | ')})`,
        this.probeReport,
      );
    }
    return this.probeReport;
  }

  private doProbe(): Promise<ProbeReport> {
    return probeContainer(this, ALL_PARTS);
  }

  /** Run only some probe parts (used by tests for per-protection controls). Does not affect ensureSafe(). */
  probeParts(parts: ProbePart[]): Promise<ProbeReport> {
    return probeContainer(this, parts);
  }

  async run(code: string, handler: BrokerHandler): Promise<RunResult> {
    await this.ensureSafe();
    return this.runUnchecked(code, handler);
  }

  /** Runs without consulting the probe. Used by the probe itself. */
  runUnchecked(code: string, handler: BrokerHandler, extra: { skipHardening?: boolean } = {}): Promise<RunResult> {
    const started = Date.now();
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    const maxOut = this.opts.maxOutputBytes ?? 256_000;
    const maxCalls = this.opts.maxBrokerCalls ?? 200;
    const maxFrame = this.opts.maxFrameBytes ?? 8_000_000;
    const toolNames = this.opts.toolNames ?? DEFAULT_TOOL_NAMES;
    const name = `${NAME_PREFIX}${randomBytes(8).toString('hex')}`;
    const nonce = randomBytes(16).toString('hex');
    const args = this.buildArgs(name);

    return new Promise<RunResult>((resolve) => {
      let stdout = '';
      let stderr = '';
      let truncated = false;
      let timedOut = false;
      let calls = 0;
      let settled = false;
      let fatalReason: string | undefined;
      let doneMsg: { ok: boolean; value?: string; error?: string } | undefined;
      let exitCode: number | null = null;
      let queue: Promise<void> = Promise.resolve();
      let killed = false;
      let cleanup: Promise<unknown> = Promise.resolve();
      let cleanupError: string | undefined;

      const child: ChildProcess = spawn(this.docker, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });

      const killContainer = () => {
        if (killed) return;
        killed = true;
        // Exactly this container, by its unique name. Never by image or by pattern.
        cleanup = (async () => {
          for (let attempt = 0; attempt < 3; attempt++) {
            const removed = await dockerExec(this.docker, ['rm', '--force', name], 15_000);
            if (removed.code === 0 || /no such container/i.test(removed.stderr)) return;
            // --rm can race explicit removal. Wait for the exact container to disappear.
            const exists = await dockerExec(this.docker, ['inspect', '--format', '{{.Id}}', name], 15_000);
            if (exists.code !== 0 && /no such/i.test(exists.stderr)) return;
            await new Promise(resolve => setTimeout(resolve, 250));
          }
          cleanupError = `could not remove sandbox container ${name}`;
        })();
        try {
          child.kill();
        } catch {
          /* gone */
        }
      };

      const addOut = (text: string) => {
        if (stdout.length >= maxOut) {
          truncated = true;
          return;
        }
        stdout += text;
        if (stdout.length > maxOut) {
          stdout = stdout.slice(0, maxOut);
          truncated = true;
        }
      };

      const reply = (m: Record<string, unknown>) => {
        if (settled || !child.stdin || child.stdin.destroyed) return;
        try {
          child.stdin.write(JSON.stringify({ type: 'result', ...m }) + '\n');
        } catch {
          /* container gone */
        }
      };

      const parser = new FrameParser({
        nonce: this.opts._unsafeNoNonce ? null : nonce,
        maxFrameBytes: maxFrame,
        onText: addOut,
        onFatal: (r) => {
          fatalReason = r;
          killContainer();
        },
        onFrame: (raw) => {
          if (doneMsg) return; // frames after `done` are ignored
          if (raw.type === 'done') {
            doneMsg = { ok: !!raw.ok, value: typeof raw.value === 'string' ? raw.value : undefined, error: typeof raw.error === 'string' ? raw.error : undefined };
            return;
          }
          if (raw.type === 'call' && Number.isSafeInteger(raw.id) && typeof raw.name === 'string') {
            const id = raw.id as number;
            const toolName = raw.name as string;
            queue = queue.then(async () => {
              if (settled || doneMsg) return;
              calls++;
              if (calls > maxCalls) return reply({ id, ok: false, error: `broker call limit (${maxCalls}) exceeded`, code: 'ERR_BROKER_LIMIT' });
              if (!toolNames.includes(toolName)) return reply({ id, ok: false, error: `unknown tool ${toolName}`, code: 'ERR_UNKNOWN_TOOL' });
              try {
                const value = await handler({ name: toolName, args: raw.args });
                reply({ id, ok: true, value: value === undefined ? null : value });
              } catch (e: any) {
                reply({ id, ok: false, error: String(e?.message ?? e).slice(0, 2000), code: e?.name === 'GovernorDenied' ? 'ERR_GOVERNOR_DENIED' : 'ERR_BROKER' });
              }
            });
          }
        },
      });

      child.stdout!.on('data', (c: Buffer) => parser.push(c));
      child.stderr!.on('data', (c: Buffer) => {
        if (stderr.length < maxOut) stderr += c.toString('utf8').slice(0, maxOut - stderr.length);
      });
      child.stdin!.on('error', () => {});

      const timer = setTimeout(() => {
        timedOut = true;
        killContainer();
      }, timeoutMs);

      const finish = (extraErr?: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        parser.end();
        let value: unknown;
        let ok = false;
        let error = extraErr;
        if (doneMsg) {
          ok = doneMsg.ok && !timedOut && !fatalReason;
          if (doneMsg.ok && doneMsg.value !== undefined) {
            try {
              value = JSON.parse(doneMsg.value);
            } catch {
              value = doneMsg.value;
            }
          }
          if (!doneMsg.ok) error = doneMsg.error;
        }
        if (fatalReason) error = `protocol violation: ${fatalReason}`;
        else if (timedOut) error = `timed out after ${timeoutMs} ms`;
        else if (!doneMsg && !error) error = exitCode === 137 ? 'sandbox container was killed (exit 137: out of memory or killed)' : 'sandbox container exited without a result';
        void cleanup.then(() => resolve({ ok: ok && !cleanupError, value, error: cleanupError ? `${error ?? 'execution failed'}; ${cleanupError}` : error, stdout, stderr, timedOut, outputTruncated: truncated, brokerCalls: calls, durationMs: Date.now() - started, forgedFrames: parser.forged, exitCode }));
      };

      child.on('error', (e) => finish(`failed to start docker: ${e.message}`));
      child.on('close', (code) => {
        exitCode = code;
        setImmediate(() => finish(code !== null && code !== 0 && !doneMsg && /docker:|Error response|Unable to find image/i.test(stderr) ? `docker could not start the container: ${stderr.trim().slice(0, 300)}` : undefined));
      });

      // One message carries everything the runner needs, including the secret nonce. Docker buffers it until the container reads stdin.
      child.stdin!.write(JSON.stringify({ type: 'run', nonce, code, tools: toolNames, skipHardening: !!(extra.skipHardening || this.opts._layerOnly) }) + '\n');
    });
  }
}

