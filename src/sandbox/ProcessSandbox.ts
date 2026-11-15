import { ChildProcess, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { probeSandbox, ProbeReport } from './probe';

export interface BrokerCall {
  name: string;
  args: unknown;
}
export type BrokerHandler = (call: BrokerCall) => Promise<unknown>;

export interface SandboxOptions {
  workspaceDir: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  memoryMb?: number;
  maxBrokerCalls?: number;
  /** Names exposed to generated code as `tools.<name>(args)`. */
  toolNames?: string[];
  /** Override for tests. */
  runnerPath?: string;
  /**
   * TEST-ONLY CONTROLS. These deliberately weaken the sandbox so tests can prove that the probe and the
   * adversarial tests FAIL without the protection. Never set by the engine, CLI or server.
   */
  _unsafeDisablePermissionModel?: boolean;
  _unsafeSkipHardening?: boolean;
  /**
   * TEST-ONLY. Grants the child direct read/write on the workspace. The probe PROVES this is unsafe on Windows:
   * a junction inside the workspace lets the child read and write outside it. Brokered access is the only supported mode.
   */
  _unsafeDirectWorkspaceAccess?: boolean;
}

export interface RunResult {
  ok: boolean;
  value?: unknown;
  error?: string;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  outputTruncated: boolean;
  brokerCalls: number;
  durationMs: number;
}

export class SandboxUnavailable extends Error {
  constructor(msg: string, public readonly report?: ProbeReport) {
    super(msg);
    this.name = 'SandboxUnavailable';
  }
}

/**
 * Tool names the runner may expose. Kept here so the broker and the sandbox agree.
 */
export const DEFAULT_TOOL_NAMES = ['readFile', 'writeFile', 'listDir', 'fetchUrl', 'runCommand', 'spend'];

/**
 * Runs generated JavaScript in a separate Node process started with `--permission` (no child_process, worker
 * threads, addons, WASI, network or filesystem access beyond what is explicitly granted), a scrubbed environment,
 * a memory cap, a wall-clock timeout and an output cap. Capabilities are brokered over IPC.
 *
 * It FAILS CLOSED: `ensureSafe()` runs a probe of forbidden operations through the very same code path and
 * throws SandboxUnavailable if any of them is not denied by this Node build. `run()` calls it first.
 */
export class ProcessSandbox {
  private probeReport?: ProbeReport;
  private probing?: Promise<ProbeReport>;
  readonly workspaceDir: string;
  private readonly runnerPath: string;

  constructor(private readonly opts: SandboxOptions) {
    fs.mkdirSync(opts.workspaceDir, { recursive: true });
    this.workspaceDir = fs.realpathSync(opts.workspaceDir);
    this.runnerPath = path.resolve(opts.runnerPath ?? path.join(__dirname, 'runner.cjs'));
    if (!fs.existsSync(this.runnerPath)) throw new SandboxUnavailable(`sandbox runner missing: ${this.runnerPath}`);
  }

  get lastProbe(): ProbeReport | undefined {
    return this.probeReport;
  }

  /** Minimal environment for the child: no inherited secrets, no PATH. */
  private childEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { NODE_ENV: 'production' };
    if (process.platform === 'win32' && process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    return env;
  }

  /** The exact argv used to start the child (exported for tests and for `starclaw doctor`). */
  buildArgs(): string[] {
    const mb = this.opts.memoryMb ?? 256;
    const args: string[] = [`--max-old-space-size=${mb}`, '--disable-proto=delete'];
    if (!this.opts._unsafeDisablePermissionModel) {
      args.push('--permission', `--allow-fs-read=${this.runnerPath}`);
      if (this.opts._unsafeDirectWorkspaceAccess) args.push(`--allow-fs-read=${this.workspaceDir}`, `--allow-fs-write=${this.workspaceDir}`);
    }
    args.push(this.runnerPath);
    return args;
  }

  /** Probe once per instance; throws SandboxUnavailable (and records why) if any forbidden op is not denied. */
  async ensureSafe(): Promise<ProbeReport> {
    if (this.probeReport) {
      if (!this.probeReport.ok) throw new SandboxUnavailable(this.failureMessage(this.probeReport), this.probeReport);
      return this.probeReport;
    }
    if (!this.probing) {
      this.probing = probeSandbox((o) => new ProcessSandbox({ ...this.opts, ...o }), this.opts);
    }
    this.probeReport = await this.probing;
    if (!this.probeReport.ok) throw new SandboxUnavailable(this.failureMessage(this.probeReport), this.probeReport);
    return this.probeReport;
  }

  private failureMessage(r: ProbeReport): string {
    return (
      `Refusing to run generated code: the sandbox probe failed on Node ${r.nodeVersion} (${r.platform}). ` +
      r.failures.map((f) => `${f.name}: ${f.detail}`).join(' | ')
    );
  }

  /** Run `code` after verifying the sandbox. Broker calls are handled one at a time, in order. */
  async run(code: string, handler: BrokerHandler): Promise<RunResult> {
    await this.ensureSafe();
    return this.runUnchecked(code, handler);
  }

  /** Used by the probe itself (it cannot require its own result). Not exported through the engine. */
  async runUnchecked(code: string, handler: BrokerHandler): Promise<RunResult> {
    const started = Date.now();
    const timeoutMs = this.opts.timeoutMs ?? 60_000;
    const maxOut = this.opts.maxOutputBytes ?? 256_000;
    const maxCalls = this.opts.maxBrokerCalls ?? 200;
    const toolNames = this.opts.toolNames ?? DEFAULT_TOOL_NAMES;

    return new Promise<RunResult>((resolve) => {
      let stdout = '';
      let stderr = '';
      let truncated = false;
      let timedOut = false;
      let calls = 0;
      let settled = false;
      let doneMsg: { ok: boolean; value?: string; error?: string } | undefined;
      let queue: Promise<void> = Promise.resolve();

      const child: ChildProcess = spawn(process.execPath, this.buildArgs(), {
        cwd: this.workspaceDir,
        env: this.childEnv(),
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        windowsHide: true,
        shell: false,
      });

      const cap = (cur: string, chunk: Buffer): string => {
        if (cur.length >= maxOut) {
          truncated = true;
          return cur;
        }
        const next = cur + chunk.toString('utf8');
        if (next.length > maxOut) {
          truncated = true;
          return next.slice(0, maxOut);
        }
        return next;
      };
      child.stdout!.on('data', (c: Buffer) => (stdout = cap(stdout, c)));
      child.stderr!.on('data', (c: Buffer) => (stderr = cap(stderr, c)));

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL'); // our own child: killed by handle/PID, never by image name
      }, timeoutMs);

      const finish = (extraErr?: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        let value: unknown;
        let ok = false;
        let error = extraErr;
        if (doneMsg) {
          ok = doneMsg.ok && !timedOut;
          if (doneMsg.ok && doneMsg.value !== undefined) {
            try {
              value = JSON.parse(doneMsg.value);
            } catch {
              value = doneMsg.value;
            }
          }
          if (!doneMsg.ok) error = doneMsg.error;
        }
        if (timedOut) error = `timed out after ${timeoutMs} ms`;
        else if (!doneMsg && !error) error = 'sandbox process exited without a result';
        resolve({ ok, value, error, stdout, stderr, timedOut, outputTruncated: truncated, brokerCalls: calls, durationMs: Date.now() - started });
      };

      child.on('error', (e) => finish(`failed to start sandbox: ${e.message}`));
      child.on('close', () => {
        // Let queued broker replies settle, but there is nobody left to reply to.
        setImmediate(() => finish());
      });

      child.on('message', (raw: any) => {
        if (!raw || typeof raw !== 'object') return;
        if (raw.type === 'ready') {
          child.send({ type: 'run', code, tools: toolNames, skipHardening: !!this.opts._unsafeSkipHardening });
          return;
        }
        if (raw.type === 'done') {
          doneMsg = { ok: !!raw.ok, value: typeof raw.value === 'string' ? raw.value : undefined, error: typeof raw.error === 'string' ? raw.error : undefined };
          return;
        }
        if (raw.type === 'call' && Number.isInteger(raw.id) && typeof raw.name === 'string') {
          const id: number = raw.id;
          const name: string = raw.name;
          queue = queue.then(async () => {
            if (settled) return;
            const reply = (m: Record<string, unknown>) => {
              if (!settled && child.connected) child.send({ type: 'result', id, ...m });
            };
            calls++;
            if (calls > maxCalls) return reply({ ok: false, error: `broker call limit (${maxCalls}) exceeded`, code: 'ERR_BROKER_LIMIT' });
            if (!toolNames.includes(name)) return reply({ ok: false, error: `unknown tool ${name}`, code: 'ERR_UNKNOWN_TOOL' });
            try {
              const value = await handler({ name, args: raw.args });
              reply({ ok: true, value: value === undefined ? null : value });
            } catch (e: any) {
              reply({ ok: false, error: String(e?.message ?? e).slice(0, 2000), code: e?.name === 'GovernorDenied' ? 'ERR_GOVERNOR_DENIED' : 'ERR_BROKER' });
            }
          });
        }
      });
    });
  }
}
