import type { ProbeReport } from './probe';

export interface BrokerCall {
  name: string;
  args: unknown;
}
export type BrokerHandler = (call: BrokerCall) => Promise<unknown>;

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
  /** Frames printed by generated code that looked like protocol frames but did not carry the secret nonce. */
  forgedFrames?: number;
  /** Container mode: the container's exit code when known (137 = SIGKILL, e.g. OOM kill). */
  exitCode?: number | null;
}

export class SandboxUnavailable extends Error {
  constructor(msg: string, public readonly report?: ProbeReport) {
    super(msg);
    this.name = 'SandboxUnavailable';
  }
}

/** Tool names the runner may expose. Kept here so the broker and the sandbox agree. */
export const DEFAULT_TOOL_NAMES = ['readFile', 'writeFile', 'listDir', 'applyPatch', 'editFile', 'fetchUrl', 'search', 'runCommand', 'shell', 'notifyOwner', 'scheduleCreate', 'spend', 'browseOpen', 'browseNavigate', 'browseReadText', 'browseReadLinks', 'browseClose'];

export type SandboxKind = 'process' | 'container';

/** What the engine needs from any isolation layer. */
export interface Sandbox {
  readonly kind: SandboxKind | 'auto';
  /** Probe (once) and throw SandboxUnavailable unless every forbidden operation is denied. */
  ensureSafe(): Promise<ProbeReport>;
  /** ensureSafe(), then run. Broker calls are handled one at a time, in order. */
  run(code: string, handler: BrokerHandler): Promise<RunResult>;
  readonly lastProbe: ProbeReport | undefined;
  /** One human line: which layer is active and why. */
  describe(): string;
}
