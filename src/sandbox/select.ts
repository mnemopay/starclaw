import { ContainerSandbox } from './ContainerSandbox';
import { defaultImageTag } from './dockerImage';
import type { ProbeReport } from './probe';
import { ProcessSandbox } from './ProcessSandbox';
import { BrokerHandler, RunResult, Sandbox, SandboxUnavailable } from './types';

export type SandboxMode = 'auto' | 'container' | 'process';

export interface SelectConfig {
  mode: SandboxMode;
  requireContainer: boolean;
  workspaceDir: string;
  timeoutMs: number;
  maxOutputBytes: number;
  memoryMb: number;
  maxBrokerCalls: number;
  containerImage?: string;
  containerPidsLimit: number;
  containerRuntime?: string;
  /** Test injection. */
  container?: ContainerSandbox;
  process?: ProcessSandbox;
}

export interface Attempt {
  layer: 'container' | 'process';
  ok: boolean;
  detail: string;
}

/**
 * Chooses the isolation layer lazily (the container probe needs Docker, so it cannot run in a constructor):
 *  - container: container probe must pass, else refuse.
 *  - process:   process probe must pass, else refuse (unless requireContainer).
 *  - auto:      container if its probe passes; else process if ITS probe passes; else refuse.
 *  - requireContainer overrides mode: anything but a passing container probe means generated code does not run.
 */
export class SelectingSandbox implements Sandbox {
  readonly kind = 'auto' as const;
  active?: Sandbox;
  attempts: Attempt[] = [];
  private selecting?: Promise<Sandbox>;
  readonly container: ContainerSandbox;
  readonly proc: ProcessSandbox;

  constructor(readonly config: SelectConfig) {
    this.container =
      config.container ??
      new ContainerSandbox({
        image: config.containerImage ?? defaultImageTag(),
        timeoutMs: config.timeoutMs,
        maxOutputBytes: config.maxOutputBytes,
        memoryMb: config.memoryMb,
        pidsLimit: config.containerPidsLimit,
        maxBrokerCalls: config.maxBrokerCalls,
        runtime: config.containerRuntime,
      });
    this.proc =
      config.process ??
      new ProcessSandbox({ workspaceDir: config.workspaceDir, timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, memoryMb: config.memoryMb, maxBrokerCalls: config.maxBrokerCalls });
  }

  get effectiveMode(): SandboxMode {
    return this.config.requireContainer ? 'container' : this.config.mode;
  }

  get lastProbe(): ProbeReport | undefined {
    return this.active?.lastProbe ?? this.container.lastProbe ?? this.proc.lastProbe;
  }
  get containerProbe() {
    return this.container.lastProbe;
  }
  get processProbe() {
    return this.proc.lastProbe;
  }

  describe(): string {
    const mode = this.config.requireContainer ? 'container (--require-container)' : this.config.mode;
    if (!this.active) return `sandbox mode ${mode}: not selected yet${this.attempts.length ? ' (' + this.attempts.map((a) => `${a.layer}: ${a.ok ? 'ok' : 'unavailable'}`).join('; ') + ')' : ''}`;
    const why = this.attempts.filter((a) => !a.ok).map((a) => `${a.layer} layer unavailable: ${a.detail}`);
    return `ACTIVE LAYER: ${this.active.kind} (mode ${mode})${why.length ? ' because ' + why.join('; ') : ''}. ${this.active.describe()}`;
  }

  async ensureSafe(): Promise<ProbeReport> {
    if (!this.selecting) this.selecting = this.select();
    const active = await this.selecting;
    return active.ensureSafe();
  }

  private async tryLayer(layer: 'container' | 'process'): Promise<Sandbox | undefined> {
    const sb: Sandbox = layer === 'container' ? this.container : this.proc;
    try {
      await sb.ensureSafe();
      this.attempts.push({ layer, ok: true, detail: 'probe passed' });
      return sb;
    } catch (e: any) {
      this.attempts.push({ layer, ok: false, detail: String(e?.message ?? e).slice(0, 600) });
      return undefined;
    }
  }

  private async select(): Promise<Sandbox> {
    const mode = this.effectiveMode;
    let chosen: Sandbox | undefined;
    if (mode === 'container') chosen = await this.tryLayer('container');
    else if (mode === 'process') chosen = await this.tryLayer('process');
    else chosen = (await this.tryLayer('container')) ?? (await this.tryLayer('process'));
    if (!chosen) {
      const rc = this.config.requireContainer ? ' (--require-container is set)' : '';
      throw new SandboxUnavailable(`Refusing to run generated code${rc}: no isolation layer passed its probe in mode "${mode}". ${this.attempts.map((a) => `[${a.layer}] ${a.detail}`).join(' ')}`, this.lastProbe);
    }
    this.active = chosen;
    return chosen;
  }

  async run(code: string, handler: BrokerHandler): Promise<RunResult> {
    await this.ensureSafe();
    return this.active!.run(code, handler);
  }
}
