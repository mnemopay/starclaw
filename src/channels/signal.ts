import type { StarClawEngine } from '../engine';
import { CodeApprover } from './codeApproval';
import { GoalQueue, renderGoalResult } from './queue';
import { isLoopbackHttp } from './slack';
import { SeenIds } from './verify';

/**
 * Signal through a signal-cli-rest-api bridge that YOU run on this PC (https://github.com/bbernhard/signal-cli-rest-api).
 * Signal has no official bot API; the bridge holds the bot account's keys and does the end-to-end encryption, so the
 * sender number it reports is Signal-verified. StarClaw talks to it on loopback only and never exposes it.
 * Approvals are code replies ("yes CODE" / "no CODE") from the owner's number.
 */

export const SIGNAL_NUMBER_RE = /^\+[1-9]\d{6,14}$/;

export interface SignalEnvelope { source?: string; sourceNumber?: string; timestamp?: number; dataMessage?: { message?: string | null; timestamp?: number } }
export interface SignalApi {
  receive(): Promise<SignalEnvelope[]>;
  send(to: string, text: string): Promise<void>;
}

export class FetchSignalApi implements SignalApi {
  private readonly base: string;
  constructor(base: string, private readonly account: string) {
    const u = new URL(base);
    if (!isLoopbackHttp(u) && !(u.protocol === 'https:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname))) throw new Error('the Signal bridge must be on this PC (http://127.0.0.1:PORT)');
    if (!SIGNAL_NUMBER_RE.test(account)) throw new Error('the Signal bot account must be a number in +international format');
    this.base = base.replace(/\/+$/, '');
  }
  async receive(): Promise<SignalEnvelope[]> {
    const res = await fetch(`${this.base}/v1/receive/${encodeURIComponent(this.account)}?timeout=20`, { signal: AbortSignal.timeout(40_000), redirect: 'error' });
    if (!res.ok) throw new Error(`signal receive failed: HTTP ${res.status}`);
    const j: any = await res.json();
    return Array.isArray(j) ? j.map((x: any) => x?.envelope).filter(Boolean).slice(0, 200) : [];
  }
  async send(to: string, text: string): Promise<void> {
    const res = await fetch(`${this.base}/v2/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ number: this.account, recipients: [to], message: text.slice(0, 6000) }),
      signal: AbortSignal.timeout(30_000),
      redirect: 'error',
    });
    if (!res.ok) throw new Error(`signal send failed: HTTP ${res.status}`);
  }
}

export interface SignalGatewayOptions {
  engine: StarClawEngine;
  api: SignalApi;
  approver: CodeApprover;
  owner: string;
  allowPublic: boolean;
  queue: GoalQueue;
  log?: (s: string) => void;
}

/** Handles one received envelope: approval code replies first, then goals (owner, or tainted non-owner with allowPublic). */
export class SignalGateway {
  private readonly seen = new SeenIds();
  constructor(private readonly o: SignalGatewayOptions) {
    if (!SIGNAL_NUMBER_RE.test(o.owner)) throw new Error("SignalGateway requires the owner's number in +international format");
  }

  async onEnvelope(env: SignalEnvelope): Promise<void> {
    const from = env.sourceNumber ?? env.source;
    const text = env.dataMessage?.message;
    if (typeof from !== 'string' || !SIGNAL_NUMBER_RE.test(from) || typeof text !== 'string') return;
    const key = `${from}:${env.dataMessage?.timestamp ?? env.timestamp}`;
    if (!this.seen.firstTime(key)) return;
    const isOwner = from === this.o.owner;
    const send = (t: string) => this.o.api.send(from, t).catch(() => {});
    const r = this.o.approver.handleReply(text, isOwner);
    if (r === 'answered') return void (await send('Got it.'));
    if (r === 'not-pending') return void (await send('That request is no longer pending.'));
    if (!isOwner && !this.o.allowPublic) return;
    const goal = text.trim();
    if (!goal) return;
    if (isOwner && goal === '/new') return void (await send(this.o.engine.newSession() === false ? 'A goal is active or queued. Wait for it to finish before starting a new session.' : 'New session started (taint cleared).'));
    if (goal.length > 8000) return void (await send('Goal too long (8000 chars max).'));
    const engine = this.o.engine;
    const job = this.o.queue.enqueue(async () => {
      await send(`Working on it${isOwner ? '' : ' (non-owner request: sensitive actions need the owner)'}...`);
      const res = await engine.executeGoal(goal, { origin: isOwner ? 'owner' : 'non-owner', originRef: `signal:${from}` });
      await send(renderGoalResult(res));
    });
    if (!job) return void (await send('Busy: too many goals queued. Try again later.'));
    await job.catch((e) => this.o.log?.(`signal goal error: ${String(e?.message ?? e).slice(0, 200)}`));
  }
}

/** Polls the bridge. Errors back off; handlers are not awaited, so a long goal never blocks approval replies. */
export class SignalPoller {
  private stopped = false;
  constructor(private readonly api: SignalApi, private readonly gateway: SignalGateway, private readonly log: (s: string) => void = () => {}, private readonly idleMs = 1000) {}
  async run(): Promise<void> {
    while (!this.stopped) {
      try {
        const envs = await this.api.receive();
        for (const e of envs) this.gateway.onEnvelope(e).catch((err) => this.log(`signal handler error: ${err?.message ?? err}`));
        if (!envs.length) await new Promise((r) => setTimeout(r, this.idleMs));
      } catch (e: any) {
        this.log(`signal poll error: ${String(e?.message ?? e).slice(0, 200)}`);
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }
  stop() {
    this.stopped = true;
  }
}
