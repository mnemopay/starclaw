import * as dotenv from 'dotenv';
import { createEngine, CommonCliOptions } from './bootstrap';
import { ChannelRuntime, RunningChannels } from './channels/runtime';
import { GoalQueue } from './channels/queue';
import { loadPolicy } from './governance/policy';
import type { Approver } from './governance/types';
import type { OwnerNotifier } from './notify/Notifier';
import { FetchTelegramApi, TelegramApprover, TelegramPoller } from './channels/telegram';
import type { StarClawEngine } from './engine';
import { TelegramNotifier } from './notify/Notifier';
import { Scheduler } from './scheduler/Scheduler';
import { createTelegramHandler } from './telegram';

/** Wire a Scheduler to an engine. "Auto-paused" notices go to the owner through the engine's rate-limited system channel. */
export function createScheduler(engine: StarClawEngine, log: (s: string) => void = () => {}): Scheduler {
  return new Scheduler({
    store: engine.jobs,
    runner: engine,
    audit: engine.audit,
    policy: engine.policy.scheduled,
    log,
    onPaused: async (job, reason) => {
      await engine.notifySystem(`job "${job.name}" was paused: ${reason}`);
    },
  });
}

export interface DaemonOptions extends CommonCliOptions {
  /** Run without Telegram: jobs run, but (with Telegram as the owner channel) nothing can ask or message the owner: every `ask` is denied; tools.notifyOwner is unavailable. */
  noTelegram?: boolean;
}

/**
 * The long-running process: Telegram gateway (owner goals + approvals) plus the scheduler. Fail closed: with Telegram
 * enabled it refuses to start without TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID.
 */
export async function runDaemon(o: DaemonOptions): Promise<{ stop: () => void }> {
  dotenv.config({ quiet: true } as any);
  const policy = loadPolicy(o.policy);
  // Slack/Discord: resolved FIRST so a misconfigured enabled channel refuses to start (fail closed) before anything else runs.
  const channels = new ChannelRuntime(policy, process.env);
  const ownerChannel = policy.channels.ownerChannel;
  let approver: Approver | undefined = channels.ownerApprover;
  let notifier: OwnerNotifier | undefined = channels.ownerNotifier;
  let tgApprover: TelegramApprover | undefined;
  let api: FetchTelegramApi | undefined;
  let ownerId = 0;
  // The Telegram gateway runs only when Telegram is the owner channel (the default): its approvals/notifications are what it carries.
  if (!o.noTelegram && ownerChannel === 'telegram') {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const ownerRaw = process.env.TELEGRAM_OWNER_ID;
    if (!token || !ownerRaw || !/^-?\d+$/.test(ownerRaw)) throw new Error('TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID are required (or pass --no-telegram). Refusing to start.');
    ownerId = Number(ownerRaw);
    api = new FetchTelegramApi(token);
    tgApprover = new TelegramApprover(api, ownerId);
    approver = tgApprover;
    notifier = new TelegramNotifier(api, ownerId);
  }
  const engine = createEngine(o, approver, { notifier });
  await engine.boot();
  const scheduler = createScheduler(engine, (s) => console.error(s));
  scheduler.start();
  const goals = new GoalQueue(); // one queue for every chat channel: they share one engine session and one taint state
  let poller: TelegramPoller | undefined;
  if (api && tgApprover) {
    const handler = createTelegramHandler(engine, api, tgApprover, ownerId, process.env.TELEGRAM_ALLOW_PUBLIC === '1', goals);
    poller = new TelegramPoller(api, handler, (s) => console.error(s));
    void poller.run();
  }
  let hooks: RunningChannels | undefined;
  try {
    hooks = await channels.start(engine, goals, { log: (s) => console.error(s) });
  } catch (e) {
    scheduler.stop();
    poller?.stop();
    throw e;
  }
  const names = [channels.slack && 'slack', channels.discord && 'discord'].filter(Boolean).join('+') || 'off';
  console.error(`starclaw-daemon: running (telegram ${poller ? 'on' : 'off'}, webhook channels ${names}${hooks ? ' on 127.0.0.1:' + hooks.port : ''}, owner channel ${ownerChannel}, ${engine.jobs.list().length} job(s))`);
  return {
    stop: () => {
      scheduler.stop();
      poller?.stop();
      void hooks?.stop();
    },
  };
}
