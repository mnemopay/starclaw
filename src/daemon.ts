import * as dotenv from 'dotenv';
import { createEngine, CommonCliOptions } from './bootstrap';
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
  /** Run without Telegram: jobs run, but nothing can ask or message the owner (every `ask` is denied; tools.notifyOwner is unavailable). */
  noTelegram?: boolean;
}

/**
 * The long-running process: Telegram gateway (owner goals + approvals) plus the scheduler. Fail closed: with Telegram
 * enabled it refuses to start without TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID.
 */
export async function runDaemon(o: DaemonOptions): Promise<{ stop: () => void }> {
  dotenv.config({ quiet: true } as any);
  let approver: TelegramApprover | undefined;
  let notifier: TelegramNotifier | undefined;
  let api: FetchTelegramApi | undefined;
  let ownerId = 0;
  if (!o.noTelegram) {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const ownerRaw = process.env.TELEGRAM_OWNER_ID;
    if (!token || !ownerRaw || !/^-?\d+$/.test(ownerRaw)) throw new Error('TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID are required (or pass --no-telegram). Refusing to start.');
    ownerId = Number(ownerRaw);
    api = new FetchTelegramApi(token);
    approver = new TelegramApprover(api, ownerId);
    notifier = new TelegramNotifier(api, ownerId);
  }
  const engine = createEngine(o, approver, { notifier });
  await engine.boot();
  const scheduler = createScheduler(engine, (s) => console.error(s));
  scheduler.start();
  let poller: TelegramPoller | undefined;
  if (api && approver) {
    const handler = createTelegramHandler(engine, api, approver, ownerId, process.env.TELEGRAM_ALLOW_PUBLIC === '1');
    poller = new TelegramPoller(api, handler, (s) => console.error(s));
    void poller.run();
  }
  console.error(`starclaw-daemon: running (telegram ${poller ? 'on' : 'off'}, ${engine.jobs.list().length} job(s))`);
  return {
    stop: () => {
      scheduler.stop();
      poller?.stop();
    },
  };
}
