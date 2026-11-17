#!/usr/bin/env node
import type { TelegramApprover, TelegramUpdate, TelegramApi } from './channels/telegram';
import type { StarClawEngine } from './engine';
import { GoalQueue, renderGoalResult } from './channels/queue';

/**
 * Telegram gateway. Fail closed: refuses to start without TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID.
 * Only the owner can give goals or answer approvals. Messages from anyone else are ignored unless
 * TELEGRAM_ALLOW_PUBLIC=1, in which case they run as NON-OWNER goals (the session is tainted from the start,
 * so exec/network/spend/skill-save always need the owner's approval).
 */
export function createTelegramHandler(engine: StarClawEngine, api: TelegramApi, approver: TelegramApprover, ownerId: number, allowPublic: boolean, goals: GoalQueue = new GoalQueue()) {
  const send = (chat: number, text: string) => api.call('sendMessage', { chat_id: chat, text: text.slice(0, 3900) }).catch(() => {});
  return async (u: TelegramUpdate) => {
    if (await approver.handleUpdate(u)) return;
    const m = u.message;
    if (!m || typeof m.text !== 'string') return;
    const isOwner = m.from?.id === ownerId && m.chat.id === ownerId;
    if (!isOwner && !allowPublic) return; // silently ignored
    if (isOwner && m.text === '/new') {
      engine.newSession();
      await send(m.chat.id, 'New session started (taint cleared).');
      return;
    }
    if (m.text === '/start') {
      await send(m.chat.id, 'StarClaw is online. Risky actions will ask the owner for approval.');
      return;
    }
    const origin = isOwner ? 'owner' : 'non-owner';
    // One queue shared with the Slack/Discord gateways (when enabled): they all drive the same engine session and taint state.
    const job = goals.enqueue(async () => {
      await send(m.chat.id, `Working on it${isOwner ? '' : ' (non-owner request: sensitive actions need the owner)'}...`);
      const r = await engine.executeGoal(m.text!, { origin, originRef: `telegram:${m.from?.id ?? 'unknown'}` });
      await send(m.chat.id, renderGoalResult(r));
    });
    if (!job) {
      await send(m.chat.id, 'Busy: too many goals queued. Try again later.');
      return;
    }
    await job.catch(() => {});
  };
}

async function main() {
  // Same process as "starclaw daemon": Telegram gateway + scheduler. Refuses to start without a token and a numeric owner id.
  const { runDaemon } = await import('./daemon');
  await runDaemon({ policy: process.env.STARCLAW_POLICY });
}

if (require.main === module) main().catch((e) => { console.error(`starclaw-telegram: ${e.message}`); process.exit(1); });
