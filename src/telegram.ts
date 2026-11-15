#!/usr/bin/env node
import * as dotenv from 'dotenv';
import { createEngine } from './bootstrap';
import { FetchTelegramApi, TelegramApprover, TelegramPoller, TelegramUpdate, TelegramApi } from './channels/telegram';
import type { StarClawEngine } from './engine';

/**
 * Telegram gateway. Fail closed: refuses to start without TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID.
 * Only the owner can give goals or answer approvals. Messages from anyone else are ignored unless
 * TELEGRAM_ALLOW_PUBLIC=1, in which case they run as NON-OWNER goals (the session is tainted from the start,
 * so exec/network/spend/skill-save always need the owner's approval).
 */
export function createTelegramHandler(engine: StarClawEngine, api: TelegramApi, approver: TelegramApprover, ownerId: number, allowPublic: boolean) {
  let queue: Promise<void> = Promise.resolve();
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
    queue = queue.then(async () => {
      await send(m.chat.id, `Working on it${isOwner ? '' : ' (non-owner request: sensitive actions need the owner)'}...`);
      const r = await engine.executeGoal(m.text!, { origin, originRef: `telegram:${m.from?.id ?? 'unknown'}` });
      const body = r.success ? [r.reply, r.stdout, r.result === undefined || r.result === null ? '' : typeof r.result === 'string' ? r.result : JSON.stringify(r.result)].filter(Boolean).join('\n') || 'Done.' : `Failed: ${r.error}`;
      await send(m.chat.id, body + (r.tainted ? '\n[session tainted]' : ''));
    });
    await queue.catch(() => {});
  };
}

async function main() {
  dotenv.config({ quiet: true } as any);
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const ownerRaw = process.env.TELEGRAM_OWNER_ID;
  if (!token || !ownerRaw || !/^-?\d+$/.test(ownerRaw)) {
    console.error('starclaw-telegram: TELEGRAM_BOT_TOKEN and a numeric TELEGRAM_OWNER_ID are required. Refusing to start.');
    process.exit(1);
  }
  const ownerId = Number(ownerRaw);
  const api = new FetchTelegramApi(token);
  const approver = new TelegramApprover(api, ownerId);
  const engine = createEngine({ policy: process.env.STARCLAW_POLICY }, approver);
  await engine.boot();
  const handler = createTelegramHandler(engine, api, approver, ownerId, process.env.TELEGRAM_ALLOW_PUBLIC === '1');
  console.log('starclaw-telegram: running');
  await new TelegramPoller(api, handler, (s) => console.error(s)).run();
}

if (require.main === module) main().catch((e) => { console.error(`starclaw-telegram: ${e.message}`); process.exit(1); });
