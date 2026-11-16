import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from '../governance/types';

/** Minimal Telegram Bot API surface (fakeable in tests). The token never leaves FetchTelegramApi. */
export interface TelegramApi {
  call(method: string, params: Record<string, unknown>): Promise<any>;
}

export class FetchTelegramApi implements TelegramApi {
  constructor(private readonly token: string, private readonly base = 'https://api.telegram.org') {
    if (!/^\d+:[A-Za-z0-9_-]{20,}$/.test(token)) throw new Error('TELEGRAM_BOT_TOKEN does not look like a bot token');
  }
  async call(method: string, params: Record<string, unknown>): Promise<any> {
    const res = await fetch(`${this.base}/bot${this.token}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(60_000),
    });
    const body: any = await res.json().catch(() => ({}));
    if (!res.ok || !body.ok) throw new Error(`telegram ${method} failed: HTTP ${res.status} ${body?.description ?? ''}`.trim());
    return body.result;
  }
}

export interface TelegramUpdate {
  update_id: number;
  message?: { message_id: number; text?: string; chat: { id: number }; from?: { id: number } };
  callback_query?: { id: string; from: { id: number }; data?: string; message?: { message_id: number; chat: { id: number } } };
}

const CB_PREFIX = 'sc';

/**
 * Approvals over Telegram. Only the configured owner may answer: the callback's sender id AND the chat id must
 * both equal `ownerId`. Inline Approve/Deny buttons; the timeout (enforced by the Governor, and mirrored here by
 * the abort signal) is a deny. Constructing without an owner id throws (fail closed).
 */
export class TelegramApprover implements Approver {
  readonly name = 'telegram';
  /** Reaches the owner away from the terminal: scheduled (unattended) runs may use it for approvals. */
  readonly async = true;
  private pending = new Map<string, { resolve: (a: ApprovalAnswer) => void; chatId: number; messageId?: number }>();

  constructor(private readonly api: TelegramApi, private readonly ownerId: number) {
    if (!Number.isSafeInteger(ownerId) || ownerId === 0) throw new Error('TelegramApprover requires a numeric owner chat id');
  }

  async request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    const text = describeRequest(req).slice(0, 3900) + `\n\nAuto-deny at ${new Date(req.expiresAt).toISOString()}`;
    const sent = await this.api.call('sendMessage', {
      chat_id: this.ownerId,
      text,
      reply_markup: {
        inline_keyboard: [[
          { text: 'Approve', callback_data: `${CB_PREFIX}:a:${req.id}` },
          { text: 'Deny', callback_data: `${CB_PREFIX}:d:${req.id}` },
        ]],
      },
    });
    if (signal.aborted) return 'deny'; // expired while the message was being sent
    return new Promise<ApprovalAnswer>((resolve) => {
      const entry = { resolve, chatId: this.ownerId, messageId: sent?.message_id as number | undefined };
      this.pending.set(req.id, entry);
      signal.addEventListener('abort', () => {
        if (this.pending.delete(req.id)) {
          this.api.call('editMessageText', { chat_id: entry.chatId, message_id: entry.messageId, text: `Request ${req.id} expired: DENIED (timeout)` }).catch(() => {});
          resolve('deny');
        }
      });
    });
  }

  /** Feed every update from the gateway here. Returns true if the update was an approval answer. */
  async handleUpdate(u: TelegramUpdate): Promise<boolean> {
    const cq = u.callback_query;
    if (!cq || typeof cq.data !== 'string') return false;
    const m = /^sc:([ad]):([0-9a-f-]{36})$/.exec(cq.data);
    if (!m) return false;
    const entry = this.pending.get(m[2]);
    const fromOwner = cq.from?.id === this.ownerId && cq.message?.chat?.id === this.ownerId;
    if (!fromOwner) {
      await this.api.call('answerCallbackQuery', { callback_query_id: cq.id, text: 'Not authorised.' }).catch(() => {});
      return true; // consumed, but never resolves the request
    }
    if (!entry) {
      await this.api.call('answerCallbackQuery', { callback_query_id: cq.id, text: 'Request no longer pending.' }).catch(() => {});
      return true;
    }
    this.pending.delete(m[2]);
    const answer: ApprovalAnswer = m[1] === 'a' ? 'approve' : 'deny';
    entry.resolve(answer);
    await this.api.call('answerCallbackQuery', { callback_query_id: cq.id, text: answer === 'approve' ? 'Approved' : 'Denied' }).catch(() => {});
    if (entry.messageId !== undefined) {
      await this.api.call('editMessageText', { chat_id: entry.chatId, message_id: entry.messageId, text: `Request ${m[2]}: ${answer === 'approve' ? 'APPROVED' : 'DENIED'}` }).catch(() => {});
    }
    return true;
  }

  get pendingCount() {
    return this.pending.size;
  }
}

/** Long-polling loop. Calls `onUpdate` for every update; errors back off and never crash the process. */
export class TelegramPoller {
  private offset = 0;
  private stopped = false;
  constructor(private readonly api: TelegramApi, private readonly onUpdate: (u: TelegramUpdate) => Promise<void>, private readonly log: (s: string) => void = () => {}) {}

  async run(): Promise<void> {
    while (!this.stopped) {
      try {
        const updates: TelegramUpdate[] = await this.api.call('getUpdates', { offset: this.offset, timeout: 30, allowed_updates: ['message', 'callback_query'] });
        for (const u of updates) {
          this.offset = Math.max(this.offset, u.update_id + 1);
          // Do not await: a long-running goal must not block approval callbacks.
          this.onUpdate(u).catch((e) => this.log(`update handler error: ${e?.message ?? e}`));
        }
      } catch (e: any) {
        this.log(`poll error: ${e?.message ?? e}`);
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }
  stop() {
    this.stopped = true;
  }
}
