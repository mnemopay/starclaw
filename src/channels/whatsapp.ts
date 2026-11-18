import { createHmac, timingSafeEqual } from 'node:crypto';
import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from '../governance/types';
import type { StarClawEngine } from '../engine';
import { scrubSecrets } from './config';
import { GoalQueue, renderGoalResult } from './queue';
import type { ChannelRoute, RouteRequest } from './server';
import { isLoopbackHttp } from './slack';
import { ReplayGuard, SeenIds } from './verify';

/**
 * WhatsApp over Meta's official Cloud API. Goals arrive as signed webhooks (X-Hub-Signature-256 = HMAC-SHA256 of the raw
 * body with the app secret); replies, approvals and notifications go out through the Graph API with a token that never
 * leaves FetchWhatsAppApi. Only the owner's number counts. Approvals are two reply buttons that only resolve when pressed
 * from the owner's number on a request that is still pending.
 *
 * WhatsApp only lets a business send free-form messages within 24 hours of the person's last message: approvals and
 * notifications reach the owner only inside that window (send the bot any message to open it).
 */

export const WA_NUMBER_RE = /^[1-9]\d{6,14}$/; // E.164 digits, no '+'
const BUTTON_RE = /^sc:([ad]):([0-9a-f-]{36})$/;

export interface WhatsAppApi {
  sendText(to: string, text: string): Promise<void>;
  sendButtons(to: string, body: string, buttons: Array<{ id: string; title: string }>): Promise<void>;
}

export class FetchWhatsAppApi implements WhatsAppApi {
  readonly #token: string;
  constructor(token: string, private readonly phoneNumberId: string, private readonly version: string, private readonly base = 'https://graph.facebook.com') {
    if (token.length < 20 || /\s/.test(token)) throw new Error('the WhatsApp access token does not look like a token');
    if (!/^\d{5,25}$/.test(phoneNumberId)) throw new Error('the WhatsApp phone number id must be numeric');
    const u = new URL(base);
    if (u.protocol !== 'https:' && !isLoopbackHttp(u)) throw new Error('WhatsApp API base must be https (http only for loopback tests)');
    this.#token = token;
  }
  private async post(body: Record<string, unknown>): Promise<void> {
    let res: Response;
    try {
      res = await fetch(`${this.base}/${this.version}/${this.phoneNumberId}/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${this.#token}` },
        body: JSON.stringify({ messaging_product: 'whatsapp', recipient_type: 'individual', ...body }),
        signal: AbortSignal.timeout(30_000),
        redirect: 'error',
      });
    } catch (e: any) {
      throw new Error(`whatsapp send failed: ${scrubSecrets(String(e?.message ?? e), [this.#token]).slice(0, 200)}`);
    }
    if (!res.ok) {
      const t = await res.text().catch(() => '');
      throw new Error(`whatsapp send failed: HTTP ${res.status} ${scrubSecrets(t, [this.#token]).slice(0, 200)}`);
    }
  }
  sendText(to: string, text: string) {
    return this.post({ to, type: 'text', text: { body: text.slice(0, 4096), preview_url: false } });
  }
  sendButtons(to: string, body: string, buttons: Array<{ id: string; title: string }>) {
    return this.post({ to, type: 'interactive', interactive: { type: 'button', body: { text: body.slice(0, 1024) }, action: { buttons: buttons.slice(0, 3).map((b) => ({ type: 'reply', reply: { id: b.id, title: b.title.slice(0, 20) } })) } } });
  }
  toJSON() {
    return { token: '[redacted]' };
  }
}

export function assertWhatsAppOwner(n: string, who: string) {
  if (typeof n !== 'string' || !WA_NUMBER_RE.test(n)) throw new Error(`${who} requires the owner's WhatsApp number (international format, digits only)`);
}

export class WhatsAppApprover implements Approver {
  readonly name = 'whatsapp';
  readonly async = true;
  private pending = new Map<string, (a: ApprovalAnswer) => void>();
  constructor(private readonly api: WhatsAppApi, private readonly owner: string) {
    assertWhatsAppOwner(owner, 'WhatsAppApprover');
  }

  async request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    const full = describeRequest(req).slice(0, 3800) + `\n\nAuto-deny at ${new Date(req.expiresAt).toISOString()}`;
    return new Promise<ApprovalAnswer>((resolve) => {
      this.pending.set(req.id, resolve);
      const expire = () => {
        if (this.pending.delete(req.id)) resolve('deny');
      };
      if (signal.aborted) return expire();
      signal.addEventListener('abort', expire);
      // The full request first (a button message body is capped at 1024 chars), then the buttons.
      this.api
        .sendText(this.owner, full)
        .then(() => this.api.sendButtons(this.owner, `Approve request ${req.id.slice(0, 8)} (${req.action.class} ${req.action.target})?`.slice(0, 1000), [
          { id: `sc:a:${req.id}`, title: 'Approve' },
          { id: `sc:d:${req.id}`, title: 'Deny' },
        ]))
        .catch(() => {
          if (this.pending.delete(req.id)) resolve('deny');
        });
    });
  }

  /** A button press. Resolves only for the owner's number and a pending request; true if it was one of ours. */
  handleButton(from: string, id: string): boolean {
    const m = BUTTON_RE.exec(id);
    if (!m) return false;
    if (from !== this.owner) return true; // consumed, never resolves
    const resolve = this.pending.get(m[2]);
    if (!resolve) return true;
    this.pending.delete(m[2]);
    resolve(m[1] === 'a' ? 'approve' : 'deny');
    return true;
  }

  get pendingCount() {
    return this.pending.size;
  }
}

export interface WhatsAppGatewayOptions {
  engine: StarClawEngine;
  api: WhatsAppApi;
  approver: WhatsAppApprover;
  owner: string;
  allowPublic: boolean;
  queue: GoalQueue;
  toleranceSec: number;
  now?: () => number;
  log?: (s: string) => void;
}

/** Goals from WhatsApp text messages. Anyone but the owner is ignored, or with allowPublic runs as a TAINTED non-owner goal. */
export class WhatsAppGateway {
  private readonly seen = new SeenIds();
  constructor(private readonly o: WhatsAppGatewayOptions) {
    assertWhatsAppOwner(o.owner, 'WhatsAppGateway');
  }

  async onMessage(m: any): Promise<void> {
    if (!m || typeof m.from !== 'string' || !WA_NUMBER_RE.test(m.from) || typeof m.id !== 'string' || m.id.length > 200) return;
    if (!this.seen.firstTime(m.id)) return; // Meta redelivers
    const ts = Number(m.timestamp);
    const now = (this.o.now ?? Date.now)();
    if (!Number.isFinite(ts) || Math.abs(now / 1000 - ts) > Math.max(this.o.toleranceSec, 600)) return; // stale or replayed message
    if (m.type === 'interactive' && m.interactive?.type === 'button_reply' && typeof m.interactive.button_reply?.id === 'string') {
      this.o.approver.handleButton(m.from, m.interactive.button_reply.id);
      return;
    }
    if (m.type !== 'text' || typeof m.text?.body !== 'string') return;
    const isOwner = m.from === this.o.owner;
    if (!isOwner && !this.o.allowPublic) return;
    const text = m.text.body.trim();
    if (!text) return;
    const to: string = m.from;
    const send = (t: string) => this.o.api.sendText(to, t).catch(() => {});
    if (isOwner && text === '/new') {
      await send(this.o.engine.newSession() === false ? 'A goal is active or queued. Wait for it to finish before starting a new session.' : 'New session started (taint cleared).');
      return;
    }
    if (text.length > 8000) return void (await send('Goal too long (8000 chars max).'));
    const engine = this.o.engine;
    const job = this.o.queue.enqueue(async () => {
      await send(`Working on it${isOwner ? '' : ' (non-owner request: sensitive actions need the owner)'}...`);
      const r = await engine.executeGoal(text, { origin: isOwner ? 'owner' : 'non-owner', originRef: `whatsapp:${to}` });
      await send(renderGoalResult(r));
    });
    if (!job) return void (await send('Busy: too many goals queued. Try again later.'));
    await job.catch((e) => this.o.log?.(`whatsapp goal error: ${String(e?.message ?? e).slice(0, 200)}`));
  }
}

/** X-Hub-Signature-256: "sha256=" + hex HMAC-SHA256(appSecret, rawBody), compared in constant time. */
export function verifyMetaSignature(appSecret: string, header: string | undefined, rawBody: Buffer): boolean {
  if (!appSecret || typeof header !== 'string' || !/^sha256=[0-9a-f]{64}$/.test(header)) return false;
  const mac = createHmac('sha256', appSecret).update(rawBody).digest();
  const given = Buffer.from(header.slice(7), 'hex');
  return given.length === mac.length && timingSafeEqual(given, mac);
}

const hdr = (h: RouteRequest['headers'], name: string): string | undefined => {
  const v = h[name];
  return Array.isArray(v) ? v[0] : v;
};

/**
 * GET /whatsapp/webhook: Meta's one-time verification (hub.verify_token must equal the configured token).
 * POST /whatsapp/webhook: messages, signature checked first; a replayed signature is refused.
 */
export function whatsappRoutes(o: { gateway: WhatsAppGateway; appSecret: string; verifyToken: string; log?: (s: string) => void; now?: () => number }): ChannelRoute[] {
  const log = o.log ?? (() => {});
  const now = o.now ?? Date.now;
  const replay = new ReplayGuard(15 * 60_000);
  return [
    {
      path: '/whatsapp/webhook',
      async get(query) {
        const token = query.get('hub.verify_token') ?? '';
        const challenge = query.get('hub.challenge') ?? '';
        const ok = query.get('hub.mode') === 'subscribe' && token.length === o.verifyToken.length && timingSafeEqual(Buffer.from(token), Buffer.from(o.verifyToken));
        if (!ok || !/^[A-Za-z0-9._-]{1,200}$/.test(challenge)) return { status: 403, body: { error: 'forbidden' } };
        return { status: 200, body: challenge };
      },
      async handle(req) {
        const sig = hdr(req.headers, 'x-hub-signature-256');
        if (!verifyMetaSignature(o.appSecret, sig, req.rawBody)) {
          log('whatsapp request rejected: bad signature');
          return { status: 401, body: { error: 'unauthorized' } };
        }
        if (replay.isReplay(sig!, now())) {
          log('whatsapp request rejected: replay');
          return { status: 401, body: { error: 'unauthorized' } };
        }
        let p: any;
        try {
          p = JSON.parse(req.rawBody.toString('utf8'));
        } catch {
          return { status: 400, body: { error: 'bad request' } };
        }
        if (p?.object !== 'whatsapp_business_account' || !Array.isArray(p.entry)) return { status: 200, body: {} };
        for (const e of p.entry.slice(0, 20)) {
          for (const c of Array.isArray(e?.changes) ? e.changes.slice(0, 20) : []) {
            const msgs = c?.field === 'messages' && Array.isArray(c?.value?.messages) ? c.value.messages.slice(0, 50) : [];
            // Acknowledge at once; goals run in the background (Meta retries slow webhooks).
            for (const m of msgs) o.gateway.onMessage(m).catch((err) => log(`whatsapp message error: ${String(err?.message ?? err).slice(0, 200)}`));
          }
        }
        return { status: 200, body: {} };
      },
    },
  ];
}
