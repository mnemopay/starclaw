import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from '../governance/types';
import type { StarClawEngine } from '../engine';
import { SLACK_TOKEN_RE, SLACK_USER_ID_RE, scrubSecrets } from './config';
import { GoalQueue, renderGoalResult } from './queue';
import type { ChannelRoute, RouteRequest, RouteResponse } from './server';
import { ReplayGuard, SeenIds, verifySlackSignature } from './verify';

/** Minimal Slack Web API surface (fakeable in tests). The bot token never leaves FetchSlackApi. */
export interface SlackApi {
  call(method: string, params: Record<string, unknown>): Promise<any>;
}

export function isLoopbackHttp(u: URL) {
  return u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
}

export class FetchSlackApi implements SlackApi {
  /** `base` exists for tests (a local fake). It is a constructor argument only, never read from env or policy, so the token cannot be pointed elsewhere by config. */
  readonly #token: string;
  constructor(token: string, private readonly base = 'https://slack.com') {
    if (!SLACK_TOKEN_RE.test(token)) throw new Error('the Slack bot token does not look like a bot token (xoxb-...)');
    this.#token = token;
    const u = new URL(base);
    if (u.protocol !== 'https:' && !isLoopbackHttp(u)) throw new Error('Slack API base must be https (http only for loopback tests)');
  }
  async call(method: string, params: Record<string, unknown>): Promise<any> {
    if (!/^[a-z]+\.[A-Za-z.]+$/.test(method)) throw new Error('invalid Slack method name');
    let res: Response;
    try {
      res = await fetch(`${this.base}/api/${method}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8', authorization: `Bearer ${this.#token}` },
        body: JSON.stringify(params),
        signal: AbortSignal.timeout(30_000),
        redirect: 'error', // never forward the Authorization header to another host
      });
    } catch (e: any) {
      throw new Error(`slack ${method} request failed: ${scrubSecrets(String(e?.message ?? e), [this.#token]).slice(0, 200)}`);
    }
    const body: any = await res.json().catch(() => ({}));
    if (!res.ok || !body.ok) throw new Error(`slack ${method} failed: HTTP ${res.status} ${scrubSecrets(String(body?.error ?? ''), [this.#token]).slice(0, 100)}`.trim());
    return body;
  }
  toJSON() {
    return { token: '[redacted]' };
  }
}

/** Slack's text format treats & < > specially: neutralise them so agent/model output cannot inject mentions or links. */
export function slackEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function slackUnescape(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}
const PLAIN = { mrkdwn: false, link_names: false, unfurl_links: false, unfurl_media: false } as const;

const ACTION_RE = /^sc:([ad]):([0-9a-f-]{36})$/;

/** The one structural check shared by approver, notifier and gateway. */
export function assertSlackOwnerId(ownerId: string, who: string) {
  if (typeof ownerId !== 'string' || !SLACK_USER_ID_RE.test(ownerId)) throw new Error(`${who} requires the owner's Slack member id (U...)`);
}

interface SlackInteraction {
  type?: string;
  user?: { id?: string };
  channel?: { id?: string };
  container?: { channel_id?: string; message_ts?: string };
  message?: { ts?: string };
  actions?: Array<{ action_id?: string; value?: string }>;
}

/**
 * Approvals over Slack. The request is DMed to the owner (there is no recipient parameter) with Approve/Deny buttons.
 * A click counts only if the Slack user id equals the owner id AND it came from the very message we posted (channel and
 * ts both match); every other click, malformed value, or replay is ignored. A timeout/abort is a deny.
 */
export class SlackApprover implements Approver {
  readonly name = 'slack';
  /** Reaches the owner away from the terminal: scheduled (unattended) runs may use it for approvals. */
  readonly async = true;
  private pending = new Map<string, { resolve: (a: ApprovalAnswer) => void; channel?: string; ts?: string }>();

  constructor(private readonly api: SlackApi, private readonly ownerId: string) {
    assertSlackOwnerId(ownerId, 'SlackApprover');
  }

  async request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    const text = describeRequest(req).slice(0, 2800) + `\n\nAuto-deny at ${new Date(req.expiresAt).toISOString()}`;
    return new Promise<ApprovalAnswer>((resolve) => {
      // Register BEFORE sending so a fast click cannot arrive for a request we do not know about yet.
      const entry: { resolve: (a: ApprovalAnswer) => void; channel?: string; ts?: string } = { resolve };
      this.pending.set(req.id, entry);
      const expire = () => {
        if (this.pending.delete(req.id)) {
          if (entry.channel && entry.ts) this.api.call('chat.update', { channel: entry.channel, ts: entry.ts, text: `Request ${req.id} expired: DENIED (timeout)`, blocks: [] }).catch(() => {});
          resolve('deny');
        }
      };
      if (signal.aborted) return expire();
      signal.addEventListener('abort', expire);
      this.api
        .call('chat.postMessage', {
          channel: this.ownerId,
          text: `StarClaw approval request ${req.id}`,
          blocks: [
            { type: 'section', text: { type: 'plain_text', text, emoji: false } },
            {
              type: 'actions',
              block_id: `sc_${req.id}`,
              elements: [
                { type: 'button', action_id: 'sc_approve', style: 'primary', text: { type: 'plain_text', text: 'Approve' }, value: `sc:a:${req.id}` },
                { type: 'button', action_id: 'sc_deny', style: 'danger', text: { type: 'plain_text', text: 'Deny' }, value: `sc:d:${req.id}` },
              ],
            },
          ],
        })
        .then((sent) => {
          entry.channel = typeof sent?.channel === 'string' ? sent.channel : undefined;
          entry.ts = typeof sent?.ts === 'string' ? sent.ts : undefined;
          if (signal.aborted) expire();
        })
        .catch(() => {
          // Could not reach the owner: nobody can approve, so it is a deny (the Governor would time out anyway).
          if (this.pending.delete(req.id)) resolve('deny');
        });
    });
  }

  /** Feed every interactivity payload here. Returns true if it was one of OUR approval buttons (answered or refused). */
  async handleInteraction(p: SlackInteraction): Promise<boolean> {
    if (p?.type !== 'block_actions' || !Array.isArray(p.actions)) return false;
    const a = p.actions[0];
    const m = typeof a?.value === 'string' ? ACTION_RE.exec(a.value) : null;
    if (!m) return false;
    const entry = this.pending.get(m[2]);
    const userId = p.user?.id;
    const channel = p.channel?.id ?? p.container?.channel_id;
    const ts = p.message?.ts ?? p.container?.message_ts;
    const fromOwner = userId === this.ownerId && !!entry && entry.channel !== undefined && channel === entry.channel && entry.ts !== undefined && ts === entry.ts;
    if (!fromOwner) {
      if (typeof userId === 'string' && SLACK_USER_ID_RE.test(userId) && typeof channel === 'string' && /^[A-Z0-9]{3,32}$/.test(channel)) {
        await this.api.call('chat.postEphemeral', { channel, user: userId, text: userId === this.ownerId && !entry ? 'Request no longer pending.' : 'Not authorised.' }).catch(() => {});
      }
      return true; // consumed, but never resolves the request
    }
    this.pending.delete(m[2]);
    const answer: ApprovalAnswer = m[1] === 'a' ? 'approve' : 'deny';
    entry!.resolve(answer);
    await this.api.call('chat.update', { channel: entry!.channel, ts: entry!.ts, text: `Request ${m[2]}: ${answer === 'approve' ? 'APPROVED' : 'DENIED'}`, blocks: [] }).catch(() => {});
    return true;
  }

  get pendingCount() {
    return this.pending.size;
  }
}

export interface SlackGatewayOptions {
  engine: StarClawEngine;
  api: SlackApi;
  ownerId: string;
  allowPublic: boolean;
  queue: GoalQueue;
  log?: (s: string) => void;
}

/**
 * Goals from Slack. Accepts only direct messages to the bot (message.im). The owner's id must match exactly. Anyone else is
 * ignored, or with `allowPublic` runs as a NON-OWNER goal (the session is tainted from the start, exactly like Telegram).
 * The bot's own messages and edits/other subtypes are ignored so it can never talk to itself.
 */
export class SlackGateway {
  private readonly log: (s: string) => void;
  private readonly seenEvents = new SeenIds();
  constructor(private readonly o: SlackGatewayOptions) {
    assertSlackOwnerId(o.ownerId, 'SlackGateway');
    this.log = o.log ?? (() => {});
  }

  /** True the first time an event id is seen (Slack redelivers events it believes were not acknowledged). */
  firstDelivery(eventId: unknown): boolean {
    return typeof eventId === 'string' && eventId.length > 0 && eventId.length < 100 && this.seenEvents.firstTime(eventId);
  }

  async onEvent(ev: any): Promise<void> {
    if (!ev || ev.type !== 'message' || ev.channel_type !== 'im') return;
    if (ev.bot_id || ev.subtype || typeof ev.text !== 'string' || typeof ev.user !== 'string' || typeof ev.channel !== 'string') return;
    if (!SLACK_USER_ID_RE.test(ev.user) || !/^[A-Z0-9]{3,32}$/.test(ev.channel)) return;
    const isOwner = ev.user === this.o.ownerId;
    if (!isOwner && !this.o.allowPublic) return; // silently ignored
    const text = slackUnescape(ev.text).trim();
    if (!text) return;
    const channel: string = ev.channel;
    const send = (t: string) => this.o.api.call('chat.postMessage', { channel, text: slackEscape(t).slice(0, 3900), ...PLAIN }).catch(() => {});
    if (isOwner && text === '/new') {
      this.o.engine.newSession();
      await send('New session started (taint cleared).');
      return;
    }
    if (text.length > 8000) {
      await send('Goal too long (8000 chars max).');
      return;
    }
    const engine = this.o.engine;
    const job = this.o.queue.enqueue(async () => {
      await send(`Working on it${isOwner ? '' : ' (non-owner request: sensitive actions need the owner)'}...`);
      const r = await engine.executeGoal(text, { origin: isOwner ? 'owner' : 'non-owner', originRef: `slack:${ev.user}` });
      await send(renderGoalResult(r));
    });
    if (!job) {
      await send('Busy: too many goals queued. Try again later.');
      return;
    }
    await job.catch((e) => this.log(`slack goal error: ${String(e?.message ?? e).slice(0, 200)}`));
  }
}

const hdr = (h: RouteRequest['headers'], name: string): string | undefined => {
  const v = h[name];
  return Array.isArray(v) ? v[0] : v;
};

export interface SlackRouteOptions {
  gateway: SlackGateway;
  approver: SlackApprover;
  signingSecret: string;
  toleranceSec: number;
  now?: () => number;
  log?: (s: string) => void;
}

/** POST /slack/events (Events API, JSON) and POST /slack/interactions (buttons, form-encoded). Both verify X-Slack-Signature first. */
export function slackRoutes(o: SlackRouteOptions): ChannelRoute[] {
  const now = o.now ?? Date.now;
  const log = o.log ?? (() => {});
  const replay = new ReplayGuard((o.toleranceSec + 60) * 1000);
  const authenticate = (req: RouteRequest): RouteResponse | undefined => {
    const v = verifySlackSignature({
      signingSecret: o.signingSecret,
      timestamp: hdr(req.headers, 'x-slack-request-timestamp'),
      signature: hdr(req.headers, 'x-slack-signature'),
      rawBody: req.rawBody,
      nowMs: now(),
      toleranceSec: o.toleranceSec,
    });
    if (!v.ok) {
      log(`slack request rejected: ${v.reason}`);
      return { status: 401, body: { error: 'unauthorized' } };
    }
    if (replay.isReplay(hdr(req.headers, 'x-slack-signature')!, now())) {
      log('slack request rejected: replay');
      return { status: 401, body: { error: 'unauthorized' } };
    }
    return undefined;
  };
  return [
    {
      path: '/slack/events',
      async handle(req) {
        const denied = authenticate(req);
        if (denied) return denied;
        let p: any;
        try {
          p = JSON.parse(req.rawBody.toString('utf8'));
        } catch {
          return { status: 400, body: { error: 'bad request' } };
        }
        if (p?.type === 'url_verification' && typeof p.challenge === 'string' && p.challenge.length <= 500) return { status: 200, body: { challenge: p.challenge } };
        if (p?.type === 'event_callback' && o.gateway.firstDelivery(p.event_id)) {
          // Acknowledge at once (Slack wants a reply within 3 s); a long goal must not block approval clicks.
          o.gateway.onEvent(p.event).catch((e) => log(`slack event error: ${String(e?.message ?? e).slice(0, 200)}`));
        }
        return { status: 200, body: {} };
      },
    },
    {
      path: '/slack/interactions',
      async handle(req) {
        const denied = authenticate(req);
        if (denied) return denied;
        let payload: any;
        try {
          const raw = new URLSearchParams(req.rawBody.toString('utf8')).get('payload');
          payload = raw ? JSON.parse(raw) : undefined;
        } catch {
          payload = undefined;
        }
        if (!payload || typeof payload !== 'object') return { status: 400, body: { error: 'bad request' } };
        await o.approver.handleInteraction(payload);
        return { status: 200, body: '' };
      },
    },
  ];
}
