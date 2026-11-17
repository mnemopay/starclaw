import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from '../governance/types';
import type { StarClawEngine } from '../engine';
import { DISCORD_SNOWFLAKE_RE, DISCORD_TOKEN_RE, scrubSecrets } from './config';
import { GoalQueue, renderGoalResult } from './queue';
import type { ChannelRoute, RouteRequest } from './server';
import { isLoopbackHttp } from './slack';
import { ReplayGuard, verifyDiscordSignature } from './verify';
import type { KeyObject } from 'node:crypto';

export type DiscordMethod = 'GET' | 'POST' | 'PATCH' | 'PUT';

/** Minimal Discord REST surface (fakeable in tests). The bot token never leaves FetchDiscordApi. */
export interface DiscordApi {
  call(method: DiscordMethod, path: string, body?: unknown): Promise<any>;
}

/** A path with anything token-like collapsed, safe to put in an error message. */
function labelPath(p: string): string {
  return p
    .split('/')
    .map((seg) => (seg.length > 24 && !/^@/.test(seg) ? ':id' : seg))
    .join('/')
    .slice(0, 80);
}

export class FetchDiscordApi implements DiscordApi {
  /** `base` is a constructor argument only (tests); never from env or policy. */
  readonly #token: string;
  constructor(token: string, private readonly base = 'https://discord.com/api/v10') {
    if (!DISCORD_TOKEN_RE.test(token)) throw new Error('the Discord bot token does not look like a bot token');
    this.#token = token;
    const u = new URL(base);
    if (u.protocol !== 'https:' && !isLoopbackHttp(u)) throw new Error('Discord API base must be https (http only for loopback tests)');
  }
  async call(method: DiscordMethod, path: string, body?: unknown): Promise<any> {
    if (!/^\/[A-Za-z0-9/@_.-]{1,300}$/.test(path) || path.includes('..')) throw new Error('invalid Discord API path');
    const headers: Record<string, string> = { 'content-type': 'application/json', 'user-agent': 'DiscordBot (https://github.com/mnemopay/starclaw, 2)' };
    // Interaction follow-ups (/webhooks/...) are authorised by the interaction token in the path: do not send the bot token there.
    if (!path.startsWith('/webhooks/')) headers.authorization = `Bot ${this.#token}`;
    let res: Response;
    try {
      res = await fetch(`${this.base}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30_000),
        redirect: 'error',
      });
    } catch (e: any) {
      throw new Error(`discord ${method} ${labelPath(path)} request failed: ${scrubSecrets(String(e?.message ?? e), [this.#token]).slice(0, 200)}`);
    }
    const text = await res.text().catch(() => '');
    let parsed: any = {};
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      /* non-JSON error page */
    }
    if (!res.ok) throw new Error(`discord ${method} ${labelPath(path)} failed: HTTP ${res.status} ${scrubSecrets(String(parsed?.message ?? ''), [this.#token]).slice(0, 100)}`.trim());
    return parsed;
  }
  toJSON() {
    return { token: '[redacted]' };
  }
}

const dmCache = new WeakMap<DiscordApi, Map<string, string>>();
/** Open (or reuse) the DM channel with the owner. Shared by the approver, the notifier and the goal gateway. */
export async function openOwnerDm(api: DiscordApi, ownerId: string): Promise<string> {
  let m = dmCache.get(api);
  if (!m) dmCache.set(api, (m = new Map()));
  const hit = m.get(ownerId);
  if (hit) return hit;
  const ch = await api.call('POST', '/users/@me/channels', { recipient_id: ownerId });
  if (typeof ch?.id !== 'string' || !DISCORD_SNOWFLAKE_RE.test(ch.id)) throw new Error('discord did not return a DM channel id');
  m.set(ownerId, ch.id);
  return ch.id;
}

export function assertDiscordOwnerId(ownerId: string, who: string) {
  if (typeof ownerId !== 'string' || !DISCORD_SNOWFLAKE_RE.test(ownerId)) throw new Error(`${who} requires the owner's numeric Discord user id`);
}

const NO_MENTIONS = { parse: [] as string[] };
const EPHEMERAL = 64;
const CUSTOM_ID_RE = /^sc:([ad]):([0-9a-f-]{36})$/;

export interface DiscordInteraction {
  id?: string;
  type?: number;
  token?: string;
  application_id?: string;
  channel_id?: string;
  user?: { id?: string };
  member?: { user?: { id?: string } };
  message?: { id?: string };
  data?: { name?: string; custom_id?: string; options?: Array<{ name?: string; value?: unknown }> };
}
export type DiscordReply = { type: number; data?: Record<string, unknown> };

export const interactionUserId = (i: DiscordInteraction): string | undefined => i.member?.user?.id ?? i.user?.id;
const ephemeral = (content: string): DiscordReply => ({ type: 4, data: { content, flags: EPHEMERAL, allowed_mentions: NO_MENTIONS } });

/**
 * Approvals over Discord: the request is posted to the owner's DM with Approve/Deny buttons. A click counts only if the
 * Discord user id equals the owner id AND it came from the very message we posted (channel and message id match).
 * Everything else, and any replay, is refused; timeout/abort is a deny.
 */
export class DiscordApprover implements Approver {
  readonly name = 'discord';
  readonly async = true;
  private pending = new Map<string, { resolve: (a: ApprovalAnswer) => void; channelId?: string; messageId?: string }>();

  constructor(private readonly api: DiscordApi, private readonly ownerId: string) {
    assertDiscordOwnerId(ownerId, 'DiscordApprover');
  }

  async request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    const content = describeRequest(req).slice(0, 1800) + `\n\nAuto-deny at ${new Date(req.expiresAt).toISOString()}`;
    return new Promise<ApprovalAnswer>((resolve) => {
      const entry: { resolve: (a: ApprovalAnswer) => void; channelId?: string; messageId?: string } = { resolve };
      this.pending.set(req.id, entry);
      const expire = () => {
        if (this.pending.delete(req.id)) {
          if (entry.channelId && entry.messageId) {
            this.api.call('PATCH', `/channels/${entry.channelId}/messages/${entry.messageId}`, { content: `Request ${req.id} expired: DENIED (timeout)`, components: [], allowed_mentions: NO_MENTIONS }).catch(() => {});
          }
          resolve('deny');
        }
      };
      if (signal.aborted) return expire();
      signal.addEventListener('abort', expire);
      openOwnerDm(this.api, this.ownerId)
        .then((dm) =>
          this.api.call('POST', `/channels/${dm}/messages`, {
            content,
            allowed_mentions: NO_MENTIONS,
            components: [
              {
                type: 1,
                components: [
                  { type: 2, style: 3, label: 'Approve', custom_id: `sc:a:${req.id}` },
                  { type: 2, style: 4, label: 'Deny', custom_id: `sc:d:${req.id}` },
                ],
              },
            ],
          }),
        )
        .then((sent) => {
          entry.channelId = typeof sent?.channel_id === 'string' ? sent.channel_id : undefined;
          entry.messageId = typeof sent?.id === 'string' ? sent.id : undefined;
          if (signal.aborted) expire();
        })
        .catch(() => {
          if (this.pending.delete(req.id)) resolve('deny');
        });
    });
  }

  /** Feed MESSAGE_COMPONENT interactions here. Returns the HTTP reply, or null if it is not one of our buttons. */
  handleInteraction(i: DiscordInteraction): DiscordReply | null {
    const m = typeof i?.data?.custom_id === 'string' ? CUSTOM_ID_RE.exec(i.data.custom_id) : null;
    if (!m) return null;
    const entry = this.pending.get(m[2]);
    const fromOwner =
      interactionUserId(i) === this.ownerId && !!entry && entry.channelId !== undefined && i.channel_id === entry.channelId && entry.messageId !== undefined && i.message?.id === entry.messageId;
    if (!fromOwner) return ephemeral(interactionUserId(i) === this.ownerId && !entry ? 'Request no longer pending.' : 'Not authorised.'); // never resolves
    this.pending.delete(m[2]);
    const answer: ApprovalAnswer = m[1] === 'a' ? 'approve' : 'deny';
    entry!.resolve(answer);
    // type 7 = UPDATE_MESSAGE: rewrite the request message and remove its buttons.
    return { type: 7, data: { content: `Request ${m[2]}: ${answer === 'approve' ? 'APPROVED' : 'DENIED'}`, components: [], allowed_mentions: NO_MENTIONS } };
  }

  get pendingCount() {
    return this.pending.size;
  }
}

export interface DiscordGatewayOptions {
  engine: StarClawEngine;
  api: DiscordApi;
  approver: DiscordApprover;
  applicationId: string;
  ownerId: string;
  allowPublic: boolean;
  queue: GoalQueue;
  log?: (s: string) => void;
}

/**
 * Goals from Discord arrive as the `/starclaw goal:<text>` slash command (no gateway connection, no message-content intent).
 * The sender's user id must equal the owner id. Anyone else is refused with a bare "Not authorised.", or with `allowPublic`
 * runs as a NON-OWNER goal (tainted from the start, exactly like Telegram). All replies are ephemeral (visible to the sender only).
 */
export class DiscordGateway {
  private readonly log: (s: string) => void;
  constructor(private readonly o: DiscordGatewayOptions) {
    assertDiscordOwnerId(o.ownerId, 'DiscordGateway');
    this.log = o.log ?? (() => {});
  }

  /** Returns the synchronous HTTP reply for one verified interaction. Long work continues in the background. */
  handle(i: DiscordInteraction): DiscordReply {
    if (i?.type === 1) return { type: 1 }; // PING
    if (i?.type === 3) return this.o.approver.handleInteraction(i) ?? ephemeral('Not authorised.');
    if (i?.type !== 2 || i.data?.name !== 'starclaw') return ephemeral('Unsupported.');
    if (i.application_id !== this.o.applicationId) return ephemeral('Not authorised.');
    const userId = interactionUserId(i);
    if (typeof userId !== 'string' || !DISCORD_SNOWFLAKE_RE.test(userId)) return ephemeral('Not authorised.');
    const isOwner = userId === this.o.ownerId;
    if (!isOwner && !this.o.allowPublic) return ephemeral('Not authorised.');
    const goal = i.data.options?.find((x) => x?.name === 'goal')?.value;
    if (typeof goal !== 'string' || !goal.trim()) return ephemeral('Give me a goal.');
    const text = goal.trim();
    if (isOwner && text === '/new') {
      this.o.engine.newSession();
      return ephemeral('New session started (taint cleared).');
    }
    if (text.length > 8000 || typeof i.token !== 'string' || !/^[A-Za-z0-9_-]{20,300}$/.test(i.token)) return ephemeral('Goal too long or malformed.');
    const token = i.token;
    const engine = this.o.engine;
    const job = this.o.queue.enqueue(async () => {
      const r = await engine.executeGoal(text, { origin: isOwner ? 'owner' : 'non-owner', originRef: `discord:${userId}` });
      await this.finish(token, isOwner, renderGoalResult(r));
    });
    if (!job) return ephemeral('Busy: too many goals queued. Try again later.');
    job.catch((e) => this.log(`discord goal error: ${String(e?.message ?? e).slice(0, 200)}`));
    // type 5 = DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE (ephemeral): the real answer follows via the interaction webhook.
    return { type: 5, data: { flags: EPHEMERAL } };
  }

  private async finish(token: string, isOwner: boolean, body: string) {
    const content = body.slice(0, 1900);
    try {
      await this.o.api.call('PATCH', `/webhooks/${this.o.applicationId}/${token}/messages/@original`, { content, allowed_mentions: NO_MENTIONS });
    } catch (e: any) {
      // The interaction token is only valid for 15 minutes. The owner still gets the answer, by DM; a stranger cannot be reached.
      this.log(`discord follow-up failed: ${String(e?.message ?? e).slice(0, 200)}`);
      if (isOwner) {
        const dm = await openOwnerDm(this.o.api, this.o.ownerId);
        await this.o.api.call('POST', `/channels/${dm}/messages`, { content, allowed_mentions: NO_MENTIONS });
      }
    }
  }
}

export interface DiscordRouteOptions {
  gateway: DiscordGateway;
  publicKey: KeyObject;
  toleranceSec: number;
  now?: () => number;
  log?: (s: string) => void;
}

const hdr = (h: RouteRequest['headers'], name: string): string | undefined => {
  const v = h[name];
  return Array.isArray(v) ? v[0] : v;
};

/** POST /discord/interactions: Ed25519 signature first, then replay check, then the gateway. */
export function discordRoutes(o: DiscordRouteOptions): ChannelRoute[] {
  const now = o.now ?? Date.now;
  const log = o.log ?? (() => {});
  const replay = new ReplayGuard((o.toleranceSec + 60) * 1000);
  return [
    {
      path: '/discord/interactions',
      async handle(req) {
        const sig = hdr(req.headers, 'x-signature-ed25519');
        const v = verifyDiscordSignature({
          publicKey: o.publicKey,
          timestamp: hdr(req.headers, 'x-signature-timestamp'),
          signature: sig,
          rawBody: req.rawBody,
          nowMs: now(),
          toleranceSec: o.toleranceSec,
        });
        if (!v.ok) {
          log(`discord request rejected: ${v.reason}`);
          return { status: 401, body: { error: 'unauthorized' } };
        }
        if (replay.isReplay(sig!.toLowerCase(), now())) {
          log('discord request rejected: replay');
          return { status: 401, body: { error: 'unauthorized' } };
        }
        let i: DiscordInteraction;
        try {
          i = JSON.parse(req.rawBody.toString('utf8'));
        } catch {
          return { status: 400, body: { error: 'bad request' } };
        }
        return { status: 200, body: o.gateway.handle(i) };
      },
    },
  ];
}

/** The slash command definition `starclaw discord register` uploads. */
export function discordCommandDefinition() {
  return [
    {
      name: 'starclaw',
      type: 1,
      description: 'Give StarClaw a goal (owner only)',
      options: [{ type: 3, name: 'goal', description: 'What should StarClaw do?', required: true, max_length: 2000 }],
    },
  ];
}

/** Upload the slash command (global, or to one guild where it appears instantly). Bulk-overwrite: it replaces this application's commands. */
export async function registerDiscordCommand(api: DiscordApi, applicationId: string, guildId?: string): Promise<number> {
  if (!DISCORD_SNOWFLAKE_RE.test(applicationId)) throw new Error('invalid application id');
  if (guildId !== undefined && !DISCORD_SNOWFLAKE_RE.test(guildId)) throw new Error('invalid guild id');
  const path = guildId ? `/applications/${applicationId}/guilds/${guildId}/commands` : `/applications/${applicationId}/commands`;
  const res = await api.call('PUT', path, discordCommandDefinition());
  return Array.isArray(res) ? res.length : 0;
}
