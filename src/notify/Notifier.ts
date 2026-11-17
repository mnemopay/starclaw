import * as fs from 'node:fs';
import * as path from 'node:path';
import type { DiscordApi } from '../channels/discord';
import { assertDiscordOwnerId, openOwnerDm } from '../channels/discord';
import type { SlackApi } from '../channels/slack';
import { assertSlackOwnerId, slackEscape } from '../channels/slack';
import type { TelegramApi } from '../channels/telegram';
import type { Policy } from '../governance/policy';

/** Sends a message to the ONE configured owner. There is deliberately no recipient parameter anywhere. */
export interface OwnerNotifier {
  readonly name: string;
  send(text: string): Promise<void>;
}

export class TelegramNotifier implements OwnerNotifier {
  readonly name = 'telegram';
  constructor(private readonly api: TelegramApi, private readonly ownerId: number) {
    if (!Number.isSafeInteger(ownerId) || ownerId === 0) throw new Error('TelegramNotifier requires a numeric owner chat id');
  }
  async send(text: string): Promise<void> {
    await this.api.call('sendMessage', { chat_id: this.ownerId, text: text.slice(0, 3900) });
  }
}

/** Slack DM to the ONE configured owner (no recipient parameter). Text is escaped so message content cannot mention or link. */
export class SlackNotifier implements OwnerNotifier {
  readonly name = 'slack';
  constructor(private readonly api: SlackApi, private readonly ownerId: string) {
    assertSlackOwnerId(ownerId, 'SlackNotifier');
  }
  async send(text: string): Promise<void> {
    await this.api.call('chat.postMessage', { channel: this.ownerId, text: slackEscape(text).slice(0, 3900), mrkdwn: false, link_names: false, unfurl_links: false, unfurl_media: false });
  }
}

/** Discord DM to the ONE configured owner. Mentions are disabled on the message. */
export class DiscordNotifier implements OwnerNotifier {
  readonly name = 'discord';
  constructor(private readonly api: DiscordApi, private readonly ownerId: string) {
    assertDiscordOwnerId(ownerId, 'DiscordNotifier');
  }
  async send(text: string): Promise<void> {
    const dm = await openOwnerDm(this.api, this.ownerId);
    await this.api.call('POST', `/channels/${dm}/messages`, { content: text.slice(0, 1900), allowed_mentions: { parse: [] } });
  }
}

/** Records messages in memory (tests). */
export class MemoryNotifier implements OwnerNotifier {
  readonly name = 'memory';
  sent: string[] = [];
  async send(text: string) {
    this.sent.push(text);
  }
}

/**
 * Persistent sliding-window rate limiter for proactive messages ("message you first" must not become spam).
 * Timestamps are kept in a small JSON file in the state directory so a restart cannot reset the limit.
 */
export class NotifyLimiter {
  constructor(private readonly file: string, private readonly lim: Policy['notify']) {}

  private load(): number[] {
    try {
      const v = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return Array.isArray(v) ? v.filter((n) => Number.isFinite(n)) : [];
    } catch {
      return [];
    }
  }

  /** Throws if sending now would exceed a limit. Does not record. */
  check(now = Date.now()): void {
    const ts = this.load().filter((t) => now - t < 86_400_000);
    if (ts.length >= this.lim.maxPerDay) throw new Error(`notify.owner rate limit: ${this.lim.maxPerDay} messages per day reached`);
    const hour = ts.filter((t) => now - t < 3_600_000).length;
    if (hour >= this.lim.maxPerHour) throw new Error(`notify.owner rate limit: ${this.lim.maxPerHour} messages per hour reached`);
  }

  record(now = Date.now()): void {
    const ts = this.load().filter((t) => now - t < 86_400_000);
    ts.push(now);
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(ts));
  }
}
