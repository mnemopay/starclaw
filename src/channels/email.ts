import type { StarClawEngine } from '../engine';
import { CodeApprover } from './codeApproval';
import { GoalQueue, renderGoalResult } from './queue';
import { SeenIds } from './verify';

/**
 * Email: IMAP in, SMTP out, to and from ONE owner address.
 *
 * Anyone can put any address in From:, so the address alone proves nothing. A message counts as the owner's only when
 * the FIRST (topmost) Authentication-Results header written by YOUR mail provider (its authserv-id, e.g. mx.google.com)
 * says dmarc=pass for the owner's domain. Headers a sender adds lower down are ignored. Approvals additionally need the
 * one-time code that was only ever sent to the owner's inbox.
 */

export interface Mail { uid: number; messageId?: string; from: string; subject: string; text: string; headerLines: Array<{ key: string; line: string }> }
export interface MailClient {
  /** Unseen messages in INBOX (bounded); each is marked seen once returned. */
  fetchUnseen(): Promise<Mail[]>;
  send(to: string, subject: string, text: string): Promise<void>;
  close(): Promise<void>;
}

export const EMAIL_RE = /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/;

/** The verdict from the topmost Authentication-Results header whose authserv-id is the provider's. */
export function providerVerdict(headerLines: Mail['headerLines'], authservId: string): { dmarc?: string; headerFrom?: string } | undefined {
  for (const h of headerLines) {
    if (h.key.toLowerCase() !== 'authentication-results') continue;
    const value = h.line.replace(/^[^:]*:\s*/, '').replace(/\r?\n[ \t]+/g, ' ');
    const id = value.split(';')[0].trim().split(/\s+/)[0]?.toLowerCase();
    if (id !== authservId.toLowerCase()) continue;
    const dmarc = /\bdmarc=([a-z]+)/i.exec(value)?.[1]?.toLowerCase();
    // header.from=domain from the dmarc result (the domain DMARC evaluated)
    const dm = /\bdmarc=[a-z]+[^;]*?\bheader\.from=([A-Za-z0-9.-]+)/i.exec(value)?.[1]?.toLowerCase();
    return { dmarc, headerFrom: dm };
  }
  return undefined;
}

export function isOwnerMail(m: Mail, owner: string, authservId: string): boolean {
  if (m.from.toLowerCase() !== owner.toLowerCase()) return false;
  const v = providerVerdict(m.headerLines, authservId);
  const domain = owner.split('@')[1].toLowerCase();
  return !!v && v.dmarc === 'pass' && v.headerFrom === domain;
}

/** The new text of a reply: lines before the first quote marker ("> ...", "On ... wrote:", "-----Original Message-----"). */
export function replyText(text: string): string {
  const out: string[] = [];
  for (const line of text.replace(/\r\n/g, '\n').split('\n')) {
    if (/^\s*>/.test(line) || /^On .{1,200}wrote:\s*$/.test(line.trim()) || /^-{2,}\s*Original Message\s*-{2,}/i.test(line.trim())) break;
    out.push(line);
  }
  return out.join('\n').trim();
}

export interface EmailGatewayOptions {
  engine: StarClawEngine;
  client: MailClient;
  approver: CodeApprover;
  owner: string;
  authservId: string;
  allowPublic: boolean;
  queue: GoalQueue;
  log?: (s: string) => void;
}

export class EmailGateway {
  private readonly seen = new SeenIds(24 * 3600_000);
  constructor(private readonly o: EmailGatewayOptions) {
    if (!EMAIL_RE.test(o.owner)) throw new Error("EmailGateway requires the owner's email address");
  }

  async onMail(m: Mail): Promise<void> {
    if (!EMAIL_RE.test(m.from)) return;
    if (m.messageId && !this.seen.firstTime(m.messageId)) return;
    const isOwner = isOwnerMail(m, this.o.owner, this.o.authservId);
    if (m.from.toLowerCase() === this.o.owner.toLowerCase() && !isOwner) this.o.log?.('email: a message claiming to be from the owner failed the provider DMARC check; ignored');
    const body = replyText(m.text);
    const firstLine = body.split('\n').find((l) => l.trim()) ?? '';
    const subject = `Re: ${m.subject.replace(/^(re:\s*)+/i, '')}`.slice(0, 200);
    const send = (t: string) => this.o.client.send(m.from, subject, t).catch(() => {});
    const r = this.o.approver.handleReply(firstLine, isOwner);
    if (r === 'answered') return void (await send('Got it.'));
    if (r === 'not-pending') return void (await send('That request is no longer pending.'));
    if (!isOwner && !this.o.allowPublic) return;
    const goal = (body || m.subject).trim();
    if (!goal) return;
    if (isOwner && goal === '/new') return void (await send(this.o.engine.newSession() === false ? 'A goal is active or queued. Wait for it to finish before starting a new session.' : 'New session started (taint cleared).'));
    if (goal.length > 8000) return void (await send('Goal too long (8000 chars max).'));
    const engine = this.o.engine;
    const job = this.o.queue.enqueue(async () => {
      const res = await engine.executeGoal(goal, { origin: isOwner ? 'owner' : 'non-owner', originRef: `email:${m.from}` });
      await send(renderGoalResult(res));
    });
    if (!job) return void (await send('Busy: too many goals queued. Try again later.'));
    await job.catch((e) => this.o.log?.(`email goal error: ${String(e?.message ?? e).slice(0, 200)}`));
  }
}

export class EmailPoller {
  private stopped = false;
  constructor(private readonly client: MailClient, private readonly gateway: EmailGateway, private readonly intervalMs: number, private readonly log: (s: string) => void = () => {}) {}
  async run(): Promise<void> {
    while (!this.stopped) {
      try {
        for (const m of await this.client.fetchUnseen()) this.gateway.onMail(m).catch((e) => this.log(`email handler error: ${e?.message ?? e}`));
      } catch (e: any) {
        this.log(`email poll error: ${String(e?.message ?? e).slice(0, 200)}`);
      }
      await new Promise((r) => setTimeout(r, this.intervalMs));
    }
  }
  stop() {
    this.stopped = true;
    void this.client.close();
  }
}

/** The real client (imapflow + nodemailer + mailparser), TLS on both sides. Credentials stay inside this object. */
export class ImapSmtpClient implements MailClient {
  readonly #user: string;
  readonly #pass: string;
  constructor(private readonly cfg: { imapHost: string; imapPort: number; smtpHost: string; smtpPort: number; user: string; password: string; maxPerPoll?: number }) {
    this.#user = cfg.user;
    this.#pass = cfg.password;
  }
  async fetchUnseen(): Promise<Mail[]> {
    const { ImapFlow } = await import('imapflow');
    const { simpleParser } = await import('mailparser');
    const client = new ImapFlow({ host: this.cfg.imapHost, port: this.cfg.imapPort, secure: true, auth: { user: this.#user, pass: this.#pass }, logger: false });
    await client.connect();
    const out: Mail[] = [];
    const lock = await client.getMailboxLock('INBOX');
    try {
      const uids = ((await client.search({ seen: false }, { uid: true })) || []).slice(0, this.cfg.maxPerPoll ?? 20);
      for (const uid of uids) {
        const msg = await client.fetchOne(String(uid), { source: true, uid: true }, { uid: true });
        if (!msg || !msg.source || msg.source.length > 1_000_000) continue;
        const p = await simpleParser(msg.source);
        const from = p.from?.value?.[0]?.address ?? '';
        out.push({ uid, messageId: p.messageId ?? undefined, from, subject: String(p.subject ?? '').slice(0, 300), text: String(p.text ?? '').slice(0, 50_000), headerLines: (p.headerLines ?? []).slice(0, 200) });
        await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
      }
    } finally {
      lock.release();
      await client.logout().catch(() => {});
    }
    return out;
  }
  async send(to: string, subject: string, text: string): Promise<void> {
    const nodemailer = await import('nodemailer');
    const t = nodemailer.createTransport({ host: this.cfg.smtpHost, port: this.cfg.smtpPort, secure: this.cfg.smtpPort === 465, requireTLS: true, auth: { user: this.#user, pass: this.#pass } });
    await t.sendMail({ from: this.#user, to, subject, text: text.slice(0, 20_000) });
  }
  async close(): Promise<void> {}
  toJSON() {
    return { user: this.#user, password: '[redacted]' };
  }
}
