import type * as http from 'node:http';
import type { StarClawEngine } from '../engine';
import type { Policy } from '../governance/policy';
import type { Approver } from '../governance/types';
import { DiscordNotifier, EmailNotifier, OwnerNotifier, SignalNotifier, SlackNotifier, WhatsAppNotifier } from '../notify/Notifier';
import { CodeApprover } from './codeApproval';
import { DiscordConfig, EmailConfig, SignalConfig, SlackConfig, WhatsAppConfig, resolveDiscordConfig, resolveEmailConfig, resolveSignalConfig, resolveSlackConfig, resolveWhatsAppConfig } from './config';
import { DiscordApi, DiscordApprover, DiscordGateway, FetchDiscordApi, discordRoutes } from './discord';
import { EmailGateway, EmailPoller, ImapSmtpClient, MailClient } from './email';
import { GoalQueue } from './queue';
import { ChannelRoute, closeServer, createChannelServer, listenLoopback } from './server';
import { FetchSignalApi, SignalApi, SignalGateway, SignalPoller } from './signal';
import { FetchSlackApi, SlackApi, SlackApprover, SlackGateway, slackRoutes } from './slack';
import { discordPublicKey } from './verify';
import { FetchWhatsAppApi, WhatsAppApi, WhatsAppApprover, WhatsAppGateway, whatsappRoutes } from './whatsapp';

export interface ChannelDeps {
  /** Tests inject local fakes; production leaves these unset and gets the real, token-holding clients. */
  slackApi?: SlackApi;
  discordApi?: DiscordApi;
  whatsappApi?: WhatsAppApi;
  signalApi?: SignalApi;
  mailClient?: MailClient;
}

export interface RunningChannels {
  /** Port of the webhook listener, or 0 when only polling channels (Signal, email) are enabled. */
  port: number;
  stop(): Promise<void>;
}

/**
 * Resolves every enabled channel's configuration FIRST (fail closed: a channel that is enabled but misconfigured throws
 * before anything starts), builds the approver/notifier for whichever channel is `channels.ownerChannel`, and defers
 * listening/polling until `start`.
 */
export class ChannelRuntime {
  readonly slack?: { cfg: SlackConfig; api: SlackApi; approver: SlackApprover; notifier: SlackNotifier };
  readonly discord?: { cfg: DiscordConfig; api: DiscordApi; approver: DiscordApprover; notifier: DiscordNotifier };
  readonly whatsapp?: { cfg: WhatsAppConfig; api: WhatsAppApi; approver: WhatsAppApprover; notifier: WhatsAppNotifier };
  readonly signal?: { cfg: SignalConfig; api: SignalApi; approver: CodeApprover; notifier: SignalNotifier };
  readonly email?: { cfg: EmailConfig; client: MailClient; approver: CodeApprover; notifier: EmailNotifier };

  constructor(private readonly policy: Policy, env: Record<string, string | undefined>, deps: ChannelDeps = {}) {
    if (policy.slack.enabled) {
      const cfg = resolveSlackConfig(policy, env);
      const api = deps.slackApi ?? new FetchSlackApi(cfg.botToken);
      this.slack = { cfg, api, approver: new SlackApprover(api, cfg.ownerId), notifier: new SlackNotifier(api, cfg.ownerId) };
    }
    if (policy.discord.enabled) {
      const cfg = resolveDiscordConfig(policy, env);
      const api = deps.discordApi ?? new FetchDiscordApi(cfg.botToken);
      this.discord = { cfg, api, approver: new DiscordApprover(api, cfg.ownerId), notifier: new DiscordNotifier(api, cfg.ownerId) };
    }
    if (policy.whatsapp.enabled) {
      const cfg = resolveWhatsAppConfig(policy, env);
      const api = deps.whatsappApi ?? new FetchWhatsAppApi(cfg.token, cfg.phoneNumberId, cfg.version);
      this.whatsapp = { cfg, api, approver: new WhatsAppApprover(api, cfg.owner), notifier: new WhatsAppNotifier(api, cfg.owner) };
    }
    if (policy.signal.enabled) {
      const cfg = resolveSignalConfig(policy, env);
      const api = deps.signalApi ?? new FetchSignalApi(cfg.bridgeUrl, cfg.account);
      this.signal = { cfg, api, approver: new CodeApprover('signal', (t) => api.send(cfg.owner, t)), notifier: new SignalNotifier(api, cfg.owner) };
    }
    if (policy.email.enabled) {
      const cfg = resolveEmailConfig(policy, env);
      const client = deps.mailClient ?? new ImapSmtpClient(cfg);
      this.email = { cfg, client, approver: new CodeApprover('email', (t, subject) => client.send(cfg.owner, subject, t), 15_000), notifier: new EmailNotifier(client, cfg.owner) };
    }
  }

  get enabled(): boolean {
    return !!(this.slack || this.discord || this.whatsapp || this.signal || this.email);
  }
  private get webhookEnabled(): boolean {
    return !!(this.slack || this.discord || this.whatsapp);
  }

  /** The approver/notifier for the owner channel; undefined when it is Telegram (the daemon builds that). */
  get ownerApprover(): Approver | undefined {
    const oc = this.policy.channels.ownerChannel;
    return oc === 'telegram' ? undefined : this[oc]?.approver;
  }
  get ownerNotifier(): OwnerNotifier | undefined {
    const oc = this.policy.channels.ownerChannel;
    return oc === 'telegram' ? undefined : this[oc]?.notifier;
  }

  /** Start the loopback listener (webhook channels) and the pollers (Signal, email). `port` overrides the policy port (tests pass 0). */
  async start(engine: StarClawEngine, queue: GoalQueue, o: { port?: number; log?: (s: string) => void; now?: () => number } = {}): Promise<RunningChannels | undefined> {
    if (!this.enabled) return undefined;
    const ch = this.policy.channels;
    const log = o.log ?? (() => {});
    const routes: ChannelRoute[] = [];
    if (this.slack) {
      const gateway = new SlackGateway({ engine, api: this.slack.api, ownerId: this.slack.cfg.ownerId, allowPublic: this.slack.cfg.allowPublic, queue, log });
      routes.push(...slackRoutes({ gateway, approver: this.slack.approver, signingSecret: this.slack.cfg.signingSecret, toleranceSec: ch.timestampToleranceSeconds, now: o.now, log }));
    }
    if (this.discord) {
      const gateway = new DiscordGateway({
        engine,
        api: this.discord.api,
        approver: this.discord.approver,
        applicationId: this.discord.cfg.applicationId,
        ownerId: this.discord.cfg.ownerId,
        allowPublic: this.discord.cfg.allowPublic,
        queue,
        log,
      });
      routes.push(...discordRoutes({ gateway, publicKey: discordPublicKey(this.discord.cfg.publicKeyHex), toleranceSec: ch.timestampToleranceSeconds, now: o.now, log }));
    }
    if (this.whatsapp) {
      const w = this.whatsapp;
      const gateway = new WhatsAppGateway({ engine, api: w.api, approver: w.approver, owner: w.cfg.owner, allowPublic: w.cfg.allowPublic, queue, toleranceSec: ch.timestampToleranceSeconds, now: o.now, log });
      routes.push(...whatsappRoutes({ gateway, appSecret: w.cfg.appSecret, verifyToken: w.cfg.verifyToken, log, now: o.now }));
    }
    const pollers: Array<{ stop(): void }> = [];
    if (this.signal) {
      const s = this.signal;
      const p = new SignalPoller(s.api, new SignalGateway({ engine, api: s.api, approver: s.approver, owner: s.cfg.owner, allowPublic: s.cfg.allowPublic, queue, log }), log);
      void p.run();
      pollers.push(p);
    }
    if (this.email) {
      const e = this.email;
      const p = new EmailPoller(e.client, new EmailGateway({ engine, client: e.client, approver: e.approver, owner: e.cfg.owner, authservId: e.cfg.authservId, allowPublic: e.cfg.allowPublic, queue, log }), e.cfg.pollSeconds * 1000, log);
      void p.run();
      pollers.push(p);
    }
    let server: http.Server | undefined;
    let port = 0;
    if (this.webhookEnabled) {
      server = createChannelServer({ routes, maxBodyBytes: ch.maxBodyBytes, log });
      try {
        port = await listenLoopback(server, o.port ?? ch.port);
      } catch (e) {
        for (const p of pollers) p.stop();
        throw e;
      }
    }
    engine.audit.append('channels.start', {
      slack: !!this.slack, discord: !!this.discord, whatsapp: !!this.whatsapp, signal: !!this.signal, email: !!this.email,
      ownerChannel: ch.ownerChannel, host: server ? '127.0.0.1' : null, port: server ? port : null,
      allowPublic: { slack: this.slack?.cfg.allowPublic ?? false, discord: this.discord?.cfg.allowPublic ?? false, whatsapp: this.whatsapp?.cfg.allowPublic ?? false, signal: this.signal?.cfg.allowPublic ?? false, email: this.email?.cfg.allowPublic ?? false },
    });
    return {
      port,
      stop: async () => {
        for (const p of pollers) p.stop();
        if (server) await closeServer(server);
      },
    };
  }
}
