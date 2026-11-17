import type * as http from 'node:http';
import type { StarClawEngine } from '../engine';
import type { Policy } from '../governance/policy';
import type { Approver } from '../governance/types';
import { DiscordNotifier, OwnerNotifier, SlackNotifier } from '../notify/Notifier';
import { DiscordConfig, SlackConfig, resolveDiscordConfig, resolveSlackConfig } from './config';
import { DiscordApi, DiscordApprover, DiscordGateway, FetchDiscordApi, discordRoutes } from './discord';
import { GoalQueue } from './queue';
import { ChannelRoute, closeServer, createChannelServer, listenLoopback } from './server';
import { FetchSlackApi, SlackApi, SlackApprover, SlackGateway, slackRoutes } from './slack';
import { discordPublicKey } from './verify';

export interface ChannelDeps {
  /** Tests inject local fakes; production leaves these unset and gets the real, token-holding clients. */
  slackApi?: SlackApi;
  discordApi?: DiscordApi;
}

export interface RunningChannels {
  port: number;
  stop(): Promise<void>;
}

/**
 * Resolves Slack/Discord configuration FIRST (fail closed: a channel that is enabled but misconfigured throws before anything
 * starts), builds the approver/notifier for whichever channel is `channels.ownerChannel`, and defers listening until `start`.
 */
export class ChannelRuntime {
  readonly slack?: { cfg: SlackConfig; api: SlackApi; approver: SlackApprover; notifier: SlackNotifier };
  readonly discord?: { cfg: DiscordConfig; api: DiscordApi; approver: DiscordApprover; notifier: DiscordNotifier };

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
  }

  get enabled(): boolean {
    return !!(this.slack || this.discord);
  }

  /** The approver/notifier when Slack or Discord is the owner channel; undefined when it is Telegram (the daemon builds that). */
  get ownerApprover(): Approver | undefined {
    const oc = this.policy.channels.ownerChannel;
    return oc === 'slack' ? this.slack?.approver : oc === 'discord' ? this.discord?.approver : undefined;
  }
  get ownerNotifier(): OwnerNotifier | undefined {
    const oc = this.policy.channels.ownerChannel;
    return oc === 'slack' ? this.slack?.notifier : oc === 'discord' ? this.discord?.notifier : undefined;
  }

  /** Start the loopback listener. `port` overrides the policy port (tests pass 0). */
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
    const server: http.Server = createChannelServer({ routes, maxBodyBytes: ch.maxBodyBytes, log });
    const port = await listenLoopback(server, o.port ?? ch.port);
    engine.audit.append('channels.start', { slack: !!this.slack, discord: !!this.discord, ownerChannel: ch.ownerChannel, host: '127.0.0.1', port, allowPublic: { slack: this.slack?.cfg.allowPublic ?? false, discord: this.discord?.cfg.allowPublic ?? false } });
    return { port, stop: () => closeServer(server) };
  }
}
