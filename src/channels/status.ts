import type { Policy } from '../governance/policy';
import { ChannelConfigError, resolveDiscordConfig, resolveSlackConfig } from './config';

export interface ChannelStatus {
  line: string;
  /** True when the channel is enabled but would refuse to start. */
  broken: boolean;
  warnings: string[];
}

const mark = (env: Record<string, string | undefined>, name: string) => `${name}: ${env[name] ? 'set' : 'NOT set'}`;

/** One doctor line per channel. Prints env var NAMES and set/NOT set only: never a value. */
export function slackStatus(policy: Policy, env: Record<string, string | undefined>): ChannelStatus {
  const s = policy.slack;
  if (!s.enabled) return { line: 'Slack: disabled (policy slack.enabled = false)', broken: false, warnings: [] };
  const base = `Slack: enabled; ${mark(env, s.botTokenEnv)}; ${mark(env, s.signingSecretEnv)}; ${mark(env, s.ownerIdEnv)}; non-owner DMs: ${s.allowPublic ? 'run TAINTED' : 'ignored'}`;
  try {
    resolveSlackConfig(policy, env);
    return { line: base + '; config OK', broken: false, warnings: s.allowPublic ? ['slack.allowPublic is on: anyone who can DM the bot can start a (tainted) goal and spend your LLM budget'] : [] };
  } catch (e) {
    return { line: base, broken: true, warnings: [e instanceof ChannelConfigError ? e.message : 'invalid Slack configuration'] };
  }
}

export function discordStatus(policy: Policy, env: Record<string, string | undefined>): ChannelStatus {
  const d = policy.discord;
  if (!d.enabled) return { line: 'Discord: disabled (policy discord.enabled = false)', broken: false, warnings: [] };
  const base = `Discord: enabled; ${mark(env, d.botTokenEnv)}; ${mark(env, d.publicKeyEnv)}; ${mark(env, d.applicationIdEnv)}; ${mark(env, d.ownerIdEnv)}; non-owner commands: ${d.allowPublic ? 'run TAINTED' : 'refused'}`;
  try {
    resolveDiscordConfig(policy, env);
    return { line: base + '; config OK', broken: false, warnings: d.allowPublic ? ['discord.allowPublic is on: anyone who can use the slash command can start a (tainted) goal and spend your LLM budget'] : [] };
  } catch (e) {
    return { line: base, broken: true, warnings: [e instanceof ChannelConfigError ? e.message : 'invalid Discord configuration'] };
  }
}

/** The shared listener line (only when a webhook channel is enabled). */
export function listenerStatus(policy: Policy): ChannelStatus {
  const c = policy.channels;
  if (!policy.slack.enabled && !policy.discord.enabled) return { line: `Channels: no webhook channel enabled; owner channel: ${c.ownerChannel}`, broken: false, warnings: [] };
  return {
    line: `Channels: webhook listener 127.0.0.1:${c.port} (loopback only; Slack/Discord need a tunnel or reverse proxy YOU run to reach it); owner channel (approvals + notifyOwner): ${c.ownerChannel}; signature window ${c.timestampToleranceSeconds}s`,
    broken: false,
    warnings: [],
  };
}
