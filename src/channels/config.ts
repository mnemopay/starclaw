import type { Policy } from '../governance/policy';
import { discordPublicKey } from './verify';

/** Thrown when a channel is enabled but its configuration is missing or malformed. Messages name env VARS, never their values. */
export class ChannelConfigError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'ChannelConfigError';
  }
}

export const SLACK_TOKEN_RE = /^xoxb-[A-Za-z0-9-]{10,}$/;
export const SLACK_USER_ID_RE = /^[UW][A-Z0-9]{2,31}$/;
export const DISCORD_SNOWFLAKE_RE = /^\d{17,20}$/;
export const DISCORD_TOKEN_RE = /^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{20,}$/;

type Env = Record<string, string | undefined>;

function need(env: Env, name: string, what: string): string {
  const v = env[name];
  if (typeof v !== 'string' || v.trim() === '') throw new ChannelConfigError(`${what}: environment variable ${name} is not set. Refusing to start.`);
  return v.trim();
}

export interface SlackConfig {
  botToken: string;
  signingSecret: string;
  ownerId: string;
  allowPublic: boolean;
}

/** Fail closed: every field must be present and well-formed, or this throws. Values are never included in messages. */
export function resolveSlackConfig(policy: Policy, env: Env): SlackConfig {
  const s = policy.slack;
  const botToken = need(env, s.botTokenEnv, 'slack');
  const signingSecret = need(env, s.signingSecretEnv, 'slack');
  const ownerId = need(env, s.ownerIdEnv, 'slack');
  if (!SLACK_TOKEN_RE.test(botToken)) throw new ChannelConfigError(`slack: ${s.botTokenEnv} does not look like a Slack bot token (xoxb-...)`);
  if (signingSecret.length < 16) throw new ChannelConfigError(`slack: ${s.signingSecretEnv} is too short to be a Slack signing secret`);
  if (!SLACK_USER_ID_RE.test(ownerId)) throw new ChannelConfigError(`slack: ${s.ownerIdEnv} must be the owner's Slack member id (U... or W...), not a name or channel`);
  return { botToken, signingSecret, ownerId, allowPublic: s.allowPublic };
}

export interface DiscordConfig {
  botToken: string;
  publicKeyHex: string;
  applicationId: string;
  ownerId: string;
  allowPublic: boolean;
}

export function resolveDiscordConfig(policy: Policy, env: Env): DiscordConfig {
  const d = policy.discord;
  const botToken = need(env, d.botTokenEnv, 'discord');
  const publicKeyHex = need(env, d.publicKeyEnv, 'discord');
  const applicationId = need(env, d.applicationIdEnv, 'discord');
  const ownerId = need(env, d.ownerIdEnv, 'discord');
  if (!DISCORD_TOKEN_RE.test(botToken)) throw new ChannelConfigError(`discord: ${d.botTokenEnv} does not look like a Discord bot token`);
  try {
    discordPublicKey(publicKeyHex);
  } catch {
    throw new ChannelConfigError(`discord: ${d.publicKeyEnv} must be the application's 64-hex-character public key`);
  }
  if (!DISCORD_SNOWFLAKE_RE.test(applicationId)) throw new ChannelConfigError(`discord: ${d.applicationIdEnv} must be a numeric application id`);
  if (!DISCORD_SNOWFLAKE_RE.test(ownerId)) throw new ChannelConfigError(`discord: ${d.ownerIdEnv} must be the owner's numeric Discord user id`);
  return { botToken, publicKeyHex, applicationId, ownerId, allowPublic: d.allowPublic };
}

/** Remove any occurrence of known secrets from a string (used on every error message that leaves an API client). */
export function scrubSecrets(s: string, secrets: Array<string | undefined>): string {
  let out = s;
  for (const sec of secrets) if (sec && sec.length >= 6) out = out.split(sec).join('[REDACTED]');
  return out;
}
