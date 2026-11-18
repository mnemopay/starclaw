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

export interface WhatsAppConfig { token: string; appSecret: string; verifyToken: string; phoneNumberId: string; owner: string; version: string; allowPublic: boolean }

export function resolveWhatsAppConfig(policy: Policy, env: Env): WhatsAppConfig {
  const w = policy.whatsapp;
  const token = need(env, w.tokenEnv, 'whatsapp');
  const appSecret = need(env, w.appSecretEnv, 'whatsapp');
  const verifyToken = need(env, w.verifyTokenEnv, 'whatsapp');
  const phoneNumberId = need(env, w.phoneNumberIdEnv, 'whatsapp');
  const owner = need(env, w.ownerNumberEnv, 'whatsapp').replace(/^\+/, '');
  if (token.length < 20 || /\s/.test(token)) throw new ChannelConfigError(`whatsapp: ${w.tokenEnv} does not look like an access token`);
  if (appSecret.length < 16) throw new ChannelConfigError(`whatsapp: ${w.appSecretEnv} is too short to be the app secret`);
  if (verifyToken.length < 16) throw new ChannelConfigError(`whatsapp: ${w.verifyTokenEnv} must be at least 16 characters (choose a random string)`);
  if (!/^\d{5,25}$/.test(phoneNumberId)) throw new ChannelConfigError(`whatsapp: ${w.phoneNumberIdEnv} must be the numeric phone number ID from the WhatsApp app dashboard`);
  if (!/^[1-9]\d{6,14}$/.test(owner)) throw new ChannelConfigError(`whatsapp: ${w.ownerNumberEnv} must be the owner's number in international format (digits)`);
  return { token, appSecret, verifyToken, phoneNumberId, owner, version: w.graphApiVersion, allowPublic: w.allowPublic };
}

export interface SignalConfig { bridgeUrl: string; account: string; owner: string; allowPublic: boolean }

export function resolveSignalConfig(policy: Policy, env: Env): SignalConfig {
  const s = policy.signal;
  const account = need(env, s.accountEnv, 'signal');
  const owner = need(env, s.ownerNumberEnv, 'signal');
  const u = new URL(s.bridgeUrl);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)) throw new ChannelConfigError('signal: signal.bridgeUrl must point at the bridge on this PC (127.0.0.1)');
  for (const [n, v] of [[s.accountEnv, account], [s.ownerNumberEnv, owner]] as const) if (!/^\+[1-9]\d{6,14}$/.test(v)) throw new ChannelConfigError(`signal: ${n} must be a number in +international format`);
  if (account === owner) throw new ChannelConfigError('signal: the bot account and the owner must be different numbers');
  return { bridgeUrl: s.bridgeUrl, account, owner, allowPublic: s.allowPublic };
}

export interface EmailConfig { imapHost: string; imapPort: number; smtpHost: string; smtpPort: number; user: string; password: string; owner: string; authservId: string; pollSeconds: number; allowPublic: boolean }

export function resolveEmailConfig(policy: Policy, env: Env): EmailConfig {
  const e = policy.email;
  const user = need(env, e.userEnv, 'email');
  const password = need(env, e.passwordEnv, 'email');
  const owner = need(env, e.ownerAddressEnv, 'email');
  const addr = /^[^\s@<>()",;:]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/;
  if (!addr.test(user)) throw new ChannelConfigError(`email: ${e.userEnv} must be the mailbox address StarClaw logs in as`);
  if (!addr.test(owner)) throw new ChannelConfigError(`email: ${e.ownerAddressEnv} must be the owner's email address`);
  if (owner.toLowerCase() === user.toLowerCase()) throw new ChannelConfigError("email: the agent's mailbox and the owner's address must be different");
  if (!e.imapHost || !e.smtpHost || !e.authservId) throw new ChannelConfigError('email: imapHost, smtpHost and authservId are required');
  return { imapHost: e.imapHost, imapPort: e.imapPort, smtpHost: e.smtpHost, smtpPort: e.smtpPort, user, password, owner, authservId: e.authservId, pollSeconds: e.pollSeconds, allowPublic: e.allowPublic };
}
