import * as fs from 'node:fs';
import { z } from 'zod';
import { ACTION_CLASSES, Action, ActionClass, Verdict } from './types';

const VerdictSchema = z.enum(['allow', 'ask', 'deny']);

const RuleSchema = z
  .object({
    class: z.enum(ACTION_CLASSES),
    /** Glob over the action target (path, hostname, command, payee). `*` = any chars except `/`, `**` = anything. */
    target: z.string().min(1).max(500).optional(),
    inWorkspace: z.boolean().optional(),
    /** spend only: rule applies when cents <= maxCents */
    maxCents: z.number().int().nonnegative().optional(),
    verdict: VerdictSchema,
  })
  .strict();

export const ShellPolicySchema = z
  .object({
    /** Only "none" exists. Adding open networking to the shell container is intentionally not possible via policy. */
    network: z.literal('none').default('none'),
    timeoutSeconds: z.number().int().min(1).max(600).default(60),
    memoryMb: z.number().int().min(64).max(1024).default(256),
    pidsLimit: z.number().int().min(16).max(512).default(128),
    maxOutputBytes: z.number().int().min(1024).max(2_000_000).default(64_000),
    /** Image built by `starclaw shell build`. Default: starclaw-shell:<package version>. */
    image: z.string().regex(/^[a-z0-9][a-z0-9._/:@-]{0,200}$/).optional(),
    /** Limits on the workspace copy that goes into the container (and on what may come back). */
    workspace: z
      .object({
        maxFiles: z.number().int().min(1).max(20_000).default(2000),
        maxBytes: z.number().int().min(1024).max(256_000_000).default(32_000_000),
        maxFileBytes: z.number().int().min(1024).max(64_000_000).default(8_000_000),
        maxChangedFiles: z.number().int().min(0).max(5000).default(500),
        maxDeletedFiles: z.number().int().min(0).max(5000).default(100),
      })
      .strict()
      .default({ maxFiles: 2000, maxBytes: 32_000_000, maxFileBytes: 8_000_000, maxChangedFiles: 500, maxDeletedFiles: 100 }),
  })
  .strict();

export const ScheduledPolicySchema = z
  .object({
    /** Total scheduled runs per UTC day, all jobs together. */
    maxRunsPerDay: z.number().int().min(0).max(10_000).default(24),
    /** LLM spend per UTC day attributable to scheduled runs (integer cents), on top of llmBudget.perDayCents. */
    maxLlmCentsPerDay: z.number().int().min(0).max(1_000_000).default(50),
    maxJobsTotal: z.number().int().min(0).max(1000).default(10),
    /** What an unattended run does with an `ask`: deny at once, or ask the owner through an asynchronous approver (Telegram). */
    defaultVerdictForAsk: z.enum(['deny', 'ask-async']).default('deny'),
    /** How long an asynchronous approval stays valid before it is a deny. */
    approvalTimeoutSeconds: z.number().int().min(30).max(86_400).default(900),
    /** Shortest allowed gap between runs of one job (also bounds cron expressions). */
    minIntervalSeconds: z.number().int().min(60).max(86_400).default(300),
    /** Wall-clock cap for one scheduled run. */
    maxRunSeconds: z.number().int().min(10).max(7200).default(600),
    maxRunsPerJobPerDay: z.number().int().min(1).max(10_000).default(24),
    /** After this many consecutive failures a job is paused. */
    maxConsecutiveFailures: z.number().int().min(1).max(100).default(5),
    backoffBaseSeconds: z.number().int().min(10).max(3600).default(60),
    /** IANA timezone used to interpret cron expressions. */
    timezone: z
      .string()
      .min(1)
      .max(64)
      .refine((tz) => {
        try {
          new Intl.DateTimeFormat('en-US', { timeZone: tz });
          return true;
        } catch {
          return false;
        }
      }, 'not a valid IANA timezone')
      .default('UTC'),
  })
  .strict();

export const NotifyPolicySchema = z
  .object({
    maxPerHour: z.number().int().min(0).max(1000).default(4),
    maxPerDay: z.number().int().min(0).max(10_000).default(20),
    maxChars: z.number().int().min(20).max(3500).default(1000),
  })
  .strict();

/** An allowed domain: an exact host (`example.com`) or `*.sub.example.com` (subdomains only). No IPs, no localhost. */
export const BROWSER_DOMAIN_RE = /^(\*\.)?(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

export const BrowserPolicySchema = z
  .object({
    /** Off by default. When false every tools.browse* call is refused before anything else happens. */
    enabled: z.boolean().default(false),
    /** REQUIRED non-empty when enabled. Enforced here before any request, and again by the browser's own egress proxy. */
    allowedDomains: z
      .array(z.string().regex(BROWSER_DOMAIN_RE, 'must be a lowercase domain like example.com or *.docs.example.com (no IPs, no localhost, no scheme, no path)'))
      .max(50)
      .default([]),
    /** Actions per tab, counting the open. */
    maxActions: z.number().int().min(1).max(200).default(20),
    /** Browser-side spend envelope for the tab, integer cents. */
    budgetCents: z.number().int().min(0).max(1_000_000).default(0),
    /** Optional per-action cost the browser charges against the budget. */
    actionCostCents: z.number().int().min(0).max(100_000).optional(),
    ttlSeconds: z.number().int().min(30).max(3600).default(900),
    /** Hard caps on what one read may return. */
    maxReadBytes: z.number().int().min(1024).max(262_144).default(65_536),
    maxLinks: z.number().int().min(1).max(500).default(100),
    timeoutSeconds: z.number().int().min(1).max(120).default(70),
    /**
     * Off by default. When false the tab is opened without `allow_input` (the browser then refuses typing too) and
     * tools.browseType is refused before any request or approval prompt. Typing hands data to a website.
     */
    allowInput: z.boolean().default(false),
  })
  .strict()
  .refine((b) => !b.enabled || b.allowedDomains.length > 0, { message: 'browser.allowedDomains must be non-empty when browser.enabled is true', path: ['allowedDomains'] });

/**
 * The signed skills registry (deliberately NOT an open store). Disabled by default: when false, `starclaw skills install`
 * and running a registry skill are refused and nothing else changes. There is no network fetch: bundles are installed
 * from a local file the owner points to.
 */
export const SkillsRegistryPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    /** Hard caps applied BEFORE a bundle is parsed / while it is validated. */
    maxBundleBytes: z.number().int().min(1024).max(5_000_000).default(524_288),
    maxFiles: z.number().int().min(1).max(64).default(16),
    maxFileBytes: z.number().int().min(1).max(2_000_000).default(262_144),
  })
  .strict();

const EnvNameSchema = z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/, 'must be the NAME of an environment variable (e.g. SLACK_BOT_TOKEN), never the secret itself');

/**
 * Slack channel (Events API over a signed webhook). Secrets and the owner id come ONLY from the environment variables named
 * here; the policy file holds names, never values. Disabled by default. Fails closed (the daemon refuses to start) when enabled
 * without a bot token, a signing secret and an owner user id.
 */
export const SlackPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    botTokenEnv: EnvNameSchema.default('SLACK_BOT_TOKEN'),
    signingSecretEnv: EnvNameSchema.default('SLACK_SIGNING_SECRET'),
    ownerIdEnv: EnvNameSchema.default('SLACK_OWNER_ID'),
    /** Like TELEGRAM_ALLOW_PUBLIC=1: messages from anyone else run as TAINTED non-owner goals. Default false = they are ignored. */
    allowPublic: z.boolean().default(false),
  })
  .strict();

/** Discord channel (slash command + button interactions over a signed webhook; no gateway, no message-content intent). */
export const DiscordPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    botTokenEnv: EnvNameSchema.default('DISCORD_BOT_TOKEN'),
    /** The application's Ed25519 public key (hex): used to verify every interaction. Not secret, but it must come from the environment too. */
    publicKeyEnv: EnvNameSchema.default('DISCORD_PUBLIC_KEY'),
    applicationIdEnv: EnvNameSchema.default('DISCORD_APPLICATION_ID'),
    ownerIdEnv: EnvNameSchema.default('DISCORD_OWNER_ID'),
    allowPublic: z.boolean().default(false),
  })
  .strict();

/**
 * WhatsApp (Meta's official Cloud API; webhooks signed with the app secret). Names of env vars only, never values.
 * Free-form messages to the owner only work within 24 h of the owner's last message (WhatsApp rule).
 */
export const WhatsAppPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    tokenEnv: EnvNameSchema.default('WHATSAPP_TOKEN'),
    appSecretEnv: EnvNameSchema.default('WHATSAPP_APP_SECRET'),
    verifyTokenEnv: EnvNameSchema.default('WHATSAPP_VERIFY_TOKEN'),
    phoneNumberIdEnv: EnvNameSchema.default('WHATSAPP_PHONE_NUMBER_ID'),
    /** The owner's number, digits only in international format (e.g. 15551234567). */
    ownerNumberEnv: EnvNameSchema.default('WHATSAPP_OWNER_NUMBER'),
    /** Graph API version in the send URL. v25.0 is supported until 2028-07-29 per Meta's changelog (checked 2026-11-18). */
    graphApiVersion: z.string().regex(/^v\d{1,3}\.\d$/).default('v25.0'),
    allowPublic: z.boolean().default(false),
  })
  .strict();

/** Signal through a signal-cli-rest-api bridge YOU run on this PC (loopback only). */
export const SignalPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    bridgeUrl: z.string().url().max(200).default('http://127.0.0.1:8080'),
    /** The bot's own Signal number (+international). */
    accountEnv: EnvNameSchema.default('SIGNAL_ACCOUNT'),
    ownerNumberEnv: EnvNameSchema.default('SIGNAL_OWNER_NUMBER'),
    allowPublic: z.boolean().default(false),
  })
  .strict();

const HOSTNAME = z.string().regex(/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i, 'must be a host name like imap.gmail.com');

/** Email: IMAP (TLS) in, SMTP (TLS) out, one owner address; owner mail must pass your provider's DMARC check. */
export const EmailPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    imapHost: HOSTNAME.optional(),
    imapPort: z.number().int().min(1).max(65535).default(993),
    smtpHost: HOSTNAME.optional(),
    smtpPort: z.union([z.literal(465), z.literal(587)]).default(465),
    userEnv: EnvNameSchema.default('EMAIL_USER'),
    passwordEnv: EnvNameSchema.default('EMAIL_PASSWORD'),
    ownerAddressEnv: EnvNameSchema.default('EMAIL_OWNER_ADDRESS'),
    /** Your mail provider's authserv-id: the first word of the Authentication-Results header IT adds (Gmail: mx.google.com). */
    authservId: HOSTNAME.optional(),
    pollSeconds: z.number().int().min(15).max(3600).default(60),
    allowPublic: z.boolean().default(false),
  })
  .strict()
  .superRefine((e, ctx) => {
    if (!e.enabled) return;
    for (const k of ['imapHost', 'smtpHost', 'authservId'] as const) if (!e[k]) ctx.addIssue({ code: 'custom', path: [k], message: `email.${k} is required when email.enabled is true` });
  });

/** The one loopback listener shared by Slack and Discord, and which channel carries approvals and owner notifications. */
export const ChannelsPolicySchema = z
  .object({
    /** Listens on 127.0.0.1 ONLY. Exposing it to Slack/Discord needs a tunnel/reverse proxy that YOU set up (see README). */
    port: z.number().int().min(1024).max(65535).default(8787),
    /** Which channel carries approvals and tools.notifyOwner. Telegram stays the default (existing behaviour). */
    ownerChannel: z.enum(['telegram', 'slack', 'discord', 'whatsapp', 'signal', 'email']).default('telegram'),
    /** A signed request older (or newer) than this is rejected. */
    timestampToleranceSeconds: z.number().int().min(30).max(900).default(300),
    maxBodyBytes: z.number().int().min(1024).max(1_000_000).default(262_144),
  })
  .strict();

/** An MCP tool name as StarClaw accepts it (the action target is `server/tool`, so `/` is never allowed). */
export const MCP_TOOL_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

export const McpServerSchema = z
  .object({
    /** Used in rules as the first part of the target: `{ class: "mcp.call", target: "github/list_*", verdict: "allow" }`. */
    name: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/, 'lowercase letters, digits, _ and -, starting with a letter'),
    transport: z.enum(['stdio', 'http']),
    /** stdio: the program to start (it runs on this PC, OUTSIDE StarClaw's sandbox). */
    command: z.string().min(1).max(500).optional(),
    args: z.array(z.string().max(2000)).max(64).default([]),
    /** stdio: NAMES of environment variables to pass to the server (nothing else of yours is inherited). */
    env: z.array(EnvNameSchema).max(32).default([]),
    /** http: the server's endpoint. https, or http to this PC only. */
    url: z.string().url().max(500).optional(),
    /** http: NAME of the env var holding a bearer token. */
    bearerTokenEnv: EnvNameSchema.optional(),
    /** Only these tools are offered and callable (others are refused before anyone is asked). Absent = all the server lists. */
    tools: z.array(z.string().regex(MCP_TOOL_RE)).max(200).optional(),
    timeoutSeconds: z.number().int().min(1).max(300).default(30),
    /** Text a single call may return to the agent (more is cut). */
    maxResultChars: z.number().int().min(200).max(200_000).default(20_000),
  })
  .strict()
  .superRefine((s, ctx) => {
    if (s.transport === 'stdio') {
      if (!s.command) ctx.addIssue({ code: 'custom', path: ['command'], message: 'a stdio server needs a command' });
      if (s.url || s.bearerTokenEnv) ctx.addIssue({ code: 'custom', path: ['url'], message: 'url/bearerTokenEnv are for http servers' });
    } else {
      if (!s.url) ctx.addIssue({ code: 'custom', path: ['url'], message: 'an http server needs a url' });
      else {
        const u = new URL(s.url);
        const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
        if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) ctx.addIssue({ code: 'custom', path: ['url'], message: 'must be https (plain http only to localhost)' });
        if (u.username || u.password) ctx.addIssue({ code: 'custom', path: ['url'], message: 'must not contain credentials (use bearerTokenEnv)' });
      }
      if (s.command || s.args.length || s.env.length) ctx.addIssue({ code: 'custom', path: ['command'], message: 'command/args/env are for stdio servers' });
    }
  });
export type McpServerConfig = z.infer<typeof McpServerSchema>;

/** MCP servers the agent may call (tools.mcpList / tools.mcpCall). Disabled by default; every call is an `mcp.call` action. */
export const McpPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    servers: z.array(McpServerSchema).max(20).default([]),
  })
  .strict()
  .refine((m) => new Set(m.servers.map((s) => s.name)).size === m.servers.length, { message: 'MCP server names must be unique', path: ['servers'] });

export const SubagentsPolicySchema = z
  .object({
    /** Off by default. When false every tools.spawnAgent call is refused before anything else happens. */
    enabled: z.boolean().default(false),
    /** How deep the tree may go. 1 = the run you start may spawn children, and those children cannot spawn. */
    maxDepth: z.number().int().min(1).max(3).default(1),
    /** Children of ONE run running at the same time. */
    maxConcurrent: z.number().int().min(1).max(8).default(2),
    /** Children one run may start in total. */
    maxTotalPerRun: z.number().int().min(1).max(50).default(4),
    /** Longest wall-clock life of a child; also its default. Never longer than what is left of its parent's. */
    maxSeconds: z.number().int().min(10).max(3600).default(300),
    /** Most governed actions (tool calls) one child may attempt. */
    maxActionsPerChild: z.number().int().min(1).max(500).default(50),
    /** Largest LLM budget a child may be given (integer cents, carved from the parent's remaining per-run budget). Also its default. */
    maxLlmCentsPerChild: z.number().int().min(1).max(10_000).default(10),
    /** Largest spend a child may be given (integer cents, carved from the parent's remaining spend cap). 0 = children can never spend. */
    maxSpendCentsPerChild: z.number().int().min(0).max(1_000_000).default(0),
    /** A child's result is cut to this many characters before the parent sees it. */
    maxResultChars: z.number().int().min(200).max(100_000).default(4000),
  })
  .strict();

export const PolicySchema = z
  .object({
    version: z.literal(1),
    workspace: z.string().min(1).default('./workspace'),
    agent: z
      .object({
        maxSteps: z.number().int().min(1).max(12).default(4),
        maxRuntimeRetries: z.number().int().min(0).max(2).default(1),
        maxSeconds: z.number().int().min(1).max(3600).default(300),
        /** Refuse writeFile/editFile/applyPatch on an EXISTING file the job has not read with tools.readFile (nothing is written; the model is told to read first). */
        requireReadBeforeEdit: z.boolean().default(true),
        /**
         * OPT-IN. Default false: a denied step ends the job (the safe behaviour). When true, a denial is returned to the
         * model as feedback and the job may replan within maxSteps; the identical action (same payload hash) is never
         * proposed to a human again in that job, and every new action still goes through approval.
         */
        continueAfterDeny: z.boolean().default(false),
      })
      .strict()
      .default({ maxSteps: 4, maxRuntimeRetries: 1, maxSeconds: 300, requireReadBeforeEdit: true, continueAfterDeny: false }),
    approvalTimeoutSeconds: z.number().int().min(5).max(3600).default(120),
    defaults: z
      .object({
        exec: VerdictSchema.default('ask'),
        'fs.read': VerdictSchema.default('ask'),
        'fs.write': VerdictSchema.default('ask'),
        'net.egress': VerdictSchema.default('ask'),
        spend: VerdictSchema.default('ask'),
        'skill.save': VerdictSchema.default('ask'),
        'memory.write': VerdictSchema.default('ask'),
        'shell.exec': VerdictSchema.default('ask'),
        /** LEGACY unsandboxed host command. `ask` here means: a human at the terminal/Telegram must approve; with no approver, and in every scheduled run, it is denied. */
        'host.exec': VerdictSchema.default('ask'),
        /** Whatever this says, an agent-created schedule always needs a human (see ALWAYS_ASK). */
        'schedule.create': VerdictSchema.default('ask'),
        /** Messages only ever go to the configured owner; rate-limited and length-capped. Tainted sessions escalate to ask. */
        'notify.owner': VerdictSchema.default('allow'),
        /** Whatever this says, opening a browser tab always needs a human (see ALWAYS_ASK). */
        'browser.open': VerdictSchema.default('ask'),
        'browser.navigate': VerdictSchema.default('allow'),
        'browser.read': VerdictSchema.default('allow'),
        /** Like navigate: allowed in a clean session, escalated to a human once the session is tainted (opening a page taints it). */
        'browser.click': VerdictSchema.default('allow'),
        /** Typing (needs browser.allowInput too). Whatever this says, it is never auto-allowed in a tainted session or an unattended run. */
        'browser.type': VerdictSchema.default('ask'),
        /** Starting a sub-agent. Needs subagents.enabled too. Whatever this says, an unattended run never auto-allows it, and a tainted session must ask. */
        'agent.spawn': VerdictSchema.default('ask'),
        /** Whatever this says, installing a registry skill always needs a human (see ALWAYS_ASK). */
        'skill.install': VerdictSchema.default('ask'),
        /** Calling a tool on an MCP server (needs mcp.enabled too). Never auto-allowed in a tainted session or an unattended run. */
        'mcp.call': VerdictSchema.default('ask'),
      })
      .strict()
      .default({
        exec: 'ask', 'fs.read': 'ask', 'fs.write': 'ask', 'net.egress': 'ask', spend: 'ask', 'skill.save': 'ask', 'memory.write': 'ask',
        'shell.exec': 'ask', 'host.exec': 'ask', 'schedule.create': 'ask', 'notify.owner': 'allow',
        'browser.open': 'ask', 'browser.navigate': 'allow', 'browser.read': 'allow', 'browser.click': 'allow', 'browser.type': 'ask', 'agent.spawn': 'ask', 'skill.install': 'ask',
        'mcp.call': 'ask',
      }),
    rules: z.array(RuleSchema).max(500).default([{ class: 'fs.read', inWorkspace: true, verdict: 'allow' }]),
    spend: z
      .object({
        /** Per-action cap in integer cents. 0 = spending is impossible. */
        maxPerActionCents: z.number().int().nonnegative().max(100_000_000).default(0),
        /** Total cap per UTC day (persisted across restarts) and per token, integer cents. */
        maxTotalCents: z.number().int().nonnegative().max(1_000_000_000).default(0),
        tokenMinutes: z.number().int().min(1).max(43_200).default(60),
      })
      .strict()
      .default({ maxPerActionCents: 0, maxTotalCents: 0, tokenMinutes: 60 }),
    llmBudget: z
      .object({
        perRunCents: z.number().int().nonnegative().max(1_000_000).default(50),
        perDayCents: z.number().int().nonnegative().max(10_000_000).default(500),
      })
      .strict()
      .default({ perRunCents: 50, perDayCents: 500 }),
    net: z
      .object({
        /** Allow connecting to loopback / private / link-local addresses (SSRF risk). */
        allowPrivateAddresses: z.boolean().default(false),
        maxResponseBytes: z.number().int().min(1024).max(50_000_000).default(1_000_000),
        timeoutSeconds: z.number().int().min(1).max(300).default(20),
        maxRedirects: z.number().int().min(0).max(10).default(3),
      })
      .strict()
      .default({ allowPrivateAddresses: false, maxResponseBytes: 1_000_000, timeoutSeconds: 20, maxRedirects: 3 }),
    sandbox: z
      .object({
        timeoutSeconds: z.number().int().min(1).max(3600).default(60),
        maxOutputBytes: z.number().int().min(1024).max(10_000_000).default(256_000),
        memoryMb: z.number().int().min(32).max(4096).default(256),
        maxBrokerCalls: z.number().int().min(1).max(10_000).default(200),
        /** container = Docker layer required; process = Node permission model only; auto = container if its probe passes, else process, else refuse. */
        mode: z.enum(['auto', 'container', 'process']).default('auto'),
        /** If true, anything but a passing container probe means generated code does NOT run (overrides mode). */
        requireContainer: z.boolean().default(false),
        /** Docker image built by `starclaw sandbox build`. Default: starclaw-sandbox:<package version>. */
        containerImage: z.string().regex(/^[a-z0-9][a-z0-9._/:@-]{0,200}$/).optional(),
        containerPidsLimit: z.number().int().min(8).max(512).default(64),
        /** Optional OCI runtime passthrough, e.g. "runsc" (gVisor). Passed to docker --runtime; NOT tested by this project. */
        containerRuntime: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,40}$/).optional(),
      })
      .strict()
      .default({ timeoutSeconds: 60, maxOutputBytes: 256_000, memoryMb: 256, maxBrokerCalls: 200, mode: 'auto', requireContainer: false, containerPidsLimit: 64 }),
    /** Model provider. API keys come ONLY from environment variables (never from this file). */
    llm: z
      .object({
        provider: z.enum(['groq', 'anthropic', 'openai-compat']).default('groq'),
        /** Required for anthropic and openai-compat (no stale defaults are baked in). */
        model: z.string().regex(/^[A-Za-z0-9._:/@-]{1,120}$/).optional(),
        /** Optional cheaper model for intent classification. */
        smallModel: z.string().regex(/^[A-Za-z0-9._:/@-]{1,120}$/).optional(),
        /** openai-compat: e.g. https://api.openai.com/v1, https://openrouter.ai/api/v1, http://localhost:11434/v1. http is allowed for loopback only. */
        baseUrl: z.string().url().max(300).optional(),
        /** NAME of the environment variable holding the key (default GROQ_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY). */
        apiKeyEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).optional(),
        /** Integer cents per million tokens. If omitted, a conservative PLACEHOLDER is used and doctor warns. */
        prices: z
          .object({ inputCentsPerMTok: z.number().int().nonnegative().max(1_000_000), outputCentsPerMTok: z.number().int().nonnegative().max(1_000_000) })
          .strict()
          .optional(),
        maxResponseBytes: z.number().int().min(1024).max(20_000_000).default(2_000_000),
        timeoutSeconds: z.number().int().min(1).max(600).default(60),
        /** Output-token cap for each code-generation / repair call. Too low cuts whole-file edits off mid-program. */
        maxOutputTokens: z.number().int().min(256).max(131_072).default(8192),
        /** OpenAI-compatible providers (incl. Groq): retries after HTTP 429, honouring Retry-After (each wait capped at 60 s). */
        rateLimitRetries: z.number().int().min(0).max(10).default(3),
        /**
         * Most tokens (input estimate + max output) one request may carry. Older observations are shortened (head + tail,
         * with a marker) to fit. Default: 7000 for provider groq (its free tier rejects bigger requests with HTTP 413),
         * otherwise no limit. Raise it on a paid Groq tier.
         */
        requestTokenLimit: z.number().int().min(2000).max(2_000_000).optional(),
      })
      .strict()
      .default({ provider: 'groq', maxResponseBytes: 2_000_000, timeoutSeconds: 60, maxOutputTokens: 8192, rateLimitRetries: 3 }),
    /** Web search provider for tools.search. Default: none (the tool refuses). */
    search: z
      .object({
        provider: z.enum(['none', 'searxng', 'brave']).default('none'),
        /** Self-hosted SearXNG base URL (JSON output must be enabled on the instance). */
        searxngUrl: z.string().url().max(300).optional(),
        /** Allow the provider host itself to be a private/loopback address (typical for a self-hosted SearXNG). Applies to the provider host only. */
        allowPrivateProvider: z.boolean().default(false),
        maxResults: z.number().int().min(1).max(20).default(10),
        /** NAME of the env var holding the Brave key (default BRAVE_API_KEY). */
        apiKeyEnv: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).optional(),
      })
      .strict()
      .default({ provider: 'none', allowPrivateProvider: false, maxResults: 10 }),
    /** The governed shell container (tools.shell). Network is "none" only: there is deliberately no way to open it up. */
    shell: ShellPolicySchema.default(ShellPolicySchema.parse({})),
    /** Scheduler / heartbeat (unattended runs). Conservative defaults. */
    scheduled: ScheduledPolicySchema.default(ScheduledPolicySchema.parse({})),
    /** tools.notifyOwner limits. */
    notify: NotifyPolicySchema.default(NotifyPolicySchema.parse({})),
    /** The governed browser tab (tools.browse*). Disabled by default; needs the MnemoPay Native Browser running with its control API on. */
    browser: BrowserPolicySchema.default(BrowserPolicySchema.parse({})),
    /** Signed, owner-approved skills registry (disabled by default). */
    skillsRegistry: SkillsRegistryPolicySchema.default(SkillsRegistryPolicySchema.parse({})),
    /** Slack / Discord channels (disabled by default). */
    slack: SlackPolicySchema.default(SlackPolicySchema.parse({})),
    discord: DiscordPolicySchema.default(DiscordPolicySchema.parse({})),
    whatsapp: WhatsAppPolicySchema.default(WhatsAppPolicySchema.parse({})),
    signal: SignalPolicySchema.default(SignalPolicySchema.parse({})),
    email: EmailPolicySchema.default(EmailPolicySchema.parse({})),
    channels: ChannelsPolicySchema.default(ChannelsPolicySchema.parse({})),
    /** Governed sub-agents (tools.spawnAgent): children that can only ever hold LESS authority than the run that starts them. Disabled by default. */
    subagents: SubagentsPolicySchema.default(SubagentsPolicySchema.parse({})),
    /** MCP servers (tools.mcpList / tools.mcpCall). Disabled by default; only servers declared here exist. */
    mcp: McpPolicySchema.default(McpPolicySchema.parse({})),
    /** Treat stdout of host commands and of the shell container as untrusted (taints the session). */
    execOutputTaints: z.boolean().default(true),
  })
  .strict()
  .superRefine((p, ctx) => {
    const oc = p.channels.ownerChannel;
    if (oc !== 'telegram' && !p[oc].enabled) {
      ctx.addIssue({ code: 'custom', path: ['channels', 'ownerChannel'], message: `channels.ownerChannel is "${oc}" but ${oc}.enabled is false` });
    }
  });

export type Policy = z.infer<typeof PolicySchema>;

export class PolicyError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'PolicyError';
  }
}

export function defaultPolicy(): Policy {
  return PolicySchema.parse({ version: 1 });
}

/** Parse + validate. Any problem throws PolicyError: callers must not fall back to something looser. */
export function parsePolicy(json: string): Policy {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (e: any) {
    throw new PolicyError(`policy is not valid JSON: ${e.message}`);
  }
  const r = PolicySchema.safeParse(raw);
  if (!r.success) {
    throw new PolicyError('policy is invalid: ' + r.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; '));
  }
  return r.data;
}

export function loadPolicy(file?: string, fallbackFile = 'starclaw.policy.json'): Policy {
  if (file) {
    let text: string;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (e: any) {
      throw new PolicyError(`cannot read policy file ${file}: ${e.message}`);
    }
    return parsePolicy(text);
  }
  if (fs.existsSync(fallbackFile)) return parsePolicy(fs.readFileSync(fallbackFile, 'utf8'));
  return defaultPolicy();
}

export function globToRegExp(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else re += '[^/]*';
    } else re += c.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$', 'i');
}

export interface PolicyEvaluation {
  verdict: Verdict;
  source: 'rule' | 'default';
  ruleIndex?: number;
}

/**
 * Deny-overrides: any matching `deny` rule wins; otherwise the first matching allow/ask rule; otherwise the
 * class default. Taint escalation is applied by the Governor, not here.
 */
export function evaluatePolicy(policy: Policy, action: Action): PolicyEvaluation {
  const matches: Array<{ i: number; verdict: Verdict }> = [];
  policy.rules.forEach((rule, i) => {
    if (rule.class !== action.class) return;
    if (rule.inWorkspace !== undefined && rule.inWorkspace !== !!action.inWorkspace) return;
    if (rule.maxCents !== undefined && (action.cents === undefined || action.cents > rule.maxCents)) return;
    if (rule.target !== undefined && !globToRegExp(rule.target).test(action.target)) return;
    matches.push({ i, verdict: rule.verdict });
  });
  const deny = matches.find((m) => m.verdict === 'deny');
  if (deny) return { verdict: 'deny', source: 'rule', ruleIndex: deny.i };
  if (matches.length) return { verdict: matches[0].verdict, source: 'rule', ruleIndex: matches[0].i };
  return { verdict: policy.defaults[action.class as ActionClass], source: 'default' };
}
