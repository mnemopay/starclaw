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

export const PolicySchema = z
  .object({
    version: z.literal(1),
    workspace: z.string().min(1).default('./workspace'),
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
      })
      .strict()
      .default({ exec: 'ask', 'fs.read': 'ask', 'fs.write': 'ask', 'net.egress': 'ask', spend: 'ask', 'skill.save': 'ask', 'memory.write': 'ask' }),
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
      })
      .strict()
      .default({ provider: 'groq', maxResponseBytes: 2_000_000, timeoutSeconds: 60 }),
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
    /** Treat stdout of host commands as untrusted (taints the session). */
    execOutputTaints: z.boolean().default(true),
  })
  .strict();

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
