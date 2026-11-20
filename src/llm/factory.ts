import type { Policy } from '../governance/policy';
import { AnthropicLLM, OpenAICompatLLM } from './BackendLLM';
import { GROQ_DEFAULTS, GroqLLM } from './GroqLLM';
import { LlmError } from './http';
import type { LLM } from './types';

type Env = Record<string, string | undefined>;
type LlmPolicy = Policy['llm'];

const DEFAULT_KEY_ENV: Record<LlmPolicy['provider'], string> = { groq: 'GROQ_API_KEY', anthropic: 'ANTHROPIC_API_KEY', 'openai-compat': 'OPENAI_API_KEY' };

export function keyEnvName(p: LlmPolicy): string {
  return p.apiKeyEnv ?? DEFAULT_KEY_ENV[p.provider];
}

/** Build the configured model client. Keys are read from the environment only. Throws LlmError('config') when unusable. */
export function createLLM(p: LlmPolicy, env: Env = process.env, fetchImpl?: typeof fetch): LLM {
  const apiKey = env[keyEnvName(p)];
  const common = { model: p.model ?? '', smallModel: p.smallModel, price: p.prices, baseUrl: p.baseUrl, apiKey, timeoutMs: p.timeoutSeconds * 1000, maxResponseBytes: p.maxResponseBytes, maxOutputTokens: p.maxOutputTokens, fetchImpl };
  switch (p.provider) {
    case 'groq':
      return new GroqLLM(apiKey, { ...common, model: p.model, baseUrl: p.baseUrl });
    case 'anthropic':
      if (!p.model) throw new LlmError('llm.model is required for provider "anthropic" (no model name is baked in)', 'config');
      return AnthropicLLM(common);
    case 'openai-compat':
      if (!p.model) throw new LlmError('llm.model is required for provider "openai-compat"', 'config');
      return OpenAICompatLLM(common);
  }
}

export interface LlmDescription {
  provider: string;
  model: string;
  keyEnv: string;
  keyPresent: boolean;
  baseUrl?: string;
  priceStatus: 'configured' | 'built-in (unverified)' | 'ASSUMED placeholder';
  warnings: string[];
}

/** For `starclaw doctor`: no network, never prints a key. */
export function describeLlm(p: LlmPolicy, env: Env = process.env): LlmDescription {
  const keyEnv = keyEnvName(p);
  const keyPresent = !!env[keyEnv];
  const warnings: string[] = [];
  let priceStatus: LlmDescription['priceStatus'];
  if (p.prices) priceStatus = 'configured';
  else if (p.provider === 'groq' && GROQ_DEFAULTS.prices[p.model ?? GROQ_DEFAULTS.model]) {
    priceStatus = 'built-in (unverified)';
    warnings.push('Groq prices are built in from Groq\'s list prices as of 2026-11-19 and may have changed; set llm.prices to be exact.');
  } else {
    priceStatus = 'ASSUMED placeholder';
    warnings.push(`no llm.prices set for ${p.provider}/${p.model ?? '(no model)'}: using a conservative PLACEHOLDER of 1500 cents per million tokens (input and output). It is not the provider's price; LLM budgets are only as accurate as this number. Set llm.prices (use 0 for local models).`);
  }
  if (p.provider !== 'groq' && !p.model) warnings.push('llm.model is not set: this provider cannot be used until it is.');
  const loopback = !!p.baseUrl && /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]|$)/.test(p.baseUrl);
  if (!keyPresent && !(p.provider === 'openai-compat' && loopback)) warnings.push(`environment variable ${keyEnv} is not set: model calls will fail.`);
  return { provider: p.provider, model: p.model ?? (p.provider === 'groq' ? `${GROQ_DEFAULTS.model} (+ ${GROQ_DEFAULTS.smallModel} for classification)` : '(unset)'), keyEnv, keyPresent, baseUrl: p.baseUrl, priceStatus, warnings };
}
