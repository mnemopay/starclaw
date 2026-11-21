import { ASSUMED_PRICE, BackendLLM, OpenAICompatBackend, type BackendConfig, type Price } from './BackendLLM';
import { LlmError } from './http';

/**
 * Groq's built-in models and list prices (integer cents per million tokens), taken from Groq's model page on 2026-11-19:
 * gpt-oss-120b $0.15 in / $0.60 out, gpt-oss-20b $0.075 in (rounded UP to 8 cents) / $0.30 out. Prices change: set
 * llm.prices to be exact. The previous built-ins (llama-3.3-70b-versatile, llama-3.1-8b-instant) are no longer served on
 * Groq's on-demand tier (404 model_not_found), which broke every default install.
 */
export const GROQ_DEFAULTS = {
  baseUrl: 'https://api.groq.com/openai/v1',
  model: 'openai/gpt-oss-120b',
  smallModel: 'openai/gpt-oss-20b',
  /** Groq's free tier counts input + max_tokens against ~8,000 tokens per minute per model; stay under it. */
  requestTokenLimit: 7000,
  prices: {
    'openai/gpt-oss-120b': { inputCentsPerMTok: 15, outputCentsPerMTok: 60 },
    'openai/gpt-oss-20b': { inputCentsPerMTok: 8, outputCentsPerMTok: 30 },
  } as Record<string, Price>,
};

export type GroqOptions = Partial<Omit<BackendConfig, 'apiKey'>>;

/**
 * Groq over its OpenAI-compatible endpoint. llm.model / llm.smallModel / llm.prices override the built-ins exactly as
 * for the other providers; a model without a known or configured price uses the conservative placeholder.
 */
export class GroqLLM extends BackendLLM {
  constructor(apiKey = process.env.GROQ_API_KEY, opts: GroqOptions = {}) {
    if (!apiKey) throw new LlmError('GROQ_API_KEY is not set. Set it in the environment or a .env file to use the Groq backend.', 'config');
    const model = opts.model || GROQ_DEFAULTS.model;
    // A custom big model with no smallModel classifies with the same model, so its price applies to both.
    const smallModel = opts.smallModel ?? (opts.model ? undefined : GROQ_DEFAULTS.smallModel);
    const price = opts.price ?? GROQ_DEFAULTS.prices[model];
    // An unknown small model is costed at the placeholder, never at the (cheaper) big-model price.
    const smallPrice = smallModel ? (opts.price ?? GROQ_DEFAULTS.prices[smallModel] ?? ASSUMED_PRICE) : undefined;
    const cfg: BackendConfig = { ...opts, apiKey, model, smallModel, price, smallPrice, baseUrl: opts.baseUrl ?? GROQ_DEFAULTS.baseUrl, requestTokenLimit: opts.requestTokenLimit ?? GROQ_DEFAULTS.requestTokenLimit };
    super(new GroqBackend(cfg), cfg);
  }
}

class GroqBackend extends OpenAICompatBackend {
  override readonly provider = 'groq';
}
