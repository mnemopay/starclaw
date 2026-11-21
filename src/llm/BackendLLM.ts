import { reserveChat } from './reserve';
import type { LlmUsage } from '../governance/budget';
import { assertSafeBaseUrl, LlmError, postJson, scrub } from './http';
import { codegenSystemPrompt } from './prompts';
import type { ChatTurn, CodegenRequest, Intent, LLM, LlmResult, LlmCallOptions, LlmRetry } from './types';

export interface Price {
  inputCentsPerMTok: number;
  outputCentsPerMTok: number;
}

/**
 * Placeholder used ONLY when the policy gives no price for the chosen model. It is deliberately high (so budgets
 * trip early rather than late) and is NOT any provider's real price. `starclaw doctor` warns when it is in use.
 */
export const ASSUMED_PRICE: Price = { inputCentsPerMTok: 1500, outputCentsPerMTok: 1500 };

export interface ChatRequest {
  system: string;
  messages: ChatTurn[];
  maxTokens: number;
  temperature: number;
  model: string;
}
export interface ChatResponse {
  text: string;
  usage: LlmUsage;
  /** The provider stopped because it reached max_tokens (OpenAI finish_reason "length", Anthropic stop_reason "max_tokens"). */
  truncated?: boolean;
  /** Retries that happened inside this request. */
  retries?: LlmRetry[];
}
export interface ChatBackend {
  readonly provider: string;
  complete(req: ChatRequest): Promise<ChatResponse>;
}

export interface BackendConfig {
  model: string;
  /** Optional cheaper model used for intent classification. */
  smallModel?: string;
  price?: Price;
  /** Price of smallModel when it differs from `price` (Groq's built-in pair). Defaults to `price`. */
  smallPrice?: Price;
  /** Output-token cap for code generation and repair (policy llm.maxOutputTokens). */
  maxOutputTokens?: number;
  baseUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
  /** OpenAI-compatible only: how many times to retry after HTTP 429 (default 3). */
  rateLimitRetries?: number;
  /** Upper bound on one 429 wait in seconds (default 60). */
  maxRateLimitWaitSeconds?: number;
  /** Test hook for the 429 wait. */
  sleep?: (ms: number) => Promise<void>;
}

const nonNegInt = (n: unknown): number => {
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) throw new LlmError('provider response has missing or invalid usage', 'malformed');
  return n;
};

function stripFences(s: string): string {
  return s.replace(/```(?:javascript|typescript|js|ts)?/g, '').trim();
}

/** Default output cap for code generation and repair when the policy does not set llm.maxOutputTokens. */
export const DEFAULT_MAX_OUTPUT_TOKENS = 8192;
/** Reasoning models spend tokens before the one-word answer, so the classifier needs more than a few tokens. */
const CLASSIFY_MAX_TOKENS = 256;
const CONVERSE_MAX_TOKENS = 2048;

type Truncation = 'throw' | 'throw-if-empty' | 'allow';

/** Prompts + parsing shared by every provider. Everything the model returns is untrusted text. */
export class BackendLLM implements LLM {
  readonly priceAssumed: boolean;
  readonly price: Price;
  constructor(private readonly backend: ChatBackend, private readonly cfg: BackendConfig) {
    this.priceAssumed = !cfg.price;
    this.price = cfg.price ?? ASSUMED_PRICE;
  }
  get provider() {
    return this.backend.provider;
  }
  get model() {
    return this.cfg.model;
  }

  get maxOutputTokens() {
    return this.cfg.maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS;
  }

  private async chat(model: string, system: string, messages: ChatTurn[], maxTokens: number, temperature: number, options: LlmCallOptions | undefined, onTruncated: Truncation, price: Price = this.price): Promise<LlmResult<string>> {
    const reservation = reserveChat(options, { system, messages }, maxTokens, price);
    const r = await this.backend.complete({ system, messages, maxTokens: reservation.maxTokens, temperature, model });
    reservation.settle(r.usage);
    if (r.truncated && (onTruncated === 'throw' || (onTruncated === 'throw-if-empty' && !r.text.trim()))) {
      const why =
        reservation.maxTokens < maxTokens
          ? `the remaining LLM budget only funded ${reservation.maxTokens} of ${maxTokens} output tokens; raise the run's LLM budget`
          : `raise llm.maxOutputTokens in the policy (now ${this.maxOutputTokens}) or ask for a smaller step`;
      throw new LlmError(
        `${this.backend.provider} model "${model}" hit its ${reservation.maxTokens}-token output cap before finishing${r.text.trim() ? ' (the output was cut off)' : ' and returned no text'}: ${why}`,
        'output-limit',
      );
    }
    return { value: r.text, usage: r.usage, price, priceAssumed: this.priceAssumed, prepaid: reservation.prepaid, ...(r.retries?.length ? { retries: r.retries } : {}) };
  }

  async classifyIntent(goal: string, options?: LlmCallOptions): Promise<LlmResult<Intent>> {
    const r = await this.chat(
      this.cfg.smallModel ?? this.cfg.model,
      'Classify the user message as "conversation" (chat, greetings, questions needing no action) or "task" (anything needing files, web, code or commands). Reply with exactly one word.',
      [{ role: 'user', content: goal }],
      CLASSIFY_MAX_TOKENS,
      0.1,
      options,
      'allow',
      this.cfg.smallModel ? (this.cfg.smallPrice ?? this.price) : this.price,
    );
    // Anything that is not clearly "conversation" is a task: fail towards the governed path.
    return { ...r, value: /^\s*"?conversation/i.test(r.value) ? 'conversation' : 'task' };
  }

  async generateCode(req: CodegenRequest, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const history = req.history.slice(-10);
    const r = await this.chat(this.cfg.model, codegenSystemPrompt(req.memoryContext, req.tainted, req.subagent), [...history, { role: 'user', content: `Goal: ${req.goal}\n\nWrite the code.` }], this.maxOutputTokens, 0.2, options, 'throw');
    return { ...r, value: stripFences(r.value) };
  }

  async converse(message: string, history: ChatTurn[], options?: LlmCallOptions): Promise<LlmResult<string>> {
    return this.chat(this.cfg.model, 'You are StarClaw, a governed autonomous agent. In conversation mode you cannot take actions. Be concise and helpful.', [...history.slice(-10), { role: 'user', content: message }], Math.min(CONVERSE_MAX_TOKENS, this.maxOutputTokens), 0.7, options, 'throw-if-empty');
  }

  async fixCode(goal: string, code: string, error: string, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const r = await this.chat(
      this.cfg.model,
      'Fix the JavaScript so it parses. Use require()/module.exports, no import/export. Output only raw code, no markdown.',
      [{ role: 'user', content: `Goal: ${goal}\nError: ${error}\nCode:\n${code}` }],
      this.maxOutputTokens,
      0.1,
      options,
      'throw',
    );
    return { ...r, value: stripFences(r.value) };
  }
}

function mergeTurns(messages: ChatTurn[]): ChatTurn[] {
  // Providers require alternating roles starting with "user": merge adjacent same-role turns, drop leading assistants.
  const out: ChatTurn[] = [];
  for (const m of messages) {
    if (!m.content) continue;
    const last = out[out.length - 1];
    if (last && last.role === m.role) last.content += '\n\n' + m.content;
    else out.push({ role: m.role, content: m.content });
  }
  while (out.length && out[0].role !== 'user') out.shift();
  return out;
}

/** Anthropic Messages API over plain fetch. Only `text` content blocks are used; tool_use blocks etc. are ignored. */
export class AnthropicBackend implements ChatBackend {
  readonly provider = 'anthropic';
  private readonly base: URL;
  constructor(private readonly cfg: BackendConfig) {
    if (!cfg.apiKey) throw new LlmError('ANTHROPIC_API_KEY (or the env var named by llm.apiKeyEnv) is not set', 'config');
    this.base = assertSafeBaseUrl(cfg.baseUrl ?? 'https://api.anthropic.com');
  }
  async complete(req: ChatRequest): Promise<ChatResponse> {
    const url = new URL('/v1/messages', this.base).toString();
    const j = await postJson({
      url,
      headers: { 'x-api-key': this.cfg.apiKey!, 'anthropic-version': '2023-06-01' },
      body: { model: req.model, max_tokens: req.maxTokens, temperature: req.temperature, system: req.system, messages: mergeTurns(req.messages) },
      timeoutMs: this.cfg.timeoutMs ?? 60_000,
      maxResponseBytes: this.cfg.maxResponseBytes ?? 2_000_000,
      secrets: [this.cfg.apiKey!],
      fetchImpl: this.cfg.fetchImpl,
    });
    if (!j || !Array.isArray(j.content)) throw new LlmError('Anthropic response has no content array', 'malformed');
    const text = j.content.filter((b: any) => b && b.type === 'text' && typeof b.text === 'string').map((b: any) => b.text).join('');
    return { text, truncated: j.stop_reason === 'max_tokens', usage: { inputTokens: nonNegInt(j.usage?.input_tokens), outputTokens: nonNegInt(j.usage?.output_tokens) } };
  }
}

/** OpenAI-style chat completions (OpenAI, OpenRouter, Ollama, LM Studio, vLLM, ...). Key optional for loopback servers. */
export class OpenAICompatBackend implements ChatBackend {
  readonly provider: string = 'openai-compat';
  private readonly base: URL;
  constructor(private readonly cfg: BackendConfig) {
    this.base = assertSafeBaseUrl(cfg.baseUrl ?? 'https://api.openai.com/v1');
    const host = this.base.hostname.replace(/^\[|\]$/g, '');
    const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';
    if (!cfg.apiKey && !loopback) throw new LlmError('an API key (env var named by llm.apiKeyEnv, default OPENAI_API_KEY) is required for non-local OpenAI-compatible servers', 'config');
  }
  async complete(req: ChatRequest): Promise<ChatResponse> {
    const url = this.base.toString().replace(/\/+$/, '') + '/chat/completions';
    const headers: Record<string, string> = {};
    if (this.cfg.apiKey) headers.authorization = `Bearer ${this.cfg.apiKey}`;
    const retries: LlmRetry[] = [];
    const post = (messages: ChatTurn[]) =>
      this.withRateLimitRetry(retries, () =>
        postJson({
          url,
          headers,
          body: { model: req.model, max_tokens: req.maxTokens, temperature: req.temperature, messages: [{ role: 'system', content: req.system }, ...mergeTurns(messages)] },
          timeoutMs: this.cfg.timeoutMs ?? 60_000,
          maxResponseBytes: this.cfg.maxResponseBytes ?? 2_000_000,
          secrets: this.cfg.apiKey ? [this.cfg.apiKey] : [],
          fetchImpl: this.cfg.fetchImpl,
        }),
      );
    let j: any;
    let extraInputTokens = 0;
    try {
      j = await post(req.messages);
    } catch (e) {
      // Some hosted models (gpt-oss on Groq) answer the tool docs in our prompt with a NATIVE tool call, which the
      // provider rejects (HTTP 400 tool_use_failed) because we declare no tools. Retry once with a correction.
      if (!(e instanceof LlmError && e.kind === 'http' && e.status === 400 && /tool_use_failed/.test(e.message))) throw e;
      retries.push({ kind: 'tool_use_failed' });
      j = await post([...req.messages, { role: 'user', content: NATIVE_TOOL_CALL_CORRECTION }]);
      // The rejected call reports no usage; count its input as roughly the retry's (an over-estimate) so budgets stay conservative.
      extraInputTokens = nonNegInt(j?.usage?.prompt_tokens);
    }
    const choice = j?.choices?.[0];
    const truncated = choice?.finish_reason === 'length';
    let content = choice?.message?.content;
    // Reasoning models that spend the whole budget thinking return content null (or omit it) with finish_reason "length".
    if (content == null && truncated) content = '';
    if (typeof content !== 'string') throw new LlmError('OpenAI-compatible response has no choices[0].message.content string', 'malformed');
    return { text: content, truncated, usage: { inputTokens: nonNegInt(j.usage?.prompt_tokens) + extraInputTokens, outputTokens: nonNegInt(j.usage?.completion_tokens) }, ...(retries.length ? { retries } : {}) };
  }

  /** HTTP 429: wait (Retry-After, else a default) and retry a bounded number of times. Free tiers (Groq) limit tokens per minute. */
  private async withRateLimitRetry<T>(log: LlmRetry[], fn: () => Promise<T>): Promise<T> {
    const retries = this.cfg.rateLimitRetries ?? 3;
    for (let attempt = 0; ; attempt++) {
      try {
        return await fn();
      } catch (e) {
        if (!(e instanceof LlmError && e.kind === 'rate-limit') || attempt >= retries) throw e;
        const waitS = Math.min(Math.max(e.retryAfterSeconds ?? 20, 0), this.cfg.maxRateLimitWaitSeconds ?? 60);
        log.push({ kind: 'rate-limit', waitSeconds: waitS });
        await (this.cfg.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms))))(waitS * 1000);
      }
    }
  }
}

/** Sent after a provider rejected a native tool call (see OpenAICompatBackend.complete). */
export const NATIVE_TOOL_CALL_CORRECTION =
  'Your previous reply was a native tool/function call, which is not available here and was rejected. The tools.* functions exist only inside the JavaScript program you write. Reply with the complete program as plain text, defining async function execute() and module.exports = { execute }.';

export function AnthropicLLM(cfg: BackendConfig): BackendLLM {
  return new BackendLLM(new AnthropicBackend(cfg), cfg);
}
export function OpenAICompatLLM(cfg: BackendConfig): BackendLLM {
  return new BackendLLM(new OpenAICompatBackend(cfg), cfg);
}

export { scrub };
