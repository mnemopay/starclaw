import { reserveChat } from './reserve';
import type { LlmUsage } from '../governance/budget';
import { assertSafeBaseUrl, LlmError, postJson, scrub } from './http';
import { codegenSystemPrompt } from './prompts';
import type { ChatTurn, CodegenRequest, Intent, LLM, LlmResult, LlmCallOptions } from './types';

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
  baseUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}

const nonNegInt = (n: unknown): number => {
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) throw new LlmError('provider response has missing or invalid usage', 'malformed');
  return n;
};

function stripFences(s: string): string {
  return s.replace(/```(?:javascript|typescript|js|ts)?/g, '').trim();
}

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

  private async chat(model: string, system: string, messages: ChatTurn[], maxTokens: number, temperature: number, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const reservation = reserveChat(options, { system, messages }, maxTokens, this.price);
    const r = await this.backend.complete({ system, messages, maxTokens: reservation.maxTokens, temperature, model });
    reservation.settle(r.usage);
    return { value: r.text, usage: r.usage, price: this.price, priceAssumed: this.priceAssumed, prepaid: reservation.prepaid };
  }

  async classifyIntent(goal: string, options?: LlmCallOptions): Promise<LlmResult<Intent>> {
    const r = await this.chat(
      this.cfg.smallModel ?? this.cfg.model,
      'Classify the user message as "conversation" (chat, greetings, questions needing no action) or "task" (anything needing files, web, code or commands). Reply with exactly one word.',
      [{ role: 'user', content: goal }],
      10,
      0.1,
      options,
    );
    // Anything that is not clearly "conversation" is a task: fail towards the governed path.
    return { ...r, value: /^\s*"?conversation/i.test(r.value) ? 'conversation' : 'task' };
  }

  async generateCode(req: CodegenRequest, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const history = req.history.slice(-10);
    const r = await this.chat(this.cfg.model, codegenSystemPrompt(req.memoryContext, req.tainted, req.subagent), [...history, { role: 'user', content: `Goal: ${req.goal}\n\nWrite the code.` }], 1500, 0.2, options);
    return { ...r, value: stripFences(r.value) };
  }

  async converse(message: string, history: ChatTurn[], options?: LlmCallOptions): Promise<LlmResult<string>> {
    return this.chat(this.cfg.model, 'You are StarClaw, a governed autonomous agent. In conversation mode you cannot take actions. Be concise and helpful.', [...history.slice(-10), { role: 'user', content: message }], 500, 0.7, options);
  }

  async fixCode(goal: string, code: string, error: string, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const r = await this.chat(
      this.cfg.model,
      'Fix the JavaScript so it parses. Use require()/module.exports, no import/export. Output only raw code, no markdown.',
      [{ role: 'user', content: `Goal: ${goal}\nError: ${error}\nCode:\n${code}` }],
      1500,
      0.1,
      options,
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
    return { text, usage: { inputTokens: nonNegInt(j.usage?.input_tokens), outputTokens: nonNegInt(j.usage?.output_tokens) } };
  }
}

/** OpenAI-style chat completions (OpenAI, OpenRouter, Ollama, LM Studio, vLLM, ...). Key optional for loopback servers. */
export class OpenAICompatBackend implements ChatBackend {
  readonly provider = 'openai-compat';
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
    const j = await postJson({
      url,
      headers,
      body: { model: req.model, max_tokens: req.maxTokens, temperature: req.temperature, messages: [{ role: 'system', content: req.system }, ...mergeTurns(req.messages)] },
      timeoutMs: this.cfg.timeoutMs ?? 60_000,
      maxResponseBytes: this.cfg.maxResponseBytes ?? 2_000_000,
      secrets: this.cfg.apiKey ? [this.cfg.apiKey] : [],
      fetchImpl: this.cfg.fetchImpl,
    });
    const content = j?.choices?.[0]?.message?.content;
    if (typeof content !== 'string') throw new LlmError('OpenAI-compatible response has no choices[0].message.content string', 'malformed');
    return { text: content, usage: { inputTokens: nonNegInt(j.usage?.prompt_tokens), outputTokens: nonNegInt(j.usage?.completion_tokens) } };
  }
}

export function AnthropicLLM(cfg: BackendConfig): BackendLLM {
  return new BackendLLM(new AnthropicBackend(cfg), cfg);
}
export function OpenAICompatLLM(cfg: BackendConfig): BackendLLM {
  return new BackendLLM(new OpenAICompatBackend(cfg), cfg);
}

export { scrub };
