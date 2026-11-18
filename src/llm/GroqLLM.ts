import { reserveChat } from './reserve';
import Groq from 'groq-sdk';
import type { LlmUsage } from '../governance/budget';
import { codegenSystemPrompt } from './prompts';
import type { ChatTurn, CodegenRequest, Intent, LLM, LlmResult, LlmCallOptions } from './types';

/**
 * Default price table, integer cents per million tokens. These are the maintainer's defaults and are NOT verified
 * against Groq's current price list: override via the constructor and treat budget numbers as estimates.
 */
const PRICES = {
  big: { model: 'llama-3.3-70b-versatile', inputCentsPerMTok: 59, outputCentsPerMTok: 79 },
  small: { model: 'llama-3.1-8b-instant', inputCentsPerMTok: 5, outputCentsPerMTok: 8 },
};

function stripFences(s: string): string {
  return s.replace(/```(?:javascript|typescript|js|ts)?/g, '').trim();
}

export class GroqLLM implements LLM {
  private groq: Groq;
  constructor(apiKey = process.env.GROQ_API_KEY) {
    if (!apiKey) throw new Error('GROQ_API_KEY is not set. Set it in the environment or a .env file to use the Groq backend.');
    this.groq = new Groq({ apiKey, maxRetries: 0, timeout: 60_000 }); // One reservation covers one dispatch; recovery is governed by the engine.
  }

  private async chat(tier: 'big' | 'small', messages: any[], maxTokens: number, temperature: number, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const p = PRICES[tier];
    const reservation = reserveChat(options, messages, maxTokens, p);
    const r = await this.groq.chat.completions.create({ model: p.model, max_tokens: reservation.maxTokens, temperature, messages });
    if (!r.usage || !Number.isSafeInteger(r.usage.prompt_tokens) || !Number.isSafeInteger(r.usage.completion_tokens) || r.usage.prompt_tokens < 0 || r.usage.completion_tokens < 0) throw new Error('Groq returned missing or invalid usage; reservation retained');
    const usage: LlmUsage = { inputTokens: r.usage?.prompt_tokens ?? 0, outputTokens: r.usage?.completion_tokens ?? 0 };
    reservation.settle(usage);
    return { prepaid: reservation.prepaid, value: r.choices[0]?.message?.content ?? '', usage, price: p };
  }

  async classifyIntent(goal: string, options?: LlmCallOptions): Promise<LlmResult<Intent>> {
    const r = await this.chat(
      'small',
      [
        { role: 'system', content: 'Classify the user message as "conversation" (chat, greetings, questions needing no action) or "task" (anything needing files, web, code or commands). Reply with exactly one word.' },
        { role: 'user', content: goal },
      ],
      10,
      0.1,
      options,
    );
    return { ...r, value: r.value.toLowerCase().includes('conversation') ? 'conversation' : 'task' };
  }

  async generateCode(req: CodegenRequest, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const messages: any[] = [{ role: 'system', content: codegenSystemPrompt(req.memoryContext, req.tainted, req.subagent) }];
    for (const h of req.history.slice(-10)) messages.push({ role: h.role, content: h.content });
    messages.push({ role: 'user', content: `Goal: ${req.goal}\n\nWrite the code.` });
    const r = await this.chat('big', messages, 1500, 0.2, options);
    return { ...r, value: stripFences(r.value) };
  }

  async converse(message: string, history: ChatTurn[], options?: LlmCallOptions): Promise<LlmResult<string>> {
    const messages: any[] = [{ role: 'system', content: 'You are StarClaw, a governed autonomous agent. In conversation mode you cannot take actions. Be concise and helpful.' }];
    for (const h of history.slice(-10)) messages.push({ role: h.role, content: h.content });
    messages.push({ role: 'user', content: message });
    return this.chat('big', messages, 500, 0.7, options);
  }

  async fixCode(goal: string, code: string, error: string, options?: LlmCallOptions): Promise<LlmResult<string>> {
    const r = await this.chat(
      'big',
      [
        { role: 'system', content: 'Fix the JavaScript so it parses. Use require()/module.exports, no import/export. Output only raw code, no markdown.' },
        { role: 'user', content: `Goal: ${goal}\nError: ${error}\nCode:\n${code}` },
      ],
      1500,
      0.1,
      options,
    );
    return { ...r, value: stripFences(r.value) };
  }
}
