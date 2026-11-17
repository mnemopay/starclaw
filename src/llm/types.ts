import type { LlmUsage } from '../governance/budget';

export interface ChatTurn {
  role: 'user' | 'assistant';
  content: string;
}

export interface LlmResult<T> {
  value: T;
  usage: LlmUsage;
  /** Price table used to cost this call (cents per million tokens). */
  price: { inputCentsPerMTok: number; outputCentsPerMTok: number };
  /** True when no price was configured for this model and a conservative placeholder was used. */
  priceAssumed?: boolean;
}

export type Intent = 'conversation' | 'task';

export interface CodegenRequest {
  goal: string;
  memoryContext: string;
  history: ChatTurn[];
  /** True when untrusted content is already in the session. */
  tainted: boolean;
  /** Set when the code is for a sub-agent: what it was granted. Everything else is refused by the broker. */
  subagent?: { depth: number; tools: string[]; domains: string[] | 'any'; readPaths: string[]; writePaths: string[]; spendCents: number; maxActions: number | null };
}

/**
 * The model behind the agent. Tests use a fake implementation: nothing in the engine calls a provider directly.
 * Everything returned by an LLM is untrusted input to the Governor, never a decision.
 */
export interface LLM {
  classifyIntent(goal: string): Promise<LlmResult<Intent>>;
  generateCode(req: CodegenRequest): Promise<LlmResult<string>>;
  converse(message: string, history: ChatTurn[]): Promise<LlmResult<string>>;
  fixCode(goal: string, code: string, error: string): Promise<LlmResult<string>>;
}
