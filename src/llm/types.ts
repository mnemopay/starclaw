import type { LlmBudget, LlmUsage } from '../governance/budget';

export interface LlmCallOptions { budget?: LlmBudget; }

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
  /** The backend reserved and reconciled this call before returning. */
  prepaid?: boolean;
  /** Provider-level retries that happened inside this call (recorded in the audit log as llm.retry). */
  retries?: LlmRetry[];
}

export interface LlmRetry {
  /** tool_use_failed: the provider rejected a native tool call and the request was retried with a correction. rate-limit: HTTP 429. */
  kind: 'tool_use_failed' | 'rate-limit';
  waitSeconds?: number;
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
  classifyIntent(goal: string, options?: LlmCallOptions): Promise<LlmResult<Intent>>;
  generateCode(req: CodegenRequest, options?: LlmCallOptions): Promise<LlmResult<string>>;
  converse(message: string, history: ChatTurn[], options?: LlmCallOptions): Promise<LlmResult<string>>;
  fixCode(goal: string, code: string, error: string, options?: LlmCallOptions): Promise<LlmResult<string>>;
}
