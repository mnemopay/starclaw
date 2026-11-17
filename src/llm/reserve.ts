import { BudgetExceeded, costMicrocents, type LlmPrice, type LlmUsage } from '../governance/budget';
import type { LlmCallOptions } from './types';

/** Conservative text-token estimate. Configured provider prices must include all billed token classes. */
export function reserveChat(options: LlmCallOptions | undefined, input: unknown, maxTokens: number, price: LlmPrice) {
  const budget = options?.budget;
  if (!budget) return { maxTokens, prepaid: false, settle: (_usage: LlmUsage) => {} };
  budget.assertCanSpend();
  const inputTokens = Buffer.byteLength(JSON.stringify(input), 'utf8') + 1024;
  const inputCost = inputTokens * price.inputCentsPerMTok;
  const remaining = budget.availableMicro - inputCost;
  const outputTokens = price.outputCentsPerMTok ? Math.min(maxTokens, Math.floor(remaining / price.outputCentsPerMTok)) : maxTokens;
  if (remaining < 0 || outputTokens < 1) throw new BudgetExceeded('run', 'remaining LLM budget cannot fund the prompt and one output token');
  const reservation = budget.reserve(costMicrocents({ inputTokens, outputTokens }, price));
  return { maxTokens: outputTokens, prepaid: true, settle: (usage: LlmUsage) => reservation.settle(costMicrocents(usage, price)) };
}
