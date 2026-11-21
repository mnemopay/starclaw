import type { ChatTurn } from './types';

/**
 * Fitting a request into a provider's per-request token limit (Groq's free tier counts input + max_tokens against
 * ~8,000 tokens per minute, so one big file read made the next request a 413).
 *
 * The estimate is deliberately conservative: ~3.5 characters per token over-counts English and code for the tokenizers
 * these providers use, so a request that "fits" here fits there.
 */
export const CHARS_PER_TOKEN = 3.5;
/** Per-message framing overhead (role tags etc.), in tokens. */
const MESSAGE_OVERHEAD_TOKENS = 8;
/** A trimmed message keeps at least this much of its text. */
const MIN_KEEP_CHARS = 300;
/** Below this many output tokens a code-generation reply cannot hold a useful program. */
export const MIN_OUTPUT_TOKENS = 1536;

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

export function estimateRequestTokens(system: string, messages: ChatTurn[]): number {
  return estimateTokens(system) + messages.reduce((n, m) => n + estimateTokens(m.content) + MESSAGE_OVERHEAD_TOKENS, MESSAGE_OVERHEAD_TOKENS);
}

export function omittedMarker(n: number): string {
  return `\n[${n} chars omitted to fit the model's request limit; re-read with tools.readFile({ path, startLine, endLine }) if you need them]\n`;
}

const OBSERVATION_PREFIX = /^UNTRUSTED OBSERVATION from step \d+: /;

/** Shorten `text` to about `keep` characters, keeping head and tail around an explicit marker. */
function headTail(text: string, keep: number): { text: string; omitted: number } {
  if (text.length <= keep) return { text, omitted: 0 };
  const omitted = text.length - keep;
  const head = Math.ceil(keep * 0.4);
  return { text: text.slice(0, head) + omittedMarker(omitted) + text.slice(text.length - (keep - head)), omitted };
}

/**
 * Trim one message to about `keep` characters. An engine observation is "UNTRUSTED OBSERVATION from step N: <json>\n<note>":
 * only the observed data is shortened; the note (which carries denials and instructions) is never cut.
 */
function trimMessage(content: string, keep: number): { content: string; omitted: number } {
  const m = OBSERVATION_PREFIX.exec(content);
  const nl = content.indexOf('\n');
  if (m && nl > m[0].length) {
    const prefix = content.slice(0, m[0].length);
    const data = content.slice(m[0].length, nl);
    const note = content.slice(nl);
    const r = headTail(data, Math.max(MIN_KEEP_CHARS, keep - prefix.length - note.length));
    return { content: prefix + r.text + note, omitted: r.omitted };
  }
  const r = headTail(content, keep);
  return { content: r.text, omitted: r.omitted };
}

export interface FitResult {
  messages: ChatTurn[];
  /** Output tokens that still fit under the limit (never more than requested). */
  maxTokens: number;
  omittedChars: number;
  trimmedMessages: number;
  estimatedInputTokens: number;
  /** False when even after trimming the request cannot hold MIN_OUTPUT_TOKENS (or the requested output if smaller). */
  fits: boolean;
}

/**
 * Make system + messages + output fit `limitTokens`. Never touches the system prompt or the LAST message (the goal /
 * current instruction). Shrinks the largest other messages first, keeping head + tail with an explicit marker.
 */
export function fitRequest(system: string, messages: ChatTurn[], wantOutputTokens: number, limitTokens: number): FitResult {
  const outputFloor = Math.min(wantOutputTokens, MIN_OUTPUT_TOKENS);
  // Reserve a fair share for the reply, but no more than was asked for.
  const outputReserve = Math.min(wantOutputTokens, Math.max(outputFloor, Math.floor(limitTokens * 0.4)));
  const inputBudget = limitTokens - outputReserve;
  const out = messages.map((m) => ({ ...m }));
  let omittedChars = 0;
  const trimmed = new Set<number>();
  let est = estimateRequestTokens(system, out);
  // Trimmable: everything except the last message. Shrink the largest until the input fits or nothing is left to cut.
  for (let guard = 0; est > inputBudget && guard < 200; guard++) {
    let idx = -1;
    for (let i = 0; i < out.length - 1; i++) if (out[i].content.length > MIN_KEEP_CHARS + 200 && (idx < 0 || out[i].content.length > out[idx].content.length)) idx = i;
    if (idx < 0) break;
    const overChars = Math.ceil((est - inputBudget) * CHARS_PER_TOKEN) + 400;
    const keep = Math.max(MIN_KEEP_CHARS, out[idx].content.length - overChars);
    const r = trimMessage(out[idx].content, keep);
    if (r.omitted === 0) break;
    omittedChars += r.omitted;
    trimmed.add(idx);
    out[idx] = { ...out[idx], content: r.content };
    est = estimateRequestTokens(system, out);
  }
  const maxTokens = Math.max(0, Math.min(wantOutputTokens, limitTokens - est));
  return { messages: out, maxTokens, omittedChars, trimmedMessages: trimmed.size, estimatedInputTokens: est, fits: maxTokens >= outputFloor };
}

/** Parse "Limit 8000, Requested 9665" from a provider's too-large error. */
export function parseTokenLimit(message: string): { limit?: number; requested?: number } {
  const limit = /Limit\s*:?\s*(\d{3,9})/i.exec(message)?.[1];
  const requested = /Requested\s*:?\s*(\d{3,9})/i.exec(message)?.[1];
  return { limit: limit ? Number(limit) : undefined, requested: requested ? Number(requested) : undefined };
}
