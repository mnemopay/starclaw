import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { Broker } from '../src/broker';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { estimateRequestTokens, estimateTokens, fitRequest, MIN_OUTPUT_TOKENS, parseTokenLimit } from '../src/llm/context';
import { createLLM } from '../src/llm/factory';
import { LlmError } from '../src/llm/http';
import type { ChatTurn } from '../src/llm/types';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

const KEY = 'test-key-9f8e7d6c5b4a39281706';
const llmPolicy = (o: Record<string, unknown>) => policyWith({ llm: o }).llm;
const openaiOk = (text: string) => ({ id: 'c1', choices: [{ index: 0, message: { role: 'assistant', content: text } }], usage: { prompt_tokens: 13, completion_tokens: 5 } });
const PROGRAM = 'async function execute() { return 1 }\nmodule.exports = { execute };';
const groq413 = { error: { message: 'Request too large for model `openai/gpt-oss-120b` in organization `org_x` service tier `on_demand` on tokens per minute (TPM): Limit 8000, Requested 9665, please reduce your message size and try again.', type: 'tokens', code: 'rate_limit_exceeded' } };

const closers: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});
async function withServer(handler: (n: number, body: any, res: http.ServerResponse) => void) {
  const seen: any[] = [];
  const srv = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      seen.push(body);
      handler(seen.length, body, res);
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  closers.push(() => new Promise<void>((r) => srv.close(() => r())));
  return { base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, seen };
}
const json = (res: http.ServerResponse, status: number, obj: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
};
/** What a request costs against a per-request limit: system + messages (our estimate) + max_tokens. */
const requestCost = (body: any) => estimateRequestTokens(body.messages[0].content, body.messages.slice(1)) + body.max_tokens;

const bigObservation = (step: number, chars: number, note = 'Continue the goal.') => `UNTRUSTED OBSERVATION from step ${step}: ${JSON.stringify({ ok: true, result: { content: 'x'.repeat(chars) } })}\n${note}`;

describe('alpha.13: token estimate and fitting', () => {
  test('estimate is ~3.5 chars per token, rounded up', () => {
    assert.equal(estimateTokens(''), 0);
    assert.equal(estimateTokens('a'.repeat(350)), 100);
    assert.equal(estimateTokens('a'.repeat(351)), 101);
  });

  test('a request that already fits is untouched; output is capped to what is left', () => {
    const msgs: ChatTurn[] = [{ role: 'user', content: 'hello' }];
    const f = fitRequest('sys', msgs, 8192, 7000);
    assert.deepEqual(f.messages, msgs);
    assert.equal(f.omittedChars, 0);
    assert.equal(f.maxTokens, 7000 - f.estimatedInputTokens);
    assert.ok(f.fits);
  });

  test('largest message is shortened first; system prompt and LAST message are never touched; marker says how to re-read', () => {
    const goal = 'Goal: fix the bug\n\nWrite the code.';
    const msgs: ChatTurn[] = [
      { role: 'assistant', content: 'code-1 '.repeat(50) },
      { role: 'user', content: bigObservation(1, 40_000) },
      { role: 'assistant', content: 'code-2' },
      { role: 'user', content: goal + 'y'.repeat(9000) },
    ];
    const system = 'S'.repeat(3000);
    const f = fitRequest(system, msgs, 8192, 7000);
    assert.equal(f.messages.at(-1)!.content, msgs.at(-1)!.content, 'last message intact');
    assert.equal(f.messages[0].content, msgs[0].content, 'small messages left alone');
    assert.ok(f.messages[1].content.length < msgs[1].content.length);
    assert.match(f.messages[1].content, /\[\d+ chars omitted to fit the model's request limit; re-read with tools\.readFile\(\{ path, startLine, endLine \}\)/);
    assert.ok(f.omittedChars > 30_000);
    assert.equal(f.trimmedMessages, 1);
    assert.ok(f.estimatedInputTokens + f.maxTokens <= 7000);
    assert.ok(f.maxTokens >= MIN_OUTPUT_TOKENS);
  });

  test('the note after an observation (denials) survives trimming verbatim', () => {
    const note = 'These actions were DENIED and will not be allowed if proposed again: fs.write src/x.ts. Continue the original goal another way.';
    const msgs: ChatTurn[] = [{ role: 'user', content: bigObservation(2, 50_000, note) }, { role: 'user', content: 'Goal: g' }];
    const f = fitRequest('sys', msgs, 8192, 7000);
    assert.ok(f.messages[0].content.endsWith('\n' + note));
    assert.match(f.messages[0].content, /^UNTRUSTED OBSERVATION from step 2: /);
  });

  test('when even the protected parts leave no room for a reply, fits is false', () => {
    const f = fitRequest('S'.repeat(30_000), [{ role: 'user', content: 'Goal: g' }], 8192, 7000);
    assert.equal(f.fits, false);
  });

  test('parses the provider limit from Groq\'s 413 message', () => {
    assert.deepEqual(parseTokenLimit(groq413.error.message), { limit: 8000, requested: 9665 });
    assert.deepEqual(parseTokenLimit('nothing here'), { limit: undefined, requested: undefined });
  });
});

describe('alpha.13: Groq requests stay under llm.requestTokenLimit (default 7000)', () => {
  test('a huge earlier observation is shortened, the request fits, and the trim is reported for the audit', async () => {
    const s = await withServer((_n, _b, res) => json(res, 200, openaiOk(PROGRAM)));
    const llm = createLLM(llmPolicy({ provider: 'groq', baseUrl: s.base }), { GROQ_API_KEY: KEY });
    const g = await llm.generateCode({ goal: 'fix it', memoryContext: '', history: [{ role: 'assistant', content: 'prev' }, { role: 'user', content: bigObservation(1, 30_000) }], tainted: true });
    assert.equal(s.seen.length, 1);
    assert.ok(requestCost(s.seen[0]) <= 7000, `request cost ${requestCost(s.seen[0])} must fit 7000`);
    assert.match(JSON.stringify(s.seen[0].messages), /chars omitted to fit the model's request limit/);
    assert.equal(g.retries?.[0].kind, 'context-trimmed');
    assert.equal(g.retries?.[0].limitTokens, 7000);
    assert.ok((g.retries?.[0].omittedChars ?? 0) > 10_000);
  });

  test('llm.requestTokenLimit raises the limit (paid tier): nothing is trimmed', async () => {
    const s = await withServer((_n, _b, res) => json(res, 200, openaiOk(PROGRAM)));
    const llm = createLLM(llmPolicy({ provider: 'groq', baseUrl: s.base, requestTokenLimit: 100_000 }), { GROQ_API_KEY: KEY });
    const g = await llm.generateCode({ goal: 'fix it', memoryContext: '', history: [{ role: 'user', content: bigObservation(1, 30_000) }], tainted: true });
    assert.doesNotMatch(JSON.stringify(s.seen[0].messages), /chars omitted/);
    assert.equal(g.retries, undefined);
    assert.equal(s.seen[0].max_tokens, 8192);
  });

  test('other providers have no limit by default (unchanged behaviour)', async () => {
    const s = await withServer((_n, _b, res) => json(res, 200, openaiOk(PROGRAM)));
    const llm = createLLM(llmPolicy({ provider: 'openai-compat', model: 'm', baseUrl: s.base + '/v1' }), { OPENAI_API_KEY: KEY });
    await llm.generateCode({ goal: 'fix it', memoryContext: '', history: [{ role: 'user', content: bigObservation(1, 30_000) }], tainted: true });
    assert.doesNotMatch(JSON.stringify(s.seen[0].messages), /chars omitted/);
    assert.equal(s.seen[0].max_tokens, 8192);
  });

  test('policy validates requestTokenLimit', () => {
    assert.equal(llmPolicy({ provider: 'groq', requestTokenLimit: 12_000 }).requestTokenLimit, 12_000);
    assert.throws(() => llmPolicy({ provider: 'groq', requestTokenLimit: 500 }));
  });
});

describe('alpha.13: HTTP 413 (request too large) is shrunk and resent once', () => {
  test('413 → resent under 80% of the provider limit, and the retry is reported', async () => {
    const s = await withServer((n, _b, res) => (n === 1 ? json(res, 413, groq413) : json(res, 200, openaiOk(PROGRAM))));
    const llm = createLLM(llmPolicy({ provider: 'openai-compat', model: 'm', baseUrl: s.base + '/v1' }), { OPENAI_API_KEY: KEY });
    const g = await llm.generateCode({ goal: 'fix it', memoryContext: '', history: [{ role: 'user', content: bigObservation(1, 30_000) }], tainted: true });
    assert.equal(s.seen.length, 2);
    assert.ok(requestCost(s.seen[1]) <= 6400, `resent cost ${requestCost(s.seen[1])} must fit 6400`);
    assert.deepEqual(g.retries?.map((r) => r.kind), ['request-too-large', 'context-trimmed']);
    assert.equal(g.retries?.[0].limitTokens, 6400);
  });

  test('a second 413 fails with a clear message naming llm.requestTokenLimit', async () => {
    const s = await withServer((_n, _b, res) => json(res, 413, groq413));
    const llm = createLLM(llmPolicy({ provider: 'groq', baseUrl: s.base }), { GROQ_API_KEY: KEY });
    await assert.rejects(
      () => llm.generateCode({ goal: 'fix it', memoryContext: '', history: [], tainted: false }),
      (e: any) => e instanceof LlmError && e.kind === 'request-too-large' && /llm\.requestTokenLimit/.test(e.message) && /provider limit 8000/.test(e.message),
    );
    assert.equal(s.seen.length, 2, 'bounded: one resend only');
  });

  test('a 400 context_length_exceeded is classified the same way', async () => {
    const s = await withServer((n, _b, res) => (n === 1 ? json(res, 400, { error: { code: 'context_length_exceeded', message: "This model's maximum context length is 8192 tokens" } }) : json(res, 200, openaiOk(PROGRAM))));
    const llm = createLLM(llmPolicy({ provider: 'openai-compat', model: 'm', baseUrl: s.base + '/v1' }), { OPENAI_API_KEY: KEY });
    const g = await llm.generateCode({ goal: 'fix it', memoryContext: '', history: [], tainted: false });
    assert.equal(s.seen.length, 2);
    assert.equal(g.retries?.[0].kind, 'request-too-large');
  });
});

describe('alpha.13: readFile line ranges (to fetch what a trim left out)', () => {
  test('startLine/endLine return that slice plus totalLines; no range returns the whole file as before', async () => {
    const dir = tmpDir();
    try {
      const ws = path.join(dir, 'ws');
      const state = path.join(dir, 'state');
      fs.mkdirSync(ws, { recursive: true });
      fs.writeFileSync(path.join(ws, 'f.txt'), ['l1', 'l2', 'l3', 'l4', 'l5'].join('\n'));
      const gov = new Governor({ policy: policyWith({}), audit: new AuditLog(path.join(dir, 'audit.jsonl'), Ed25519Signer.generate()), taint: new TaintTracker(), approver: new ScriptedApprover(() => 'approve') });
      const broker = new Broker({ governor: gov, workspaceDir: ws, stateDir: state, taintedFiles: new TaintedFileStore(path.join(state, 'tf.json')) });
      const part: any = await broker.handle({ name: 'readFile', args: { path: 'f.txt', startLine: 2, endLine: 3 } });
      assert.equal(part.content, 'l2\nl3');
      assert.equal(part.totalLines, 5);
      const tail: any = await broker.handle({ name: 'readFile', args: { path: 'f.txt', startLine: 4 } });
      assert.equal(tail.content, 'l4\nl5');
      const whole: any = await broker.handle({ name: 'readFile', args: { path: 'f.txt' } });
      assert.equal(whole.content, 'l1\nl2\nl3\nl4\nl5');
      assert.equal(whole.totalLines, undefined);
      await assert.rejects(() => broker.handle({ name: 'readFile', args: { path: 'f.txt', startLine: 0 } }));
    } finally {
      rm(dir);
    }
  });
});
