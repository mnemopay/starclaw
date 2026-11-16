import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { parsePolicy, Policy } from '../src/governance/policy';
import type { ApprovalAnswer, ApprovalRequest, Approver } from '../src/governance/types';
import type { ChatTurn, CodegenRequest, Intent, LLM, LlmResult } from '../src/llm/types';

export function tmpDir(prefix = 'sc-test-'): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function rm(dir: string) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

/** Build a policy from partial JSON through the real parser. */
export function policyWith(overrides: Record<string, unknown> = {}): Policy {
  // Tests default to the process layer so they are deterministic and fast; container tests opt in explicitly.
  const sandbox = { mode: 'process', ...((overrides.sandbox as object) ?? {}) };
  return parsePolicy(JSON.stringify({ version: 1, ...overrides, sandbox }));
}

/** Approver driven by a function; records every request it was shown. */
export class ScriptedApprover implements Approver {
  readonly name = 'scripted';
  seen: ApprovalRequest[] = [];
  constructor(private readonly decide: (r: ApprovalRequest) => ApprovalAnswer | Promise<ApprovalAnswer> = () => 'deny') {}
  async request(req: ApprovalRequest): Promise<ApprovalAnswer> {
    this.seen.push(req);
    return this.decide(req);
  }
}

/** Never answers until aborted. */
export class HangingApprover implements Approver {
  readonly name = 'hanging';
  aborted = false;
  request(_req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    return new Promise((resolve) => {
      signal.addEventListener('abort', () => {
        this.aborted = true;
        resolve('approve'); // even if it "answers approve" after abort, the Governor must already have denied
      });
    });
  }
}

/** Deterministic LLM. No network, no provider. */
export class FakeLLM implements LLM {
  codeQueue: string[] = [];
  intent: Intent = 'task';
  calls = { classify: 0, code: 0, converse: 0, fix: 0 };
  tokensPerCall = { inputTokens: 100, outputTokens: 100 };
  price = { inputCentsPerMTok: 100, outputCentsPerMTok: 100 };
  lastCodegen?: CodegenRequest;
  private res<T>(value: T): LlmResult<T> {
    return { value, usage: this.tokensPerCall, price: this.price };
  }
  async classifyIntent(_goal: string) {
    this.calls.classify++;
    return this.res(this.intent);
  }
  async generateCode(req: CodegenRequest) {
    this.calls.code++;
    this.lastCodegen = req;
    const code = this.codeQueue.shift();
    if (code === undefined) throw new Error('FakeLLM: no code queued');
    return this.res(code);
  }
  async converse(_m: string, _h: ChatTurn[]) {
    this.calls.converse++;
    return this.res('hello from the fake model');
  }
  async fixCode(_g: string, code: string) {
    this.calls.fix++;
    return this.res(code);
  }
}

/** A local web server that serves attacker-controlled pages. */
export async function startWebServer(routes: Record<string, string | ((req: http.IncomingMessage, res: http.ServerResponse) => void)>) {
  const hits: string[] = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url ?? '');
    const r = routes[req.url ?? ''];
    if (typeof r === 'function') return r(req, res);
    if (r === undefined) {
      res.writeHead(404);
      return res.end('nope');
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(r);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return { port, base: `http://127.0.0.1:${port}`, hits, close: () => new Promise<void>((r) => server.close(() => r())) };
}

/** The markdown-free code shape the engine expects. */
export const code = (body: string) => `async function execute() {\n${body}\n}\nmodule.exports = { execute };`;
