import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Broker } from '../src/broker';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { parsePolicy } from '../src/governance/policy';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { NEVER_AUTO_WHEN_SCHEDULED, TAINT_SENSITIVE } from '../src/governance/types';
import { McpManager } from '../src/mcp/manager';
import { DEFAULT_TOOL_NAMES } from '../src/sandbox/types';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

const FIXTURE = path.join(__dirname, 'fixtures', 'mcp-server.js');
const SERVER = { name: 'test', transport: 'stdio', command: process.execPath, args: [FIXTURE] };

describe('governed MCP', () => {
  let dir: string;
  let managers: McpManager[] = [];
  let approver: ScriptedApprover;
  let taint: TaintTracker;
  let auditPath: string;
  const signer = Ed25519Signer.generate();
  const audit = () => fs.readFileSync(auditPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

  const mk = (mcp: Record<string, unknown> = { enabled: true, servers: [SERVER] }, extra: Record<string, unknown> = {}, env?: NodeJS.ProcessEnv) => {
    const policy = policyWith({ mcp, ...extra });
    const gov = new Governor({ policy, audit: new AuditLog(auditPath, signer), taint, approver });
    const manager = policy.mcp.servers.length ? new McpManager(policy.mcp.servers, { cwd: dir, env }) : undefined;
    if (manager) managers.push(manager);
    return new Broker({ governor: gov, workspaceDir: path.join(dir, 'ws'), stateDir: path.join(dir, 'state'), taintedFiles: new TaintedFileStore(path.join(dir, 'tf.json')), mcp: manager });
  };

  before(() => { dir = tmpDir(); });
  after(async () => {
    await Promise.all(managers.map((m) => m.close()));
    rm(dir);
  });
  beforeEach(() => {
    auditPath = path.join(dir, `audit-${Math.random().toString(36).slice(2)}.jsonl`);
    approver = new ScriptedApprover(() => 'approve');
    taint = new TaintTracker();
  });

  test('policy: off by default; stdio needs a command, http needs https (http only to localhost); names unique', () => {
    assert.equal(policyWith().mcp.enabled, false);
    assert.equal(policyWith().defaults['mcp.call'], 'ask');
    const bad = [
      { name: 'x', transport: 'stdio' },
      { name: 'x', transport: 'http', url: 'http://example.com/mcp' },
      { name: 'x', transport: 'http', url: 'https://u:p@example.com/mcp' },
      { name: 'x', transport: 'http', url: 'https://example.com/mcp', command: 'node' },
      { name: 'Bad Name', transport: 'stdio', command: 'node' },
      { name: 'x', transport: 'stdio', command: 'node', tools: ['a/b'] },
    ];
    for (const s of bad) assert.throws(() => parsePolicy(JSON.stringify({ version: 1, mcp: { enabled: true, servers: [s] } })), /policy is invalid/, JSON.stringify(s));
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, mcp: { enabled: true, servers: [SERVER, SERVER] } })), /unique/);
    assert.doesNotThrow(() => parsePolicy(JSON.stringify({ version: 1, mcp: { enabled: true, servers: [{ name: 'local', transport: 'http', url: 'http://127.0.0.1:3000/mcp' }] } })));
    assert.ok(TAINT_SENSITIVE.has('mcp.call') && NEVER_AUTO_WHEN_SCHEDULED.has('mcp.call'));
    assert.ok(DEFAULT_TOOL_NAMES.includes('mcpCall') && DEFAULT_TOOL_NAMES.includes('mcpList'));
  });

  test('disabled or undeclared: refused and audited before anything starts or anyone is asked', async () => {
    const off = mk({ enabled: false, servers: [SERVER] });
    await assert.rejects(() => off.handle({ name: 'mcpCall', args: { server: 'test', tool: 'echo', args: { text: 'hi' } } }), /disabled/);
    const on = mk();
    await assert.rejects(() => on.handle({ name: 'mcpCall', args: { server: 'other', tool: 'echo' } }), /no MCP server named "other"/);
    await assert.rejects(() => on.handle({ name: 'mcpCall', args: { server: 'test', tool: '../x' } }), /invalid tool name/);
    await assert.rejects(() => on.handle({ name: 'mcpCall', args: { server: 'test', tool: 'nope' } }), /has no tool nope/);
    assert.equal(approver.seen.length, 0, 'nobody was asked');
    assert.ok(audit().filter((r) => r.type === 'mcp.refused').length >= 4);
  });

  test('CONTROL + call: the approver sees server/tool and the exact arguments; result comes back; session is tainted; audit has no result text', async () => {
    const b = mk();
    const r: any = await b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'echo', args: { text: 'hello' } } });
    assert.equal(r.text, 'echo: hello');
    assert.equal(r.untrusted, true);
    assert.equal(approver.seen.length, 1);
    const req = approver.seen[0];
    assert.equal(req.action.class, 'mcp.call');
    assert.equal(req.action.target, 'test/echo');
    assert.match(req.action.detail!, /"text": "hello"/);
    assert.equal(taint.tainted, true, 'MCP output is untrusted');
    const recs = audit();
    const decision = recs.find((r) => r.type === 'decision.request' && r.data.class === 'mcp.call');
    assert.equal(decision?.data.target, 'test/echo', 'the decision is audited with server/tool');
    const result = recs.find((r) => r.type === 'action.result' && r.data.class === 'mcp.call');
    assert.deepEqual([result?.data.ok, result?.data.tool, result?.data.isError, result?.data.textChars], [true, 'echo', false, 'echo: hello'.length]);
    assert.ok(!fs.readFileSync(auditPath, 'utf8').includes('echo: hello'), 'result text is not written to the audit log');
    const sum: any = await b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'add', args: { a: 2, b: 3 } } });
    assert.deepEqual(sum.structured, { sum: 5 });
  });

  test('a denied call never reaches the server and does not taint', async () => {
    approver = new ScriptedApprover(() => 'deny');
    const b = mk();
    await assert.rejects(() => b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'echo', args: { text: 'no' } } }), /Denied/);
    assert.equal(taint.tainted, false);
  });

  test('policy rules can allow a specific tool (target server/tool) in a clean session; anything else still asks', async () => {
    approver = new ScriptedApprover(() => 'deny');
    const b = mk({ enabled: true, servers: [SERVER] }, { rules: [{ class: 'mcp.call', target: 'test/add', verdict: 'allow' }] });
    const r: any = await b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'add', args: { a: 1, b: 1 } } });
    assert.equal(r.text, '2');
    assert.equal(approver.seen.length, 0, 'allowed by rule, nobody asked');
    // Now the session is tainted (MCP output): even the allowed tool must ask, and this approver denies.
    await assert.rejects(() => b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'add', args: { a: 1, b: 1 } } }), /Denied/);
    assert.equal(approver.seen[0]?.escalatedByTaint, true);
  });

  test('tool poisoning: listing returns descriptions as untrusted data and taints the session', async () => {
    const b = mk();
    const r: any = await b.handle({ name: 'mcpList', args: {} });
    const tools = r.servers[0].tools.map((t: any) => t.name).sort();
    assert.deepEqual(tools, ['add', 'big', 'echo', 'env', 'fail', 'weather']);
    assert.equal(r.untrusted, true);
    assert.equal(taint.tainted, true, 'descriptions could carry instructions');
    assert.match(r.servers[0].tools.find((t: any) => t.name === 'weather').description, /IGNORE ALL PREVIOUS/);
  });

  test('per-server tool allow-list: unlisted tools are hidden and refused before anyone is asked', async () => {
    const b = mk({ enabled: true, servers: [{ ...SERVER, tools: ['echo'] }] });
    const r: any = await b.handle({ name: 'mcpList', args: { server: 'test' } });
    assert.deepEqual(r.servers[0].tools.map((t: any) => t.name), ['echo']);
    await assert.rejects(() => b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'add', args: { a: 1, b: 2 } } }), /not in mcp\.servers\[test\]\.tools/);
    assert.equal(approver.seen.length, 0);
  });

  test('errors and oversized results: isError passes through; text is capped at maxResultChars', async () => {
    const b = mk({ enabled: true, servers: [{ ...SERVER, maxResultChars: 1000 }] });
    const f: any = await b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'fail', args: {} } });
    assert.deepEqual([f.isError, f.text], [true, 'it broke']);
    const big: any = await b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'big', args: {} } });
    assert.equal(big.text.length, 1000);
    assert.equal(big.truncated, true);
  });

  test("stdio servers do not inherit the owner's secrets: only env NAMES listed in the policy are passed", async () => {
    const env = { ...process.env, STARCLAW_TEST_SECRET: 'sk-should-not-leak', STARCLAW_TEST_PASSED: 'yes' };
    const b = mk({ enabled: true, servers: [{ ...SERVER, env: ['STARCLAW_TEST_PASSED'] }] }, {}, env);
    const r: any = await b.handle({ name: 'mcpCall', args: { server: 'test', tool: 'env', args: {} } });
    assert.deepEqual(JSON.parse(r.text), { secret: null, passed: 'yes' });
  });

  test('a server that cannot start is reported, audited, and nobody is asked', async () => {
    const b = mk({ enabled: true, servers: [{ name: 'broken', transport: 'stdio', command: path.join(dir, 'does-not-exist.exe'), timeoutSeconds: 5 }] });
    const list: any = await b.handle({ name: 'mcpList', args: {} });
    assert.ok(list.servers[0].error);
    assert.equal(taint.tainted, false, 'nothing answered, nothing tainted');
    await assert.rejects(() => b.handle({ name: 'mcpCall', args: { server: 'broken', tool: 'x' } }), /unavailable/);
    assert.equal(approver.seen.length, 0);
  });
});
