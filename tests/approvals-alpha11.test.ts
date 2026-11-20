import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Broker } from '../src/broker';
import { HttpApprover } from '../src/channels/http';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { DETAIL_PREVIEW_CHARS, describeRequest, type ApprovalRequest } from '../src/governance/types';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

const req = (detail: string): ApprovalRequest => ({
  id: 'r1',
  action: { class: 'fs.write', target: '/w/a.ts', summary: 'write', detail },
  provenance: { tainted: false, sources: [] },
  reason: 'policy says ask',
  escalatedByTaint: false,
  expiresAt: Date.now() + 60_000,
});

describe('approval text shows the whole action (alpha.11)', () => {
  test('a 4,491-char program (the alpha.10 demo size) is shown in full, with its length and full-payload hash', () => {
    const program = 'x'.repeat(4400) + '\nmodule.exports = { execute }; // END-MARKER';
    const t = describeRequest(req(program));
    assert.ok(t.includes('END-MARKER'), 'the end of the program is visible (alpha.10 cut it at 3,000 chars)');
    assert.ok(!/HIDDEN/.test(t));
    assert.match(t, new RegExp(`Payload: ${program.length} chars, sha256 ${sha(program)}`));
  });

  test('beyond the preview bound: an explicit HIDDEN notice with the exact count, where to see it all, and the full hash', () => {
    const big = 'a'.repeat(DETAIL_PREVIEW_CHARS + 1234);
    const t = describeRequest(req(big));
    assert.match(t, /\[1234 more chars HIDDEN here/);
    assert.match(t, /GET \/api\/approvals/);
    assert.ok(t.includes(sha(big)), 'the hash is of the FULL payload, not the preview');
  });

  test('the HTTP approval API returns the full, uncut payload and its hash', async () => {
    const a = new HttpApprover();
    const big = 'b'.repeat(DETAIL_PREVIEW_CHARS + 50);
    const p = a.request(req(big), new AbortController().signal);
    const [item] = a.list() as any[];
    assert.equal(item.detail, big);
    assert.equal(item.detailSha256, sha(big));
    a.decide('r1', 'deny');
    assert.equal(await p, 'deny');
  });
});

describe('fs.write approvals show a diff and bind to the full payload (alpha.11)', () => {
  let dir: string, ws: string, state: string;
  let approver: ScriptedApprover;
  let mk: () => Broker;
  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    fs.mkdirSync(ws, { recursive: true });
    approver = new ScriptedApprover(() => 'approve');
    const signer = Ed25519Signer.generate();
    mk = () => {
      const gov = new Governor({ policy: policyWith({ rules: [{ class: 'fs.write', verdict: 'ask' }] }), audit: new AuditLog(path.join(dir, 'audit.jsonl'), signer), taint: new TaintTracker(), approver });
      return new Broker({ governor: gov, workspaceDir: ws, stateDir: state, taintedFiles: new TaintedFileStore(path.join(state, 'tf.json')) });
    };
  });
  afterEach(() => rm(dir));

  test('replacing an existing text file: the approver sees a unified diff, so an edit near the END is visible', async () => {
    const lines = Array.from({ length: 400 }, (_, i) => `const line${i} = ${i};`);
    fs.writeFileSync(path.join(ws, 'big.ts'), lines.join('\n') + '\n');
    const next = [...lines.slice(0, 399), 'const line399 = "CHANGED";'].join('\n') + '\n';
    await mk().handle({ name: 'writeFile', args: { path: 'big.ts', content: next } });
    const a = approver.seen[0].action;
    assert.match(a.detail!, /^--- a\/big\.ts\n\+\+\+ b\/big\.ts\n@@/);
    assert.match(a.detail!, /-const line399 = 399;\n\+const line399 = "CHANGED";/);
    assert.ok(a.detail!.length < 1000, 'only the changed region plus context, not the whole file');
    assert.match(a.summary, /showing diff \+1 -1 lines/);
    assert.equal(fs.readFileSync(path.join(ws, 'big.ts'), 'utf8'), next);
  });

  test('a new file is shown as its full content (no 3,000-char cut)', async () => {
    const content = 'y'.repeat(5000) + 'TAIL';
    await mk().handle({ name: 'writeFile', args: { path: 'new.txt', content } });
    const a = approver.seen[0].action;
    assert.equal(a.detail, content);
    assert.match(a.summary, /new file; showing full new content/);
  });

  test('the audit log records the length and SHA-256 of the full payload the approver saw', async () => {
    const content = 'z'.repeat(20_000) + 'END';
    await mk().handle({ name: 'writeFile', args: { path: 'n.txt', content } });
    const recs = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const r = recs.find((x) => x.type === 'decision.request' && x.data?.class === 'fs.write');
    assert.ok(r, 'decision.request recorded');
    assert.equal(r.data.detailChars, content.length);
    assert.equal(r.data.detailSha256, sha(content));
    assert.match(r.data.detail, /\.\.\.\[truncated\]$/, 'the stored copy is cut at 16,000, but the hash binds the full payload');
  });
});
