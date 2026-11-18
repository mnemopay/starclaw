import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';
import { Broker } from '../src/broker';
import { HttpApprover } from '../src/channels/http';
import { searchTranscripts, Transcript } from '../src/channels/transcript';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TOOL_CLASSES } from '../src/governance/subagent';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { createGateway } from '../src/server';
import { CapabilitiesSchema } from '../src/skills/registry/bundle';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

const KEY = 'console-key-0123456789abcdef';

describe('conversation search', () => {
  let dir: string, consoleDir: string;
  beforeEach(() => {
    dir = tmpDir();
    consoleDir = path.join(dir, 'state', 'console');
    let n = 0;
    const t = new Transcript(consoleDir, () => new Date(Date.UTC(2026, 10, 1, 12, 0, n++)));
    t.append('user', 'Book the Lagos flight on Friday');
    t.append('agent', 'Booked: Lagos, Friday 9am', { tainted: true });
    t.rotate();
    t.append('user', 'what is the weather in Abuja');
    t.append('agent', 'Sunny in Abuja');
    fs.writeFileSync(path.join(consoleDir, 'not-a-session.jsonl'), '{"text":"lagos friday"}\n');
  });
  afterEach(() => rm(dir));

  test('all terms must match (any case); newest session first; neighbours included; junk files skipped', () => {
    const hits = searchTranscripts(consoleDir, 'LAGOS friday');
    assert.deepEqual(hits.map((h) => h.text), ['Booked: Lagos, Friday 9am', 'Book the Lagos flight on Friday']);
    assert.equal(hits[0].before?.text, 'Book the Lagos flight on Friday');
    assert.equal(hits[0].tainted, true);
    assert.deepEqual(searchTranscripts(consoleDir, 'abuja').map((h) => h.kind), ['agent', 'user']);
    assert.deepEqual(searchTranscripts(consoleDir, 'lagos abuja'), []);
    assert.deepEqual(searchTranscripts(consoleDir, 'a'), [], 'too-short terms are ignored');
    assert.equal(searchTranscripts(consoleDir, 'lagos', { limit: 1 }).length, 1);
    assert.deepEqual(searchTranscripts(path.join(dir, 'missing'), 'lagos'), []);
  });

  const signer = Ed25519Signer.generate(); // one key per audit file: the log refuses a second key (and should)
  const broker = (taint: TaintTracker, auditPath: string) => {
    const gov = new Governor({ policy: policyWith(), audit: new AuditLog(auditPath, signer), taint, approver: new ScriptedApprover() });
    return new Broker({ governor: gov, workspaceDir: path.join(dir, 'ws'), stateDir: path.join(dir, 'state'), taintedFiles: new TaintedFileStore(path.join(dir, 'tf.json')) });
  };

  test('agent tool: clean hits stay clean; a hit from an untrusted reply taints the session; the query text is not audited', async () => {
    const auditPath = path.join(dir, 'audit.jsonl');
    const clean = new TaintTracker();
    const r1: any = await broker(clean, auditPath).handle({ name: 'searchConversations', args: { query: 'weather abuja' } });
    assert.equal(r1.hits.length, 1);
    assert.equal(clean.tainted, false);
    const t = new TaintTracker();
    const r2: any = await broker(t, auditPath).handle({ name: 'searchConversations', args: { query: 'lagos' } });
    assert.equal(r2.untrusted, true);
    assert.equal(t.tainted, true, 'old untrusted content cannot come back clean');
    assert.ok(!fs.readFileSync(auditPath, 'utf8').includes('lagos'), 'the query text is not written to the audit log');
  });

  test('never available to registry skills or sub-agents', () => {
    assert.throws(() => CapabilitiesSchema.parse({ tools: ['searchConversations'] }));
    // attenuate() rejects any tool missing from TOOL_CLASSES ("unknown tool"), so a sub-agent can never be granted it.
    assert.equal('searchConversations' in TOOL_CLASSES, false);
  });

  test('owner search endpoint needs the key and returns hits with context', async () => {
    const gw = createGateway({ tainted: false, audit: { length: 0 } } as any, new HttpApprover(), KEY, { transcriptDir: consoleDir });
    const srv = gw.listen(0, '127.0.0.1');
    await new Promise((r) => srv.once('listening', r));
    const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      assert.equal((await fetch(`${base}/api/search?q=lagos`)).status, 401);
      const r = await (await fetch(`${base}/api/search?q=lagos`, { headers: { authorization: `Bearer ${KEY}` } })).json();
      assert.equal(r.hits.length, 2);
      assert.equal(r.hits[0].after, undefined);
    } finally {
      srv.close();
    }
  });
});
