import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Broker } from '../src/broker';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

// Regression tests from the 2026-11-15 red-team pass. The human approver below ALWAYS approves: hard rules
// must hold even when the person says yes.
describe('broker hard rules hold under Windows path spellings (approver approves everything)', () => {
  let dir: string, ws: string, state: string, stateFile: string;
  let broker: Broker;
  beforeEach(() => {
    dir = tmpDir('paths-');
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    fs.mkdirSync(ws, { recursive: true });
    fs.mkdirSync(state, { recursive: true });
    fs.writeFileSync(path.join(state, 'key.txt'), 'SIGNING-KEY-MATERIAL');
    fs.writeFileSync(path.join(ws, '.env'), 'API_KEY=SUPERSECRET');
    stateFile = path.join(fs.realpathSync.native(dir), 'state', 'key.txt');
    const gov = new Governor({
      policy: policyWith({}),
      audit: new AuditLog(path.join(state, 'audit.jsonl'), Ed25519Signer.generate()),
      taint: new TaintTracker(),
      approver: new ScriptedApprover(() => 'approve'),
    });
    broker = new Broker({ governor: gov, workspaceDir: ws, stateDir: state, taintedFiles: new TaintedFileStore(path.join(state, 'tf.json')) });
  });
  afterEach(() => rm(dir));

  const read = (p: string) => broker.handle({ name: 'readFile', args: { path: p } }) as Promise<{ content: string }>;

  test('CONTROL: the plain state-directory path and .env are blocked', async () => {
    await assert.rejects(() => read(stateFile), /hard rule/);
    await assert.rejects(() => read('.env'), /hard rule/);
  });

  test('the loopback admin-share spelling of a state file is blocked (it used to leak the signing key)', { skip: process.platform !== 'win32' }, async () => {
    const unc = `\\\\localhost\\${stateFile[0]}$${stateFile.slice(2)}`;
    await assert.rejects(() => read(unc), /UNC and device paths/);
    await assert.rejects(() => read(unc.replace(/\\/g, '/')), /UNC and device paths/); // //localhost/C$/... form
  });

  test('device and long-path prefixes are blocked', { skip: process.platform !== 'win32' }, async () => {
    await assert.rejects(() => read(`\\\\?\\${stateFile}`), /hard rule/);
    await assert.rejects(() => read(`\\\\.\\${stateFile}`), /hard rule/);
  });

  test('NTFS stream, trailing dot and case spellings of protected files stay blocked', { skip: process.platform !== 'win32' }, async () => {
    await assert.rejects(() => read(`.env::${'$'}DATA`), /hard rule|ENOENT/);
    await assert.rejects(() => read('.env.'), /hard rule|ENOENT/);
    await assert.rejects(() => read(stateFile.toUpperCase()), /hard rule/);
    await assert.rejects(() => read(`${stateFile}::${'$'}DATA`), /hard rule/);
  });

  test('writes through UNC spellings are blocked too', { skip: process.platform !== 'win32' }, async () => {
    const unc = `\\\\localhost\\${stateFile[0]}$${stateFile.slice(2)}`;
    await assert.rejects(() => broker.handle({ name: 'writeFile', args: { path: unc, content: 'x' } }), /UNC and device paths/);
    assert.equal(fs.readFileSync(stateFile, 'utf8'), 'SIGNING-KEY-MATERIAL');
  });
});
