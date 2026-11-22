import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { MerkleAudit } from '@mnemopay/sdk';
import { AuditLog } from '../src/governance/audit';
import { exportArticle12 } from '../src/governance/article12';
import { Ed25519Signer, verifierFromHex } from '../src/governance/signer';
import { rm, tmpDir } from './helpers';

describe('Article 12 export (MnemoPay bundle from a verified StarClaw log)', () => {
  let dir: string;
  let file: string;
  let signer: Ed25519Signer;
  beforeEach(() => {
    dir = tmpDir();
    file = path.join(dir, 'audit.jsonl');
    signer = Ed25519Signer.generate();
    const log = new AuditLog(file, signer);
    log.append('goal.received', { goal: 'say hi' });
    log.append('llm.usage', { microcents: 1_500_000 });
    log.append('llm.usage', { microcents: 2_500_000 });
    log.append('goal.completed', { kind: 'task' });
  });
  afterEach(() => rm(dir));

  const lines = () => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  const fileBody = (r: ReturnType<typeof exportArticle12>, p: string) => r.bundle.files.find((f) => f.path === p)!.body;

  test('CONTROL: a verified log exports; checksums, both chains and every original signature check out', () => {
    const r = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex, operatorId: 'acme' });
    assert.deepEqual(r.bundle.files.map((f) => f.path).sort(), ['chain.txt', 'events.csv', 'events.json', 'manifest.json', 'mission.json']);
    for (const f of r.bundle.files) assert.equal(f.sha256, createHash('sha256').update(f.body).digest('hex'), f.path);

    const events = JSON.parse(fileBody(r, 'events.json'));
    const chain = fileBody(r, 'chain.txt').trim().split('\n');
    assert.equal(events.length, 5); // audit.open + 4
    assert.equal(chain.length, 5);
    assert.equal(MerkleAudit.fromJSON({ events, chain }).verify(), true);

    const originals = lines().map((l) => JSON.parse(l));
    const v = verifierFromHex(signer.publicKeyHex);
    events.forEach((e: any, i: number) => {
      assert.equal(e.ts, originals[i].ts, 'original timestamp kept, not the export time');
      assert.equal(e.type, originals[i].type);
      assert.deepEqual(e.data.payload, originals[i].data);
      assert.equal(e.data.starclaw.hash, originals[i].hash);
      assert.equal(v.verify(e.data.starclaw.hash, e.data.starclaw.sig), true, `signature of record ${i}`);
    });
    assert.equal(events[0].type, 'audit.open');
    assert.equal(events[0].data.payload.publicKey, signer.publicKeyHex);

    const mission = JSON.parse(fileBody(r, 'mission.json'));
    assert.equal(mission.chainVerified, true);
    assert.equal(mission.operatorId, 'acme');
    assert.equal(mission.result.auditDigest, originals[4].hash);
    assert.equal(mission.result.status, 'ok');
    assert.equal(mission.result.spentUsd, 0.04); // 4,000,000 microcents = 4 cents
    assert.equal(mission.retention.months, 6);
  });

  test('a tampered log is refused: nothing is exported', () => {
    const ls = lines();
    ls[1] = ls[1].replace('say hi', 'say bye');
    fs.writeFileSync(file, ls.join('\n') + '\n');
    assert.throws(() => exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex }), /refusing to export/);
  });

  test('a log signed by a different key is refused when the key is pinned', () => {
    assert.throws(() => exportArticle12(file, { pinnedPublicKeyHex: Ed25519Signer.generate().publicKeyHex }), /refusing to export/);
  });

  test('editing an event inside the exported bundle breaks the MnemoPay chain', () => {
    const r = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex });
    const events = JSON.parse(fileBody(r, 'events.json'));
    const chain = fileBody(r, 'chain.txt').trim().split('\n');
    events[1].data.payload.goal = 'something else';
    assert.equal(MerkleAudit.fromJSON({ events, chain }).verify(), false);
  });

  test('a failed goal marks the mission status as error', () => {
    new AuditLog(file, signer).append('goal.failed', { error: 'boom' });
    const r = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex });
    assert.equal(JSON.parse(fileBody(r, 'mission.json')).result.status, 'error');
  });

  test('CLI: `starclaw audit export` writes the bundle, refuses to overwrite it, and exits 1 on a tampered log', () => {
    const cli = path.join(__dirname, '..', 'src', 'cli.ts');
    const out = path.join(dir, 'bundle');
    const run = () => spawnSync(process.execPath, ['--import', 'tsx', cli, 'audit', 'export', file, '--out', out, '--pubkey', signer.publicKeyHex], { encoding: 'utf8' });
    const good = run();
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /exported 5 events/);
    assert.deepEqual(fs.readdirSync(out).sort(), ['chain-bundle.json', 'chain.txt', 'events.csv', 'events.json', 'manifest.json', 'mission.json']);
    assert.match(good.stdout, /merkle_root [0-9a-f]{64}/);
    assert.equal(run().status, 1, 'a second export into the same directory must not overwrite');

    const ls = lines();
    ls[2] = ls[2].replace('1500000', '1');
    fs.writeFileSync(file, ls.join('\n') + '\n');
    const bad = spawnSync(process.execPath, ['--import', 'tsx', cli, 'audit', 'export', file, '--out', path.join(dir, 'bundle2'), '--pubkey', signer.publicKeyHex], { encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /refusing to export/);
    assert.equal(fs.existsSync(path.join(dir, 'bundle2')), false);
  });
});
