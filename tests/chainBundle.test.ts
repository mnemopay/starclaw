import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyBundle } from '@mnemopay/sdk/governance/audit-chain';
import { AuditLog, verifyAuditFile } from '../src/governance/audit';
import { exportArticle12 } from '../src/governance/article12';
import { buildChainBundle, eventIdFor, serializeChainBundle } from '../src/governance/chainBundle';
import { Ed25519Signer, verifierFromHex } from '../src/governance/signer';
import { rm, tmpDir } from './helpers';

const FIXTURE = path.join(__dirname, 'fixtures', 'starclaw-chainbundle', 'v1');

describe('ChainBundle v1 export (MnemoPay AuditChain format, for verifyBundle / anchoring)', () => {
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
    log.append('goal.completed', { kind: 'task' });
  });
  afterEach(() => rm(dir));

  test('CONTROL: the SDK verifyBundle accepts the exported bundle, and every original signature still checks', () => {
    const r = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex });
    const b = r.chainBundle;
    assert.equal(b.version, 1);
    assert.equal(b.events.length, 4); // audit.open + 3
    assert.deepEqual(verifyBundle(b), { ok: true });
    assert.equal(b.meta.article12_bundle_sha256, r.bundle.bundleSha256, 'links to the Article 12 bundle written alongside');
    const originals = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const v = verifierFromHex(signer.publicKeyHex);
    b.events.forEach((e, i) => {
      assert.equal(e.sequence, originals[i].seq);
      assert.equal(e.occurred_at, originals[i].ts, 'original timestamp, not the export time');
      assert.equal(e.kind, originals[i].type);
      assert.equal(e.id, eventIdFor(originals[i]));
      const sc = (e.payload as any).starclaw;
      assert.equal(sc.hash, originals[i].hash);
      assert.equal(v.verify(sc.hash, sc.sig), true, `signature of record ${i}`);
    });
  });

  test('tampering any event, its order, or the root is rejected by verifyBundle (root_mismatch)', () => {
    const b = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex }).chainBundle;
    const clone = () => JSON.parse(serializeChainBundle(b));
    const t1 = clone(); t1.events[2].payload.data.microcents = 1;
    assert.deepEqual(verifyBundle(t1), { ok: false, reason: 'root_mismatch' });
    const t2 = clone(); t2.events.pop();
    assert.equal(verifyBundle(t2).ok, false);
    const t3 = clone(); [t3.events[1], t3.events[2]] = [t3.events[2], t3.events[1]];
    assert.equal(verifyBundle(t3).ok, false);
    const t4 = clone(); t4.merkle_root = '0'.repeat(64);
    assert.equal(verifyBundle(t4).ok, false);
  });

  test('deterministic: same log -> same merkle_root and events; only the Article 12 link (which stamps its export time) varies', () => {
    const a = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex }).chainBundle;
    const b = exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex }).chainBundle;
    assert.equal(a.merkle_root, b.merkle_root);
    const strip = (x: typeof a) => serializeChainBundle({ ...x, meta: { ...x.meta, article12_bundle_sha256: undefined } });
    assert.equal(strip(a), strip(b));
    // Without the link (buildChainBundle on its own) the bytes are fully reproducible.
    const recs = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const v = verifyAuditFile(file, { pinnedPublicKeyHex: signer.publicKeyHex });
    assert.equal(serializeChainBundle(buildChainBundle(recs, v)), serializeChainBundle(buildChainBundle(recs, v)));
  });

  test('refuses a log that does not verify', () => {
    const recs = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    assert.throws(() => buildChainBundle(recs, { ...verifyAuditFile(file), ok: false }), /refusing/);
    const ls = fs.readFileSync(file, 'utf8').split('\n');
    ls[2] = ls[2].replace('1500000', '1');
    fs.writeFileSync(file, ls.join('\n'));
    assert.throws(() => exportArticle12(file, { pinnedPublicKeyHex: signer.publicKeyHex }), /refusing to export/);
  });
});

describe('shared fixture tests/fixtures/starclaw-chainbundle/v1', () => {
  const expected = JSON.parse(fs.readFileSync(path.join(FIXTURE, 'expected.json'), 'utf8'));
  const pub = fs.readFileSync(path.join(FIXTURE, 'pubkey.txt'), 'utf8').trim();

  test('the committed signed log still verifies with the pinned key', () => {
    const v = verifyAuditFile(path.join(FIXTURE, 'audit.jsonl'), { pinnedPublicKeyHex: pub });
    assert.equal(v.ok, true, JSON.stringify(v.errors));
    assert.equal(v.headChecked, true);
  });

  test('rebuilding from the log gives the committed chain-bundle.json byte for byte, with the pinned root', () => {
    const logFile = path.join(FIXTURE, 'audit.jsonl');
    const v = verifyAuditFile(logFile, { pinnedPublicKeyHex: pub });
    const recs = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const body = serializeChainBundle(buildChainBundle(recs, v));
    const committed = fs.readFileSync(path.join(FIXTURE, 'chain-bundle.json'), 'utf8');
    assert.equal(body, committed);
    assert.equal(createHash('sha256').update(committed).digest('hex'), expected.chain_bundle_sha256);
    const parsed = JSON.parse(committed);
    assert.equal(parsed.merkle_root, expected.merkle_root);
    assert.deepEqual(verifyBundle(parsed), { ok: true });
  });
});
