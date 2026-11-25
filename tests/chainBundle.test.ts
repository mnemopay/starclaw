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
    assert.equal(b.meta.event_count, 4, 'meta.event_count = number of events (for anchoring sinks)');
    assert.equal(b.meta.event_count, b.events.length);
    assert.deepEqual(Object.keys(b.meta), ['format', 'source', 'log_records', 'log_first_seq', 'log_last_hash', 'public_key_hex', 'key_pinned', 'event_count', 'article12_bundle_sha256']);
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

const fixtureDir = (v: string) => path.join(__dirname, 'fixtures', 'starclaw-chainbundle', v);
const readFixture = (v: string) => {
  const d = fixtureDir(v);
  const pub = fs.readFileSync(path.join(d, 'pubkey.txt'), 'utf8').trim();
  const logFile = path.join(d, 'audit.jsonl');
  return {
    expected: JSON.parse(fs.readFileSync(path.join(d, 'expected.json'), 'utf8')),
    pub,
    logFile,
    committed: fs.readFileSync(path.join(d, 'chain-bundle.json'), 'utf8'),
    rebuild: () => {
      const v = verifyAuditFile(logFile, { pinnedPublicKeyHex: pub });
      const recs = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
      return buildChainBundle(recs, v);
    },
  };
};
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

describe('shared fixture tests/fixtures/starclaw-chainbundle/v1 (frozen: AgentAudit CI pins these bytes)', () => {
  const fx = readFixture('v1');

  test('the committed signed log still verifies with the pinned key', () => {
    const v = verifyAuditFile(fx.logFile, { pinnedPublicKeyHex: fx.pub });
    assert.equal(v.ok, true, JSON.stringify(v.errors));
    assert.equal(v.headChecked, true);
  });

  test('the committed v1 chain-bundle.json is unchanged (pinned sha256 and root) and still verifies', () => {
    assert.equal(sha256(fx.committed), '54f963b67973e6a81e07741d62e799008583e80d9e9f30dc09c6469f4824abfc');
    assert.equal(sha256(fx.committed), fx.expected.chain_bundle_sha256);
    const parsed = JSON.parse(fx.committed);
    assert.equal(parsed.merkle_root, fx.expected.merkle_root);
    assert.equal('event_count' in parsed.meta, false, 'v1 predates meta.event_count');
    assert.deepEqual(verifyBundle(parsed), { ok: true });
  });

  test('rebuilding from the log gives v1 byte for byte once meta.event_count (added in alpha.15) is removed', () => {
    const b = fx.rebuild();
    const { event_count, ...metaV1 } = b.meta;
    assert.equal(event_count, 5);
    assert.equal(serializeChainBundle({ ...b, meta: metaV1 as typeof b.meta }), fx.committed);
  });
});

describe('shared fixture tests/fixtures/starclaw-chainbundle/v2 (meta.event_count)', () => {
  const fx = readFixture('v2');
  const v1 = readFixture('v1');

  test('same signed log as v1, and it verifies with the pinned key', () => {
    assert.equal(fs.readFileSync(fx.logFile, 'utf8'), fs.readFileSync(v1.logFile, 'utf8'));
    assert.equal(fx.pub, v1.pub);
    const v = verifyAuditFile(fx.logFile, { pinnedPublicKeyHex: fx.pub });
    assert.equal(v.ok, true, JSON.stringify(v.errors));
    assert.equal(v.headChecked, true);
  });

  test('rebuilding from the log gives the committed v2 chain-bundle.json byte for byte, with the pinned sha256', () => {
    assert.equal(serializeChainBundle(fx.rebuild()), fx.committed);
    assert.equal(sha256(fx.committed), 'df1e3f662f1663103cd97aa9af4c8c578e722e3d6628cca3007ad344e072ac6e');
    assert.equal(sha256(fx.committed), fx.expected.chain_bundle_sha256);
    assert.notEqual(fx.expected.chain_bundle_sha256, v1.expected.chain_bundle_sha256);
  });

  test('v2 carries meta.event_count = events.length and verifyBundle accepts it', () => {
    const parsed = JSON.parse(fx.committed);
    assert.equal(parsed.meta.event_count, 5);
    assert.equal(parsed.meta.event_count, parsed.events.length);
    assert.equal(parsed.meta.event_count, fx.expected.event_count);
    assert.deepEqual(verifyBundle(parsed), { ok: true });
  });

  test('merkle_root is unchanged: v1 root == v2 root (event_count is meta, not a leaf)', () => {
    const r1 = JSON.parse(v1.committed).merkle_root;
    const r2 = JSON.parse(fx.committed).merkle_root;
    assert.equal(r1, '35a592434300017e903062fbff4488a2f3322479626289c37e78984fb54ddd04');
    assert.equal(r2, r1);
    assert.equal(fx.expected.merkle_root, v1.expected.merkle_root);
    assert.deepEqual(JSON.parse(fx.committed).events, JSON.parse(v1.committed).events);
  });
});
