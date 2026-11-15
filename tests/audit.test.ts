import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { AuditLog, headPath, verifyAuditFile } from '../src/governance/audit';
import { Ed25519Signer } from '../src/governance/signer';
import { rm, tmpDir } from './helpers';

describe('tamper-evident audit log', () => {
  let dir: string;
  let file: string;
  let signer: Ed25519Signer;
  beforeEach(() => {
    dir = tmpDir();
    file = path.join(dir, 'audit.jsonl');
    signer = Ed25519Signer.generate();
    const log = new AuditLog(file, signer);
    for (let i = 0; i < 6; i++) log.append('decision.request', { n: i, target: `t${i}` });
  });
  afterEach(() => rm(dir));

  const lines = () => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  const write = (ls: string[]) => fs.writeFileSync(file, ls.join('\n') + '\n');
  const verify = (extra = {}) => verifyAuditFile(file, { pinnedPublicKeyHex: signer.publicKeyHex, ...extra });

  test('CONTROL: an untouched log verifies (chain, signatures, head)', () => {
    const r = verify();
    assert.equal(r.ok, true, JSON.stringify(r.errors));
    assert.equal(r.records, 7); // audit.open + 6
    assert.equal(r.headChecked, true);
  });

  test('modifying a record is detected', () => {
    const ls = lines();
    ls[3] = ls[3].replace('"t2"', '"EVIL"');
    assert.notEqual(ls[3], lines()[3]);
    write(ls);
    const r = verify();
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /hash mismatch/.test(e.reason)));
  });

  test('modifying a record AND recomputing its hash is still detected (signature / chain)', () => {
    const ls = lines();
    const rec = JSON.parse(ls[3]);
    rec.data.target = 'EVIL';
    // attacker recomputes the hash but has no signing key
    const { canonicalize, sha256Hex } = require('../src/governance/canonical');
    rec.hash = sha256Hex(canonicalize({ v: rec.v, seq: rec.seq, ts: rec.ts, prev: rec.prev, type: rec.type, data: rec.data }));
    ls[3] = JSON.stringify(rec);
    write(ls);
    const r = verify();
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /signature invalid/.test(e.reason)));
    assert.ok(r.errors.some((e) => /prev-hash/.test(e.reason)), 'the next record no longer chains');
  });

  test('deleting a record in the middle is detected', () => {
    const ls = lines();
    ls.splice(3, 1);
    write(ls);
    const r = verify();
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /sequence mismatch|prev-hash/.test(e.reason)));
  });

  test('reordering records is detected', () => {
    const ls = lines();
    [ls[2], ls[3]] = [ls[3], ls[2]];
    write(ls);
    const r = verify();
    assert.equal(r.ok, false);
  });

  test('truncating the tail is detected via the signed head checkpoint', () => {
    write(lines().slice(0, 4));
    const r = verify();
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /truncated/.test(e.reason)), JSON.stringify(r.errors));
  });

  test('CONTROL: without the head checkpoint, tail truncation is NOT detectable (documents the limit)', () => {
    write(lines().slice(0, 4));
    fs.rmSync(headPath(file));
    const strict = verify();
    assert.equal(strict.ok, false, 'strict mode fails when the head is missing');
    const lax = verify({ allowMissingHead: true });
    assert.equal(lax.ok, true, 'chain alone cannot see a clean tail cut');
    assert.ok(lax.warnings.some((w) => /tail truncation cannot be ruled out/.test(w)));
  });

  test('a half-written last line (no newline) is detected', () => {
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').trimEnd());
    assert.equal(verify().ok, false);
  });

  test('a log fully re-signed with a different key is rejected when the key is pinned', () => {
    const attackerKey = Ed25519Signer.generate();
    const forged = path.join(dir, 'forged.jsonl');
    const f = new AuditLog(forged, attackerKey);
    f.append('decision.request', { n: 1 });
    assert.equal(verifyAuditFile(forged, { pinnedPublicKeyHex: attackerKey.publicKeyHex }).ok, true, 'internally consistent');
    const r = verifyAuditFile(forged, { pinnedPublicKeyHex: signer.publicKeyHex });
    assert.equal(r.ok, false);
    // And unpinned verification only warns: documents why --pubkey exists.
    const unpinned = verifyAuditFile(forged);
    assert.equal(unpinned.ok, true);
    assert.ok(unpinned.warnings.some((w) => /not pinned/.test(w)));
  });

  test('appending a forged record without the key is detected', () => {
    const ls = lines();
    const rec = JSON.parse(ls[ls.length - 1]);
    const forged = { ...rec, seq: rec.seq + 1, prev: rec.hash, type: 'decision.result', data: { allowed: true } };
    fs.appendFileSync(file, JSON.stringify(forged) + '\n');
    assert.equal(verify().ok, false);
  });

  test('reopening continues the same chain and refuses a broken log (fail closed)', () => {
    const again = new AuditLog(file, signer);
    again.append('x', {});
    assert.equal(verify().ok, true);
    const ls = lines();
    ls[2] = ls[2].replace('"t1"', '"zzz"');
    write(ls);
    assert.throws(() => new AuditLog(file, signer), /failed verification/);
  });

  test('secrets in event data are redacted before they are hashed and written', () => {
    const log = new AuditLog(path.join(dir, 'r.jsonl'), signer);
    log.append('x', { note: 'key sk-abcdefghijklmnopqrstuvwxyz0123 and Bearer abcdefghijklmnop1234567890' });
    const text = fs.readFileSync(path.join(dir, 'r.jsonl'), 'utf8');
    assert.ok(!text.includes('sk-abcdefghijklmnopqrstuvwxyz0123'));
    assert.ok(!text.includes('abcdefghijklmnop1234567890'));
    assert.ok(text.includes('[REDACTED]'));
  });

  test('CLI: `starclaw audit verify` exits 0 on a good log and 1 on a tampered one', () => {
    const cli = path.join(__dirname, '..', 'src', 'cli.ts');
    const run = () => spawnSync(process.execPath, ['--import', 'tsx', cli, 'audit', 'verify', file, '--pubkey', signer.publicKeyHex], { encoding: 'utf8' });
    const good = run();
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /OK: 7 records/);
    const ls = lines();
    ls[1] = ls[1].replace('"n":0', '"n":9');
    write(ls);
    const bad = run();
    assert.equal(bad.status, 1);
    assert.match(bad.stdout, /FAILED/);
  });
});
