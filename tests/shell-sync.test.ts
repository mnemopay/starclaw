/** Pure tests (no Docker): tar parsing of hostile archives, workspace staging, and the write-back planner/applier. */
import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildTar, readTar, TarReadLimits } from '../src/shell/tar';
import { applyPlan, planChanges, Snapshot, stageWorkspace, StageError, validateRelPath } from '../src/shell/workspaceSync';
import { rm, tmpDir } from './helpers';

const LIM: TarReadLimits = { maxEntries: 100, maxTotalBytes: 100_000, maxFileBytes: 10_000 };
const F = (p: string, s: string) => ({ path: p, data: Buffer.from(s) });

/** Rewrite the typeflag of the first header and fix its checksum (builds link/device entries the writer cannot). */
function withType(buf: Buffer, flag: string, linkname = ''): Buffer {
  const b = Buffer.from(buf);
  b.write(flag, 156, 1, 'ascii');
  if (linkname) b.write(linkname, 157, 100, 'utf8');
  b.fill(0x20, 148, 156);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += b[i];
  b.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return b;
}

const emptySnap = (files: Record<string, string> = {}): Snapshot => {
  const snap: Snapshot = { files: new Map(), dirs: new Set(), tar: Buffer.alloc(0), totalBytes: 0, skipped: [] };
  const crypto = require('node:crypto');
  for (const [k, v] of Object.entries(files)) snap.files.set(k, { size: v.length, sha256: crypto.createHash('sha256').update(v).digest('hex') });
  return snap;
};

describe('tar reader (parses output of untrusted code)', () => {
  test('round trip: files, directories, long paths', () => {
    const long = 'a'.repeat(60) + '/' + 'b'.repeat(60) + '/file.txt';
    const r = readTar(buildTar([{ path: 'd' }, F('d/x.txt', 'hello'), F(long, 'deep')]), LIM);
    assert.equal(r.error, undefined);
    assert.equal(r.complete, true);
    assert.deepEqual(r.entries.map((e) => [e.path, e.kind]), [['d', 'dir'], ['d/x.txt', 'file'], [long, 'file']]);
    assert.equal(r.entries[1].data!.toString(), 'hello');
  });

  test('symlinks, hard links, devices and fifos are reported as "other" (never files)', () => {
    for (const flag of ['2', '1', '3', '4', '6']) {
      const r = readTar(Buffer.concat([withType(buildTar([F('evil', '')]).subarray(0, 512), flag, '/etc/passwd'), Buffer.alloc(1024)]), LIM);
      assert.equal(r.entries[0].kind, 'other', `typeflag ${flag}`);
      assert.equal(r.entries[0].typeflag, flag);
    }
  });

  test('corrupt checksum, truncation, oversized entries and too many entries are refused', () => {
    const good = buildTar([F('a', 'hello')]);
    const bad = Buffer.from(good);
    bad[0] ^= 0xff;
    assert.match(readTar(bad, LIM).error ?? '', /checksum/);
    assert.equal(readTar(good.subarray(0, 512 + 3), LIM).complete, false);
    assert.match(readTar(buildTar([F('big', 'x'.repeat(20_000))]), LIM).error ?? '', /per-file cap/);
    assert.match(readTar(buildTar([F('a', 'x'.repeat(9000)), F('b', 'x'.repeat(9000))]), { ...LIM, maxTotalBytes: 10_000 }).error ?? '', /total cap/);
    assert.match(readTar(buildTar([F('a', '1'), F('b', '2'), F('c', '3')]), { ...LIM, maxEntries: 2 }).error ?? '', /entries/);
  });

  test('a lying header (size larger than the stream) cannot read past the buffer', () => {
    const b = buildTar([F('a', 'hello')]).subarray(0, 512);
    const forged = Buffer.from(b);
    forged.write('00000200000\0', 124, 12, 'ascii'); // claims 65536 bytes
    forged.fill(0x20, 148, 156);
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += forged[i];
    forged.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    const r = readTar(Buffer.concat([forged, Buffer.alloc(600)]), LIM);
    assert.ok(r.error || !r.complete);
  });
});

describe('relative path validation', () => {
  for (const [p, why] of [
    ['../x', 'dotdot'], ['a/../../x', 'dotdot'], ['/etc/passwd', 'absolute'], ['C:/x', 'drive'], ['a\\b', 'backslash'], ['a:stream', 'ads'], ['CON', 'reserved'], ['dir/NUL.txt', 'reserved'],
    ['file.', 'trailing dot'], ['file ', 'trailing space'], ['PROGRA~1/x', '8.3'], ['a//b', 'empty segment'], ['x\u0001y', 'control'], ['a/./b', 'dot'],
  ] as const) test(`refuses ${why}: ${JSON.stringify(p)}`, () => assert.ok(validateRelPath(p), `${p} was accepted`));
  for (const p of ['a.txt', 'dir/sub/file.name.ext', '.gitignore', 'with space/x']) test(`accepts ${JSON.stringify(p)}`, () => assert.equal(validateRelPath(p), undefined));
});

describe('workspace staging and write-back', () => {
  let dir: string, ws: string, state: string, outside: string;
  const stage = (lim = { maxFiles: 100, maxBytes: 1_000_000, maxFileBytes: 100_000 }) => stageWorkspace(fs.realpathSync.native(ws), fs.realpathSync.native(state), lim);
  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(ws, '.starclaw'); // state dir INSIDE the workspace, the worst case
    outside = path.join(dir, 'outside');
    for (const d of [ws, state, outside]) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'SECRET');
    fs.writeFileSync(path.join(state, 'signing.key'), 'KEY');
    fs.writeFileSync(path.join(ws, 'a.txt'), 'A');
    fs.writeFileSync(path.join(ws, '.env'), 'E=1');
    fs.writeFileSync(path.join(ws, '.env.local'), 'E=2');
  });
  afterEach(() => rm(dir));

  test('stages regular files only: skips .env*, the state directory, junctions and symlinks', () => {
    fs.symlinkSync(outside, path.join(ws, 'jct'), 'junction');
    let fileLink = false;
    try {
      fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(ws, 'flink'), 'file');
      fileLink = true;
    } catch {
      /* no privilege to create file symlinks */
    }
    const snap = stage();
    assert.deepEqual([...snap.files.keys()], ['a.txt']);
    const why = Object.fromEntries(snap.skipped.map((s) => [s.path, s.reason]));
    assert.match(why['jct'], /symlink\/junction/);
    assert.match(why['.env'], /environment/);
    assert.match(why['.env.local'], /environment/);
    assert.match(why['.starclaw'], /state directory/);
    if (fileLink) assert.match(why['flink'], /symlink/);
    const parsed = readTar(snap.tar, { maxEntries: 100, maxTotalBytes: 1e6, maxFileBytes: 1e5 });
    assert.deepEqual(parsed.entries.map((e) => e.path), ['a.txt']);
    assert.ok(!snap.tar.includes('SECRET') && !snap.tar.includes('KEY'));
  });

  test('fails closed (StageError) when the workspace exceeds a cap, instead of copying part of it', () => {
    for (let i = 0; i < 5; i++) fs.writeFileSync(path.join(ws, `f${i}`), 'x');
    assert.throws(() => stage({ maxFiles: 3, maxBytes: 1e6, maxFileBytes: 1e5 }), StageError);
    assert.throws(() => stage({ maxFiles: 100, maxBytes: 3, maxFileBytes: 1e5 }), StageError);
    fs.writeFileSync(path.join(ws, 'big'), 'x'.repeat(5000));
    assert.throws(() => stage({ maxFiles: 100, maxBytes: 1e6, maxFileBytes: 1000 }), StageError);
  });

  const plan = (entries: Parameters<typeof buildTar>[0], snap: Snapshot) => planChanges(readTar(buildTar(entries), LIM), snap, { maxChangedFiles: 50, maxDeletedFiles: 10 });
  const allow = () => {};

  test('plan: new, changed, unchanged and deleted files; hostile names are refused, not written', () => {
    const snap = emptySnap({ 'a.txt': 'A', 'gone.txt': 'G' });
    const p = plan([F('a.txt', 'A'), F('new.txt', 'N'), F('../escape.txt', 'x'), F('C:/win.txt', 'x'), F('a:ads', 'x'), F('CON', 'x'), F('Dup.txt', '1'), F('dup.txt', '2')], snap);
    assert.deepEqual(p.writes.map((w) => w.rel).sort(), ['Dup.txt', 'new.txt']);
    assert.equal(p.unchanged, 1);
    assert.deepEqual(p.deletes, ['gone.txt']);
    const refused = p.refused.map((r) => r.path);
    for (const x of ['../escape.txt', 'C:/win.txt', 'a:ads', 'CON', 'dup.txt']) assert.ok(refused.includes(x), `${x} not refused: ${refused}`);
  });

  test('plan: an archive that is cut short or malformed aborts everything (nothing is deleted on a truncated stream)', () => {
    const snap = emptySnap({ 'a.txt': 'A' });
    const cut = readTar(buildTar([F('x', 'y')]).subarray(0, 600), LIM);
    assert.throws(() => planChanges(cut, snap, { maxChangedFiles: 50, maxDeletedFiles: 10 }), StageError);
  });

  test('plan: caps on changed and deleted paths', () => {
    const many = Array.from({ length: 5 }, (_, i) => F(`n${i}`, 'x'));
    assert.throws(() => planChanges(readTar(buildTar(many), LIM), emptySnap(), { maxChangedFiles: 3, maxDeletedFiles: 10 }), StageError);
    const snap = emptySnap(Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`d${i}`, 'x'])));
    assert.throws(() => planChanges(readTar(buildTar([]), LIM), snap, { maxChangedFiles: 3, maxDeletedFiles: 2 }), StageError);
  });

  test('apply: writes, deletes and creates directories; refuses what the hard-rule guard refuses', () => {
    const wsReal = fs.realpathSync.native(ws);
    const snap = emptySnap({ 'a.txt': 'A' });
    const p = plan([{ path: 'sub' }, F('sub/n.txt', 'N'), F('a.txt', 'A2'), F('.git/config', 'x')], snap);
    const rep = applyPlan(p, snap, wsReal, (abs) => {
      if (/[\\/]\.git[\\/]/.test(abs)) throw new Error('denied by hard rule: writing inside .git is not allowed');
    });
    assert.deepEqual(rep.written.sort(), ['a.txt', 'sub/n.txt']);
    assert.equal(fs.readFileSync(path.join(wsReal, 'a.txt'), 'utf8'), 'A2');
    assert.ok(rep.refused.some((r) => r.path === '.git/config'));
    assert.equal(fs.existsSync(path.join(wsReal, '.git')), false);
  });

  test('apply: a parent directory that became a junction is refused (no write lands outside)', () => {
    const wsReal = fs.realpathSync.native(ws);
    fs.symlinkSync(outside, path.join(wsReal, 'swapped'), 'junction');
    const snap = emptySnap();
    const rep = applyPlan(plan([F('swapped/pwn.txt', 'x'), F('swapped/deeper/pwn.txt', 'x')], snap), snap, wsReal, allow);
    assert.equal(fs.existsSync(path.join(outside, 'pwn.txt')), false);
    assert.equal(fs.existsSync(path.join(outside, 'deeper')), false);
    assert.equal(rep.written.length, 0);
    assert.equal(rep.refused.length, 2);
  });

  test('apply: a target that is a symlink on the host is refused; a file changed on the host is a conflict', () => {
    const wsReal = fs.realpathSync.native(ws);
    let canFileLink = true;
    try {
      fs.symlinkSync(path.join(outside, 'secret.txt'), path.join(wsReal, 'lnk'), 'file');
    } catch {
      canFileLink = false;
    }
    const snap = emptySnap(canFileLink ? { 'a.txt': 'A', lnk: 'x' } : { 'a.txt': 'A' });
    fs.writeFileSync(path.join(wsReal, 'a.txt'), 'CHANGED-ON-HOST');
    const files = [F('a.txt', 'FROM-CONTAINER'), ...(canFileLink ? [F('lnk', 'new')] : [])];
    const rep = applyPlan(plan(files, snap), snap, wsReal, allow);
    assert.deepEqual(rep.conflicts.map((c) => c.path), ['a.txt']);
    assert.equal(fs.readFileSync(path.join(wsReal, 'a.txt'), 'utf8'), 'CHANGED-ON-HOST');
    if (canFileLink) {
      assert.ok(rep.refused.some((r) => r.path === 'lnk'));
      assert.equal(fs.readFileSync(path.join(outside, 'secret.txt'), 'utf8'), 'SECRET', 'the link target was overwritten');
    }
  });

  test('apply: deleting follows the same rules (never deletes through a link, never deletes a host-edited file)', () => {
    const wsReal = fs.realpathSync.native(ws);
    fs.writeFileSync(path.join(wsReal, 'keep.txt'), 'edited');
    const snap = emptySnap({ 'keep.txt': 'original', 'a.txt': 'A' });
    const rep = applyPlan(plan([], snap), snap, wsReal, allow);
    assert.deepEqual(rep.deleted, ['a.txt']);
    assert.deepEqual(rep.conflicts.map((c) => c.path), ['keep.txt']);
    assert.equal(fs.existsSync(path.join(wsReal, 'keep.txt')), true);
  });
});
