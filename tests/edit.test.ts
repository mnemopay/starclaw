import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Broker, BrokerOptions } from '../src/broker';
import { applyUnifiedDiff, editByFind, readText, unifiedDiff } from '../src/edit';
import { AuditLog } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { TaintedFileStore, TaintTracker } from '../src/governance/taint';
import { ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

describe('edit helpers (pure)', () => {
  const orig = 'one\ntwo\nthree\nfour\nfive\n';
  test('a unified diff applies; line-number drift is tolerated only when the block is unique', () => {
    const p = '--- a/f\n+++ b/f\n@@ -2,3 +2,3 @@\n two\n-three\n+THREE\n four\n';
    assert.deepEqual(applyUnifiedDiff(orig, p, true), { ok: true, result: 'one\ntwo\nTHREE\nfour\nfive\n', hunks: 1 });
    const drift = '@@ -9,3 +9,3 @@\n two\n-three\n+THREE\n four\n';
    assert.equal((applyUnifiedDiff(orig, drift, true) as any).result, 'one\ntwo\nTHREE\nfour\nfive\n');
    const ambiguous = applyUnifiedDiff('a\nx\nb\na\nx\nb\n', '@@ -9,2 +9,2 @@\n a\n-x\n+y\n', true);
    assert.equal(ambiguous.ok, false);
    assert.match((ambiguous as any).error, /more than one place/);
  });
  test('stale or wrong context is refused, never fuzzed', () => {
    const r = applyUnifiedDiff(orig, '@@ -2,3 +2,3 @@\n two\n-THREE\n+x\n four\n', true);
    assert.equal(r.ok, false);
    assert.match((r as any).error, /does not apply cleanly/);
    assert.equal(applyUnifiedDiff(orig, '@@ -2,3 +2,3 @@\n  two\n-three\n+x\n four\n', true).ok, false, 'whitespace differences are not forgiven');
  });
  test('malformed, multi-file, rename and binary patches are refused', () => {
    for (const bad of ['', 'garbage', '@@ -1,2 +1,2 @@\n one\n', '@@ nope @@\n', '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-one\n+1\n--- a/y\n+++ b/y\n@@ -1 +1 @@\n-a\n+b\n', 'rename from a\nrename to b\n', 'Binary files a and b differ\n', 'diff --git a/x b/x\ndeleted file mode 100644\n']) {
      assert.equal(applyUnifiedDiff(orig, bad, true).ok, false, JSON.stringify(bad));
    }
  });
  test('creation patches only work when the file does not exist', () => {
    const p = '--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1,2 @@\n+hello\n+world\n';
    assert.deepEqual(applyUnifiedDiff('', p, false), { ok: true, result: 'hello\nworld\n', hunks: 1 });
    assert.equal(applyUnifiedDiff('existing\n', p, true).ok, false);
    assert.equal(applyUnifiedDiff('', '@@ -1 +1 @@\n-a\n+b\n', false).ok, false);
  });
  test('no-newline-at-EOF markers are honoured', () => {
    const r = applyUnifiedDiff('a\nb', '@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n', true);
    assert.deepEqual(r, { ok: true, result: 'a\nc', hunks: 1 });
  });
  test('editByFind enforces expectCount exactly', () => {
    assert.equal((editByFind('a a a', 'a', 'b', 3) as any).result, 'b b b');
    assert.equal(editByFind('a a a', 'a', 'b', 1).ok, false);
    assert.equal(editByFind('abc', 'zzz', 'b', 1).ok, false);
    assert.equal(editByFind('abc', '', 'b', 1).ok, false);
    assert.equal((editByFind('x\ny', 'x\r\ny', 'z', 1) as any).result, 'z', 'CRLF in find is normalised');
  });
  test('readText refuses binary, invalid UTF-8, mixed and bare-CR files; recognises CRLF and BOM', () => {
    assert.equal(readText(Buffer.from([0x50, 0x4b, 0, 0, 1, 2])).ok, false);
    assert.equal(readText(Buffer.from([0xff, 0xfe, 0xfd, 0x41])).ok, false);
    assert.equal(readText(Buffer.from('a\r\nb\nc')).ok, false);
    assert.equal(readText(Buffer.from('a\rb')).ok, false);
    const t = readText(Buffer.from('﻿a\r\nb\r\n'));
    assert.deepEqual(t.ok && [t.eol, t.bom, t.text], ['crlf', true, 'a\nb\n']);
  });
  test('unifiedDiff shows removed and added lines with context', () => {
    const d = unifiedDiff('a\nb\nc\nd\ne\nf\n', 'a\nb\nc\nD\ne\nf\n', 'x.txt');
    assert.match(d.diff, /^--- a\/x\.txt\n\+\+\+ b\/x\.txt\n@@ /);
    assert.ok(d.diff.includes('-d\n+D\n'));
    assert.deepEqual([d.added, d.removed], [1, 1]);
    assert.equal(unifiedDiff('same', 'same', 'x').diff, '');
  });
});

describe('broker file editing', () => {
  let dir: string, ws: string, state: string, outside: string;
  let taint: TaintTracker;
  let approver: ScriptedApprover;
  let tainted: TaintedFileStore;
  const open = (policy: Record<string, unknown> = {}, o: Partial<BrokerOptions> = {}, appr: ScriptedApprover | null = approver) => {
    const gov = new Governor({ policy: policyWith(policy), audit: new AuditLog(path.join(dir, 'audit.jsonl'), signer), taint, approver: appr ?? undefined });
    return { gov, broker: new Broker({ governor: gov, workspaceDir: ws, stateDir: state, taintedFiles: tainted, ...o }) };
  };
  let signer: Ed25519Signer;
  const file = (name: string) => path.join(ws, name);
  const write = (name: string, content: string | Buffer) => {
    fs.mkdirSync(path.dirname(file(name)), { recursive: true });
    fs.writeFileSync(file(name), content);
  };
  const leftovers = () => fs.readdirSync(ws, { recursive: true }).map(String).filter((n) => n.includes('.starclaw-tmp-'));

  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    outside = path.join(dir, 'outside');
    fs.mkdirSync(ws, { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'OUTSIDE');
    taint = new TaintTracker();
    signer = Ed25519Signer.generate();
    approver = new ScriptedApprover(() => 'approve');
    tainted = new TaintedFileStore(path.join(dir, 'tf.json'));
  });
  afterEach(() => rm(dir));

  test('editFile: the approver is shown the DIFF; the file changes atomically; the audit log records hashes', async () => {
    write('a.txt', 'alpha\nbeta\ngamma\n');
    const { broker } = open();
    const r: any = await broker.handle({ name: 'editFile', args: { path: 'a.txt', find: 'beta', replace: 'BETA' } });
    assert.equal(r.changed, true);
    assert.equal(fs.readFileSync(file('a.txt'), 'utf8'), 'alpha\nBETA\ngamma\n');
    assert.equal(r.sha256After, sha('alpha\nBETA\ngamma\n'));
    const req = approver.seen.find((s) => s.action.class === 'fs.write')!;
    assert.match(req.action.detail!, /^--- a\/a\.txt\n\+\+\+ b\/a\.txt\n@@/);
    assert.ok(req.action.detail!.includes('-beta\n+BETA'));
    assert.match(req.action.summary, /\+1 -1 lines/);
    assert.deepEqual(leftovers(), []);
    const log = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8');
    assert.ok(log.includes('"via":"editFile"') && log.includes(r.sha256After));
    assert.ok(log.includes('-beta\\n+BETA'), 'the diff itself is in the audit record');
  });

  test('applyPatch: multi-hunk patch applies; a patch that does not apply is refused BEFORE any human is asked and changes nothing', async () => {
    write('b.txt', 'l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\n');
    const { broker } = open();
    const good = '--- a/b.txt\n+++ b/b.txt\n@@ -1,2 +1,2 @@\n-l1\n+L1\n l2\n@@ -7,2 +7,2 @@\n l7\n-l8\n+L8\n';
    await broker.handle({ name: 'applyPatch', args: { path: 'b.txt', patch: good } });
    assert.equal(fs.readFileSync(file('b.txt'), 'utf8'), 'L1\nl2\nl3\nl4\nl5\nl6\nl7\nL8\n');
    const asked = approver.seen.length;
    await assert.rejects(() => broker.handle({ name: 'applyPatch', args: { path: 'b.txt', patch: '@@ -1,2 +1,2 @@\n-nope\n+x\n l2\n' } }), /does not apply cleanly/);
    assert.equal(approver.seen.length, asked, 'no approval request for a patch that cannot apply');
    assert.equal(fs.readFileSync(file('b.txt'), 'utf8'), 'L1\nl2\nl3\nl4\nl5\nl6\nl7\nL8\n');
  });

  test('CRLF file + LF patch/find: applied, the file stays CRLF everywhere; mixed endings are refused', async () => {
    write('crlf.txt', 'one\r\ntwo\r\nthree\r\n');
    const { broker } = open();
    await broker.handle({ name: 'applyPatch', args: { path: 'crlf.txt', patch: '@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n' } });
    assert.equal(fs.readFileSync(file('crlf.txt'), 'utf8'), 'one\r\nTWO\r\nthree\r\n');
    await broker.handle({ name: 'editFile', args: { path: 'crlf.txt', find: 'one\nTWO', replace: 'ONE\nTWO' } });
    assert.equal(fs.readFileSync(file('crlf.txt'), 'utf8'), 'ONE\r\nTWO\r\nthree\r\n');
    write('mixed.txt', 'a\r\nb\nc\r\n');
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'mixed.txt', find: 'b', replace: 'B' } }), /mixed line endings/);
    assert.equal(fs.readFileSync(file('mixed.txt'), 'utf8'), 'a\r\nb\nc\r\n');
  });

  test('UTF-8 BOM is preserved', async () => {
    write('bom.txt', '﻿hello\nworld\n');
    const { broker } = open();
    await broker.handle({ name: 'editFile', args: { path: 'bom.txt', find: 'world', replace: 'there' } });
    assert.equal(fs.readFileSync(file('bom.txt'), 'utf8'), '﻿hello\nthere\n');
  });

  test('binary and non-UTF-8 files are refused', async () => {
    write('bin.dat', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 1, 2, 3]));
    write('latin1.txt', Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0a]));
    const { broker } = open();
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'bin.dat', find: 'PNG', replace: 'X' } }), /binary/);
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'latin1.txt', find: 'caf', replace: 'X' } }), /not valid UTF-8/);
  });

  test('size caps: oversized patch, oversized file, oversized result', async () => {
    write('big.txt', 'x'.repeat(1_100_000));
    write('ok.txt', 'a\n');
    const { broker } = open();
    await assert.rejects(() => broker.handle({ name: 'applyPatch', args: { path: 'ok.txt', patch: '@@ -1 +1 @@\n-a\n+' + 'y'.repeat(250_000) + '\n' } }));
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'big.txt', find: 'x', replace: 'y', expectCount: 1 } }), /larger than/);
    write('grow.txt', 'q\n'.repeat(400_000));
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'grow.txt', find: 'q', replace: 'qqqqqqqqqq', expectCount: 400_000 } }), /Too big|too many|exceed|expectCount|more than/i);
    assert.equal(fs.readFileSync(file('ok.txt'), 'utf8'), 'a\n');
  });

  describe('path attacks (hard rules, no approver is even asked)', () => {
    const attempt = (broker: Broker, p: string, patch?: string) =>
      broker.handle({ name: 'applyPatch', args: { path: p, patch: patch ?? '--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+PWNED\n' } });

    test('..\\ and absolute traversal, state dir, .env and .git targets', async () => {
      const { broker } = open();
      fs.mkdirSync(path.join(ws, '.git'), { recursive: true });
      for (const p of ['..\\outside\\pwned.txt', '../outside/pwned.txt', path.join(outside, 'pwned.txt'), '.env', 'sub/.env.production', '.git/config', path.join(state, 'audit.key'), '..\\state\\x']) {
        await assert.rejects(() => attempt(broker, p), /hard rule/, p);
      }
      assert.equal(fs.existsSync(path.join(outside, 'pwned.txt')), false);
      assert.equal(fs.existsSync(file('.env')), false);
      assert.equal(approver.seen.filter((s) => s.action.class === 'fs.write').length, 0);
      if (process.platform === 'win32') await assert.rejects(() => attempt(broker, '\\\\localhost\\C$\\Windows\\Temp\\x.txt'), /UNC and device/);
    });

    test('a junction/symlink directory inside the workspace pointing outside', async () => {
      const { broker } = open();
      fs.symlinkSync(outside, file('link'), 'junction');
      await assert.rejects(() => attempt(broker, 'link/secret.txt', '@@ -1 +1 @@\n-OUTSIDE\n+HACKED\n'), /hard rule/);
      await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'link/secret.txt', find: 'OUTSIDE', replace: 'HACKED' } }), /hard rule/);
      await assert.rejects(() => attempt(broker, 'link/new.txt'), /hard rule/);
      assert.equal(fs.readFileSync(path.join(outside, 'secret.txt'), 'utf8'), 'OUTSIDE');
      assert.equal(fs.existsSync(path.join(outside, 'new.txt')), false);
      fs.unlinkSync(file('link'));
    });

    test('a symbolic link to a file is never edited through', async (t) => {
      write('real.txt', 'content\n');
      try {
        fs.symlinkSync(file('real.txt'), file('alias.txt'), 'file');
      } catch (e: any) {
        return t.skip(`cannot create file symlinks here: ${e.code}`);
      }
      const { broker } = open();
      await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'alias.txt', find: 'content', replace: 'X' } }), /symbolic link/);
      assert.equal(fs.readFileSync(file('real.txt'), 'utf8'), 'content\n');
    });

    test('CONTROL: the same edit on an ordinary workspace file succeeds (the refusals above are due to the path, not a broken tool)', async () => {
      write('fine.txt', 'x\n');
      const { broker } = open();
      await broker.handle({ name: 'editFile', args: { path: 'fine.txt', find: 'x', replace: 'y' } });
      assert.equal(fs.readFileSync(file('fine.txt'), 'utf8'), 'y\n');
    });
  });

  test('approval is required: a denial or no approver leaves the file untouched', async () => {
    write('c.txt', 'keep\n');
    const deny = open({}, {}, new ScriptedApprover(() => 'deny')).broker;
    await assert.rejects(() => deny.handle({ name: 'editFile', args: { path: 'c.txt', find: 'keep', replace: 'lost' } }), /Denied/);
    const none = open({}, {}, null).broker;
    await assert.rejects(() => none.handle({ name: 'editFile', args: { path: 'c.txt', find: 'keep', replace: 'lost' } }), /Denied/);
    assert.equal(fs.readFileSync(file('c.txt'), 'utf8'), 'keep\n');
  });

  test('preconditions: expectSha256 and expectCount', async () => {
    write('d.txt', 'a a\n');
    const { broker } = open();
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'd.txt', find: 'a', replace: 'b', expectCount: 2, expectSha256: sha('something else') } }), /expectSha256 precondition failed/);
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'd.txt', find: 'a', replace: 'b' } }), /matched 2 time/);
    await broker.handle({ name: 'editFile', args: { path: 'd.txt', find: 'a', replace: 'b', expectCount: 2, expectSha256: sha('a a\n') } });
    assert.equal(fs.readFileSync(file('d.txt'), 'utf8'), 'b b\n');
  });

  test('a no-op edit changes nothing and asks nobody', async () => {
    write('e.txt', 'same\n');
    const { broker } = open();
    const r: any = await broker.handle({ name: 'editFile', args: { path: 'e.txt', find: 'same', replace: 'same' } });
    assert.equal(r.changed, false);
    assert.equal(approver.seen.filter((s) => s.action.class === 'fs.write').length, 0);
  });

  test('creating a file with a patch works in the workspace; creating .env with a patch is refused', async () => {
    const { broker } = open();
    await broker.handle({ name: 'applyPatch', args: { path: 'new/dir/n.txt', patch: '--- /dev/null\n+++ b/n.txt\n@@ -0,0 +1,2 @@\n+one\n+two\n' } });
    assert.equal(fs.readFileSync(file('new/dir/n.txt'), 'utf8'), 'one\ntwo\n');
    await assert.rejects(() => broker.handle({ name: 'applyPatch', args: { path: '.env', patch: '--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+API_KEY=attacker\n' } }), /hard rule/);
    assert.equal(fs.existsSync(file('.env')), false);
    await assert.rejects(() => broker.handle({ name: 'applyPatch', args: { path: 'new/dir/n.txt', patch: '--- /dev/null\n+++ b/n.txt\n@@ -0,0 +1 @@\n+clobber\n' } }), /already exists/);
  });

  describe('TOCTOU: the world changes while the human is deciding', () => {
    test('a concurrent modification after the diff was shown is detected and NOT clobbered', async () => {
      write('t.txt', 'v1\n');
      const { broker } = open({}, { _testBeforeCommit: (real) => fs.writeFileSync(real, 'v1\nsomeone else was here\n') });
      await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 't.txt', find: 'v1', replace: 'v2' } }), /changed after the diff was shown/);
      assert.equal(fs.readFileSync(file('t.txt'), 'utf8'), 'v1\nsomeone else was here\n');
      assert.deepEqual(leftovers(), []);
    });

    test('CONTROL: without the post-approval re-check the racing change IS silently overwritten', async () => {
      write('t2.txt', 'v1\n');
      const { broker } = open({}, { _testBeforeCommit: (real) => fs.writeFileSync(real, 'v1\nsomeone else was here\n'), _unsafeSkipRecheck: true });
      await broker.handle({ name: 'editFile', args: { path: 't2.txt', find: 'v1', replace: 'v2' } });
      assert.equal(fs.readFileSync(file('t2.txt'), 'utf8'), 'v2\n', 'the other writer\'s change was lost: that is the race the re-check prevents');
    });

    test('the file replaced by a symlink after approval is refused', async (t) => {
      write('s.txt', 'x\n');
      write('victim.txt', 'victim\n');
      const swap = (real: string) => {
        fs.unlinkSync(real);
        fs.symlinkSync(file('victim.txt'), real, 'file');
      };
      try {
        fs.symlinkSync(file('victim.txt'), file('probe-link'), 'file');
        fs.unlinkSync(file('probe-link'));
      } catch (e: any) {
        return t.skip(`cannot create file symlinks here: ${e.code}`);
      }
      const { broker } = open({}, { _testBeforeCommit: swap });
      await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 's.txt', find: 'x', replace: 'y' } }), /symbolic link|resolves somewhere else/);
      assert.equal(fs.readFileSync(file('victim.txt'), 'utf8'), 'victim\n');
    });

    test('the parent directory swapped for a junction to outside after approval: nothing is written outside', async () => {
      write('sub/f.txt', 'x\n');
      let swapped = false;
      const swap = () => {
        fs.renameSync(file('sub'), file('sub_real'));
        fs.symlinkSync(outside, file('sub'), 'junction');
        swapped = true;
      };
      const { broker } = open({}, { _testBeforeCommit: swap });
      await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'sub/f.txt', find: 'x', replace: 'ESCAPED' } }), /hard rule|resolves somewhere else|escaped|disappeared/);
      assert.equal(swapped, true, 'the swap really happened');
      assert.deepEqual(fs.readdirSync(outside).sort(), ['secret.txt'], 'nothing was created outside the workspace');
      fs.unlinkSync(file('sub'));
    });
  });

  test('files written while the session is tainted taint later readers', async () => {
    write('tw.txt', 'a\n');
    const { broker, gov } = open();
    gov.taint.mark('web', 'http://x/page');
    await broker.handle({ name: 'editFile', args: { path: 'tw.txt', find: 'a', replace: 'from the web' } });
    gov.taint.reset();
    await broker.handle({ name: 'readFile', args: { path: 'tw.txt' } });
    assert.equal(gov.taint.tainted, true);
  });

  test('editing needs the same fs.read gate as reading: when reads are denied by policy, find/expectCount cannot be used as a content oracle', async () => {
    write('o.txt', 'secret-token-123\n');
    const { broker } = open({ rules: [{ class: 'fs.read', verdict: 'deny' }] });
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'o.txt', find: 'secret-token-123', replace: 'x' } }), /Denied/);
    await assert.rejects(() => broker.handle({ name: 'editFile', args: { path: 'o.txt', find: 'guess', replace: 'x' } }), /Denied/, 'a wrong guess gives the same answer as a right one');
  });
});
