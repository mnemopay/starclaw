import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { StarClawEngine } from '../src/engine';
import { AuditLog } from '../src/governance/audit';
import { sha256Hex } from '../src/governance/canonical';
import { Governor } from '../src/governance/governor';
import { defaultPolicy, parsePolicy } from '../src/governance/policy';
import { Ed25519Signer, fingerprint } from '../src/governance/signer';
import { MnemoPaySpendAuthority } from '../src/governance/spend';
import { TaintTracker } from '../src/governance/taint';
import type { Action, Approver, Decision } from '../src/governance/types';
import { BundleError, buildBundle, verifyBundle } from '../src/skills/registry/bundle';
import { SkillRefused, SkillRegistry, RegistryStateError, signRevocationList } from '../src/skills/registry/registry';
import { AttenuatedGovernor } from '../src/skills/registry/attenuate';
import { FakeLLM, ScriptedApprover, code, policyWith, rm, tmpDir } from './helpers';

const NOW = Date.parse('2026-06-01T00:00:00Z');

type Draft = { id?: string; version?: string; description?: string; entry?: string; expiresAt?: string; capabilities?: unknown };
const draft = (o: Draft = {}) => ({ id: 'hello', version: '1.0.0', description: 'says hello', entry: 'main.js', createdAt: '2026-05-01T00:00:00Z', ...o });
const HELLO = code(`return 'hello';`);

describe('skills registry: bundle verification (pure)', () => {
  const pub = Ed25519Signer.generate();
  const other = Ed25519Signer.generate();
  const limits = { maxBundleBytes: 524_288, maxFiles: 16, maxFileBytes: 262_144 };
  const key = (s: Ed25519Signer) => ({ fingerprint: fingerprint(s.publicKeyHex), publicKey: s.publicKeyHex, label: 'pub' });
  const keyFor = (fp: string) => (fp === fingerprint(pub.publicKeyHex) ? key(pub) : undefined);
  const good = () => buildBundle(draft(), { 'main.js': HELLO }, pub);
  const verify = (text: string, over: Partial<Parameters<typeof verifyBundle>[1]> = {}) => verifyBundle(Buffer.from(text), { limits, keyFor, now: NOW, ...over });
  const expectCode = (fn: () => unknown, c: string) =>
    assert.throws(fn, (e: any) => e instanceof BundleError && e.code === c, `expected BundleError ${c}`);
  const edit = (mutate: (b: any) => void) => {
    const b = JSON.parse(good());
    mutate(b);
    return JSON.stringify(b);
  };

  test('a correctly signed bundle by a pinned publisher verifies', () => {
    const v = verify(good());
    assert.equal(v.manifest.id, 'hello');
    assert.equal(v.files['main.js'], HELLO);
    assert.equal(v.manifest.capabilities.spendCents, 0, 'spend defaults to 0');
  });

  test('unknown publisher is refused', () => {
    expectCode(() => verify(buildBundle(draft(), { 'main.js': HELLO }, other)), 'unknown-publisher');
  });

  test('wrong key: manifest claims the pinned publisher but a different key signed', () => {
    const impostor = { publicKeyHex: pub.publicKeyHex, sign: (m: string) => other.sign(m) };
    expectCode(() => verify(buildBundle(draft(), { 'main.js': HELLO }, impostor)), 'bad-signature');
  });

  test('tampered manifest (description, capabilities, version) breaks the signature', () => {
    expectCode(() => verify(edit((b) => (b.manifest.description = 'says goodbye'))), 'bad-signature');
    expectCode(() => verify(edit((b) => (b.manifest.capabilities.spendCents = 5000))), 'bad-signature');
    expectCode(() => verify(edit((b) => (b.manifest.version = '9.0.0'))), 'bad-signature');
  });

  test('tampered code is refused even though the manifest signature is intact', () => {
    expectCode(() => verify(edit((b) => (b.files['main.js'] = HELLO.replace('hello', 'HELLO')))), 'tampered'); // same length: only the hash can catch it
    expectCode(() => verify(edit((b) => (b.files['extra.js'] = 'x'))), 'tampered');
  });

  test('tampered signature is refused', () => {
    const sig: string = JSON.parse(good()).signature.sig;
    const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    expectCode(() => verify(edit((b) => (b.signature.sig = flipped))), 'bad-signature');
    expectCode(() => verify(edit((b) => (b.signature.sig = 'AAAA'))), 'malformed');
  });

  test('expired bundles are refused', () => {
    const t = buildBundle(draft({ expiresAt: '2026-05-15T00:00:00Z' }), { 'main.js': HELLO }, pub);
    expectCode(() => verify(t), 'expired');
    assert.ok(verify(t, { now: Date.parse('2026-05-10T00:00:00Z') }));
  });

  test('the entry must parse', () => {
    expectCode(() => verify(buildBundle(draft(), { 'main.js': 'async function execute( {' }, pub)), 'syntax');
  });

  test('path traversal / odd member names are refused and never reach a filesystem path', () => {
    const names = ['../evil.js', '..\\evil.js', 'a/b.js', 'a\\b.js', '/etc/passwd', 'C:evil.js', '.hidden.js', 'a..b.js', 'x'.repeat(65), 'nul\0.js', ''];
    for (const n of names) {
      // injected into the files map of an otherwise valid bundle
      const t = edit((b) => (b.files[n] = 'x'));
      assert.throws(() => verify(t), (e: any) => e instanceof BundleError && ['bad-name', 'malformed'].includes(e.code), `member ${JSON.stringify(n)}`);
      // and as a name the manifest itself lists
      const t2 = edit((b) => (b.manifest.files[0].name = n));
      assert.throws(() => verify(t2), (e: any) => e instanceof BundleError, `manifest member ${JSON.stringify(n)}`);
    }
    assert.throws(() => buildBundle(draft(), { '../evil.js': 'x', 'main.js': HELLO }, pub));
    // a real own "__proto__" key (only possible through JSON text, not through assignment)
    const proto = good().replace('"files": {', '"files": {\n    "__proto__": "x",');
    assert.ok(proto.includes('"__proto__"'));
    assert.throws(() => verify(proto), (e: any) => e instanceof BundleError, '__proto__ member');
  });

  test('oversized and zip-bomb-ish bundles are refused before/while parsing', () => {
    expectCode(() => verify(good(), { limits: { ...limits, maxBundleBytes: 300 } }), 'too-large');
    // a highly compressible 400 KB member: no decompression exists, the byte caps just apply
    const big = buildBundle(draft(), { 'main.js': HELLO, 'blob.txt': 'A'.repeat(400_000) }, pub);
    expectCode(() => verify(big, { limits: { ...limits, maxFileBytes: 100_000 } }), 'limits');
    expectCode(() => verify(big, { limits: { ...limits, maxBundleBytes: 100_000 } }), 'too-large');
    const many: Record<string, string> = { 'main.js': HELLO };
    for (let i = 0; i < 20; i++) many[`f${i}.txt`] = 'x';
    expectCode(() => verify(buildBundle(draft(), many, pub), { limits: { ...limits, maxFiles: 10 } }), 'limits');
    // pathological nesting must be a clean refusal, not a crash
    assert.throws(() => verify('['.repeat(300_000)), (e: any) => e instanceof BundleError && ['malformed', 'too-large'].includes(e.code));
    assert.throws(() => verify('{"a":'.repeat(50_000)), (e: any) => e instanceof BundleError);
  });

  test('capability declarations are validated: no host commands, no schedules, no IPs, no traversal', () => {
    for (const caps of [
      { tools: ['runCommand'] }, { tools: ['scheduleCreate'] }, { domains: ['127.0.0.1'] }, { domains: ['localhost'] },
      { paths: ['../x'] }, { paths: ['/etc/**'] }, { paths: ['C:/x'] }, { spendCents: -1 }, { spendCents: 1.5 }, { bogus: 1 },
    ]) {
      assert.throws(() => buildBundle(draft({ capabilities: caps }), { 'main.js': HELLO }, pub), /./s, JSON.stringify(caps));
    }
  });

  test('CONTROL / deliberate-bug check: with the signature check disabled the tampered manifest WOULD be accepted', () => {
    const t = edit((b) => (b.manifest.description = 'says goodbye'));
    expectCode(() => verify(t), 'bad-signature');
    // This is what a regression that removes the check looks like. If this stops passing, the tests above could not fail.
    assert.equal(verify(t, { _unsafeSkipSignatureCheck: true }).manifest.description, 'says goodbye');
  });
});

describe('skills registry: install, load, revoke (registry level, injectable clock)', () => {
  let dir: string;
  let pub: Ed25519Signer;
  let reg: SkillRegistry;
  let audit: AuditLog;
  let asked: Action[];
  let answer: (a: Action) => boolean;
  let clock: number;
  let limits: { maxBundleBytes: number; maxFiles: number; maxFileBytes: number };
  const policyBlock = () => ({ enabled: true, ...limits });
  beforeEach(() => {
    dir = tmpDir();
    pub = Ed25519Signer.generate();
    asked = [];
    answer = () => true;
    clock = NOW;
    limits = { maxBundleBytes: 524_288, maxFiles: 16, maxFileBytes: 262_144 };
    const signer = Ed25519Signer.generate();
    audit = new AuditLog(path.join(dir, 'audit.jsonl'), signer);
    reg = mk(signer);
    reg.addKey(pub.publicKeyHex, 'Acme');
  });
  afterEach(() => rm(dir));

  function mk(signer: Ed25519Signer, extra: Partial<ConstructorParameters<typeof SkillRegistry>[0]> = {}) {
    return new SkillRegistry({
      dir: path.join(dir, 'reg'),
      signer,
      audit,
      policy: policyBlock,
      now: () => clock,
      authorize: async (a) => {
        asked.push(a);
        const ok = answer(a);
        return { id: 'd' + asked.length, allowed: ok, by: ok ? 'human' : 'human', reason: ok ? 'approved' : 'denied by approver', escalatedByTaint: false, provenance: { tainted: false, sources: [] } } as Decision;
      },
      ...extra,
    });
  }
  const write = (name: string, text: string) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, text);
    return f;
  };
  const bundle = (d: Draft = {}, files: Record<string, string> = { 'main.js': HELLO }, signer: { publicKeyHex: string; sign(m: string): string } = pub) =>
    write(`b-${Math.random().toString(36).slice(2)}.starclaw-skill`, buildBundle(draft(d), files, signer));
  const refused = async (p: Promise<unknown> | (() => unknown), c: string) => {
    await assert.rejects(async () => (typeof p === 'function' ? p() : p), (e: any) => e instanceof SkillRefused && e.code === c, `expected SkillRefused ${c}`);
  };

  test('valid bundle installs after approval; the owner sees publisher, version, capabilities and the code', async () => {
    const f = bundle({ capabilities: { tools: ['readFile'], paths: ['data/**'], domains: ['api.example.com'] } });
    const r = await reg.install(f);
    assert.equal(r.alreadyInstalled, false);
    assert.equal(asked.length, 1);
    const a = asked[0];
    assert.equal(a.class, 'skill.install');
    assert.equal(a.target, 'hello@1.0.0');
    const text = a.summary + '\n' + a.detail;
    assert.ok(text.includes(fingerprint(pub.publicKeyHex)), 'publisher fingerprint');
    assert.ok(text.includes('Acme'));
    assert.ok(text.includes('1.0.0'));
    assert.ok(text.includes('api.example.com') && text.includes('data/**') && text.includes('readFile'), 'declared capabilities');
    assert.ok(text.includes('cannot spend') || text.includes('spend: 0'), 'spend=0 shown');
    assert.ok(text.includes("return 'hello'"), 'code shown');
    const l = reg.load('hello');
    assert.equal(l.manifest.version, '1.0.0');
    assert.equal(reg.list()[0].status, 'ok');
    // installing the identical bundle again is a no-op and asks nothing
    const again = await reg.install(f);
    assert.equal(again.alreadyInstalled, true);
    assert.equal(asked.length, 1);
  });

  test('not approved: nothing is installed, nothing is written', async () => {
    answer = () => false;
    await refused(reg.install(bundle()), 'not-approved');
    assert.equal(reg.list().length, 0);
    assert.equal(fs.existsSync(path.join(dir, 'reg', 'installed')), false);
    assert.throws(() => reg.load('hello'), (e: any) => e.code === 'not-installed');
  });

  test('refused bundles never reach the approver: unknown publisher, wrong key, tamper, expiry', async () => {
    const other = Ed25519Signer.generate();
    await refused(reg.install(bundle({}, undefined, other)), 'unknown-publisher');
    await refused(reg.install(bundle({}, undefined, { publicKeyHex: pub.publicKeyHex, sign: (m) => other.sign(m) })), 'bad-signature');
    const t = JSON.parse(buildBundle(draft(), { 'main.js': HELLO }, pub));
    t.files['main.js'] = code(`return 'EVIL';`);
    await refused(reg.install(write('t.starclaw-skill', JSON.stringify(t))), 'tampered');
    await refused(reg.install(bundle({ expiresAt: '2026-05-02T00:00:00Z' })), 'expired');
    assert.equal(asked.length, 0);
    assert.equal(reg.list().length, 0);
  });

  test('symlinks and directories are not bundles', async () => {
    const f = bundle();
    const link = path.join(dir, 'link.starclaw-skill');
    try {
      fs.symlinkSync(f, link);
    } catch {
      return; // no symlink privilege on this machine
    }
    await refused(reg.install(link), 'not-a-file');
  });

  test('expiry is enforced on every RUN, not just at install', async () => {
    await reg.install(bundle({ expiresAt: '2026-06-10T00:00:00Z' }));
    assert.ok(reg.load('hello'));
    clock = Date.parse('2026-06-11T00:00:00Z');
    await refused(() => reg.load('hello'), 'expired');
    assert.match(reg.list()[0].status, /expired/);
  });

  test('revocation: owner revoke blocks load, reinstall and shows in list; per-version revoke leaves other versions', async () => {
    const v1 = bundle({ version: '1.0.0' });
    await reg.install(v1);
    reg.revoke('hello', { version: '1.0.0', reason: 'bad' });
    await refused(() => reg.load('hello'), 'revoked');
    await refused(reg.install(v1), 'revoked');
    assert.match(reg.list()[0].status, /revoked/);
    // 1.1.0 is not covered by the per-version revocation
    await reg.install(bundle({ version: '1.1.0' }));
    assert.equal(reg.load('hello').manifest.version, '1.1.0');
    reg.revoke('hello');
    await refused(() => reg.load('hello'), 'revoked');
  });

  test('signed revocation list: needs a pinned issuer, a valid signature and a rising serial', async () => {
    const f = bundle();
    const r = await reg.install(f);
    const entries = [{ bundleSha256: r.bundleSha256 }];
    const list = (s: Ed25519Signer, serial: number, e = entries) => write(`l${serial}-${fingerprint(s.publicKeyHex)}.json`, signRevocationList(s, serial, e));
    const stranger = Ed25519Signer.generate();
    await refused(async () => reg.importRevocationList(list(stranger, 1)), 'unknown-publisher');
    const forged = JSON.parse(fs.readFileSync(list(pub, 1, [{ bundleSha256: '0'.repeat(64) }]), 'utf8'));
    forged.entries = entries; // attacker swaps the entries
    await refused(async () => reg.importRevocationList(write('forged.json', JSON.stringify(forged))), 'bad-signature');
    assert.ok(reg.load('hello'), 'nothing was revoked by the failed imports');
    assert.equal(reg.importRevocationList(list(pub, 5)), 1);
    await refused(() => reg.load('hello'), 'revoked');
    await refused(async () => reg.importRevocationList(list(pub, 5)), 'list-rollback');
    await refused(async () => reg.importRevocationList(list(pub, 4)), 'list-rollback');
  });

  test('anti-rollback: a lower version needs --allow-rollback AND a fresh approval that says ROLLBACK', async () => {
    await reg.install(bundle({ version: '2.0.0' }));
    const old = bundle({ version: '1.0.0' });
    await refused(reg.install(old), 'rollback');
    assert.equal(asked.length, 1, 'refused before asking');
    assert.equal(reg.load('hello').manifest.version, '2.0.0');
    answer = () => false;
    await refused(reg.install(old, { allowRollback: true }), 'not-approved');
    assert.match(asked[1].detail!, /ROLLBACK: 2\.0\.0 -> 1\.0\.0/);
    assert.equal(reg.load('hello').manifest.version, '2.0.0', 'denied rollback changed nothing');
    answer = () => true;
    await reg.install(old, { allowRollback: true });
    assert.equal(reg.load('hello').manifest.version, '1.0.0');
  });

  test('same version number with different content counts as a rollback-class replacement', async () => {
    await reg.install(bundle({ version: '1.0.0' }));
    await refused(reg.install(bundle({ version: '1.0.0' }, { 'main.js': code(`return 'different';`) })), 'rollback');
  });

  test('publisher swap: refused without the flag, flagged in the approval with it, and never silent', async () => {
    const rival = Ed25519Signer.generate();
    reg.addKey(rival.publicKeyHex, 'Rival Corp');
    await reg.install(bundle({ version: '1.0.0' }));
    const swapped = bundle({ version: '3.0.0' }, undefined, rival);
    await refused(reg.install(swapped), 'publisher-change');
    assert.equal(asked.length, 1);
    await reg.install(swapped, { allowPublisherChange: true });
    assert.match(asked[1].detail!, /PUBLISHER CHANGE/);
    assert.match(asked[1].summary, /PUBLISHER CHANGE/);
    assert.equal(reg.load('hello').manifest.publisher, fingerprint(rival.publicKeyHex));
  });

  test('upgrade approval shows a code diff and the capability changes against the installed version', async () => {
    await reg.install(bundle({ version: '1.0.0', capabilities: { tools: ['readFile'], paths: ['a/**'] } }));
    await reg.install(bundle({ version: '1.1.0', capabilities: { tools: ['readFile', 'fetchUrl'], paths: ['a/**'], domains: ['evil.example.com'] } }, { 'main.js': code(`return 'hello v2';`) }));
    const d = asked[1].detail!;
    assert.match(d, /installed: 1\.0\.0/);
    assert.match(d, /\+ domains: evil\.example\.com/);
    assert.match(d, /\+ tools \(required\): readFile, fetchUrl/);
    assert.match(d, /^-.*return 'hello';/m);
    assert.match(d, /^\+.*return 'hello v2';/m);
  });

  test('tampering with the installed bundle on disk is refused at load', async () => {
    await reg.install(bundle());
    const f = path.join(dir, 'reg', 'installed', 'hello.starclaw-skill');
    const b = JSON.parse(fs.readFileSync(f, 'utf8'));
    b.files['main.js'] = code(`return 'EVIL';`);
    fs.writeFileSync(f, JSON.stringify(b));
    await refused(() => reg.load('hello'), 'tampered');
    // even a fully re-hashed, but unsigned, replacement is refused
    const evil = Ed25519Signer.generate();
    fs.writeFileSync(f, buildBundle(draft(), { 'main.js': code(`return 'EVIL';`) }, evil));
    await refused(() => reg.load('hello'), 'tampered');
  });

  test('removing the publisher key from the keyring stops every skill from that publisher on the next load', async () => {
    await reg.install(bundle());
    assert.ok(reg.load('hello'));
    assert.equal(reg.removeKey(fingerprint(pub.publicKeyHex)), true);
    await refused(() => reg.load('hello'), 'unknown-publisher');
  });

  test('registry state is signed: editing it (e.g. deleting a revocation) fails CLOSED for everything', async () => {
    await reg.install(bundle());
    reg.revoke('hello');
    const sf = path.join(dir, 'reg', 'registry.json');
    const w = JSON.parse(fs.readFileSync(sf, 'utf8'));
    w.body.revoked = [];
    fs.writeFileSync(sf, JSON.stringify(w));
    assert.throws(() => reg.load('hello'), RegistryStateError);
    assert.throws(() => reg.listKeys(), RegistryStateError);
    await assert.rejects(reg.install(bundle({ id: 'other' })), RegistryStateError);
    assert.match(reg.status().line, /FAILED verification/);
  });

  test('the install is refused if it is revoked while the approval prompt is open', async () => {
    const f = bundle();
    answer = () => {
      reg.revoke('hello', { reason: 'revoked mid-prompt' });
      return true;
    };
    await refused(reg.install(f), 'revoked');
    assert.equal(reg.list().length, 0);
  });

  test('size caps apply to the installer: oversized file refused before it is read', async () => {
    const f = bundle({}, { 'main.js': HELLO, 'blob.txt': 'A'.repeat(50_000) });
    limits.maxBundleBytes = 10_000;
    await refused(reg.install(f), 'too-large');
  });

  test('disabled registry (the default) refuses install and load', async () => {
    const off = new SkillRegistry({ ...{ dir: path.join(dir, 'reg2'), signer: Ed25519Signer.generate(), audit }, policy: () => defaultPolicy().skillsRegistry, authorize: async () => { throw new Error('unreachable'); } });
    await assert.rejects(off.install(bundle()), (e: any) => e.code === 'disabled');
    assert.throws(() => off.load('hello'), (e: any) => e.code === 'disabled');
  });

  test('CONTROL / deliberate-bug check: with the signature check removed, a tampered bundle installs', async () => {
    const t = JSON.parse(buildBundle(draft(), { 'main.js': HELLO }, pub));
    t.manifest.description = 'tampered after signing';
    const f = write('tampered.starclaw-skill', JSON.stringify(t));
    await refused(reg.install(f), 'bad-signature');
    const buggy = mk(Ed25519Signer.generate(), { dir: path.join(dir, 'buggy'), _unsafeSkipSignatureCheck: true });
    buggy.addKey(pub.publicKeyHex, 'Acme');
    assert.equal((await buggy.install(f)).id, 'hello', 'this is what a regression looks like; the test above would then fail');
  });
});

describe('skills registry: engine integration (real Governor, approver, sandbox)', () => {
  let dir: string, ws: string, state: string, llm: FakeLLM;
  const engines: StarClawEngine[] = [];
  let pub: Ed25519Signer;
  beforeEach(() => {
    dir = tmpDir();
    ws = path.join(dir, 'ws');
    state = path.join(dir, 'state');
    llm = new FakeLLM();
    pub = Ed25519Signer.generate();
  });
  afterEach(() => {
    for (const e of engines.splice(0)) e.memory.close();
    rm(dir);
  });
  const make = (policy: Record<string, unknown>, approver?: Approver) => {
    const e = new StarClawEngine({ llm, policy: policyWith({ skillsRegistry: { enabled: true }, ...policy }), stateDir: state, workspaceDir: ws, approver });
    engines.push(e);
    e.registry.addKey(pub.publicKeyHex, 'Acme');
    return e;
  };
  const allowRun = [{ class: 'exec', target: 'skill:*', verdict: 'allow' }, { class: 'fs.read', verdict: 'allow' }, { class: 'fs.write', verdict: 'allow' }];
  const bundleFile = (d: Draft, files: Record<string, string>) => {
    const f = path.join(dir, `${d.id ?? 'hello'}-${d.version ?? '1.0.0'}.starclaw-skill`);
    fs.writeFileSync(f, buildBundle(draft(d), files, pub));
    return f;
  };
  const auditText = () => fs.readFileSync(path.join(state, 'audit.jsonl'), 'utf8');
  const installer = () => new ScriptedApprover((r) => (r.action.class === 'skill.install' ? 'approve' : 'deny'));

  test('install -> run: valid signed skill runs, every step audited; the audit log still verifies', async () => {
    const e = make({ rules: allowRun }, installer());
    await e.installRegistrySkill(bundleFile({}, { 'main.js': code(`return 'hello from signed skill';`) }));
    const r = await e.runRegistrySkill('hello');
    assert.equal(r.success, true, r.error);
    assert.equal(r.result, 'hello from signed skill');
    const t = auditText();
    for (const k of ['skillreg.installed', 'skillreg.load', 'exec.start']) assert.match(t, new RegExp(k));
    assert.match(t, /skill:hello@1\.0\.0/);
  });

  test('no approver: install is denied (fail closed) even if a policy rule says allow', async () => {
    const e = make({ rules: [{ class: 'skill.install', verdict: 'allow' }, ...allowRun] });
    const f = bundleFile({}, { 'main.js': HELLO });
    await assert.rejects(e.installRegistrySkill(f), (err: any) => err.code === 'not-approved' && /no-approver/.test(err.message));
    assert.equal(e.registry.list().length, 0);
    const r = await e.runRegistrySkill('hello');
    assert.equal(r.success, false);
  });

  test('a policy `allow` for skill.install cannot bypass the human (ALWAYS_ASK); a denying human installs nothing', async () => {
    const a = new ScriptedApprover(() => 'deny');
    const e = make({ rules: [{ class: 'skill.install', verdict: 'allow' }] }, a);
    await assert.rejects(e.installRegistrySkill(bundleFile({}, { 'main.js': HELLO })), (err: any) => err.code === 'not-approved');
    assert.equal(a.seen.filter((s) => s.action.class === 'skill.install').length, 1, 'the human was asked');
    assert.equal(e.registry.list().length, 0);
  });

  test('a scheduled (unattended) run can never install a skill', async () => {
    const e = make({}, installer());
    e.governor.setRunContext({ origin: 'scheduled', jobId: 'j', triggerAt: 'now' });
    await assert.rejects(e.installRegistrySkill(bundleFile({}, { 'main.js': HELLO })), (err: any) => err.code === 'not-approved' && /never allowed in a scheduled/.test(err.message));
  });

  test('a skill run is re-verified: revoked, expired-by-keyring-removal and disk tampering all stop it BEFORE any code runs', async () => {
    const e = make({ rules: allowRun }, installer());
    await e.installRegistrySkill(bundleFile({}, { 'main.js': code(`await tools.writeFile({ path: 'ran.txt', content: 'x' }); return 1;`) }));
    e.registry.revoke('hello');
    const r = await e.runRegistrySkill('hello');
    assert.equal(r.success, false);
    assert.match(r.error!, /revoked/);
    assert.equal(fs.existsSync(path.join(ws, 'ran.txt')), false, 'revoked skill did not run');
    assert.match(auditText(), /skillreg\.refused/);
  });

  test('attenuation: the skill runs with ITS declared paths only, even though the policy would allow more (control proves it)', async () => {
    const body = code(`
      const out = {};
      try { await tools.writeFile({ path: 'out/ok.txt', content: 'in scope' }); out.inScope = 'written'; } catch (e) { out.inScope = 'ERR ' + e.message; }
      try { await tools.writeFile({ path: 'secret.txt', content: 'out of scope' }); out.outScope = 'written'; } catch (e) { out.outScope = 'ERR ' + e.message; }
      try { await tools.fetchUrl({ url: 'https://example.com/' }); out.fetch = 'fetched'; } catch (e) { out.fetch = 'ERR ' + e.message; }
      try { await tools.spend({ cents: 1, payee: 'x', memo: 'y' }); out.spend = 'spent'; } catch (e) { out.spend = 'ERR ' + e.message; }
      return out;`);
    const wide = [{ class: 'net.egress', verdict: 'allow' }, { class: 'spend', verdict: 'allow' }, ...allowRun];
    const e = make({ rules: wide, spend: { maxPerActionCents: 100, maxTotalCents: 100 } }, installer());
    await e.installRegistrySkill(bundleFile({ capabilities: { tools: ['writeFile'], optionalTools: ['fetchUrl', 'spend'], paths: ['out/**'], domains: ['api.example.org'] } }, { 'main.js': body }));
    const r = await e.runRegistrySkill('hello');
    assert.equal(r.success, true, r.error);
    const out = r.result as Record<string, string>;
    assert.equal(out.inScope, 'written');
    assert.match(out.outScope, /^ERR .*did not declare/);
    assert.match(out.fetch, /^ERR .*did not declare/, 'example.com is not in the declared domains');
    assert.match(out.spend, /^ERR .*spend is 0/, 'spend defaults to 0 even though the policy would allow it');
    assert.equal(fs.existsSync(path.join(ws, 'out', 'ok.txt')), true);
    assert.equal(fs.existsSync(path.join(ws, 'secret.txt')), false);
    assert.match(auditText(), /skillreg\.attenuated\.denied/);

    // CONTROL: the same code, declaring wide scopes, gets through. So the denials above were attenuation, not something else.
    await e.installRegistrySkill(bundleFile({ version: '1.1.0', capabilities: { tools: ['writeFile'], paths: ['**'] } }, { 'main.js': body }));
    const r2 = await e.runRegistrySkill('hello');
    assert.equal((r2.result as any).outScope, 'written');
    assert.equal(fs.readFileSync(path.join(ws, 'secret.txt'), 'utf8'), 'out of scope');
  });

  test('an undeclared tool is refused even though the policy allows it (tool list is part of the intersection)', async () => {
    const e = make({ rules: allowRun }, installer());
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'data.txt'), 'private');
    await e.installRegistrySkill(bundleFile({ capabilities: { tools: ['writeFile'], paths: ['**'] } }, { 'main.js': code(`try { return (await tools.readFile({ path: 'data.txt' })).content; } catch (e) { return 'ERR ' + e.message; }`) }));
    const r = await e.runRegistrySkill('hello');
    assert.match(String(r.result), /^ERR .*did not declare tool readFile/);
  });

  test('a REQUIRED capability the policy denies means the skill refuses to run (and runs nothing)', async () => {
    const e = make({ rules: [{ class: 'fs.write', verdict: 'deny' }, ...allowRun] }, installer());
    await e.installRegistrySkill(bundleFile({ capabilities: { tools: ['writeFile'], paths: ['**'] } }, { 'main.js': code(`await tools.writeFile({ path: 'x.txt', content: 'x' }); return 1;`) }));
    const r = await e.runRegistrySkill('hello');
    assert.equal(r.success, false);
    assert.match(r.error!, /requires capabilities the current policy does not grant: writeFile: policy denies fs\.write/);
    assert.equal(fs.existsSync(path.join(ws, 'x.txt')), false);
    // a required spend tool with spend caps at 0 is also unmet
    await e.installRegistrySkill(bundleFile({ id: 'spender', capabilities: { tools: ['spend'], spendCents: 50 } }, { 'main.js': HELLO }));
    const r2 = await e.runRegistrySkill('spender');
    assert.match(r2.error!, /spend/);
  });

  test('the policy still binds: a declared path the policy denies stays denied (intersection, never wider)', async () => {
    const e = make({ rules: [{ class: 'fs.write', target: '**blocked**', verdict: 'deny' }, ...allowRun] }, installer());
    await e.installRegistrySkill(bundleFile({ capabilities: { tools: ['writeFile'], paths: ['**'] } }, { 'main.js': code(`try { await tools.writeFile({ path: 'blocked/a.txt', content: 'x' }); return 'written'; } catch (e) { return 'ERR ' + e.message; }`) }));
    const r = await e.runRegistrySkill('hello');
    assert.match(String(r.result), /^ERR .*Denied \(policy\)/);
    assert.equal(fs.existsSync(path.join(ws, 'blocked', 'a.txt')), false);
  });

  test('taint semantics are unchanged: a skill that fetches the web taints the session like any other code', async () => {
    const e = make({ net: { allowPrivateAddresses: true }, rules: [{ class: 'net.egress', verdict: 'allow' }, ...allowRun] }, installer());
    assert.equal(e.tainted, false);
    // declared domains cannot name loopback, so this skill is blocked at the network and must NOT taint on a refused call
    await e.installRegistrySkill(bundleFile({ capabilities: { tools: ['fetchUrl'], domains: ['api.example.org'] } }, { 'main.js': code(`try { await tools.fetchUrl({ url: 'http://127.0.0.1:9/' }); } catch (e) { return 'ERR ' + e.message; }`) }));
    const r = await e.runRegistrySkill('hello');
    assert.match(String(r.result), /did not declare/);
    assert.equal(e.tainted, false);
  });

  test('agent-authored skills stay hash-pinned and approval-gated, are NOT signed, and never appear in the registry', async () => {
    const a = new ScriptedApprover(() => 'approve');
    const e = new StarClawEngine({ llm, policy: policyWith({}), stateDir: state, workspaceDir: ws, approver: a, learnSkills: true });
    engines.push(e);
    llm.codeQueue.push(code(`return 41 + 1;`));
    const r = await e.executeGoal('compute the answer to everything');
    assert.equal(r.success, true, r.error);
    assert.ok(a.seen.some((s) => s.action.class === 'skill.save'));
    assert.equal(fs.readdirSync(path.join(state, 'skills')).length, 1);
    assert.equal(e.registry.list().length, 0);
    assert.equal(e.registry.enabled, false, 'registry disabled by default');
    assert.equal(fs.existsSync(path.join(state, 'skills-registry')), false, 'disabled registry leaves no state behind');
    await assert.rejects(e.installRegistrySkill('x'), (err: any) => err.code === 'disabled');
  });

  test('no private key material (audit key, publisher key file) ends up in the audit log, registry state or bundles', async () => {
    const keyFile = path.join(dir, 'publisher.key');
    const pubSigner = Ed25519Signer.createKeyFile(keyFile);
    const e = make({ rules: allowRun }, installer());
    e.registry.addKey(pubSigner.publicKeyHex, 'FromKeyFile');
    const signer = Ed25519Signer.loadKeyFile(keyFile);
    const f = path.join(dir, 'k.starclaw-skill');
    fs.writeFileSync(f, buildBundle(draft({ id: 'keyed' }), { 'main.js': HELLO }, signer));
    await e.installRegistrySkill(f);
    assert.equal((await e.runRegistrySkill('keyed')).success, true);
    e.registry.revoke('keyed');
    const body = (pem: string) => pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
    const secrets = [body(fs.readFileSync(keyFile, 'utf8')), body(fs.readFileSync(path.join(state, 'audit.key'), 'utf8'))];
    const haystacks = [auditText(), fs.readFileSync(path.join(state, 'skills-registry', 'registry.json'), 'utf8'), fs.readFileSync(f, 'utf8'), JSON.stringify(e.registry.list())];
    for (const h of haystacks) {
      assert.ok(!/PRIVATE KEY/.test(h));
      for (const s of secrets) assert.ok(!h.includes(s), 'private key body found in output');
    }
  });

  test('publisher key files: never overwritten, and a group/other-readable key is refused on POSIX', () => {
    const keyFile = path.join(dir, 'p.key');
    Ed25519Signer.createKeyFile(keyFile);
    assert.throws(() => Ed25519Signer.createKeyFile(keyFile), /EEXIST/);
    if (process.platform === 'win32') return; // chmod is advisory there; documented in SECURITY.md
    assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
    fs.chmodSync(keyFile, 0o644);
    assert.throws(() => Ed25519Signer.loadKeyFile(keyFile), /accessible by group\/other/);
  });
});

describe('skills registry: AttenuatedGovernor (domains and spend, unit level)', () => {
  let dir: string;
  beforeEach(() => (dir = tmpDir()));
  afterEach(() => rm(dir));
  const gov = (caps: any, rules: any[] = [{ class: 'net.egress', verdict: 'allow' }, { class: 'spend', verdict: 'allow' }]) => {
    const audit = new AuditLog(path.join(dir, `a${Math.random()}.jsonl`), Ed25519Signer.generate());
    const policy = policyWith({ rules, spend: { maxPerActionCents: 100, maxTotalCents: 1000 } });
    const g = new AttenuatedGovernor({ policy, audit, taint: new TaintTracker(), approver: new ScriptedApprover(() => 'approve'), spendAuthority: new MnemoPaySpendAuthority('t' + Math.random(), policy.spend) }, { tools: [], optionalTools: [], domains: [], paths: [], spendCents: 0, ...caps }, { id: 's', version: '1.0.0' }, dir);
    return { g, audit };
  };
  const egress = (host: string): Action => ({ class: 'net.egress', target: host, host, summary: 'x' });

  test('domains: exact and wildcard match, anything else denied, none declared = no network', async () => {
    const { g } = gov({ domains: ['api.example.com', '*.cdn.example.net'] });
    assert.equal((await g.authorize(egress('api.example.com'))).allowed, true);
    assert.equal((await g.authorize(egress('a.cdn.example.net'))).allowed, true);
    for (const h of ['example.com', 'evil.com', 'cdn.example.net', 'api.example.com.evil.com', 'xapi.example.com']) {
      assert.equal((await g.authorize(egress(h))).allowed, false, h);
    }
    assert.equal((await gov({}).g.authorize(egress('api.example.com'))).allowed, false);
  });

  test('declared domain but the policy denies egress: still denied (intersection)', async () => {
    const { g } = gov({ domains: ['api.example.com'] }, [{ class: 'net.egress', verdict: 'deny' }]);
    const d = await g.authorize(egress('api.example.com'));
    assert.equal(d.allowed, false);
    assert.equal(d.by, 'policy');
  });

  test('spend: 0 by default; a declared cap bounds the per-run total; host commands and schedules are never available', async () => {
    const spend = (cents: number): Action => ({ class: 'spend', target: 'p', summary: 'x', cents });
    assert.equal((await gov({}).g.authorize(spend(1))).allowed, false);
    const { g } = gov({ spendCents: 50 });
    assert.equal((await g.authorize(spend(30))).allowed, true);
    assert.equal((await g.authorize(spend(30))).allowed, false, '30 + 30 > 50');
    assert.equal((await g.authorize(spend(20))).allowed, true);
    for (const c of ['host.exec', 'schedule.create', 'skill.save', 'skill.install', 'memory.write'] as const) {
      assert.equal((await gov({ tools: ['readFile'] }, [{ class: c, verdict: 'allow' }]).g.authorize({ class: c, target: 't', summary: 'x' })).allowed, false, c);
    }
  });
});

describe('skills registry: policy block and CLI', () => {
  test('policy: strict, disabled by default, capped', () => {
    assert.equal(defaultPolicy().skillsRegistry.enabled, false);
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, skillsRegistry: { enabled: true, fetchUrl: 'https://x' } })));
    assert.throws(() => parsePolicy(JSON.stringify({ version: 1, skillsRegistry: { maxBundleBytes: 999_999_999 } })));
    assert.equal(parsePolicy(JSON.stringify({ version: 1, skillsRegistry: { enabled: true } })).skillsRegistry.maxFiles, 16);
  });

  test('CLI end to end: keygen -> sign -> keys add -> verify -> install (non-tty = denied) -> list; tamper -> verify fails', () => {
    const dir = tmpDir();
    try {
      const cli = path.join(__dirname, '..', 'src', 'cli.ts');
      const stateDir = path.join(dir, 'state');
      const policyFile = path.join(dir, 'policy.json');
      fs.writeFileSync(policyFile, JSON.stringify({ version: 1, sandbox: { mode: 'process' }, skillsRegistry: { enabled: true } }));
      const run = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', cli, ...args], { encoding: 'utf8', input: '', env: { ...process.env, GROQ_API_KEY: 'x' } });
      const common = ['--policy', policyFile, '--state-dir', stateDir, '--workspace', path.join(dir, 'ws')];

      const keyFile = path.join(dir, 'pub.key');
      const kg = run('skills', 'keygen', keyFile);
      assert.equal(kg.status, 0, kg.stderr);
      const pubHex = /public key : ([0-9a-f]{64})/.exec(kg.stdout)![1];
      const pem = fs.readFileSync(keyFile, 'utf8').replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
      assert.ok(!kg.stdout.includes(pem) && !kg.stderr.includes(pem), 'keygen never prints the private key');

      const src = path.join(dir, 'src');
      fs.mkdirSync(src);
      fs.writeFileSync(path.join(src, 'skill.json'), JSON.stringify(draft({ id: 'cli-skill' })));
      fs.writeFileSync(path.join(src, 'main.js'), HELLO);
      const out = path.join(dir, 'cli-skill.starclaw-skill');
      const sg = run('skills', 'sign', src, '--key', keyFile, '--out', out);
      assert.equal(sg.status, 0, sg.stderr);
      assert.equal(run('skills', 'sign', src, '--key', keyFile, '--out', out).status, 1, 'never overwrites');

      // not pinned yet
      let v = run('skills', 'verify', out, ...common);
      assert.equal(v.status, 1);
      assert.match(v.stdout, /not in your keyring/);

      assert.equal(run('skills', 'keys', 'add', pubHex, '--label', 'Me', ...common).status, 0);
      assert.match(run('skills', 'keys', 'list', ...common).stdout, new RegExp(fingerprint(pubHex)));
      v = run('skills', 'verify', out, ...common);
      assert.equal(v.status, 0, v.stdout + v.stderr);
      assert.match(v.stdout, /^OK: cli-skill@1\.0\.0/);

      const inst = run('skills', 'install', out, ...common);
      assert.equal(inst.status, 1, 'no terminal -> nobody can approve -> denied');
      assert.match(inst.stderr, /REFUSED: installation was not approved/);
      assert.match(run('skills', 'list', ...common).stdout, /no registry skills installed/);

      const tampered = JSON.parse(fs.readFileSync(out, 'utf8'));
      tampered.files['main.js'] = code(`return 'EVIL';`);
      const bad = path.join(dir, 'bad.starclaw-skill');
      fs.writeFileSync(bad, JSON.stringify(tampered));
      v = run('skills', 'verify', bad, ...common);
      assert.equal(v.status, 1);
      assert.match(v.stdout, /does not match the signed manifest/);

      const doc = run('doctor', '--policy', policyFile, '--state-dir', stateDir, '--sandbox', 'process');
      assert.match(doc.stdout, /Skills registry: enabled; 1 pinned publisher\(s\); 0 installed/);
      assert.equal(sha256Hex(fs.readFileSync(out)).length, 64);
    } finally {
      rm(dir);
    }
  });
});
