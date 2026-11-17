import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { unifiedDiff } from '../../edit';
import { AuditLog } from '../../governance/audit';
import { canonicalize, sha256Hex } from '../../governance/canonical';
import type { Policy } from '../../governance/policy';
import { Signer, fingerprint, verifierFromHex } from '../../governance/signer';
import type { Action, Decision } from '../../governance/types';
import { BUNDLE_EXT, BundleError, BundleLimits, Capabilities, Manifest, PinnedKey, VerifiedBundle, compareVersions, verifyBundle } from './bundle';

/** Raised when the registry's own state file fails its signature: EVERYTHING is refused until the owner looks. */
export class RegistryStateError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'RegistryStateError';
  }
}
/** A skill (or install) was refused. `code` is stable for tests and audit. */
export class SkillRefused extends Error {
  constructor(public readonly code: string, msg: string) {
    super(msg);
    this.name = 'SkillRefused';
  }
}

const Fp = z.string().regex(/^[0-9a-f]{16}$/);
const Sha = z.string().regex(/^[0-9a-f]{64}$/);
const RevocationEntry = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,59}$/).optional(),
    version: z.string().regex(/^\d{1,6}\.\d{1,6}\.\d{1,6}$/).optional(),
    publisher: Fp.optional(),
    bundleSha256: Sha.optional(),
  })
  .strict()
  .refine((e) => e.id !== undefined || e.publisher !== undefined || e.bundleSha256 !== undefined, 'a revocation must name an id, a publisher or a bundle hash');
export type RevocationEntryT = z.infer<typeof RevocationEntry>;

const StateSchema = z
  .object({
    version: z.literal(1),
    serial: z.number().int().min(0),
    keys: z.array(z.object({ fingerprint: Fp, publicKey: z.string().regex(/^[0-9a-f]{64}$/), label: z.string().max(80), addedAt: z.string() }).strict()),
    installed: z.record(
      z.string(),
      z.object({ id: z.string(), version: z.string(), publisher: Fp, bundleSha256: Sha, installedAt: z.string(), approvedDecision: z.string() }).strict(),
    ),
    revoked: z.array(z.object({ entry: RevocationEntry, reason: z.string().max(200), at: z.string(), source: z.string().max(80) }).strict()),
    /** Highest serial accepted per issuer of a signed revocation list (anti-rollback of the lists themselves). */
    listSerials: z.record(z.string(), z.number().int().min(0)),
  })
  .strict();
type State = z.infer<typeof StateSchema>;

const emptyState = (): State => ({ version: 1, serial: 0, keys: [], installed: {}, revoked: [], listSerials: {} });

const STATE_DOMAIN = 'starclaw-skills-state:v1:';
const LIST_FORMAT = 'starclaw-revocations/1';
const RevocationListSchema = z
  .object({
    format: z.literal(LIST_FORMAT),
    issuer: Fp,
    serial: z.number().int().min(1),
    issuedAt: z.string(),
    entries: z.array(RevocationEntry).min(1).max(1000),
    sig: z.string().max(200),
  })
  .strict();

/** Publisher side helper: a signed revocation list that `skills revoke --list` can import. */
export function signRevocationList(signer: Signer, serial: number, entries: RevocationEntryT[], issuedAt = new Date().toISOString()): string {
  const body = { issuer: fingerprint(signer.publicKeyHex), serial, issuedAt, entries };
  const sig = signer.sign(`${LIST_FORMAT}:${canonicalize(body)}`);
  return JSON.stringify({ format: LIST_FORMAT, ...body, sig }, null, 2) + '\n';
}

export interface RegistryOptions {
  /** `<stateDir>/skills-registry`. */
  dir: string;
  /** The engine's own signer: signs the registry state so that editing it on disk fails closed. */
  signer: Signer;
  audit: AuditLog;
  policy: () => Policy['skillsRegistry'];
  /** Routed through the Governor: policy + taint + the real approver. No approver = deny. */
  authorize: (a: Action) => Promise<Decision>;
  now?: () => number;
  /** TEST-ONLY CONTROL (see verifyBundle). */
  _unsafeSkipSignatureCheck?: boolean;
}

export interface InstallOptions {
  allowRollback?: boolean;
  allowPublisherChange?: boolean;
}
export interface InstallResult {
  id: string;
  version: string;
  publisher: string;
  bundleSha256: string;
  alreadyInstalled: boolean;
}
export interface LoadedSkill {
  manifest: Manifest;
  code: string;
  files: Record<string, string>;
  bundleSha256: string;
  publisher: PinnedKey;
}

export class SkillRegistry {
  private readonly stateFile: string;
  private readonly installedDir: string;

  constructor(private readonly o: RegistryOptions) {
    this.stateFile = path.join(o.dir, 'registry.json');
    this.installedDir = path.join(o.dir, 'installed');
  }

  private now() {
    return this.o.now ? this.o.now() : Date.now();
  }
  private limits(): BundleLimits {
    const p = this.o.policy();
    return { maxBundleBytes: p.maxBundleBytes, maxFiles: p.maxFiles, maxFileBytes: p.maxFileBytes };
  }
  get enabled(): boolean {
    return this.o.policy().enabled;
  }
  private requireEnabled() {
    if (!this.enabled) throw new SkillRefused('disabled', 'the skills registry is disabled (policy skillsRegistry.enabled = false)');
  }

  // ---- signed state --------------------------------------------------------------------------------------------

  private readState(): State {
    if (!fs.existsSync(this.stateFile)) return emptyState();
    let wrapper: any;
    try {
      wrapper = JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
    } catch {
      throw new RegistryStateError('skills registry state is unreadable; refusing everything');
    }
    if (!wrapper || typeof wrapper.sig !== 'string' || !wrapper.body) throw new RegistryStateError('skills registry state is malformed; refusing everything');
    if (!this.o.signer.verify(STATE_DOMAIN + canonicalize(wrapper.body), wrapper.sig)) {
      throw new RegistryStateError('skills registry state failed its signature (edited on disk?); refusing everything');
    }
    const r = StateSchema.safeParse(wrapper.body);
    if (!r.success) throw new RegistryStateError('skills registry state has an invalid shape; refusing everything');
    return r.data;
  }

  private writeState(s: State) {
    s.serial += 1;
    fs.mkdirSync(this.o.dir, { recursive: true });
    const body = JSON.parse(canonicalize(s));
    const sig = this.o.signer.sign(STATE_DOMAIN + canonicalize(body));
    const tmp = this.stateFile + `.${randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ body, sig }, null, 2));
    fs.renameSync(tmp, this.stateFile);
  }

  // ---- keyring -------------------------------------------------------------------------------------------------

  listKeys(): PinnedKey[] {
    return this.readState().keys.map((k) => ({ fingerprint: k.fingerprint, publicKey: k.publicKey, label: k.label }));
  }

  /** Pin a publisher key (hex Ed25519 public key). Owner action: the CLI audits it. */
  addKey(publicKeyHex: string, label: string): PinnedKey {
    verifierFromHex(publicKeyHex); // throws on a malformed key
    const pk = publicKeyHex.toLowerCase();
    const fp = fingerprint(pk);
    const s = this.readState();
    if (s.keys.some((k) => k.fingerprint === fp)) throw new SkillRefused('duplicate-key', `publisher ${fp} is already pinned`);
    s.keys.push({ fingerprint: fp, publicKey: pk, label: label.slice(0, 80), addedAt: new Date(this.now()).toISOString() });
    this.writeState(s);
    this.o.audit.append('skillreg.key.added', { fingerprint: fp, label: label.slice(0, 80) });
    return { fingerprint: fp, publicKey: pk, label };
  }

  removeKey(fp: string): boolean {
    const s = this.readState();
    const n = s.keys.length;
    s.keys = s.keys.filter((k) => k.fingerprint !== fp);
    if (s.keys.length === n) return false;
    this.writeState(s);
    this.o.audit.append('skillreg.key.removed', { fingerprint: fp });
    return true;
  }

  // ---- verification --------------------------------------------------------------------------------------------

  private keyFor(s: State) {
    return (fp: string): PinnedKey | undefined => {
      const k = s.keys.find((x) => x.fingerprint === fp);
      return k ? { fingerprint: k.fingerprint, publicKey: k.publicKey, label: k.label } : undefined;
    };
  }

  private verifyBytes(bytes: Buffer, s: State): VerifiedBundle {
    return verifyBundle(bytes, { limits: this.limits(), keyFor: this.keyFor(s), now: this.now(), _unsafeSkipSignatureCheck: this.o._unsafeSkipSignatureCheck });
  }

  private readBundleFile(file: string): Buffer {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) throw new SkillRefused('not-a-file', `${file} is not a regular file`);
    if (st.size > this.limits().maxBundleBytes) throw new BundleError('too-large', `bundle is ${st.size} bytes; the limit is ${this.limits().maxBundleBytes}`);
    return fs.readFileSync(file);
  }

  /** `skills verify`: fully verify a bundle file against the keyring (signature, hashes, expiry, revocation). Installs nothing. */
  verifyFile(file: string): VerifiedBundle {
    const s = this.readState();
    const v = this.verifyBytes(this.readBundleFile(file), s);
    const rev = this.revocationOf(s, v);
    if (rev) throw new SkillRefused('revoked', `skill ${v.manifest.id}@${v.manifest.version} is revoked (${rev})`);
    return v;
  }

  private revocationOf(s: State, v: { manifest: Manifest; bundleSha256: string }): string | undefined {
    for (const r of s.revoked) {
      const e = r.entry;
      if (e.id !== undefined && e.id !== v.manifest.id) continue;
      if (e.version !== undefined && e.version !== v.manifest.version) continue;
      if (e.publisher !== undefined && e.publisher !== v.manifest.publisher) continue;
      if (e.bundleSha256 !== undefined && e.bundleSha256 !== v.bundleSha256) continue;
      return r.reason || r.source;
    }
    return undefined;
  }

  // ---- install -------------------------------------------------------------------------------------------------

  private refuse(code: string, msg: string, extra: Record<string, unknown> = {}): never {
    this.o.audit.append('skillreg.refused', { code, reason: msg.slice(0, 300), ...extra });
    throw new SkillRefused(code, msg);
  }

  async install(file: string, opts: InstallOptions = {}): Promise<InstallResult> {
    this.requireEnabled();
    const s0 = this.readState();
    let bytes: Buffer;
    let v: VerifiedBundle;
    try {
      bytes = this.readBundleFile(file);
      v = this.verifyBytes(bytes, s0);
    } catch (e: any) {
      if (e instanceof BundleError) this.refuse(e.code, e.message, { phase: 'install', file: path.basename(file) });
      if (e instanceof SkillRefused) this.refuse(e.code, e.message, { phase: 'install' });
      this.refuse('unreadable', `cannot read bundle: ${String(e?.message ?? e).slice(0, 200)}`, { phase: 'install' });
    }
    const m = v.manifest;
    const rev = this.revocationOf(s0, v);
    if (rev) this.refuse('revoked', `skill ${m.id}@${m.version} is revoked (${rev})`, { id: m.id, version: m.version });

    const prev = s0.installed[m.id];
    let prevLoaded: LoadedSkill | undefined;
    const flags: string[] = [];
    if (prev) {
      if (prev.bundleSha256 === v.bundleSha256 && prev.publisher === m.publisher) return { id: m.id, version: m.version, publisher: m.publisher, bundleSha256: v.bundleSha256, alreadyInstalled: true };
      const cmp = compareVersions(m.version, prev.version);
      if (cmp < 0) flags.push(`ROLLBACK: ${prev.version} -> ${m.version}`);
      if (cmp === 0) flags.push(`SAME VERSION ${m.version} WITH DIFFERENT CONTENT`);
      if (prev.publisher !== m.publisher) flags.push(`PUBLISHER CHANGE: ${prev.publisher} -> ${m.publisher}`);
      if ((cmp <= 0) && !opts.allowRollback) this.refuse('rollback', `${m.id} ${prev.version} is installed; refusing ${cmp < 0 ? 'a lower' : 'a same-numbered but different'} version without --allow-rollback and a fresh approval`, { id: m.id, installed: prev.version, offered: m.version });
      if (prev.publisher !== m.publisher && !opts.allowPublisherChange) this.refuse('publisher-change', `${m.id} is installed from publisher ${prev.publisher}; refusing publisher ${m.publisher} without --allow-publisher-change and a fresh approval`, { id: m.id });
      try {
        prevLoaded = this.loadInternal(m.id, s0);
      } catch {
        flags.push('(the installed version could not be re-verified, so no diff against it is shown)');
      }
    }

    const decision = await this.o.authorize(this.approvalAction(v, prevLoaded, flags));
    if (!decision.allowed) this.refuse('not-approved', `installation was not approved (${decision.by}: ${decision.reason})`, { id: m.id, version: m.version });

    // The world may have changed while a human was deciding: re-read state, re-verify the SAME bytes, re-check revocation.
    const s1 = this.readState();
    try {
      v = this.verifyBytes(bytes, s1);
    } catch (e: any) {
      this.refuse(e instanceof BundleError ? e.code : 'changed', `bundle no longer verifies after approval: ${e.message}`, { id: m.id });
    }
    const rev1 = this.revocationOf(s1, v);
    if (rev1) this.refuse('revoked', `skill ${m.id}@${m.version} was revoked while the approval was pending (${rev1})`, { id: m.id });
    const now1 = s1.installed[m.id];
    if ((prev?.bundleSha256 ?? null) !== (now1?.bundleSha256 ?? null)) this.refuse('changed', `the installed version of ${m.id} changed while the approval was pending; run install again`, { id: m.id });

    fs.mkdirSync(this.installedDir, { recursive: true });
    const target = path.join(this.installedDir, `${m.id}${BUNDLE_EXT}`);
    const tmp = target + `.${randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, bytes);
    fs.renameSync(tmp, target);
    s1.installed[m.id] = { id: m.id, version: m.version, publisher: m.publisher, bundleSha256: v.bundleSha256, installedAt: new Date(this.now()).toISOString(), approvedDecision: decision.id };
    this.writeState(s1);
    this.o.audit.append('skillreg.installed', {
      id: m.id, version: m.version, publisher: m.publisher, bundleSha256: v.bundleSha256, decisionId: decision.id,
      replaced: prev ? { version: prev.version, publisher: prev.publisher } : undefined, flags, capabilities: m.capabilities,
    });
    return { id: m.id, version: m.version, publisher: m.publisher, bundleSha256: v.bundleSha256, alreadyInstalled: false };
  }

  /** What the owner sees: publisher, version, declared capabilities, and a diff against any installed version. */
  private approvalAction(v: VerifiedBundle, prev: LoadedSkill | undefined, flags: string[]): Action {
    const m = v.manifest;
    const c = m.capabilities;
    const lines: string[] = [];
    if (flags.length) lines.push(...flags.map((f) => `!! ${f}`), '');
    lines.push(
      `Publisher : ${m.publisher} (pinned as "${v.publisher.label}")`,
      `Skill     : ${m.id} version ${m.version}${prev ? ` (installed: ${prev.manifest.version})` : ' (new install)'}`,
      `About     : ${m.description}`,
      `Expires   : ${m.expiresAt ?? 'never'}`,
      `Bundle    : sha256 ${v.bundleSha256}`,
      'DECLARED CAPABILITIES (it can never do more than these AND the current policy allow):',
      ...describeCaps(c).map((l) => '  ' + l),
    );
    if (prev) {
      const pc = describeCaps(prev.manifest.capabilities);
      const nc = describeCaps(c);
      const gained = nc.filter((l) => !pc.includes(l));
      const lost = pc.filter((l) => !nc.includes(l));
      lines.push('CAPABILITY CHANGES vs installed: ' + (gained.length || lost.length ? '' : 'none'));
      for (const l of gained) lines.push('  + ' + l);
      for (const l of lost) lines.push('  - ' + l);
    }
    lines.push('FILES:');
    for (const f of m.files) lines.push(`  ${f.name}  ${f.bytes} bytes  sha256 ${f.sha256.slice(0, 16)}${f.name === m.entry ? '  (entry)' : ''}`);
    lines.push('CODE' + (prev ? ' DIFF vs installed version:' : ':'));
    for (const f of m.files) {
      const before = prev?.manifest.files.find((x) => x.name === f.name) ? readMember(prev, f.name) : '';
      const d = unifiedDiff(before, v.files[f.name], f.name);
      if (prev && d.diff === '') lines.push(`  (${f.name} unchanged)`);
      else lines.push(d.diff === '' ? `  (${f.name} empty)` : d.diff);
    }
    if (prev) for (const pf of prev.manifest.files) if (!m.files.some((f) => f.name === pf.name)) lines.push(`  (${pf.name} REMOVED)`);
    return {
      class: 'skill.install',
      target: `${m.id}@${m.version}`,
      summary: `Install signed skill ${m.id}@${m.version} from publisher ${m.publisher}${flags.length ? ' [' + flags.map((f) => f.split(':')[0]).join(', ') + ']' : ''}; capabilities: ${describeCaps(c).join('; ').slice(0, 160)}`,
      detail: lines.join('\n'),
    };
  }

  // ---- load (every run) ----------------------------------------------------------------------------------------

  /**
   * Fully re-verify an installed skill and return its code. Called on EVERY run: state signature, install record,
   * revocation, bundle bytes vs the recorded hash, publisher still pinned, signature, member hashes, expiry.
   */
  load(id: string): LoadedSkill {
    this.requireEnabled();
    try {
      const l = this.loadInternal(id, this.readState());
      this.o.audit.append('skillreg.load', { id, version: l.manifest.version, publisher: l.manifest.publisher, bundleSha256: l.bundleSha256 });
      return l;
    } catch (e: any) {
      if (e instanceof SkillRefused) this.refuse(e.code, e.message, { phase: 'load', id });
      if (e instanceof BundleError) this.refuse(e.code, e.message, { phase: 'load', id });
      throw e;
    }
  }

  private loadInternal(id: string, s: State): LoadedSkill {
    if (!/^[a-z0-9][a-z0-9_-]{0,59}$/.test(id)) throw new SkillRefused('bad-id', 'invalid skill id');
    const rec = s.installed[id];
    if (!rec) throw new SkillRefused('not-installed', `skill ${id} is not installed`);
    // Revocation first: a revoked skill never even has its bytes parsed.
    const pre = this.revocationOf(s, { manifest: { id: rec.id, version: rec.version, publisher: rec.publisher } as Manifest, bundleSha256: rec.bundleSha256 });
    if (pre) throw new SkillRefused('revoked', `skill ${id}@${rec.version} is revoked (${pre})`);
    const file = path.join(this.installedDir, `${id}${BUNDLE_EXT}`);
    let bytes: Buffer;
    try {
      bytes = this.readBundleFile(file);
    } catch (e: any) {
      if (e instanceof BundleError || e instanceof SkillRefused) throw e;
      throw new SkillRefused('missing', `installed bundle for ${id} is missing or unreadable`);
    }
    if (sha256Hex(bytes) !== rec.bundleSha256) throw new SkillRefused('tampered', `installed bundle for ${id} was modified after it was approved (hash mismatch)`);
    const v = this.verifyBytes(bytes, s);
    if (v.manifest.id !== rec.id || v.manifest.version !== rec.version || v.manifest.publisher !== rec.publisher) throw new SkillRefused('tampered', 'installed bundle does not match its install record');
    const rev = this.revocationOf(s, v);
    if (rev) throw new SkillRefused('revoked', `skill ${id}@${rec.version} is revoked (${rev})`);
    return { manifest: v.manifest, code: v.files[v.manifest.entry], files: v.files, bundleSha256: v.bundleSha256, publisher: v.publisher };
  }

  list(): Array<{ id: string; version: string; publisher: string; label?: string; bundleSha256: string; installedAt: string; status: string }> {
    const s = this.readState();
    return Object.values(s.installed).map((r) => {
      let status = 'ok';
      try {
        this.loadInternal(r.id, s);
      } catch (e: any) {
        status = e instanceof SkillRefused ? `REFUSED (${e.code})` : e instanceof BundleError ? `REFUSED (${e.code})` : 'REFUSED';
      }
      return { ...r, label: s.keys.find((k) => k.fingerprint === r.publisher)?.label, status };
    });
  }

  // ---- revocation ----------------------------------------------------------------------------------------------

  /** Owner-managed revocation. With no `version`, EVERY version of `id` is revoked. */
  revoke(id: string, o: { version?: string; reason?: string } = {}) {
    const s = this.readState();
    const entry = RevocationEntry.parse({ id, version: o.version });
    s.revoked.push({ entry, reason: (o.reason ?? 'revoked by owner').slice(0, 200), at: new Date(this.now()).toISOString(), source: 'owner' });
    this.writeState(s);
    this.o.audit.append('skillreg.revoked', { id, version: o.version, source: 'owner', reason: (o.reason ?? '').slice(0, 200) });
  }

  /** Import a revocation list signed by a PINNED publisher key. Serial must exceed the last accepted one for that issuer. */
  importRevocationList(file: string): number {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > 1_000_000) this.refuse('revocation-list', 'revocation list must be a regular file under 1 MB');
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      return this.refuse('revocation-list', 'revocation list is not valid JSON');
    }
    const l = RevocationListSchema.safeParse(raw);
    if (!l.success) return this.refuse('revocation-list', 'revocation list is malformed');
    const s = this.readState();
    const key = s.keys.find((k) => k.fingerprint === l.data.issuer);
    if (!key) return this.refuse('unknown-publisher', `revocation list issuer ${l.data.issuer} is not in your keyring`);
    const { sig, format, ...body } = l.data;
    if (!verifierFromHex(key.publicKey).verify(`${LIST_FORMAT}:${canonicalize(body)}`, sig)) return this.refuse('bad-signature', 'revocation list signature does not verify');
    const last = s.listSerials[l.data.issuer] ?? 0;
    if (l.data.serial <= last) return this.refuse('list-rollback', `revocation list serial ${l.data.serial} is not newer than ${last}`);
    for (const entry of l.data.entries) s.revoked.push({ entry, reason: `signed list serial ${l.data.serial}`, at: new Date(this.now()).toISOString(), source: `list:${l.data.issuer}` });
    s.listSerials[l.data.issuer] = l.data.serial;
    this.writeState(s);
    this.o.audit.append('skillreg.revoked', { source: `list:${l.data.issuer}`, serial: l.data.serial, entries: l.data.entries.length });
    return l.data.entries.length;
  }

  revocations(): State['revoked'] {
    return this.readState().revoked;
  }

  /** One doctor line. Never prints key material. */
  status(): { line: string; warnings: string[] } {
    const p = this.o.policy();
    if (!p.enabled) return { line: 'Skills registry: disabled (policy skillsRegistry.enabled = false)', warnings: [] };
    try {
      const s = this.readState();
      const refused = this.list().filter((x) => x.status !== 'ok').length;
      return {
        line: `Skills registry: enabled; ${s.keys.length} pinned publisher(s); ${Object.keys(s.installed).length} installed (${refused} refused); ${s.revoked.length} revocation(s); local files only, no network fetch`,
        warnings: [
          ...(s.keys.length === 0 ? ['no publisher keys are pinned: nothing can be installed (starclaw skills keys add)'] : []),
          ...(refused ? [`${refused} installed skill(s) currently REFUSE to run (starclaw skills list)`] : []),
        ],
      };
    } catch (e: any) {
      return { line: 'Skills registry: enabled but its state FAILED verification; every registry skill is refused', warnings: [String(e.message)] };
    }
  }
}

function readMember(l: LoadedSkill, name: string): string {
  return l.files[name] ?? '';
}

export function describeCaps(c: Capabilities): string[] {
  return [
    `tools (required): ${c.tools.join(', ') || 'none'}`,
    `tools (optional): ${c.optionalTools.join(', ') || 'none'}`,
    `domains: ${c.domains.join(', ') || 'none (no network)'}`,
    `paths: ${c.paths.join(', ') || 'none (no file access)'}`,
    `spend: ${c.spendCents} cents per run${c.spendCents === 0 ? ' (cannot spend)' : ''}`,
  ];
}
