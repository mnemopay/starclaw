import * as vm from 'node:vm';
import { z } from 'zod';
import { canonicalize, sha256Hex } from '../../governance/canonical';
import { fingerprint, verifierFromHex } from '../../governance/signer';
import { BROWSER_DOMAIN_RE } from '../../governance/policy';
import { DEFAULT_TOOL_NAMES } from '../../sandbox/types';

/**
 * The `.starclaw-skill` bundle: ONE self-describing JSON document (no archive library, nothing is ever extracted to
 * disk by member name, no decompression so no zip bombs):
 *
 *   { "format": "starclaw-skill/1",
 *     "manifest": { id, version, publisher, description, entry, createdAt, expiresAt?, files:[{name,sha256,bytes}], capabilities },
 *     "files":    { "<flat member name>": "<utf8 text>" },
 *     "signature": { "alg": "ed25519", "keyId": "<publisher fingerprint>", "sig": "<base64>" } }
 *
 * The publisher signs `starclaw-skill/1:sha256:<sha256 of the canonical manifest>`. The manifest commits to every
 * member's sha256 and size, so a verified manifest pins the code. The public key is NOT in the bundle: trust comes only
 * from the owner's keyring.
 */
export const BUNDLE_FORMAT = 'starclaw-skill/1';
export const BUNDLE_EXT = '.starclaw-skill';

export class BundleError extends Error {
  constructor(public readonly code: BundleErrorCode, msg: string) {
    super(msg);
    this.name = 'BundleError';
  }
}
export type BundleErrorCode =
  | 'too-large' | 'malformed' | 'bad-name' | 'unknown-publisher' | 'bad-signature' | 'tampered'
  | 'expired' | 'syntax' | 'limits';

export interface BundleLimits {
  maxBundleBytes: number;
  maxFiles: number;
  maxFileBytes: number;
}

/** Tools a registry skill may declare. `runCommand` (unsandboxed host) and `scheduleCreate` can NEVER be declared. */
// searchConversations reads the owner's private history: never available to a third-party skill.
export const DECLARABLE_TOOLS = DEFAULT_TOOL_NAMES.filter((t) => t !== 'runCommand' && t !== 'scheduleCreate' && t !== 'spawnAgent' && t !== 'searchConversations') as [string, ...string[]];

const SkillId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,59}$/, 'skill id: lowercase letters, digits, - and _ (max 60)');
const Version = z.string().regex(/^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/, 'version must be MAJOR.MINOR.PATCH');
const Fp = z.string().regex(/^[0-9a-f]{16}$/);
const Sha = z.string().regex(/^[0-9a-f]{64}$/);
export const MEMBER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MemberName = z.string().regex(MEMBER_NAME_RE, 'member names are flat: letters, digits, . _ - (no slashes, no leading dot)').refine((n) => !n.includes('..'), 'member name may not contain ".."');
/** Workspace-relative glob: no absolute paths, no "..", no drive letters, no backslashes. */
const PathScope = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9_*][A-Za-z0-9_.\-*/]*$/, 'path scope is a workspace-relative glob')
  .refine((p) => !p.split('/').some((seg) => seg === '..' || seg === '.'), 'path scope may not contain . or .. segments');
const Iso = z.string().refine((s) => !Number.isNaN(Date.parse(s)), 'not an ISO date');

export const CapabilitiesSchema = z
  .object({
    /** REQUIRED tools: the skill refuses to run when the current policy denies any of them. */
    tools: z.array(z.enum(DECLARABLE_TOOLS)).max(20).default([]),
    /** Tools it can use if allowed but does not need. */
    optionalTools: z.array(z.enum(DECLARABLE_TOOLS)).max(20).default([]),
    /** net/browser: exact host or `*.sub.example.com`. No IPs, no localhost. Empty = no network at all. */
    domains: z.array(z.string().regex(BROWSER_DOMAIN_RE)).max(50).default([]),
    /** fs: globs relative to the workspace. Empty = no file access at all. */
    paths: z.array(PathScope).max(50).default([]),
    /** Max integer cents per run. 0 (default) = the skill can never spend. */
    spendCents: z.number().int().min(0).max(100_000_000).default(0),
  })
  .strict()
  .refine((c) => ![...c.tools, ...c.optionalTools].includes('shell') || c.paths.includes('**'), { message: 'shell requires an explicit whole-workspace path grant (**); narrow shell scopes are unsupported', path: ['paths'] });
export type Capabilities = z.infer<typeof CapabilitiesSchema>;

export const ManifestSchema = z
  .object({
    id: SkillId,
    version: Version,
    publisher: Fp,
    description: z.string().min(1).max(500),
    entry: MemberName,
    createdAt: Iso,
    expiresAt: Iso.optional(),
    files: z.array(z.object({ name: MemberName, sha256: Sha, bytes: z.number().int().min(0).max(5_000_000) }).strict()).min(1).max(64),
    capabilities: CapabilitiesSchema,
  })
  .strict();
export type Manifest = z.infer<typeof ManifestSchema>;

const SignatureSchema = z.object({ alg: z.literal('ed25519'), keyId: Fp, sig: z.string().regex(/^[A-Za-z0-9+/]{80,100}={0,2}$/) }).strict();
const BundleSchema = z
  .object({ format: z.literal(BUNDLE_FORMAT), manifest: z.unknown(), files: z.record(z.string(), z.string()), signature: SignatureSchema })
  .strict();

export interface PinnedKey {
  fingerprint: string;
  publicKey: string;
  label: string;
}

export function manifestDigest(manifest: Manifest): string {
  return sha256Hex(canonicalize(manifest));
}
export function signedMessage(manifest: Manifest): string {
  return `${BUNDLE_FORMAT}:sha256:${manifestDigest(manifest)}`;
}

export interface VerifiedBundle {
  manifest: Manifest;
  files: Record<string, string>;
  /** sha256 of the exact bytes of the bundle file. */
  bundleSha256: string;
  publisher: PinnedKey;
}

export interface VerifyOptions {
  limits: BundleLimits;
  /** Looks a publisher up in the OWNER's keyring. Unknown = undefined = refuse. */
  keyFor: (fingerprint: string) => PinnedKey | undefined;
  now: number;
  /** TEST-ONLY CONTROL: skip the signature check to prove the tests notice. Never set in product code. */
  _unsafeSkipSignatureCheck?: boolean;
}

/** Parse + fully verify a bundle. Throws BundleError; there is no "partially valid" result. */
export function verifyBundle(bytes: Buffer, o: VerifyOptions): VerifiedBundle {
  if (bytes.length > o.limits.maxBundleBytes) throw new BundleError('too-large', `bundle is ${bytes.length} bytes; the limit is ${o.limits.maxBundleBytes}`);
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new BundleError('malformed', 'bundle is not valid JSON');
  }
  // Look at the RAW own keys first: a schema library may silently drop a hostile key such as an own "__proto__".
  const rawFiles = raw && typeof raw === 'object' ? (raw as any).files : undefined;
  if (rawFiles && typeof rawFiles === 'object' && !Array.isArray(rawFiles)) {
    for (const name of Object.getOwnPropertyNames(rawFiles)) {
      if (!MEMBER_NAME_RE.test(name) || name.includes('..')) throw new BundleError('bad-name', `illegal member name ${JSON.stringify(name).slice(0, 80)}`);
    }
  }
  const b = BundleSchema.safeParse(raw);
  if (!b.success) throw new BundleError('malformed', 'bundle structure is invalid: ' + b.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ').slice(0, 400));
  const entries = Object.entries(b.data.files);
  if (entries.length > o.limits.maxFiles) throw new BundleError('limits', `bundle has ${entries.length} files; the limit is ${o.limits.maxFiles}`);
  for (const [name, content] of entries) {
    if (!MEMBER_NAME_RE.test(name) || name.includes('..')) throw new BundleError('bad-name', `illegal member name ${JSON.stringify(name).slice(0, 80)}`);
    if (Buffer.byteLength(content, 'utf8') > o.limits.maxFileBytes) throw new BundleError('limits', `member ${name} exceeds ${o.limits.maxFileBytes} bytes`);
  }
  const m = ManifestSchema.safeParse(b.data.manifest);
  if (!m.success) throw new BundleError('malformed', 'manifest is invalid: ' + m.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ').slice(0, 400));
  const manifest = m.data;
  if (manifest.files.length > o.limits.maxFiles) throw new BundleError('limits', 'manifest lists too many files');

  // 1. Publisher must be pinned by the owner.
  if (b.data.signature.keyId !== manifest.publisher) throw new BundleError('bad-signature', 'signature key id does not match manifest.publisher');
  const key = o.keyFor(manifest.publisher);
  if (!key) throw new BundleError('unknown-publisher', `publisher ${manifest.publisher} is not in your keyring; refusing (pin it with: starclaw skills keys add)`);
  if (fingerprint(key.publicKey) !== manifest.publisher) throw new BundleError('bad-signature', 'keyring entry does not match its fingerprint');

  // 2. Signature over the manifest digest.
  if (!o._unsafeSkipSignatureCheck) {
    if (!verifierFromHex(key.publicKey).verify(signedMessage(manifest), b.data.signature.sig)) {
      throw new BundleError('bad-signature', 'signature does not verify against the pinned publisher key (wrong key, or the manifest was modified)');
    }
  }

  // 3. The manifest pins every member: exact set, exact hashes, exact sizes.
  const listed = new Set(manifest.files.map((f) => f.name));
  if (listed.size !== manifest.files.length) throw new BundleError('tampered', 'manifest lists a member twice');
  const present = new Set(entries.map(([n]) => n));
  for (const n of listed) if (!present.has(n)) throw new BundleError('tampered', `manifest lists ${n} but the bundle does not contain it`);
  for (const n of present) if (!listed.has(n)) throw new BundleError('tampered', `bundle contains ${n} which the signed manifest does not list`);
  const files: Record<string, string> = Object.create(null);
  for (const f of manifest.files) {
    const content = b.data.files[f.name];
    if (sha256Hex(content) !== f.sha256 || Buffer.byteLength(content, 'utf8') !== f.bytes) throw new BundleError('tampered', `member ${f.name} does not match the signed manifest (hash or size)`);
    files[f.name] = content;
  }
  if (!listed.has(manifest.entry) || !manifest.entry.endsWith('.js')) throw new BundleError('malformed', 'manifest.entry must be one of the bundled .js files');

  // 4. Validity window.
  if (manifest.expiresAt !== undefined && o.now > Date.parse(manifest.expiresAt)) throw new BundleError('expired', `skill expired at ${manifest.expiresAt}`);

  // 5. The entry must at least parse (parse only; never run here).
  try {
    new vm.Script('(function (module, exports, tools, require) {\n' + files[manifest.entry] + '\n})', { filename: manifest.entry });
  } catch (e: any) {
    throw new BundleError('syntax', `entry file does not parse: ${String(e?.message).slice(0, 200)}`);
  }
  return { manifest, files, bundleSha256: sha256Hex(bytes), publisher: key };
}

/** Compare MAJOR.MINOR.PATCH. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  return 0;
}

/** Publisher side: assemble and sign a bundle. `signer` is the publisher's Ed25519Signer (key file never leaves it). */
export function buildBundle(
  draft: { id: string; version: string; description: string; entry: string; expiresAt?: string; createdAt?: string; capabilities?: unknown },
  members: Record<string, string>,
  signer: { publicKeyHex: string; sign(message: string): string },
): string {
  const publisher = fingerprint(signer.publicKeyHex);
  const manifest = ManifestSchema.parse({
    id: draft.id,
    version: draft.version,
    publisher,
    description: draft.description,
    entry: draft.entry,
    createdAt: draft.createdAt ?? new Date().toISOString(),
    expiresAt: draft.expiresAt,
    files: Object.keys(members)
      .sort()
      .map((name) => ({ name, sha256: sha256Hex(members[name]), bytes: Buffer.byteLength(members[name], 'utf8') })),
    capabilities: CapabilitiesSchema.parse(draft.capabilities ?? {}),
  });
  const sig = signer.sign(signedMessage(manifest));
  return JSON.stringify({ format: BUNDLE_FORMAT, manifest, files: members, signature: { alg: 'ed25519', keyId: publisher, sig } }, null, 2) + '\n';
}
