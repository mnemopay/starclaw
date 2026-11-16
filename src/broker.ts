import { execFile } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { applyUnifiedDiff, EDIT_LIMITS, editByFind, encodeText, readText, unifiedDiff } from './edit';
import { Governor } from './governance/governor';
import { canonicalize } from './governance/canonical';
import { ControlClient, ControlError, defaultDiscoveryPath, readDiscovery } from './browser/control';
import { checkBrowserUrl, hostAllowed } from './browser/guard';
import { TaintedFileStore } from './governance/taint';
import { Action } from './governance/types';
import { safeGet, parseHttpUrl } from './net/safeFetch';
import { extractReadable, looksBinary, looksLikeHtml } from './net/readable';
import { createSearchProvider, SearchProvider } from './search/providers';
import type { BrokerCall } from './sandbox/ProcessSandbox';
import type { OwnerNotifier, NotifyLimiter } from './notify/Notifier';
import type { JobStore } from './scheduler/JobStore';
import type { ShellRunner } from './shell/ShellRunner';

const MAX_FILE_BYTES = 1_000_000;
const MAX_WRITE_BYTES = 5_000_000;

const norm = (p: string) => (process.platform === 'win32' ? p.toLowerCase() : p);

/** Resolve symlinks/junctions for the deepest existing ancestor, then re-append the non-existent tail. */
export function realResolve(p: string): string {
  const abs = path.resolve(p);
  let cur = abs;
  const tail: string[] = [];
  for (;;) {
    try {
      const real = fs.realpathSync.native(cur);
      return tail.length ? path.join(real, ...tail.reverse()) : real;
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return abs;
      tail.push(path.basename(cur));
      cur = parent;
    }
  }
}

export function isInside(child: string, parent: string): boolean {
  const rel = path.relative(norm(parent), norm(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

export interface BrokerOptions {
  governor: Governor;
  workspaceDir: string;
  /** Directory holding keys, audit log, memory db: never readable or writable through the broker. */
  stateDir: string;
  taintedFiles: TaintedFileStore;
  /** TEST-ONLY: called after approval and before the write is committed (to simulate a racing writer). */
  _testBeforeCommit?: (real: string) => void | Promise<void>;
  /** TEST-ONLY CONTROL: skip the post-approval re-checks so a test can prove they are what stops the race. */
  _unsafeSkipRecheck?: boolean;
  /** TEST-ONLY: use this search provider instead of the one built from the policy. */
  _testSearchProvider?: SearchProvider;
  /** tools.shell: absent = the tool is not available. */
  shell?: ShellRunner;
  /** tools.notifyOwner: absent = the tool is not available. */
  notifier?: OwnerNotifier;
  notifyLimiter?: NotifyLimiter;
  /** tools.scheduleCreate: absent = the tool is not available. */
  jobs?: JobStore;
  /** Host-side location of the browser's control.json (default: the OS location, or MNEMOPAY_CONTROL_DISCOVERY). Never reachable from generated code. */
  browserDiscoveryPath?: string;
}

const PathArgs = z.object({ path: z.string().min(1).max(1000) }).strict();
const WriteArgs = z.object({ path: z.string().min(1).max(1000), content: z.string().max(MAX_WRITE_BYTES) }).strict();
const FetchArgs = z.object({ url: z.string().min(1).max(4000), format: z.enum(['raw', 'text']).default('raw'), maxChars: z.number().int().min(200).max(100_000).default(20_000), maxLinks: z.number().int().min(0).max(50).default(20) }).strict();
const SearchArgs = z.object({ query: z.string().min(1).max(300), limit: z.number().int().min(1).max(20).optional() }).strict();
const CmdArgs = z.object({ file: z.string().min(1).max(500), args: z.array(z.string().max(2000)).max(64).default([]) }).strict();
const Sha = z.string().regex(/^[0-9a-fA-F]{64}$/);
const PatchArgs = z.object({ path: z.string().min(1).max(1000), patch: z.string().min(1).max(EDIT_LIMITS.maxPatchBytes), expectSha256: Sha.optional() }).strict();
const EditArgs = z.object({ path: z.string().min(1).max(1000), find: z.string().min(1).max(100_000), replace: z.string().max(200_000), expectCount: z.number().int().min(1).max(1000).default(1), expectSha256: Sha.optional() }).strict();
const ShellArgsSchema = z.object({ command: z.string().min(1).max(4000) }).strict();
const NotifyArgs = z.object({ text: z.string().min(1).max(10_000) }).strict();
const ScheduleArgs = z.object({ name: z.string().min(1).max(60), schedule: z.string().min(1).max(100), goal: z.string().min(3).max(2000), kind: z.enum(['goal', 'heartbeat']).default('goal') }).strict();
const BrowseOpenArgs = z.object({ url: z.string().min(1).max(4000) }).strict();
const BrowseNavArgs = z.object({ url: z.string().min(1).max(4000) }).strict();
const BrowseTextArgs = z.object({ maxBytes: z.number().int().min(1).max(262_144).optional() }).strict();
const BrowseLinksArgs = z.object({ maxLinks: z.number().int().min(1).max(500).optional() }).strict();
const NoArgs = z.object({}).strict();
const SpendArgs = z.object({ cents: z.number(), payee: z.string().min(1).max(200), memo: z.string().max(500).default('') }).strict();

/**
 * Executes the capabilities that sandboxed code asks for. Every call is turned into an Action and passed through
 * the Governor; nothing here runs without a positive decision.
 */
export class Broker {
  readonly workspace: string;
  readonly stateDir: string;
  constructor(private readonly o: BrokerOptions) {
    fs.mkdirSync(o.workspaceDir, { recursive: true });
    this.workspace = fs.realpathSync.native(o.workspaceDir);
    fs.mkdirSync(o.stateDir, { recursive: true });
    this.stateDir = fs.realpathSync.native(o.stateDir);
  }

  private get gov() {
    return this.o.governor;
  }

  /** Hard rules no policy can relax. Throws after writing an audit record. */
  private checkPath(rawPath: string, write: boolean): { real: string; inWorkspace: boolean } {
    const resolved = path.resolve(this.workspace, rawPath);
    // UNC and device paths (\\server\share, \\localhost\C$\..., \\?\..., \\.\...) can name a local file under a
    // different spelling that the directory comparisons below do not recognise: a red-team run read the audit
    // signing key through \\localhost\C$\<state dir>. Never accept them, whatever the policy says.
    if (process.platform === 'win32' && resolved.startsWith('\\\\')) {
      const why = 'UNC and device paths (\\\\server\\share, \\\\?\\, \\\\.\\) are not allowed';
      this.gov.audit.append('hard-rule.denied', { class: write ? 'fs.write' : 'fs.read', target: resolved, reason: why });
      throw new Error(`denied by hard rule: ${why}`);
    }
    const real = realResolve(resolved);
    const inWorkspace = isInside(real, this.workspace);
    const base = path.basename(real).toLowerCase();
    let why: string | undefined;
    if (isInside(real, this.stateDir)) why = 'path is inside the StarClaw state directory (keys, audit log, memory)';
    else if (this.isBrowserDiscoveryPath(real)) why = 'the browser control discovery file (it holds the control token) is never accessible';
    else if (base === '.env' || base.startsWith('.env.')) why = 'environment files are never accessible';
    else if (/(^|[\\/])\.git([\\/]|$)/i.test(real) && write) why = 'writing inside .git is not allowed';
    else if (write && !inWorkspace) why = 'writes outside the workspace are not allowed';
    if (why) {
      this.gov.audit.append('hard-rule.denied', { class: write ? 'fs.write' : 'fs.read', target: real, reason: why });
      throw new Error(`denied by hard rule: ${why}`);
    }
    return { real, inWorkspace };
  }

  private get discoveryPath(): string {
    return this.o.browserDiscoveryPath ?? defaultDiscoveryPath();
  }

  /** The browser's data directory holds control.json (the control token). No tool may read it, whatever a human clicks. */
  private isBrowserDiscoveryPath(real: string): boolean {
    try {
      return isInside(real, realResolve(path.dirname(this.discoveryPath)));
    } catch {
      return false;
    }
  }

  async handle(call: BrokerCall): Promise<unknown> {
    switch (call.name) {
      case 'readFile':
        return this.readFile(PathArgs.parse(call.args));
      case 'listDir':
        return this.listDir(PathArgs.parse(call.args));
      case 'writeFile':
        return this.writeFile(WriteArgs.parse(call.args));
      case 'applyPatch':
        return this.applyPatch(PatchArgs.parse(call.args));
      case 'editFile':
        return this.editFile(EditArgs.parse(call.args));
      case 'fetchUrl':
        return this.fetchUrl(FetchArgs.parse(call.args));
      case 'search':
        return this.search(SearchArgs.parse(call.args));
      case 'runCommand':
        return this.runCommand(CmdArgs.parse(call.args));
      case 'shell':
        return this.shell(ShellArgsSchema.parse(call.args));
      case 'notifyOwner':
        return this.notifyOwner(NotifyArgs.parse(call.args));
      case 'scheduleCreate':
        return this.scheduleCreate(ScheduleArgs.parse(call.args));
      case 'spend':
        return this.spend(SpendArgs.parse(call.args));
      case 'browseOpen':
        return this.browseOpen(BrowseOpenArgs.parse(call.args));
      case 'browseNavigate':
        return this.browseNavigate(BrowseNavArgs.parse(call.args));
      case 'browseReadText':
        return this.browseRead('text', BrowseTextArgs.parse(call.args));
      case 'browseReadLinks':
        return this.browseRead('links', BrowseLinksArgs.parse(call.args));
      case 'browseClose':
        NoArgs.parse(call.args ?? {});
        return this.browseClose();
      default:
        throw new Error(`unknown tool ${call.name}`);
    }
  }

  private async readFile(a: { path: string }) {
    const { real, inWorkspace } = this.checkPath(a.path, false);
    const action: Action = { class: 'fs.read', target: real, inWorkspace, summary: `Read file ${real}` };
    return this.gov.governed(
      action,
      async () => {
        const st = fs.statSync(real);
        if (!st.isFile()) throw new Error('not a regular file');
        const fd = fs.openSync(real, 'r');
        try {
          const buf = Buffer.alloc(Math.min(st.size, MAX_FILE_BYTES));
          fs.readSync(fd, buf, 0, buf.length, 0);
          if (this.o.taintedFiles.has(real)) this.gov.taint.mark('tainted-file', real);
          return { content: buf.toString('utf8'), truncated: st.size > MAX_FILE_BYTES };
        } finally {
          fs.closeSync(fd);
        }
      },
      (r) => ({ bytes: r.content.length }),
    );
  }

  private async listDir(a: { path: string }) {
    const { real, inWorkspace } = this.checkPath(a.path, false);
    return this.gov.governed({ class: 'fs.read', target: real, inWorkspace, summary: `List directory ${real}` }, async () =>
      fs.readdirSync(real, { withFileTypes: true }).slice(0, 1000).map((d) => ({ name: d.name, dir: d.isDirectory() })),
    );
  }

  private async writeFile(a: { path: string; content: string }) {
    const { real, inWorkspace } = this.checkPath(a.path, true);
    const action: Action = {
      class: 'fs.write',
      target: real,
      inWorkspace,
      summary: `Write ${Buffer.byteLength(a.content)} bytes to ${real}`,
      detail: a.content.slice(0, 3000),
    };
    return this.gov.governed(
      action,
      async () => {
        fs.mkdirSync(path.dirname(real), { recursive: true });
        // Re-check after mkdir: the parent must still resolve inside the workspace.
        if (!isInside(realResolve(real), this.workspace)) throw new Error('path escaped the workspace');
        fs.writeFileSync(real, a.content, 'utf8');
        if (this.gov.taint.tainted) this.o.taintedFiles.add(real);
        else this.o.taintedFiles.remove(real);
        return { written: Buffer.byteLength(a.content), path: real };
      },
    );
  }

  // ---- file editing ------------------------------------------------------------------------------------------

  /**
   * Shared front half of applyPatch/editFile: hard path rules, refuse links/binary/mixed EOL/oversized files,
   * check the optional sha256 precondition, and compute the new bytes + the diff the approver will see.
   */
  private prepareEdit(rawPath: string, expectSha256: string | undefined, compute: (origLf: string, exists: boolean) => { ok: true; result: string } | { ok: false; error: string }) {
    const { real, inWorkspace } = this.checkPath(rawPath, true);
    // Editing never goes through a link (even one that stays inside the workspace) or an alternate spelling of the path.
    if (norm(path.resolve(this.workspace, rawPath)) !== norm(real)) throw new Error('refusing to edit through a symbolic link, junction or alternate path spelling');
    let orig: Buffer | null = null;
    let lst: fs.Stats | undefined;
    try {
      lst = fs.lstatSync(real);
    } catch {
      lst = undefined;
    }
    if (lst) {
      if (lst.isSymbolicLink()) throw new Error('refusing to edit through a symbolic link');
      if (!lst.isFile()) throw new Error('not a regular file');
      if (lst.size > EDIT_LIMITS.maxFileBytes) throw new Error(`file is larger than ${EDIT_LIMITS.maxFileBytes} bytes`);
      orig = fs.readFileSync(real);
    }
    const shaBefore = orig ? createHash('sha256').update(orig).digest('hex') : null;
    if (expectSha256 && shaBefore !== expectSha256.toLowerCase()) throw new Error(`expectSha256 precondition failed: the file is ${shaBefore ?? 'absent'}`);
    let eol: 'lf' | 'crlf' | 'none' = 'lf';
    let bom = false;
    let origLf = '';
    if (orig) {
      const t = readText(orig);
      if (!t.ok) throw new Error(t.reason);
      origLf = t.text;
      eol = t.eol === 'none' ? 'lf' : t.eol;
      bom = t.bom;
    }
    const r = compute(origLf, !!orig);
    if (!r.ok) throw new Error(r.error);
    const label = path.relative(this.workspace, real).split(path.sep).join('/');
    const d = unifiedDiff(origLf, r.result, label || path.basename(real));
    return { real, inWorkspace, orig, shaBefore, origLf, newLf: r.result, newBuf: encodeText(r.result, eol, bom), eol, diff: d };
  }

  private async commitEdit(kind: 'applyPatch' | 'editFile', rawPath: string, prep: ReturnType<Broker['prepareEdit']>) {
    if (prep.diff.diff === '' && prep.orig) return { path: prep.real, changed: false, sha256Before: prep.shaBefore, sha256After: prep.shaBefore, added: 0, removed: 0 };
    const action: Action = {
      class: 'fs.write',
      target: prep.real,
      inWorkspace: prep.inWorkspace,
      summary: `${kind} ${prep.real}: +${prep.diff.added} -${prep.diff.removed} lines, ${prep.newBuf.length} bytes after, ${prep.orig ? 'edit of existing file (sha256 ' + prep.shaBefore!.slice(0, 12) + ')' : 'NEW file'}, ${prep.eol.toUpperCase()} line endings preserved`.slice(0, 400),
      detail: prep.diff.diff,
    };
    return this.gov.governed(
      action,
      async () => {
        await this.o._testBeforeCommit?.(prep.real);
        const dir = path.dirname(prep.real);
        if (!this.o._unsafeSkipRecheck) {
          // Re-run every check AFTER approval: the world may have changed while a human was deciding.
          const again = this.checkPath(rawPath, true);
          if (again.real !== prep.real || norm(path.resolve(this.workspace, rawPath)) !== norm(prep.real)) throw new Error('the path now resolves somewhere else (symbolic link or junction swapped in); nothing written');
          let lst2: fs.Stats | undefined;
          try {
            lst2 = fs.lstatSync(prep.real);
          } catch {
            lst2 = undefined;
          }
          if (lst2?.isSymbolicLink()) throw new Error('target became a symbolic link; nothing written');
          if (prep.orig) {
            if (!lst2 || !lst2.isFile()) throw new Error('file disappeared since approval; nothing written');
            const nowSha = createHash('sha256').update(fs.readFileSync(prep.real)).digest('hex');
            if (nowSha !== prep.shaBefore) throw new Error('the file changed after the diff was shown to the approver; nothing written');
          } else if (lst2) throw new Error('a file appeared at the target after approval; nothing written');
        }
        fs.mkdirSync(dir, { recursive: true });
        if (!isInside(realResolve(dir), this.workspace)) throw new Error('directory escaped the workspace; nothing written');
        const tmp = path.join(dir, `.starclaw-tmp-${randomBytes(6).toString('hex')}`);
        try {
          const fd = fs.openSync(tmp, 'wx', prep.orig ? fs.statSync(prep.real).mode & 0o777 : 0o644);
          try {
            fs.writeSync(fd, prep.newBuf);
            fs.fsyncSync(fd);
          } finally {
            fs.closeSync(fd);
          }
          if (!isInside(realResolve(tmp), this.workspace)) throw new Error('temp file escaped the workspace; nothing written');
          if (prep.orig) fs.renameSync(tmp, prep.real);
          else {
            fs.linkSync(tmp, prep.real); // fails with EEXIST if something appeared meanwhile: never overwrites
            fs.unlinkSync(tmp);
          }
        } catch (e) {
          try {
            fs.unlinkSync(tmp);
          } catch {
            /* already gone */
          }
          throw e;
        }
        if (this.gov.taint.tainted) this.o.taintedFiles.add(prep.real);
        else this.o.taintedFiles.remove(prep.real);
        const after = createHash('sha256').update(prep.newBuf).digest('hex');
        return { path: prep.real, changed: true, sha256Before: prep.shaBefore, sha256After: after, added: prep.diff.added, removed: prep.diff.removed };
      },
      (r) => ({ changed: r.changed, sha256Before: r.sha256Before, sha256After: r.sha256After, added: r.added, removed: r.removed, via: kind }),
    );
  }

  /** Editing reads the file internally (to build the diff), so it must pass the same fs.read gate as readFile: otherwise find/expectCount errors would be a content oracle when reads are restricted. */
  private async readGate(rawPath: string) {
    const { real, inWorkspace } = this.checkPath(rawPath, true);
    await this.gov.governed({ class: 'fs.read', target: real, inWorkspace, summary: `Read ${real} in order to edit it` }, async () => true);
  }

  private async applyPatch(a: z.infer<typeof PatchArgs>) {
    await this.readGate(a.path);
    const prep = this.prepareEdit(a.path, a.expectSha256, (orig, exists) => {
      const r = applyUnifiedDiff(orig, a.patch, exists);
      return r.ok ? { ok: true, result: r.result } : r;
    });
    return this.commitEdit('applyPatch', a.path, prep);
  }

  private async editFile(a: z.infer<typeof EditArgs>) {
    await this.readGate(a.path);
    const prep = this.prepareEdit(a.path, a.expectSha256, (orig, exists) => {
      if (!exists) return { ok: false, error: 'file does not exist (use writeFile to create files)' };
      const r = editByFind(orig, a.find, a.replace, a.expectCount);
      return r.ok ? { ok: true, result: r.result } : r;
    });
    return this.commitEdit('editFile', a.path, prep);
  }

  private async fetchUrl(a: z.infer<typeof FetchArgs>) {
    const net = this.gov.policy.net;
    let url = a.url;
    for (let hop = 0; hop <= net.maxRedirects; hop++) {
      const u = parseHttpUrl(url);
      const action: Action = { class: 'net.egress', target: u.hostname, host: u.hostname, summary: `HTTP GET ${u.origin}${u.pathname}`, detail: u.toString() };
      const res = await this.gov.governed(
        action,
        () => safeGet(u.toString(), { allowPrivateAddresses: net.allowPrivateAddresses, maxBytes: net.maxResponseBytes, timeoutMs: net.timeoutSeconds * 1000 }),
        (r) => ({ status: r.status, bytes: r.body.length, remote: r.remoteAddress }),
      );
      // Anything that came off the network is untrusted from this point on.
      this.gov.taint.mark('web', u.toString());
      if (res.redirectTo) {
        url = res.redirectTo;
        continue;
      }
      const contentType = res.headers['content-type'] ?? '';
      if (a.format === 'raw') return { status: res.status, url: u.toString(), contentType, body: res.body, truncated: res.truncated };
      return this.readable(res, u.toString(), contentType, a);
    }
    throw new Error(`too many redirects (> ${net.maxRedirects})`);
  }

  /**
   * format:"text": decide what the body really is by looking at it (a Content-Type header is just an untrusted claim),
   * refuse compressed/binary bodies, and return bounded readable text plus a bounded list of links. We never
   * decompress anything, so a compression bomb cannot expand in our memory.
   */
  private readable(res: { status: number; headers: Record<string, string>; body: string; truncated: boolean }, url: string, contentType: string, a: { maxChars: number; maxLinks: number }) {
    const enc = (res.headers['content-encoding'] ?? 'identity').toLowerCase();
    const base = { status: res.status, url, contentType, format: 'text' as const, wireTruncated: res.truncated };
    if (enc !== 'identity' && enc !== '') return { ...base, detected: 'compressed', text: '', title: '', links: [], truncated: false, note: `response is Content-Encoding: ${enc.slice(0, 20)}; StarClaw does not decompress, so no text was extracted` };
    if (looksBinary(res.body)) return { ...base, detected: 'binary', text: '', title: '', links: [], truncated: false, note: 'body looks binary (Content-Type is only a claim); no text was extracted' };
    const claimsJson = /json/i.test(contentType);
    if (looksLikeHtml(res.body)) {
      const r = extractReadable(res.body, { maxChars: a.maxChars, maxLinks: a.maxLinks, baseUrl: url });
      return { ...base, detected: 'html', title: r.title, text: r.text, links: r.links, truncated: r.truncated || res.truncated, invisibleCharsRemoved: r.invisibleCharsRemoved, note: claimsJson ? 'Content-Type said JSON but the body is HTML' : undefined };
    }
    const text = res.body.slice(0, a.maxChars);
    return { ...base, detected: claimsJson ? 'json-or-text' : 'text', title: '', text, links: [], truncated: res.body.length > a.maxChars || res.truncated };
  }

  private searchProvider?: SearchProvider | null;
  private getSearchProvider(): SearchProvider {
    if (this.searchProvider === undefined) this.searchProvider = this.o._testSearchProvider ?? createSearchProvider(this.gov.policy.search) ?? null;
    if (!this.searchProvider) throw new Error('web search is disabled: set search.provider to "searxng" or "brave" in the policy');
    return this.searchProvider;
  }

  /**
   * Web search through the configured provider. It is a net.egress to the provider host (the full URL, including the
   * query text, is what the approver sees; API keys are headers and are never shown or logged). The results are
   * untrusted text from the internet: the session is tainted as soon as the provider answers.
   */
  private async search(a: z.infer<typeof SearchArgs>) {
    const provider = this.getSearchProvider();
    const cfg = this.gov.policy.search;
    const net = this.gov.policy.net;
    const limit = Math.min(a.limit ?? cfg.maxResults, cfg.maxResults);
    const req = provider.request(a.query, limit);
    const u = parseHttpUrl(req.url);
    const action: Action = { class: 'net.egress', target: u.hostname, host: u.hostname, summary: `Web search via ${provider.name}: "${a.query.slice(0, 120)}"`, detail: u.toString() };
    const allowPrivate = net.allowPrivateAddresses || (provider.selfHosted && cfg.allowPrivateProvider);
    const res = await this.gov.governed(action, () => safeGet(u.toString(), { allowPrivateAddresses: allowPrivate, maxBytes: net.maxResponseBytes, timeoutMs: net.timeoutSeconds * 1000, headers: req.headers }), (r) => ({ status: r.status, bytes: r.body.length, provider: provider.name }));
    // Whatever the provider sent back is untrusted, even if it turns out to be an error page.
    this.gov.taint.mark('web', `search:${provider.name}:${a.query.slice(0, 200)}`);
    if (res.redirectTo) throw new Error('search provider answered with a redirect; refusing to follow it');
    if (res.status !== 200) throw new Error(`search provider returned HTTP ${res.status}`);
    const results = provider.parse(res.body, limit);
    return { provider: provider.name, query: a.query, untrusted: true, results };
  }

  private async runCommand(a: { file: string; args: string[] }) {
    const line = [a.file, ...a.args].join(' ');
    const action: Action = { class: 'host.exec', target: path.basename(a.file), summary: `Run host command (UNSANDBOXED): ${line}`.slice(0, 300), detail: JSON.stringify({ file: a.file, args: a.args }, null, 2) };
    const out = await this.gov.governed(
      action,
      () =>
        new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
          const env: NodeJS.ProcessEnv = { PATH: process.env.PATH };
          if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
          execFile(a.file, a.args, { cwd: this.workspace, env, timeout: 30_000, maxBuffer: 1_000_000, windowsHide: true, shell: false }, (err, stdout, stderr) => {
            // String codes (ENOENT, ETIMEDOUT...) are spawn/timeout failures; numeric codes are exit statuses.
            if (err && typeof (err as any).code === 'string') return reject(err);
            resolve({ code: err ? ((err as any).code as number) : 0, stdout: String(stdout), stderr: String(stderr) });
          });
        }),
      (r) => ({ exitCode: r.code, stdoutBytes: r.stdout.length }),
    );
    if (this.gov.policy.execOutputTaints) this.gov.taint.mark('tool-output', `exec:${path.basename(a.file)}`);
    return out;
  }

  /** The broker's write-path hard rules for an absolute host path (used by the shell write-back). Audited on denial. */
  guardWritePath(abs: string): void {
    this.checkPath(abs, true);
  }

  private async shell(a: { command: string }) {
    const runner = this.o.shell;
    if (!runner) throw new Error('tools.shell is not available: the shell container is not configured');
    const command = a.command;
    const action: Action = {
      class: 'shell.exec',
      target: command.replace(/\s+/g, ' ').trim().slice(0, 300),
      summary: `Run in the locked-down shell container (no network, workspace copied in/out): ${command.replace(/\s+/g, ' ').trim()}`.slice(0, 300),
      detail: command,
    };
    const out = await this.gov.governed(
      action,
      () =>
        runner.run(command, {
          guard: (abs) => this.checkPath(abs, true),
          // The exact set of host changes is recorded BEFORE any of them is applied.
          beforeApply: (plan, staged) =>
            this.gov.audit.append('shell.writeback.plan', {
              staged,
              writes: plan.writes.slice(0, 300).map((w) => ({ path: w.rel, bytes: w.data.length, isNew: w.isNew })),
              mkdirs: plan.mkdirs.slice(0, 100),
              deletes: plan.deletes.slice(0, 300),
              refused: plan.refused.slice(0, 100),
              unchanged: plan.unchanged,
            }),
        }),
      (r) => ({
        exitCode: r.exitCode,
        timedOut: r.timedOut,
        stdoutBytes: r.stdout.length,
        stderrBytes: r.stderr.length,
        written: r.changes?.written.slice(0, 300),
        deleted: r.changes?.deleted.slice(0, 300),
        createdDirs: r.changes?.createdDirs.slice(0, 100),
        refused: r.changes?.refused.slice(0, 100),
        conflicts: r.changes?.conflicts.slice(0, 100),
        note: r.note,
      }),
    );
    // Whatever came out of the container is untrusted, and so is every file it produced.
    if (this.gov.policy.execOutputTaints) this.gov.taint.mark('tool-output', 'shell');
    for (const rel of out.changes?.written ?? []) this.o.taintedFiles.add(path.join(this.workspace, ...rel.split('/')));
    return {
      exitCode: out.exitCode,
      stdout: out.stdout,
      stderr: out.stderr,
      timedOut: out.timedOut,
      outputTruncated: out.outputTruncated,
      note: out.note,
      changes: out.changes && {
        written: out.changes.written,
        deleted: out.changes.deleted,
        createdDirs: out.changes.createdDirs,
        refused: out.changes.refused,
        conflicts: out.changes.conflicts,
      },
      skippedOnCopyIn: out.staged.skipped.length,
    };
  }

  private async notifyOwner(a: { text: string }) {
    const n = this.o.notifier;
    if (!n) throw new Error('tools.notifyOwner is not available: no owner channel (e.g. Telegram) is configured');
    const lim = this.gov.policy.notify;
    const text = a.text.slice(0, lim.maxChars);
    try {
      this.o.notifyLimiter?.check();
    } catch (e: any) {
      this.gov.audit.append('notify.rate-limited', { reason: e.message, chars: text.length });
      throw e;
    }
    const ctx = this.gov.runContext;
    const action: Action = {
      class: 'notify.owner',
      target: 'owner',
      summary: `Send the owner a message (${text.length} chars) via ${n.name}`,
      detail: text,
    };
    return this.gov.governed(
      action,
      async () => {
        const prefix = ctx?.origin === 'scheduled' ? `[StarClaw job ${ctx.jobId?.slice(0, 8) ?? ''}] ` : '[StarClaw] ';
        await n.send(prefix + text);
        this.o.notifyLimiter?.record();
        return { sent: true, chars: text.length };
      },
      (r) => ({ chars: r.chars, channel: n.name }),
    );
  }

  private async scheduleCreate(a: { name: string; schedule: string; goal: string; kind: 'goal' | 'heartbeat' }) {
    const jobs = this.o.jobs;
    if (!jobs) throw new Error('tools.scheduleCreate is not available: the scheduler is not configured');
    // Validate first so a human is never asked to approve something that cannot be created.
    const v = jobs.validate(a);
    const action: Action = {
      class: 'schedule.create',
      target: a.name,
      summary: `Create a recurring ${a.kind} job "${a.name}" (${a.schedule}); it will run UNATTENDED, next at ${new Date(v.nextRunAt).toISOString()}`.slice(0, 300),
      detail: `name=${a.name}\nkind=${a.kind}\nschedule=${a.schedule}\nshortest gap=${v.gapSeconds}s\ngoal:\n${a.goal}`,
    };
    return this.gov.governed(
      action,
      async () => {
        const job = jobs.add({ name: a.name, schedule: a.schedule, goal: a.goal, kind: a.kind, createdBy: 'agent-approved', createdTainted: this.gov.taint.tainted });
        this.gov.audit.append('scheduler.job.created', { jobId: job.id, name: job.name, kind: job.kind, schedule: job.schedule, createdBy: job.createdBy, createdTainted: job.createdTainted, goalSha: job.goal.length });
        return { id: job.id, nextRunAt: job.nextRunAt ? new Date(job.nextRunAt).toISOString() : null };
      },
    );
  }

  private async spend(a: { cents: number; payee: string; memo: string }) {
    return this.gov.spend({ cents: a.cents, payee: a.payee, memo: a.memo });
  }

  // ---- governed browser (MnemoPay Native Browser control API) ---------------------------------------------------

  /** The one open tab (host-side state; generated code never sees the tab id, the token or the discovery file). */
  private tab?: { id: string; used: number; expiresAt: number };

  private browserRefuse(tool: string, reason: string, extra: Record<string, unknown> = {}): never {
    this.gov.audit.append('browser.refused', { tool, reason, ...extra });
    throw new Error(`browser tool refused: ${reason}`);
  }

  private browserCfg(tool: string) {
    const b = this.gov.policy.browser;
    if (!b.enabled) this.browserRefuse(tool, 'the browser is disabled (policy browser.enabled = false)');
    if (b.allowedDomains.length === 0) this.browserRefuse(tool, 'browser.allowedDomains is empty');
    return b;
  }

  /** Fresh read of the discovery file on every call (the token changes per browser launch). Fails closed and audits. */
  private browserClient(tool: string): ControlClient {
    try {
      return new ControlClient(readDiscovery(this.discoveryPath), { timeoutMs: this.gov.policy.browser.timeoutSeconds * 1000 });
    } catch (e: any) {
      this.gov.audit.append('browser.unavailable', { tool, reason: String(e?.message ?? e).slice(0, 200) });
      throw e;
    }
  }

  private liveTab(tool: string) {
    const b = this.browserCfg(tool);
    const t = this.tab;
    if (!t) return this.browserRefuse(tool, 'no browser tab is open (call tools.browseOpen first)');
    if (Date.now() > t.expiresAt) {
      this.tab = undefined;
      return this.browserRefuse(tool, 'the browser tab expired (browser.ttlSeconds)');
    }
    if (t.used >= b.maxActions) return this.browserRefuse(tool, `the tab used its ${b.maxActions} allowed actions (browser.maxActions); close it and ask the owner`);
    return t;
  }

  /** Taint on any answer from the browser (success or failure: either may carry page-derived text). */
  private async browserCall<T>(label: string, fn: () => Promise<T>): Promise<T> {
    try {
      const res = await fn();
      // Every page-derived result is untrusted, whatever the server's own `untrusted` flag says.
      this.gov.taint.mark('web', `browser:${label}`);
      return res;
    } catch (e: any) {
      if (e instanceof ControlError && e.info.answered) this.gov.taint.mark('web', `browser:${label}`);
      throw e;
    }
  }

  private receiptDigest(r: unknown): string | undefined {
    if (r === undefined) return undefined;
    try {
      return createHash('sha256').update(canonicalize(r)).digest('hex');
    } catch {
      return 'unhashable';
    }
  }

  /** Withhold content when the tab ended on a host outside the allow-list (the browser does this too; we do not rely on it). */
  private assertFinalHost(data: any, allowed: readonly string[]) {
    const u = data && typeof data === 'object' ? (data.url ?? data.final_url) : undefined;
    if (typeof u !== 'string') return;
    let host: string;
    try {
      host = new URL(u).hostname;
    } catch {
      throw new Error('the browser reported an unparseable page URL; content withheld');
    }
    if (!hostAllowed(host, allowed)) throw new Error(`the tab ended on ${host}, which is not in browser.allowedDomains; content withheld`);
  }

  private async browseOpen(a: { url: string }) {
    const b = this.browserCfg('browseOpen');
    if (this.tab && Date.now() <= this.tab.expiresAt) this.browserRefuse('browseOpen', 'a browser tab is already open (one at a time); close it first');
    this.tab = undefined;
    let u: URL;
    try {
      u = checkBrowserUrl(a.url, b.allowedDomains);
    } catch (e: any) {
      return this.browserRefuse('browseOpen', e.message, { host: safeHost(a.url) });
    }
    // Fail closed BEFORE asking a human to approve something that cannot work.
    this.browserClient('browseOpen');
    const envelope = {
      budget_cents: b.budgetCents,
      max_actions: b.maxActions,
      allowed_domains: [...b.allowedDomains],
      ttl_seconds: b.ttlSeconds,
      ...(b.actionCostCents !== undefined ? { action_cost_cents: b.actionCostCents } : {}),
    };
    const clientRef = 'starclaw-' + randomBytes(6).toString('hex');
    const action: Action = {
      class: 'browser.open',
      target: u.hostname,
      host: u.hostname,
      summary: `Open a governed browser tab at ${u.origin}${u.pathname} (allowed domains: ${b.allowedDomains.join(', ')}; ${b.maxActions} actions, ${b.budgetCents}c budget, ${b.ttlSeconds}s)`.slice(0, 400),
      detail: JSON.stringify({ url: u.toString(), envelope, clientRef }, null, 2),
    };
    const out = await this.gov.governed(
      action,
      async () => {
        const client = this.browserClient('browseOpen');
        const res = await this.browserCall(u.toString(), () => client.openTab(u.toString(), envelope, clientRef));
        if (typeof res.tab_id !== 'string') throw new Error('the browser did not return a tab id');
        this.tab = { id: res.tab_id, used: 1, expiresAt: Date.now() + b.ttlSeconds * 1000 };
        this.assertFinalHost(res.data, b.allowedDomains);
        return { res, clientRef };
      },
      (r) => ({ tool: 'browseOpen', host: u.hostname, requestId: r.res.request_id, clientRef: r.clientRef, receiptSha256: this.receiptDigest(r.res.receipt), untrusted: true }),
    );
    return { untrusted: true as const, opened: true, actionsLeft: b.maxActions - 1, data: out.res.data };
  }

  private async browseNavigate(a: { url: string }) {
    const b = this.browserCfg('browseNavigate');
    const t = this.liveTab('browseNavigate');
    let u: URL;
    try {
      u = checkBrowserUrl(a.url, b.allowedDomains);
    } catch (e: any) {
      return this.browserRefuse('browseNavigate', e.message, { host: safeHost(a.url) });
    }
    const clientRef = 'starclaw-' + randomBytes(6).toString('hex');
    const action: Action = {
      class: 'browser.navigate',
      target: u.hostname,
      host: u.hostname,
      summary: `Navigate the governed browser tab to ${u.origin}${u.pathname}`.slice(0, 300),
      detail: JSON.stringify({ url: u.toString(), clientRef }, null, 2),
    };
    const out = await this.gov.governed(
      action,
      async () => {
        const client = this.browserClient('browseNavigate');
        t.used++;
        const res = await this.browserCall(u.toString(), () => client.navigate(t.id, u.toString(), clientRef));
        this.assertFinalHost(res.data, b.allowedDomains);
        return { res, clientRef };
      },
      (r) => ({ tool: 'browseNavigate', host: u.hostname, requestId: r.res.request_id, clientRef: r.clientRef, receiptSha256: this.receiptDigest(r.res.receipt), untrusted: true }),
    );
    return { untrusted: true as const, actionsLeft: b.maxActions - t.used, data: out.res.data };
  }

  private async browseRead(kind: 'text' | 'links', a: { maxBytes?: number; maxLinks?: number }) {
    const tool = kind === 'text' ? 'browseReadText' : 'browseReadLinks';
    const b = this.browserCfg(tool);
    const t = this.liveTab(tool);
    const clientRef = 'starclaw-' + randomBytes(6).toString('hex');
    const maxBytes = Math.min(a.maxBytes ?? b.maxReadBytes, b.maxReadBytes);
    const maxLinks = Math.min(a.maxLinks ?? b.maxLinks, b.maxLinks);
    const action: Action = {
      class: 'browser.read',
      target: kind,
      summary: `Read ${kind === 'text' ? `up to ${maxBytes} bytes of page text` : `up to ${maxLinks} links`} from the governed browser tab`,
      detail: JSON.stringify({ kind, limit: kind === 'text' ? maxBytes : maxLinks, clientRef }),
    };
    const out = await this.gov.governed(
      action,
      async () => {
        const client = this.browserClient(tool);
        t.used++;
        const res = await this.browserCall(kind, () => (kind === 'text' ? client.readText(t.id, maxBytes, clientRef) : client.readLinks(t.id, maxLinks, clientRef)));
        this.assertFinalHost(res.data, b.allowedDomains);
        return { res, clientRef };
      },
      (r) => ({ tool, requestId: r.res.request_id, clientRef: r.clientRef, receiptSha256: this.receiptDigest(r.res.receipt), bytes: JSON.stringify(r.res.data ?? null).length, untrusted: true }),
    );
    return { untrusted: true as const, actionsLeft: b.maxActions - t.used, data: out.res.data };
  }

  private async browseClose() {
    this.browserCfg('browseClose');
    const t = this.tab;
    if (!t) return this.browserRefuse('browseClose', 'no browser tab is open');
    const clientRef = 'starclaw-' + randomBytes(6).toString('hex');
    const action: Action = { class: 'browser.read', target: 'close', summary: 'Close the governed browser tab (ends its session)', detail: JSON.stringify({ kind: 'close', clientRef }) };
    try {
      const r = await this.gov.governed(
        action,
        async () => {
          const client = this.browserClient('browseClose');
          return this.browserCall('close', () => client.closeTab(t.id, clientRef));
        },
        (r) => ({ tool: 'browseClose', requestId: r.request_id, clientRef, receiptSha256: this.receiptDigest(r.receipt) }),
      );
      return { closed: true, requestId: r.request_id };
    } finally {
      // Whatever happened, stop using this tab id: the browser expires it by TTL anyway.
      this.tab = undefined;
    }
  }
}

function safeHost(raw: string): string | undefined {
  try {
    return new URL(raw).hostname.slice(0, 200);
  } catch {
    return undefined;
  }
}
