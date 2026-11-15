import { execFile } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';
import { Governor } from './governance/governor';
import { TaintedFileStore } from './governance/taint';
import { Action } from './governance/types';
import { safeGet, parseHttpUrl } from './net/safeFetch';
import type { BrokerCall } from './sandbox/ProcessSandbox';

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
}

const PathArgs = z.object({ path: z.string().min(1).max(1000) }).strict();
const WriteArgs = z.object({ path: z.string().min(1).max(1000), content: z.string().max(MAX_WRITE_BYTES) }).strict();
const FetchArgs = z.object({ url: z.string().min(1).max(4000) }).strict();
const CmdArgs = z.object({ file: z.string().min(1).max(500), args: z.array(z.string().max(2000)).max(64).default([]) }).strict();
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
    const real = realResolve(path.resolve(this.workspace, rawPath));
    const inWorkspace = isInside(real, this.workspace);
    const base = path.basename(real).toLowerCase();
    let why: string | undefined;
    if (isInside(real, this.stateDir)) why = 'path is inside the StarClaw state directory (keys, audit log, memory)';
    else if (base === '.env' || base.startsWith('.env.')) why = 'environment files are never accessible';
    else if (/(^|[\\/])\.git([\\/]|$)/i.test(real) && write) why = 'writing inside .git is not allowed';
    else if (write && !inWorkspace) why = 'writes outside the workspace are not allowed';
    if (why) {
      this.gov.audit.append('hard-rule.denied', { class: write ? 'fs.write' : 'fs.read', target: real, reason: why });
      throw new Error(`denied by hard rule: ${why}`);
    }
    return { real, inWorkspace };
  }

  async handle(call: BrokerCall): Promise<unknown> {
    switch (call.name) {
      case 'readFile':
        return this.readFile(PathArgs.parse(call.args));
      case 'listDir':
        return this.listDir(PathArgs.parse(call.args));
      case 'writeFile':
        return this.writeFile(WriteArgs.parse(call.args));
      case 'fetchUrl':
        return this.fetchUrl(FetchArgs.parse(call.args).url);
      case 'runCommand':
        return this.runCommand(CmdArgs.parse(call.args));
      case 'spend':
        return this.spend(SpendArgs.parse(call.args));
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

  private async fetchUrl(startUrl: string) {
    const net = this.gov.policy.net;
    let url = startUrl;
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
      return { status: res.status, url: u.toString(), contentType: res.headers['content-type'] ?? '', body: res.body, truncated: res.truncated };
    }
    throw new Error(`too many redirects (> ${net.maxRedirects})`);
  }

  private async runCommand(a: { file: string; args: string[] }) {
    const line = [a.file, ...a.args].join(' ');
    const action: Action = { class: 'exec', target: path.basename(a.file), summary: `Run host command: ${line}`.slice(0, 300), detail: JSON.stringify({ file: a.file, args: a.args }, null, 2) };
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

  private async spend(a: { cents: number; payee: string; memo: string }) {
    return this.gov.spend({ cents: a.cents, payee: a.payee, memo: a.memo });
  }
}
