import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildTar, TarFileIn, TarReadResult } from './tar';

/**
 * Workspace staging for the shell container.
 *
 * DESIGN (see SECURITY.md "Shell container" for the experiment behind it): the container never gets a bind mount of
 * the workspace. The workspace is COPIED IN as a tar stream (links, environment files and the state directory are
 * left out), the command runs against that private copy, and the resulting tree is read back as a tar stream,
 * parsed defensively, turned into an explicit change list, and applied to the host only through the broker's hard
 * path rules, with refusal of links, conflict detection against what was copied in, and caps.
 */

export interface StageLimits {
  maxFiles: number;
  maxBytes: number;
  maxFileBytes: number;
}

export interface StagedFile {
  size: number;
  sha256: string;
}

export interface Snapshot {
  /** Relative posix path -> content hash at copy-in time. */
  files: Map<string, StagedFile>;
  dirs: Set<string>;
  tar: Buffer;
  totalBytes: number;
  /** Things left out of the copy, with the reason (links, env files, invalid names, state dir ...). */
  skipped: Array<{ path: string; reason: string }>;
}

export class StageError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'StageError';
  }
}

const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/** Reason a relative path may not be staged or written back, or undefined if it is acceptable. */
export function validateRelPath(rel: string): string | undefined {
  if (rel.length === 0) return 'empty path';
  if (rel.length > 400) return 'path too long';
  if (rel.startsWith('/') || /^[a-zA-Z]:/.test(rel)) return 'absolute path';
  if (rel.includes('\\')) return 'backslash in path';
  if (rel.includes('\0') || /[\u0001-\u001f\u007f]/.test(rel)) return 'control character in path';
  const segs = rel.split('/');
  if (segs.length > 40) return 'path too deep';
  for (const s of segs) {
    if (s === '' || s === '.' || s === '..') return 'empty, "." or ".." path segment';
    if (s.length > 255) return 'path segment too long';
    if (s.includes(':')) return 'colon in path (drive letter or NTFS alternate data stream)';
    if (/[<>"|?*]/.test(s)) return 'character not valid on Windows';
    if (/[. ]$/.test(s)) return 'segment ends with a dot or space (Windows would alias it)';
    if (RESERVED.test(s)) return 'Windows reserved device name';
    if (/^~\d$/.test(s) || /~\d(\.|$)/.test(s)) return 'possible 8.3 short name';
  }
  return undefined;
}

export const isEnvName = (name: string) => {
  const b = name.toLowerCase();
  return b === '.env' || b.startsWith('.env.');
};

const norm = (p: string) => (process.platform === 'win32' ? p.toLowerCase() : p);
const insideOrEqual = (child: string, parent: string) => {
  const rel = path.relative(norm(parent), norm(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
};

function sha(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Build the copy-in tar. Fails closed (StageError) if the workspace exceeds the caps rather than copying part of it.
 * Never follows links: symlinks, junctions and anything lstat cannot classify are skipped and reported.
 */
export function stageWorkspace(workspaceReal: string, stateDirReal: string, limits: StageLimits): Snapshot {
  const files = new Map<string, StagedFile>();
  const dirs = new Set<string>();
  const skipped: Snapshot['skipped'] = [];
  const entries: TarFileIn[] = [];
  let total = 0;
  const skip = (p: string, reason: string) => {
    if (skipped.length < 200) skipped.push({ path: p, reason });
  };

  const walk = (abs: string, rel: string) => {
    // A directory swapped for a link between listing and reading must not be followed.
    let realDir: string;
    try {
      realDir = fs.realpathSync.native(abs);
    } catch {
      skip(rel || '.', 'unreadable directory');
      return;
    }
    if (!insideOrEqual(realDir, workspaceReal)) {
      skip(rel || '.', 'directory resolves outside the workspace');
      return;
    }
    let names: string[];
    try {
      names = fs.readdirSync(abs);
    } catch {
      skip(rel || '.', 'unreadable directory');
      return;
    }
    names.sort();
    for (const name of names) {
      const childRel = rel ? `${rel}/${name}` : name;
      const childAbs = path.join(abs, name);
      const bad = validateRelPath(childRel);
      if (bad) {
        skip(childRel, bad);
        continue;
      }
      if (isEnvName(name)) {
        skip(childRel, 'environment files are never copied into the container');
        continue;
      }
      let st: fs.Stats;
      try {
        st = fs.lstatSync(childAbs);
      } catch {
        skip(childRel, 'cannot be inspected (lstat failed)');
        continue;
      }
      if (st.isSymbolicLink()) {
        skip(childRel, 'symlink/junction: links are never followed or copied');
        continue;
      }
      if (st.isDirectory()) {
        let realChild: string;
        try {
          realChild = fs.realpathSync.native(childAbs);
        } catch {
          skip(childRel, 'unreadable directory');
          continue;
        }
        if (insideOrEqual(realChild, stateDirReal) || insideOrEqual(stateDirReal, realChild)) {
          skip(childRel, 'contains or is the StarClaw state directory');
          continue;
        }
        if (!insideOrEqual(realChild, workspaceReal)) {
          skip(childRel, 'directory resolves outside the workspace');
          continue;
        }
        dirs.add(childRel);
        entries.push({ path: childRel, mtimeSec: st.mtimeMs / 1000 });
        walk(childAbs, childRel);
        continue;
      }
      if (!st.isFile() || st.nlink !== 1) {
        skip(childRel, 'not a regular file');
        continue;
      }
      if (st.size > limits.maxFileBytes) throw new StageError(`workspace file ${childRel} is ${st.size} bytes, over the per-file cap of ${limits.maxFileBytes}`);
      if (files.size + 1 > limits.maxFiles) throw new StageError(`workspace has more than ${limits.maxFiles} files: too large to copy into the shell container (raise shell.workspace.maxFiles or use a smaller workspace)`);
      if (total + st.size > limits.maxBytes) throw new StageError(`workspace is larger than ${limits.maxBytes} bytes: too large to copy into the shell container`);
      let data: Buffer;
      try {
        data = fs.readFileSync(childAbs);
        const after = fs.lstatSync(childAbs);
        if (after.isSymbolicLink() || !after.isFile() || after.nlink !== 1 || !insideOrEqual(fs.realpathSync.native(childAbs), workspaceReal)) {
          skip(childRel, 'changed into a link while being read');
          continue;
        }
      } catch {
        skip(childRel, 'unreadable file');
        continue;
      }
      if (data.length > limits.maxFileBytes || total + data.length > limits.maxBytes) throw new StageError('workspace grew past the caps while it was being copied');
      total += data.length;
      files.set(childRel, { size: data.length, sha256: sha(data) });
      entries.push({ path: childRel, data, mtimeSec: st.mtimeMs / 1000 });
    }
  };
  walk(workspaceReal, '');
  return { files, dirs, tar: buildTar(entries), totalBytes: total, skipped };
}

// ---- planning what to bring back --------------------------------------------------------------------------------

export interface ChangeWrite {
  rel: string;
  data: Buffer;
  isNew: boolean;
}
export interface ChangePlan {
  writes: ChangeWrite[];
  mkdirs: string[];
  deletes: string[];
  unchanged: number;
  refused: Array<{ path: string; reason: string }>;
}

export interface PlanLimits {
  maxChangedFiles: number;
  maxDeletedFiles: number;
}

/** Turn the (untrusted) tar from the container into an explicit change list. Throws if the archive cannot be trusted at all. */
export function planChanges(res: TarReadResult, snap: Snapshot, lim: PlanLimits): ChangePlan {
  if (res.error) throw new StageError(`write-back aborted: ${res.error}`);
  if (!res.complete) throw new StageError('write-back aborted: the archive from the container was cut short');
  const plan: ChangePlan = { writes: [], mkdirs: [], deletes: [], unchanged: 0, refused: [] };
  const seen = new Set<string>();
  const seenKeys = new Set<string>();
  const refuse = (p: string, reason: string) => {
    if (plan.refused.length < 200) plan.refused.push({ path: p, reason });
  };
  for (const e of res.entries) {
    if (e.path === '') continue; // the root directory itself
    if (e.kind === 'other') {
      const what = e.typeflag === '2' ? 'symlink' : e.typeflag === '1' ? 'hard link' : e.typeflag === '3' || e.typeflag === '4' ? 'device node' : e.typeflag === '6' ? 'fifo' : `entry type "${e.typeflag}"`;
      refuse(e.path, `${what} refused (links and special files are never written to the host)`);
      continue;
    }
    const bad = validateRelPath(e.path);
    if (bad) {
      refuse(e.path, bad);
      continue;
    }
    const key = e.path.toLowerCase(); // Windows is case-insensitive: two names that collide there are refused
    if (seenKeys.has(key)) {
      refuse(e.path, 'duplicate or case-colliding path');
      continue;
    }
    seenKeys.add(key);
    seen.add(e.path);
    if (e.kind === 'dir') {
      if (!snap.dirs.has(e.path)) plan.mkdirs.push(e.path);
      continue;
    }
    const was = snap.files.get(e.path);
    const h = sha(e.data!);
    if (was && was.sha256 === h) {
      plan.unchanged++;
      continue;
    }
    plan.writes.push({ rel: e.path, data: e.data!, isNew: !was });
  }
  for (const rel of snap.files.keys()) if (!seen.has(rel) && !seenKeys.has(rel.toLowerCase())) plan.deletes.push(rel);
  if (plan.writes.length + plan.mkdirs.length > lim.maxChangedFiles) throw new StageError(`write-back aborted: ${plan.writes.length + plan.mkdirs.length} changed paths exceeds the cap of ${lim.maxChangedFiles}`);
  if (plan.deletes.length > lim.maxDeletedFiles) throw new StageError(`write-back aborted: ${plan.deletes.length} deleted files exceeds the cap of ${lim.maxDeletedFiles}`);
  return plan;
}

// ---- applying -----------------------------------------------------------------------------------------------------

export interface ApplyReport {
  written: string[];
  deleted: string[];
  createdDirs: string[];
  refused: Array<{ path: string; reason: string }>;
  conflicts: Array<{ path: string; reason: string }>;
}

/**
 * Apply a plan to the host. `guard(absPath)` is the broker's write-path hard rule (state dir, .env, .git, outside the
 * workspace) and throws when the path is not allowed. On top of that every existing path component must be a real
 * directory (no link anywhere on the way), a file that already exists must be unchanged since copy-in (otherwise
 * somebody else edited it: conflict, not overwritten), and files are written to a temp name and renamed.
 */
export function applyPlan(plan: ChangePlan, snap: Snapshot, workspaceReal: string, guard: (abs: string) => void): ApplyReport {
  const rep: ApplyReport = { written: [], deleted: [], createdDirs: [], refused: [...plan.refused], conflicts: [] };
  const refuse = (p: string, reason: string) => rep.refused.push({ path: p, reason });
  const conflict = (p: string, reason: string) => rep.conflicts.push({ path: p, reason });

  /** Every existing component between the workspace and `abs` (exclusive of abs) must be a real directory. */
  const ancestorsOk = (abs: string): string | undefined => {
    const relParts = path.relative(workspaceReal, path.dirname(abs)).split(path.sep).filter(Boolean);
    let cur = workspaceReal;
    for (const part of relParts) {
      cur = path.join(cur, part);
      let st: fs.Stats;
      try {
        st = fs.lstatSync(cur);
      } catch (e: any) {
        if (e?.code === 'ENOENT') return undefined; // the rest does not exist yet: it will be created by us
        return 'cannot inspect a parent directory';
      }
      if (st.isSymbolicLink()) return 'a parent directory is a link';
      if (!st.isDirectory()) return 'a parent is not a directory';
    }
    return undefined;
  };

  const ensureDir = (abs: string, rel: string): boolean => {
    const bad = ancestorsOk(path.join(abs, 'x'));
    if (bad) {
      refuse(rel, bad);
      return false;
    }
    fs.mkdirSync(abs, { recursive: true });
    return true;
  };

  for (const rel of plan.mkdirs) {
    const abs = path.join(workspaceReal, ...rel.split('/'));
    try {
      guard(abs);
    } catch (e: any) {
      refuse(rel, String(e.message).replace(/^denied by hard rule: /, ''));
      continue;
    }
    if (!fs.existsSync(abs)) {
      if (ensureDir(abs, rel)) rep.createdDirs.push(rel);
    }
  }

  for (const w of plan.writes) {
    const abs = path.join(workspaceReal, ...w.rel.split('/'));
    try {
      guard(abs);
    } catch (e: any) {
      refuse(w.rel, String(e.message).replace(/^denied by hard rule: /, ''));
      continue;
    }
    const bad = ancestorsOk(abs);
    if (bad) {
      refuse(w.rel, bad);
      continue;
    }
    let existing: fs.Stats | undefined;
    try {
      existing = fs.lstatSync(abs);
    } catch (e: any) {
      if (e?.code !== 'ENOENT') {
        refuse(w.rel, 'cannot inspect the existing file');
        continue;
      }
    }
    if (existing) {
      if (existing.isSymbolicLink() || !existing.isFile()) {
        refuse(w.rel, 'target exists and is a link or not a regular file');
        continue;
      }
      const was = snap.files.get(w.rel);
      if (!was) {
        conflict(w.rel, 'a file appeared on the host at this path while the command ran');
        continue;
      }
      let cur: string;
      try {
        cur = sha(fs.readFileSync(abs));
      } catch {
        refuse(w.rel, 'cannot read the existing file to check for conflicts');
        continue;
      }
      if (cur !== was.sha256) {
        conflict(w.rel, 'the host file changed while the command ran');
        continue;
      }
    } else if (snap.files.has(w.rel)) {
      conflict(w.rel, 'the host file was deleted while the command ran');
      continue;
    }
    const dir = path.dirname(abs);
    if (!ensureDir(dir, w.rel)) continue;
    const tmp = path.join(dir, `.starclaw-${randomBytes(6).toString('hex')}.tmp`);
    try {
      fs.writeFileSync(tmp, w.data, { flag: 'wx' });
      fs.renameSync(tmp, abs);
      rep.written.push(w.rel);
    } catch (e: any) {
      try {
        fs.rmSync(tmp, { force: true });
      } catch {
        /* best effort */
      }
      refuse(w.rel, `write failed: ${String(e?.code ?? e?.message).slice(0, 80)}`);
    }
  }

  for (const rel of plan.deletes) {
    const abs = path.join(workspaceReal, ...rel.split('/'));
    try {
      guard(abs);
    } catch (e: any) {
      refuse(rel, 'delete refused: ' + String(e.message).replace(/^denied by hard rule: /, ''));
      continue;
    }
    const bad = ancestorsOk(abs);
    if (bad) {
      refuse(rel, bad);
      continue;
    }
    try {
      const st = fs.lstatSync(abs);
      if (st.isSymbolicLink() || !st.isFile()) {
        refuse(rel, 'delete refused: not a regular file');
        continue;
      }
      if (sha(fs.readFileSync(abs)) !== snap.files.get(rel)!.sha256) {
        conflict(rel, 'the host file changed while the command ran: not deleted');
        continue;
      }
      fs.unlinkSync(abs);
      rep.deleted.push(rel);
    } catch (e: any) {
      if (e?.code === 'ENOENT') continue;
      refuse(rel, 'delete failed');
    }
  }
  return rep;
}
