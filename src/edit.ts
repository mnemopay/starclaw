/**
 * Pure text-editing helpers for tools.applyPatch / tools.editFile: unified-diff application that refuses anything
 * ambiguous, an exact find/replace, a diff generator for the approval prompt, and text/EOL detection.
 * Nothing here touches the filesystem.
 */

export const EDIT_LIMITS = {
  maxFileBytes: 1_000_000,
  maxPatchBytes: 200_000,
  maxResultBytes: 2_000_000,
  maxHunks: 500,
} as const;

export type Eol = 'lf' | 'crlf' | 'none';

export type TextCheck = { ok: true; text: string; bom: boolean; eol: Eol } | { ok: false; reason: string };

/** Decode a file as UTF-8 text, refusing binary content and mixed line endings. */
export function readText(buf: Buffer): TextCheck {
  const head = buf.subarray(0, 8192);
  if (head.includes(0)) return { ok: false, reason: 'file looks binary (contains NUL bytes)' };
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf);
  } catch {
    return { ok: false, reason: 'file is not valid UTF-8 text' };
  }
  let bom = false;
  if (text.charCodeAt(0) === 0xfeff) {
    bom = true;
    text = text.slice(1);
  }
  let crlf = 0;
  let lf = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 13) {
      if (text.charCodeAt(i + 1) === 10) {
        crlf++;
        i++;
      } else return { ok: false, reason: 'file contains a bare CR (old-Mac line endings): refusing to guess' };
    } else if (c === 10) lf++;
  }
  if (crlf && lf) return { ok: false, reason: `file has mixed line endings (${crlf} CRLF, ${lf} LF): refusing to guess` };
  return { ok: true, text: crlf ? text.replace(/\r\n/g, '\n') : text, bom, eol: crlf ? 'crlf' : lf ? 'lf' : 'none' };
}

export function encodeText(lfText: string, eol: Eol, bom: boolean): Buffer {
  const body = eol === 'crlf' ? lfText.replace(/\n/g, '\r\n') : lfText;
  return Buffer.from((bom ? '﻿' : '') + body, 'utf8');
}

interface Hunk {
  oldStart: number;
  oldLines: string[]; // context + removed, in order
  newLines: string[]; // context + added, in order
  noEolOld: boolean;
  noEolNew: boolean;
}

export type PatchResult = { ok: true; result: string; hunks: number } | { ok: false; error: string };

const HUNK_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** Parse a single-file unified diff. Throws Error with a precise message on anything unsupported. */
function parsePatch(patch: string): { hunks: Hunk[]; creates: boolean } {
  const lines = patch.replace(/\r\n/g, '\n').split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  let i = 0;
  let creates = false;
  let sawFileHeader = false;
  const hunks: Hunk[] = [];
  const preamble = (l: string) => /^(diff --git |index |old mode |new mode |similarity |new file mode )/.test(l);
  while (i < lines.length && !lines[i].startsWith('@@')) {
    const l = lines[i];
    if (/^(rename from|rename to|copy from|copy to|deleted file mode|Binary files|GIT binary patch)/.test(l)) throw new Error(`unsupported patch feature: "${l.slice(0, 40)}" (only in-place text edits and file creation are supported)`);
    if (l.startsWith('--- ')) {
      if (sawFileHeader) throw new Error('patch touches more than one file; send one file per call');
      sawFileHeader = true;
      if (l.slice(4).trim().startsWith('/dev/null')) creates = true;
    } else if (l.startsWith('+++ ')) {
      if (l.slice(4).trim().startsWith('/dev/null')) throw new Error('deleting files with a patch is not supported');
    } else if (!preamble(l) && l.trim() !== '') {
      throw new Error(`unexpected line before the first hunk: "${l.slice(0, 60)}"`);
    }
    i++;
  }
  if (i >= lines.length) throw new Error('patch contains no hunks');
  while (i < lines.length) {
    const m = HUNK_RE.exec(lines[i]);
    if (!m) {
      if (lines[i].startsWith('--- ') || lines[i].startsWith('diff --git ')) throw new Error('patch touches more than one file; send one file per call');
      throw new Error(`malformed hunk header: "${lines[i].slice(0, 60)}"`);
    }
    const oldCount = m[2] === undefined ? 1 : Number(m[2]);
    const newCount = m[4] === undefined ? 1 : Number(m[4]);
    const h: Hunk = { oldStart: Number(m[1]), oldLines: [], newLines: [], noEolOld: false, noEolNew: false };
    i++;
    let o = 0;
    let n = 0;
    let last: '+' | '-' | ' ' | undefined;
    while ((o < oldCount || n < newCount || (i < lines.length && lines[i].startsWith('\\'))) && i < lines.length) {
      const l = lines[i];
      const tag = l[0];
      if (tag === '\\') {
        if (last === '-') h.noEolOld = true;
        else if (last === '+') h.noEolNew = true;
        else if (last === ' ') {
          h.noEolOld = true;
          h.noEolNew = true;
        }
        i++;
        continue;
      }
      const body = l.slice(1);
      if (tag === ' ' || (l === '' && o < oldCount && n < newCount)) {
        h.oldLines.push(body);
        h.newLines.push(body);
        o++;
        n++;
        last = ' ';
      } else if (tag === '-') {
        h.oldLines.push(body);
        o++;
        last = '-';
      } else if (tag === '+') {
        h.newLines.push(body);
        n++;
        last = '+';
      } else throw new Error(`malformed hunk body line: "${l.slice(0, 60)}"`);
      i++;
    }
    if (o !== oldCount || n !== newCount) throw new Error(`hunk line counts do not match its header (@@ -${m[1]},${oldCount} +${m[3]},${newCount} @@)`);
    hunks.push(h);
    if (hunks.length > EDIT_LIMITS.maxHunks) throw new Error(`more than ${EDIT_LIMITS.maxHunks} hunks`);
  }
  return { hunks, creates };
}

function findBlock(file: string[], block: string[], from: number): number[] {
  const hits: number[] = [];
  if (block.length === 0) return hits;
  outer: for (let s = from; s + block.length <= file.length; s++) {
    for (let k = 0; k < block.length; k++) if (file[s + k] !== block[k]) continue outer;
    hits.push(s);
    if (hits.length > 1) break;
  }
  return hits;
}

/**
 * Apply a unified diff to LF-normalised text. Strict: every context and removed line must match exactly, first at
 * the position the hunk header states, otherwise at a UNIQUE position in the file; ambiguous or missing matches are
 * refusals. No whitespace fuzz. One file per patch.
 */
export function applyUnifiedDiff(origLf: string, patch: string, fileExists: boolean): PatchResult {
  if (Buffer.byteLength(patch) > EDIT_LIMITS.maxPatchBytes) return { ok: false, error: `patch exceeds ${EDIT_LIMITS.maxPatchBytes} bytes` };
  let parsed: ReturnType<typeof parsePatch>;
  try {
    parsed = parsePatch(patch);
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
  if (parsed.creates) {
    if (fileExists && origLf.length > 0) return { ok: false, error: 'patch creates a file but the file already exists and is not empty' };
  } else if (!fileExists) return { ok: false, error: 'file does not exist (use a creation patch with "--- /dev/null")' };

  const endsNl = origLf.endsWith('\n') || origLf === '';
  const file = origLf === '' ? [] : (endsNl ? origLf.slice(0, -1) : origLf).split('\n');
  const out: string[] = [];
  let cursor = 0; // index into `file` already copied
  let delta = 0;
  let finalNl = endsNl;
  let touchedEnd = false;
  for (let hi = 0; hi < parsed.hunks.length; hi++) {
    const h = parsed.hunks[hi];
    let at = h.oldStart - 1 + delta;
    if (h.oldLines.length === 0) at = Math.min(Math.max(h.oldStart, 0) + delta, file.length); // pure insertion: "-N,0" inserts AFTER line N
    const matchesHere = h.oldLines.length === 0 ? true : at >= cursor && at + h.oldLines.length <= file.length && h.oldLines.every((l, k) => file[at + k] === l);
    if (!matchesHere) {
      const hits = findBlock(file, h.oldLines, cursor);
      if (hits.length !== 1) return { ok: false, error: `hunk ${hi + 1} does not apply cleanly (${hits.length === 0 ? 'its context/removed lines were not found' : 'its context matches more than one place'}); nothing was changed` };
      at = hits[0];
    }
    if (at < cursor) return { ok: false, error: `hunk ${hi + 1} overlaps or precedes the previous hunk` };
    for (let k = cursor; k < at; k++) out.push(file[k]);
    for (const l of h.newLines) out.push(l);
    cursor = at + h.oldLines.length;
    delta = out.length - cursor;
    if (cursor === file.length) {
      touchedEnd = true;
      finalNl = !h.noEolNew;
      if (h.noEolOld && endsNl) return { ok: false, error: `hunk ${hi + 1} says the file has no trailing newline but it does` };
    }
  }
  for (let k = cursor; k < file.length; k++) out.push(file[k]);
  if (!touchedEnd) finalNl = endsNl;
  let result = out.join('\n');
  if (out.length && finalNl) result += '\n';
  if (Buffer.byteLength(result) > EDIT_LIMITS.maxResultBytes) return { ok: false, error: `result would exceed ${EDIT_LIMITS.maxResultBytes} bytes` };
  return { ok: true, result, hunks: parsed.hunks.length };
}

export type FindResult = { ok: true; result: string; count: number } | { ok: false; error: string };

/** Exact (non-overlapping) find/replace that must hit exactly `expectCount` places. Inputs are LF-normalised. */
export function editByFind(origLf: string, find: string, replace: string, expectCount: number): FindResult {
  const f = find.replace(/\r\n/g, '\n');
  const r = replace.replace(/\r\n/g, '\n');
  if (f.length === 0) return { ok: false, error: '"find" must not be empty' };
  let count = 0;
  const parts: string[] = [];
  let pos = 0;
  for (;;) {
    const i = origLf.indexOf(f, pos);
    if (i < 0) break;
    count++;
    parts.push(origLf.slice(pos, i), r);
    pos = i + f.length;
    if (count > 10_000) return { ok: false, error: 'too many matches' };
  }
  if (count !== expectCount) return { ok: false, error: `"find" matched ${count} time(s) but expectCount is ${expectCount}; nothing was changed` };
  parts.push(origLf.slice(pos));
  const result = parts.join('');
  if (Buffer.byteLength(result) > EDIT_LIMITS.maxResultBytes) return { ok: false, error: `result would exceed ${EDIT_LIMITS.maxResultBytes} bytes` };
  return { ok: true, result, count };
}

export interface DiffStats {
  diff: string;
  added: number;
  removed: number;
}

/** A single-hunk unified diff (common prefix/suffix trimmed, 3 lines of context). This is what the approver sees. */
export function unifiedDiff(oldLf: string, newLf: string, label: string): DiffStats {
  if (oldLf === newLf) return { diff: '', added: 0, removed: 0 };
  const a = oldLf === '' ? [] : oldLf.split('\n');
  const b = newLf === '' ? [] : newLf.split('\n');
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const ctx = 3;
  const start = Math.max(0, pre - ctx);
  const endA = Math.min(a.length, a.length - suf + ctx);
  const endB = Math.min(b.length, b.length - suf + ctx);
  const removed = a.slice(pre, a.length - suf);
  const added = b.slice(pre, b.length - suf);
  const lines: string[] = [`--- a/${label}`, `+++ b/${label}`, `@@ -${start + 1},${endA - start} +${start + 1},${endB - start} @@`];
  for (let k = start; k < pre; k++) lines.push(' ' + a[k]);
  for (const l of removed) lines.push('-' + l);
  for (const l of added) lines.push('+' + l);
  for (let k = a.length - suf; k < endA; k++) lines.push(' ' + a[k]);
  return { diff: lines.join('\n'), added: added.length, removed: removed.length };
}
