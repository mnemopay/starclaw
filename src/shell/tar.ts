/**
 * Minimal tar (ustar) writer and a defensive reader. The reader is the parser of a stream produced by code we do
 * NOT trust (whatever ran inside the shell container), so it enforces caps and refuses everything that is not a
 * plain file or directory. It never touches the filesystem: callers decide what to do with the entries.
 */

export interface TarFileIn {
  path: string; // relative, forward slashes
  data?: Buffer; // undefined => directory
  mtimeSec?: number;
}

const BLOCK = 512;

function octal(n: number, len: number): Buffer {
  const b = Buffer.alloc(len, 0);
  const s = n.toString(8).padStart(len - 1, '0');
  if (s.length > len - 1) throw new Error('tar: value too large for header field');
  b.write(s, 0, 'ascii');
  return b;
}

function splitName(p: string): { name: string; prefix: string } {
  if (Buffer.byteLength(p) <= 100) return { name: p, prefix: '' };
  // ustar: split at a '/' so that prefix <= 155 and name <= 100 bytes.
  for (let i = p.length - 1; i > 0; i--) {
    if (p[i] === '/') {
      const prefix = p.slice(0, i);
      const name = p.slice(i + 1);
      if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100 && name.length > 0) return { name, prefix };
    }
  }
  throw new Error(`tar: path too long for ustar: ${p.slice(0, 60)}...`);
}

export function tarEntry(e: TarFileIn): Buffer[] {
  const isDir = e.data === undefined;
  const { name, prefix } = splitName(isDir ? e.path.replace(/\/?$/, '/') : e.path);
  const size = isDir ? 0 : e.data!.length;
  const h = Buffer.alloc(BLOCK, 0);
  h.write(name, 0, 100, 'utf8');
  octal(isDir ? 0o755 : 0o644, 8).copy(h, 100);
  octal(0, 8).copy(h, 108); // uid
  octal(0, 8).copy(h, 116); // gid
  octal(size, 12).copy(h, 124);
  octal(Math.max(0, Math.floor(e.mtimeSec ?? 0)), 12).copy(h, 136);
  h.fill(0x20, 148, 156); // checksum placeholder = spaces
  h.write(isDir ? '5' : '0', 156, 1, 'ascii');
  h.write('ustar\0', 257, 6, 'ascii');
  h.write('00', 263, 2, 'ascii');
  h.write(prefix, 345, 155, 'utf8');
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += h[i];
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  const out: Buffer[] = [h];
  if (!isDir && size > 0) {
    out.push(e.data!);
    const pad = (BLOCK - (size % BLOCK)) % BLOCK;
    if (pad) out.push(Buffer.alloc(pad, 0));
  }
  return out;
}

export function buildTar(files: TarFileIn[]): Buffer {
  const parts: Buffer[] = [];
  for (const f of files) parts.push(...tarEntry(f));
  parts.push(Buffer.alloc(BLOCK * 2, 0));
  return Buffer.concat(parts);
}

export type TarEntryKind = 'file' | 'dir' | 'other';
export interface TarEntryOut {
  path: string;
  kind: TarEntryKind;
  /** Raw typeflag character, for reporting refused entries ('2' symlink, '1' hardlink, '3'/'4' devices, '6' fifo ...). */
  typeflag: string;
  size: number;
  data?: Buffer;
}
export interface TarReadResult {
  entries: TarEntryOut[];
  /** True only if the end-of-archive marker (two zero blocks) was seen: otherwise the stream was cut short. */
  complete: boolean;
  /** Set when the archive violated a cap or was malformed. Callers must treat the whole archive as untrustworthy. */
  error?: string;
}
export interface TarReadLimits {
  maxEntries: number;
  maxTotalBytes: number;
  maxFileBytes: number;
}

function readStr(b: Buffer, off: number, len: number): string {
  const end = b.indexOf(0, off);
  const stop = end >= 0 && end < off + len ? end : off + len;
  return b.toString('utf8', off, stop);
}

function parseOctal(b: Buffer, off: number, len: number): number | undefined {
  if (b[off] & 0x80) return undefined; // base-256 encoding: refused
  const s = b.toString('ascii', off, off + len).replace(/\0.*$/, '').trim();
  if (s === '') return 0;
  if (!/^[0-7]+$/.test(s)) return undefined;
  return parseInt(s, 8);
}

function checksumOk(h: Buffer): boolean {
  const want = parseOctal(h, 148, 8);
  if (want === undefined) return false;
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
  return sum === want;
}

/** Parse pax extended header records ("<len> key=value\n"); only `path` is honoured, a `size` override is refused. */
function parsePax(data: Buffer): { path?: string; size?: number } | undefined {
  const out: { path?: string; size?: number } = {};
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp < 0) return undefined;
    const len = parseInt(data.toString('ascii', i, sp), 10);
    if (!Number.isFinite(len) || len <= 0 || i + len > data.length) return undefined;
    const rec = data.toString('utf8', sp + 1, i + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) {
      const k = rec.slice(0, eq);
      const v = rec.slice(eq + 1);
      if (k === 'path') out.path = v;
      else if (k === 'size') out.size = Number(v);
    }
    i += len;
  }
  return out;
}

export function readTar(buf: Buffer, limits: TarReadLimits): TarReadResult {
  const entries: TarEntryOut[] = [];
  let off = 0;
  let total = 0;
  let longName: string | undefined;
  let paxPath: string | undefined;
  const fail = (error: string): TarReadResult => ({ entries, complete: false, error });
  let zeroBlocks = 0;
  while (off + BLOCK <= buf.length) {
    const h = buf.subarray(off, off + BLOCK);
    if (h.every((x) => x === 0)) {
      zeroBlocks++;
      off += BLOCK;
      if (zeroBlocks >= 2) return { entries, complete: true };
      continue;
    }
    zeroBlocks = 0;
    if (!checksumOk(h)) return fail('tar header checksum mismatch');
    const size = parseOctal(h, 124, 12);
    if (size === undefined) return fail('tar size field uses an unsupported encoding');
    const typeflag = String.fromCharCode(h[156] || 0x30);
    let name = readStr(h, 0, 100);
    if (h.toString('ascii', 257, 263) === 'ustar\0') {
      const prefix = readStr(h, 345, 155);
      if (prefix) name = prefix + '/' + name;
    }
    off += BLOCK;
    const padded = Math.ceil(size / BLOCK) * BLOCK;
    const meta = typeflag === 'L' || typeflag === 'x' || typeflag === 'g' || typeflag === 'K';
    if (!meta && size > limits.maxFileBytes) return fail(`entry larger than the per-file cap (${limits.maxFileBytes} bytes)`);
    if (meta) {
      if (size > 65536) return fail('oversized tar metadata record');
      if (off + padded > buf.length) return fail('tar stream ended inside an entry');
      const data = buf.subarray(off, off + size);
      off += padded;
      if (typeflag === 'L') longName = data.toString('utf8').replace(/\0.*$/, '');
      else if (typeflag === 'x') {
        const px = parsePax(data);
        if (!px) return fail('malformed pax header');
        if (px.size !== undefined) return fail('pax size override is not supported');
        paxPath = px.path;
      }
      continue;
    }
    if (entries.length >= limits.maxEntries) return fail(`more than ${limits.maxEntries} entries`);
    if (longName !== undefined) name = longName;
    if (paxPath !== undefined) name = paxPath;
    longName = undefined;
    paxPath = undefined;
    let kind: TarEntryKind = 'other';
    if (typeflag === '0') kind = 'file';
    else if (typeflag === '5') kind = 'dir';
    const clean = name.replace(/^(\.\/)+/, '').replace(/\/+$/, '');
    if (kind === 'file') {
      if (off + padded > buf.length) return fail('tar stream ended inside a file');
      total += size;
      if (total > limits.maxTotalBytes) return fail(`archive exceeds the total cap (${limits.maxTotalBytes} bytes)`);
      entries.push({ path: clean, kind, typeflag, size, data: Buffer.from(buf.subarray(off, off + size)) });
      off += padded;
    } else {
      // Directories and links carry no payload; other kinds (sparse, devices) may declare one that we must skip.
      const skip = kind === 'dir' || typeflag === '1' || typeflag === '2' ? 0 : padded;
      if (off + skip > buf.length) return fail('tar stream ended inside an entry');
      entries.push({ path: clean, kind, typeflag, size: 0 });
      off += skip;
    }
  }
  return { entries, complete: false };
}
