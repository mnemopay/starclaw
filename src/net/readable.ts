/**
 * Readable-text extraction from HTML, written as a single linear scan (no nested-quantifier regexes over the whole
 * document) so hostile or malformed input cannot cause catastrophic backtracking. The output is still UNTRUSTED:
 * stripping markup does not make instructions in the text safe, it only makes the content smaller and more readable.
 */

export interface ReadableLink {
  text: string;
  url: string;
}
export interface Readable {
  title: string;
  text: string;
  links: ReadableLink[];
  truncated: boolean;
  /** Characters removed because they are invisible/bidi-control (a common prompt-injection hiding place). */
  invisibleCharsRemoved: number;
}
export interface ReadableOptions {
  maxChars: number;
  maxLinks: number;
  baseUrl?: string;
}

const MAX_INPUT = 3_000_000;
const SKIP_ELEMENTS = new Set(['script', 'style', 'noscript', 'template', 'svg', 'iframe', 'object', 'embed', 'canvas', 'math', 'head']);
const BLOCK = new Set(['p', 'div', 'br', 'li', 'tr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'section', 'article', 'header', 'footer', 'nav', 'main', 'aside', 'ul', 'ol', 'table', 'blockquote', 'pre', 'hr', 'form', 'dl', 'dt', 'dd', 'figure', 'figcaption']);
const VOID = new Set(['br', 'hr', 'img', 'input', 'meta', 'link', 'area', 'base', 'col', 'embed', 'source', 'track', 'wbr']);
// zero-width, bidi controls, word joiners, BOM, soft hyphen, tag characters
const INVISIBLE = /[­​-‏‪-‮⁠-⁤⁦-⁩﻿\u{e0000}-\u{e007f}]/gu;

export function looksLikeHtml(body: string): boolean {
  return /<(?:!doctype html|html|head|body|div|p|a|h[1-6]|span|table|script|title|meta|ul|li)\b/i.test(body.slice(0, 2000));
}

export function looksBinary(s: string): boolean {
  const head = s.slice(0, 4096);
  if (head.includes('\u0000')) return true;
  let bad = 0;
  for (let i = 0; i < head.length; i++) {
    const c = head.charCodeAt(i);
    if (c === 0xfffd || (c < 32 && c !== 9 && c !== 10 && c !== 13)) bad++;
  }
  return head.length > 0 && bad / head.length > 0.1;
}

function decodeEntities(s: string): string {
  if (!s.includes('&')) return s;
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|[a-zA-Z]{2,8});/g, (m, e: string) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (!Number.isFinite(cp) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) || cp === 0) return ' ';
      if (cp < 32 && cp !== 9 && cp !== 10 && cp !== 13) return ' ';
      return String.fromCodePoint(cp);
    }
    switch (e) {
      case 'amp': return '&';
      case 'lt': return '<';
      case 'gt': return '>';
      case 'quot': return '"';
      case 'apos': return "'";
      case 'nbsp': return ' ';
      case 'ndash': return '-';
      case 'mdash': return '-';
      case 'hellip': return '...';
      case 'copy': return '(c)';
      default: return m;
    }
  });
}

/** Total scanning work allowed per document: bounds pathological inputs such as 100k unterminated tags. */
interface Ctx {
  work: number;
  max: number;
  exhausted: boolean;
}

interface Tag {
  name: string;
  closing: boolean;
  selfClosing: boolean;
  attrs: Map<string, string>;
  end: number; // index just past '>'
}

/** Parse the tag starting at html[i] === '<'. Returns undefined when it is not a tag (then '<' is plain text). */
function readTag(html: string, i: number, ctx: Ctx): Tag | undefined {
  if (ctx.exhausted) return undefined;
  const r = readTagInner(html, i);
  ctx.work += Math.max(r.scanned, 1);
  // Hard work budget: each failed tag scan can cost up to 20k chars, so floods of unterminated tags were quadratic.
  if (ctx.work > ctx.max) ctx.exhausted = true;
  return r.tag;
}

function readTagInner(html: string, i: number): { tag?: Tag; scanned: number } {
  let j = i + 1;
  let closing = false;
  if (html[j] === '/') {
    closing = true;
    j++;
  }
  const c = html.charCodeAt(j);
  if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return { scanned: 2 };
  const nameStart = j;
  while (j < html.length && /[A-Za-z0-9:-]/.test(html[j])) j++;
  const name = html.slice(nameStart, j).toLowerCase();
  const attrs = new Map<string, string>();
  const limit = Math.min(html.length, i + 20_000);
  let selfClosing = false;
  while (j < limit) {
    const ch = html[j];
    if (ch === '>') return { tag: { name, closing, selfClosing, attrs, end: j + 1 }, scanned: j - i };
    if (ch === '/' && html[j + 1] === '>') {
      selfClosing = true;
      j++;
      continue;
    }
    if (/\s|\//.test(ch)) {
      j++;
      continue;
    }
    // attribute name
    const as = j;
    while (j < limit && !/[\s=>/]/.test(html[j])) j++;
    const an = html.slice(as, j).toLowerCase();
    while (j < limit && /\s/.test(html[j])) j++;
    let val = '';
    if (html[j] === '=') {
      j++;
      while (j < limit && /\s/.test(html[j])) j++;
      const q = html[j];
      if (q === '"' || q === "'") {
        const e = html.indexOf(q, j + 1);
        if (e < 0 || e >= limit) return { scanned: limit - i };
        val = html.slice(j + 1, e);
        j = e + 1;
      } else {
        const vs = j;
        while (j < limit && !/[\s>]/.test(html[j])) j++;
        val = html.slice(vs, j);
      }
    }
    if (an && attrs.size < 40) attrs.set(an, val);
  }
  return { scanned: limit - i };
}

function isHiddenByAttrs(t: Tag): boolean {
  if (t.attrs.has('hidden')) return true;
  if ((t.attrs.get('aria-hidden') ?? '').toLowerCase() === 'true') return true;
  const st = (t.attrs.get('style') ?? '').toLowerCase().replace(/\s+/g, '');
  return st.includes('display:none') || st.includes('visibility:hidden') || /font-size:0(px|pt|em|%)?(;|$)/.test(st) || st.includes('opacity:0;') || st.endsWith('opacity:0');
}

/** Skip from just after an opening tag to just after its matching close tag (depth-aware for the same name). */
function skipElement(html: string, from: number, name: string, ctx: Ctx): number {
  let depth = 1;
  let i = from;
  while (i < html.length) {
    if (ctx.exhausted) return html.length;
    const lt = html.indexOf('<', i);
    if (lt < 0) return html.length;
    if (html.startsWith('<!--', lt)) {
      const e = html.indexOf('-->', lt + 4);
      i = e < 0 ? html.length : e + 3;
      continue;
    }
    // Raw-text elements: their contents are not markup, so only look for the literal closing tag.
    if (name === 'script' || name === 'style') {
      const m = html.slice(lt, lt + name.length + 3).toLowerCase();
      if (m === `</${name}` || m.startsWith(`</${name}`)) {
        const gt = html.indexOf('>', lt);
        return gt < 0 ? html.length : gt + 1;
      }
      i = lt + 1;
      continue;
    }
    const t = readTag(html, lt, ctx);
    if (!t) {
      i = lt + 1;
      continue;
    }
    if (t.name === name && !VOID.has(name)) {
      if (t.closing) depth--;
      else if (!t.selfClosing) depth++;
      if (depth === 0) return t.end;
    }
    i = t.end;
  }
  return html.length;
}

export function extractReadable(htmlIn: string, o: ReadableOptions): Readable {
  const html = htmlIn.length > MAX_INPUT ? htmlIn.slice(0, MAX_INPUT) : htmlIn;
  const ctx: Ctx = { work: 0, max: Math.max(400_000, html.length * 8), exhausted: false };
  const out: string[] = [];
  const links: ReadableLink[] = [];
  let textFull = false;
  let linkBuf: string | null = null;
  let title = '';
  let outLen = 0;
  let removed = 0;
  let linkHref = '';
  const push = (s: string) => {
    if (!s) return;
    if (!textFull) {
      out.push(s);
      outLen += s.length;
      if (outLen >= o.maxChars * 4) textFull = true;
    }
    if (linkBuf !== null && linkBuf.length < 300) linkBuf += s;
  };
  const closeLink = () => {
    if (linkBuf === null) return;
    const text = linkBuf.replace(/\s+/g, ' ').trim().slice(0, 100);
    if (links.length < o.maxLinks && linkHref) links.push({ text, url: linkHref });
    linkBuf = null;
    linkHref = '';
  };
  let i = 0;
  while (i < html.length && !ctx.exhausted && !(textFull && (o.maxLinks === 0 || links.length >= o.maxLinks))) {
    const lt = html.indexOf('<', i);
    if (lt < 0) {
      push(decodeEntities(html.slice(i)));
      break;
    }
    if (lt > i) push(decodeEntities(html.slice(i, lt)));
    if (html.startsWith('<!--', lt)) {
      const e = html.indexOf('-->', lt + 4);
      i = e < 0 ? html.length : e + 3;
      continue;
    }
    if (html[lt + 1] === '!' || html[lt + 1] === '?') {
      const e = html.indexOf('>', lt);
      i = e < 0 ? html.length : e + 1;
      continue;
    }
    const t = readTag(html, lt, ctx);
    if (!t) {
      push('<');
      i = lt + 1;
      continue;
    }
    i = t.end;
    if (t.closing) {
      if (t.name === 'a') closeLink();
      if (BLOCK.has(t.name)) push('\n');
      else if (t.name === 'td' || t.name === 'th') push(' ');
      continue;
    }
    if (t.name === 'title' && !title) {
      const e = html.toLowerCase().indexOf('</title', i);
      const raw = html.slice(i, e < 0 ? Math.min(html.length, i + 500) : Math.min(e, i + 500));
      title = decodeEntities(raw.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 300);
      i = e < 0 ? i + raw.length : e;
      continue;
    }
    if (t.name === 'head' ) {
      // keep scanning inside <head> only for <title>: skip everything else by skipping the element, but pick up a title first.
      const end = skipElement(html, i, 'head', ctx);
      const inner = html.slice(i, end);
      const m = /<title[^>]*>([\s\S]{0,600}?)<\/title/i.exec(inner.slice(0, 20_000));
      if (m && !title) title = decodeEntities(m[1].replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 300);
      i = end;
      continue;
    }
    if (SKIP_ELEMENTS.has(t.name) || isHiddenByAttrs(t)) {
      if (!t.selfClosing && !VOID.has(t.name)) i = skipElement(html, i, t.name, ctx);
      continue;
    }
    if (t.name === 'a') {
      closeLink();
      const href = t.attrs.get('href');
      if (href && o.maxLinks > 0) {
        try {
          const u = new URL(decodeEntities(href).trim(), o.baseUrl);
          if ((u.protocol === 'http:' || u.protocol === 'https:') && !u.username && !u.password && u.toString().length <= 500) {
            linkHref = u.toString();
            linkBuf = '';
          }
        } catch {
          /* ignore unparsable href */
        }
      }
      continue;
    }
    if (BLOCK.has(t.name)) push('\n');
    else if (t.name === 'td' || t.name === 'th') push(' ');
    else if (t.name === 'img') {
      const alt = (t.attrs.get('alt') ?? '').trim();
      if (alt) push(' ' + decodeEntities(alt).slice(0, 120) + ' ');
    }
  }
  closeLink();
  let text = out.join('');
  text = text.replace(INVISIBLE, () => {
    removed++;
    return '';
  });
  text = text
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ')
    .replace(/[ \t\r\f ]+/g, ' ')
    .replace(/ ?\n ?/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  let truncated = ctx.exhausted;
  if (text.length > o.maxChars) {
    text = text.slice(0, o.maxChars);
    truncated = true;
  }
  const seen = new Set<string>();
  const uniq = links.filter((l) => (seen.has(l.url) ? false : (seen.add(l.url), true))).map((l) => ({ text: l.text.replace(INVISIBLE, ''), url: l.url }));
  return { title: title.replace(INVISIBLE, ''), text, links: uniq, truncated, invisibleCharsRemoved: removed };
}
