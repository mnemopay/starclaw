import * as net from 'node:net';

/** Does `host` match an allow-list entry? Exact host, or `*.sub.example.com` (subdomains only, never the apex). */
export function hostAllowed(host: string, allowed: readonly string[]): boolean {
  const h = host.toLowerCase();
  return allowed.some((d) => {
    const dom = d.toLowerCase();
    if (dom.startsWith('*.')) return h.endsWith(dom.slice(1)) && h.length > dom.length - 1;
    return h === dom;
  });
}

/**
 * The page URL checks that need no network, run BEFORE any request to the browser. Stricter than the browser's own:
 * http/https only, no credentials, no IP literals, no localhost, no explicit non-default port, host on the allow-list.
 * Throws an Error whose message is safe to show the agent.
 */
export function checkBrowserUrl(raw: string, allowed: readonly string[]): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('invalid URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`protocol ${u.protocol} is not allowed (http/https only)`);
  if (u.username || u.password) throw new Error('URLs with embedded credentials are not allowed');
  if (u.port) throw new Error('URLs with an explicit port are not allowed in the browser tool');
  const host = u.hostname;
  if (!host || host === 'localhost' || host.endsWith('.localhost') || net.isIP(host.replace(/^\[|\]$/g, '')) !== 0) {
    throw new Error('the browser tool never visits IP addresses or localhost');
  }
  if (!hostAllowed(host, allowed)) throw new Error(`host ${host} is not in browser.allowedDomains`);
  return u;
}

/** The control API's limits (protocol.rs MAX_SELECTOR_CHARS / MAX_TYPE_CHARS), counted in Unicode code points like Rust's chars(). */
export const MAX_SELECTOR_CHARS = 512;
export const MAX_TYPE_CHARS = 4096;
/** Rust's char::is_control = Unicode category Cc: U+0000-U+001F and U+007F-U+009F. */
const CONTROL_RE = /[\u0000-\u001F\u007F-\u009F]/;
const CONTROL_EXCEPT_NL_TAB_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/;
/** A lone UTF-16 surrogate cannot be sent as valid JSON text to the browser's strict parser. */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const isWellFormed = (s: string) => !LONE_SURROGATE_RE.test(s);

/** Same rules as the browser's validate_selector, checked before anything else. Messages never quote the selector. */
export function checkSelector(s: string): void {
  if (!isWellFormed(s)) throw new Error('selector is not valid Unicode (lone surrogate)');
  if (s.trim() === '' || [...s].length > MAX_SELECTOR_CHARS) throw new Error(`selector must be 1..${MAX_SELECTOR_CHARS} characters and not blank`);
  if (CONTROL_RE.test(s)) throw new Error('selector must not contain control characters');
}

/** Same rules as the browser's validate_type_text. Messages never quote the text. */
export function checkTypeText(t: string): void {
  if (!isWellFormed(t)) throw new Error('text is not valid Unicode (lone surrogate)');
  if ([...t].length > MAX_TYPE_CHARS) throw new Error(`text must be at most ${MAX_TYPE_CHARS} characters`);
  if (CONTROL_EXCEPT_NL_TAB_RE.test(t)) throw new Error('text must not contain control characters other than newline and tab');
}
