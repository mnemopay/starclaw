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
