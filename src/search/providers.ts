import type { Policy } from '../governance/policy';

export interface SearchResult {
  title: string;
  url: string;
  snippet: string;
}

export interface SearchRequest {
  url: string;
  headers: Record<string, string>;
}

export interface SearchProvider {
  readonly name: 'searxng' | 'brave';
  /** True for a self-hosted provider that may legitimately live on a private/loopback address (needs policy opt-in). */
  readonly selfHosted: boolean;
  request(query: string, limit: number): SearchRequest;
  parse(body: string, limit: number): SearchResult[];
}

export class SearchConfigError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'SearchConfigError';
  }
}

const INVISIBLE = /[­​-‏‪-‮⁠-⁤⁦-⁩﻿\u{e0000}-\u{e007f}]/gu;

function clean(s: unknown, max: number): string {
  if (typeof s !== 'string') return '';
  return s
    .replace(/<[^>]{0,300}>/g, ' ')
    .replace(INVISIBLE, '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function cleanUrl(s: unknown): string | undefined {
  if (typeof s !== 'string' || s.length > 500) return undefined;
  try {
    const u = new URL(s);
    if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.username || u.password) return undefined;
    return u.toString();
  } catch {
    return undefined;
  }
}

/** Shared by both providers: defensive normalisation of untrusted results. */
export function normalizeResults(raw: unknown[], limit: number, pick: (r: any) => { title: unknown; url: unknown; snippet: unknown }): SearchResult[] {
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    if (out.length >= limit) break;
    if (!r || typeof r !== 'object') continue;
    const p = pick(r);
    const url = cleanUrl(p.url);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ title: clean(p.title, 200), url, snippet: clean(p.snippet, 500) });
  }
  return out;
}

function parseJson(body: string): any {
  try {
    return JSON.parse(body);
  } catch {
    throw new Error('search provider returned malformed JSON');
  }
}

export class BraveProvider implements SearchProvider {
  readonly name = 'brave' as const;
  readonly selfHosted = false;
  /** `base` is overridable for tests only; production always talks to api.search.brave.com. */
  constructor(private readonly apiKey: string, private readonly base = 'https://api.search.brave.com') {
    if (!apiKey) throw new SearchConfigError('the Brave API key environment variable (default BRAVE_API_KEY) is not set');
  }
  request(query: string, limit: number): SearchRequest {
    const u = new URL('/res/v1/web/search', this.base);
    u.searchParams.set('q', query);
    u.searchParams.set('count', String(limit));
    u.searchParams.set('text_decorations', 'false');
    return { url: u.toString(), headers: { 'X-Subscription-Token': this.apiKey, accept: 'application/json' } };
  }
  parse(body: string, limit: number): SearchResult[] {
    const j = parseJson(body);
    const arr = Array.isArray(j?.web?.results) ? j.web.results : [];
    return normalizeResults(arr, limit, (r) => ({ title: r.title, url: r.url, snippet: r.description }));
  }
}

export class SearxngProvider implements SearchProvider {
  readonly name = 'searxng' as const;
  readonly selfHosted = true;
  private readonly base: URL;
  constructor(baseUrl: string) {
    try {
      this.base = new URL(baseUrl);
    } catch {
      throw new SearchConfigError('search.searxngUrl is not a valid URL');
    }
    if (this.base.protocol !== 'http:' && this.base.protocol !== 'https:') throw new SearchConfigError('search.searxngUrl must be http(s)');
    if (this.base.username || this.base.password) throw new SearchConfigError('search.searxngUrl must not contain credentials');
  }
  request(query: string, limit: number): SearchRequest {
    const u = new URL(this.base.toString().replace(/\/+$/, '') + '/search');
    u.searchParams.set('q', query);
    u.searchParams.set('format', 'json');
    u.searchParams.set('safesearch', '1');
    void limit; // SearXNG has no portable result-count parameter; the limit is applied when parsing
    return { url: u.toString(), headers: { accept: 'application/json' } };
  }
  parse(body: string, limit: number): SearchResult[] {
    const j = parseJson(body);
    const arr = Array.isArray(j?.results) ? j.results : [];
    return normalizeResults(arr, limit, (r) => ({ title: r.title, url: r.url, snippet: r.content }));
  }
}

/** Returns undefined when search is disabled. Throws SearchConfigError when it is enabled but unusable. */
export function createSearchProvider(cfg: Policy['search'], env: Record<string, string | undefined> = process.env): SearchProvider | undefined {
  if (cfg.provider === 'none') return undefined;
  if (cfg.provider === 'brave') return new BraveProvider(env[cfg.apiKeyEnv ?? 'BRAVE_API_KEY'] ?? '');
  if (!cfg.searxngUrl) throw new SearchConfigError('search.provider is "searxng" but search.searxngUrl is not set');
  return new SearxngProvider(cfg.searxngUrl);
}
