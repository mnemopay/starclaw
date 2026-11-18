import * as fs from 'node:fs';
import * as path from 'node:path';
import * as dotenv from 'dotenv';
import { defaultPolicy, parsePolicy, type Policy } from './governance/policy';
import { createLLM } from './llm/factory';
import { scrub } from './llm/http';

/**
 * Guided model setup for `starclaw app` (first run, or `--setup`).
 *
 * Only these fixed presets are offered: the setup API never takes a URL from the browser, so it cannot be used to
 * make this machine call an arbitrary host. Nothing is saved until a real test call to the chosen model succeeds.
 */

export type PresetId = 'groq' | 'anthropic' | 'openai' | 'openrouter' | 'ollama' | 'lmstudio';

export interface Preset {
  id: PresetId;
  label: string;
  provider: Policy['llm']['provider'];
  /** openai-compat base URL (also used to list models). */
  baseUrl?: string;
  /** Env var the key is stored under; undefined = no key (local servers). */
  keyEnv?: string;
  /** Where to get a key (shown to the user). */
  keyUrl?: string;
  /** groq: the model is built in (with its prices), so there is nothing to choose. */
  fixedModel?: string;
  local?: boolean;
}

export const PRESETS: Record<PresetId, Preset> = {
  groq: { id: 'groq', label: 'Groq', provider: 'groq', keyEnv: 'GROQ_API_KEY', keyUrl: 'https://console.groq.com/keys', fixedModel: 'llama-3.3-70b-versatile' },
  anthropic: { id: 'anthropic', label: 'Anthropic (Claude)', provider: 'anthropic', baseUrl: 'https://api.anthropic.com', keyEnv: 'ANTHROPIC_API_KEY', keyUrl: 'https://console.anthropic.com/settings/keys' },
  openai: { id: 'openai', label: 'OpenAI', provider: 'openai-compat', baseUrl: 'https://api.openai.com/v1', keyEnv: 'OPENAI_API_KEY', keyUrl: 'https://platform.openai.com/api-keys' },
  openrouter: { id: 'openrouter', label: 'OpenRouter', provider: 'openai-compat', baseUrl: 'https://openrouter.ai/api/v1', keyEnv: 'OPENROUTER_API_KEY', keyUrl: 'https://openrouter.ai/keys' },
  ollama: { id: 'ollama', label: 'Ollama (on this PC)', provider: 'openai-compat', baseUrl: 'http://127.0.0.1:11434/v1', local: true },
  lmstudio: { id: 'lmstudio', label: 'LM Studio (on this PC)', provider: 'openai-compat', baseUrl: 'http://127.0.0.1:1234/v1', local: true },
};

export function isPresetId(x: unknown): x is PresetId {
  return typeof x === 'string' && Object.prototype.hasOwnProperty.call(PRESETS, x);
}

const MODEL_ID = /^[A-Za-z0-9._:/@-]{1,120}$/; // same rule as policy llm.model
const MAX_MODELS = 300;

/** Keys are pasted by a person: one line of printable ASCII, no spaces, bounded. */
export function validKey(key: unknown): key is string {
  return typeof key === 'string' && key.length >= 8 && key.length <= 400 && /^[\x21-\x7e]+$/.test(key);
}

export interface SetupDeps {
  fetchImpl?: typeof fetch;
  /** Tests point presets at local fakes. */
  presets?: Record<PresetId, Preset>;
}

async function getJson(url: string, headers: Record<string, string>, timeoutMs: number, secrets: string[], fetchImpl: typeof fetch): Promise<any> {
  let res: Response;
  try {
    res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
  } catch (e: any) {
    throw new Error(`could not reach ${new URL(url).host}: ${scrub(String(e?.cause?.code ?? e?.message ?? e), secrets)}`);
  }
  const text = (await res.text()).slice(0, 4_000_000);
  if (!res.ok) throw new Error(`${new URL(url).host} returned HTTP ${res.status}: ${scrub(text.slice(0, 200), secrets)}`);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${new URL(url).host} returned malformed JSON`);
  }
}

function authHeaders(p: Preset, key?: string): Record<string, string> {
  if (!key) return {};
  return p.provider === 'anthropic' ? { 'x-api-key': key, 'anthropic-version': '2023-06-01' } : { authorization: `Bearer ${key}` };
}

/** Model ids the provider itself lists for this key (no model names are baked in except Groq's built-in one). */
export async function listModels(id: PresetId, key: string | undefined, deps: SetupDeps = {}): Promise<string[]> {
  const p = (deps.presets ?? PRESETS)[id];
  if (p.fixedModel) return [p.fixedModel];
  const base = p.baseUrl!.replace(/\/+$/, '');
  const url = p.provider === 'anthropic' ? `${base}/v1/models?limit=1000` : `${base}/models`;
  const j = await getJson(url, authHeaders(p, key), p.local ? 2_000 : 15_000, key ? [key] : [], deps.fetchImpl ?? fetch);
  const ids: string[] = Array.isArray(j?.data) ? j.data.map((m: any) => m?.id).filter((x: unknown): x is string => typeof x === 'string' && MODEL_ID.test(x)) : [];
  return [...new Set(ids)].sort().slice(0, MAX_MODELS);
}

export interface Detected {
  /** Local model servers that answered, with their models. */
  local: Array<{ id: PresetId; label: string; models: string[] }>;
  /** Presets whose key is already in the environment (names only, never values). */
  keysPresent: PresetId[];
}

export async function detect(env: NodeJS.ProcessEnv = process.env, deps: SetupDeps = {}): Promise<Detected> {
  const presets = deps.presets ?? PRESETS;
  const local: Detected['local'] = [];
  await Promise.all(
    (Object.values(presets) as Preset[]).filter((p) => p.local).map(async (p) => {
      try {
        const models = await listModels(p.id, undefined, deps);
        if (models.length) local.push({ id: p.id, label: p.label, models });
      } catch {
        /* not running: not offered as detected */
      }
    }),
  );
  local.sort((a, b) => a.id.localeCompare(b.id));
  const keysPresent = (Object.values(presets) as Preset[]).filter((p) => p.keyEnv && env[p.keyEnv]).map((p) => p.id);
  return { local, keysPresent };
}

/** The llm policy block for a preset + model. Local models cost nothing, so their price is 0 (no placeholder). */
export function llmBlockFor(id: PresetId, model: string | undefined, presets: Record<PresetId, Preset> = PRESETS): Policy['llm'] {
  const p = presets[id];
  const base = defaultPolicy().llm;
  if (p.provider === 'groq') return { ...base, provider: 'groq' };
  if (!model || !MODEL_ID.test(model)) throw new Error('choose a model');
  return {
    ...base,
    provider: p.provider,
    model,
    ...(p.provider === 'openai-compat' ? { baseUrl: p.baseUrl } : {}),
    ...(p.keyEnv && p.keyEnv !== 'OPENAI_API_KEY' && p.keyEnv !== 'ANTHROPIC_API_KEY' ? { apiKeyEnv: p.keyEnv } : {}),
    ...(p.local ? { prices: { inputCentsPerMTok: 0, outputCentsPerMTok: 0 } } : {}),
  };
}

export interface TestResult { ok: boolean; reply?: string; ms: number; error?: string }

/** One real call through the same client the agent will use. */
export async function testModel(id: PresetId, key: string | undefined, model: string | undefined, deps: SetupDeps = {}): Promise<TestResult> {
  const presets = deps.presets ?? PRESETS;
  const p = presets[id];
  const t0 = Date.now();
  try {
    const llm = llmBlockFor(id, model, presets);
    const env: Record<string, string | undefined> = p.keyEnv ? { [p.keyEnv]: key } : {};
    const client = createLLM({ ...llm, timeoutSeconds: 45 }, env, deps.fetchImpl);
    const r = await client.converse('Setup check. Reply with the single word OK.', []);
    return { ok: true, reply: r.value.trim().slice(0, 80), ms: Date.now() - t0 };
  } catch (e: any) {
    return { ok: false, ms: Date.now() - t0, error: scrub(String(e?.message ?? e), key ? [key] : []).slice(0, 400) };
  }
}

/** Set NAME=value in a .env file: replaces an existing NAME= line, otherwise appends. Other lines are untouched. */
export function setEnvVar(envFile: string, name: string, value: string): void {
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(name) || !validKey(value)) throw new Error('refusing to write an invalid env entry');
  const existing = fs.existsSync(envFile) ? fs.readFileSync(envFile, 'utf8') : '';
  const lines = existing.length ? existing.split(/\r?\n/) : [];
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  const idx = lines.findIndex((l) => new RegExp(`^\\s*(export\\s+)?${name}\\s*=`).test(l));
  if (idx >= 0) lines[idx] = `${name}=${value}`;
  else lines.push(`${name}=${value}`);
  fs.writeFileSync(envFile, lines.join('\n') + '\n', { mode: 0o600 });
}

/**
 * Write the model choice into `<home>/starclaw.policy.json` (created from the defaults if missing; every other field
 * of an existing policy is kept) and the key into `<home>/.env`. The policy is validated before anything is written.
 */
export function saveSetup(home: string, id: PresetId, key: string | undefined, model: string | undefined, presets: Record<PresetId, Preset> = PRESETS): { policyFile: string; envFile: string; keyEnv?: string } {
  const p = presets[id];
  if (p.keyEnv && !validKey(key)) throw new Error('a valid API key is required for ' + p.label);
  const policyFile = path.join(home, 'starclaw.policy.json');
  const envFile = path.join(home, '.env');
  const current = fs.existsSync(policyFile) ? JSON.parse(fs.readFileSync(policyFile, 'utf8')) : defaultPolicy();
  const next = { ...current, llm: llmBlockFor(id, model, presets) };
  const text = JSON.stringify(next, null, 2) + '\n';
  parsePolicy(text); // throws PolicyError: nothing written
  if (p.keyEnv) setEnvVar(envFile, p.keyEnv, key!);
  fs.writeFileSync(policyFile, text);
  return { policyFile, envFile, keyEnv: p.keyEnv };
}

/** Values in `<home>/.env` (for "a key is already saved" hints; values never leave this process). */
export function homeEnv(home: string): Record<string, string> {
  const f = path.join(home, '.env');
  return fs.existsSync(f) ? dotenv.parse(fs.readFileSync(f, 'utf8')) : {};
}
