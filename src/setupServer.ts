import * as path from 'node:path';
import express from 'express';
import { bearerAuth } from './channels/http';
import { detect, homeEnv, isPresetId, listModels, PRESETS, saveSetup, testModel, validKey, type PresetId, type SetupDeps } from './setup';

export interface SetupAppOptions {
  apiKey: string;
  home: string;
  /** Called after a tested model was saved: start the agent. A throw is reported to the page. */
  onSaved: () => Promise<void>;
  deps?: SetupDeps;
  env?: NodeJS.ProcessEnv;
}

/**
 * The setup page and its API. Everything under /api needs the console key (the same bearer rule as the gateway).
 * The browser picks a preset id and pastes a key; it never supplies a URL.
 */
export function createSetupApp(o: SetupAppOptions) {
  const auth = bearerAuth(o.apiKey);
  const env = o.env ?? process.env;
  const presets = o.deps?.presets ?? PRESETS;
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", 'Cache-Control': 'no-store' });
    next();
  });
  app.get('/', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'setup.html')));

  const api = express.Router();
  api.use(auth);
  api.use(express.json({ limit: '16kb' }));

  /** A key from the request, else one already saved in the home .env or the environment. */
  const keyFor = (id: PresetId, body: any): string | undefined => {
    const p = presets[id];
    if (!p.keyEnv) return undefined;
    if (body?.key !== undefined && body.key !== '') {
      if (!validKey(body.key)) throw Object.assign(new Error('that does not look like an API key (one line, no spaces)'), { status: 400 });
      return body.key;
    }
    return homeEnv(o.home)[p.keyEnv] ?? env[p.keyEnv];
  };
  const presetOf = (body: any): PresetId => {
    if (!isPresetId(body?.preset)) throw Object.assign(new Error('unknown provider'), { status: 400 });
    return body.preset;
  };
  const wrap = (fn: (req: express.Request) => Promise<unknown>) => async (req: express.Request, res: express.Response) => {
    try {
      res.json(await fn(req));
    } catch (e: any) {
      res.status(e?.status ?? 502).json({ error: String(e?.message ?? e).slice(0, 400) });
    }
  };

  let saving = false;
  let configured = false;

  api.get('/setup/status', wrap(async () => {
    const saved = homeEnv(o.home);
    return {
      configured,
      presets: Object.values(presets).map((p) => ({ id: p.id, label: p.label, local: !!p.local, needsKey: !!p.keyEnv, keyUrl: p.keyUrl, fixedModel: p.fixedModel ?? null, keySaved: !!(p.keyEnv && (saved[p.keyEnv] || env[p.keyEnv])) })),
      detected: await detect(env, o.deps),
    };
  }));
  api.post('/setup/models', wrap(async (req) => {
    const id = presetOf(req.body);
    const key = keyFor(id, req.body);
    if (presets[id].keyEnv && !key) throw Object.assign(new Error('paste your API key first'), { status: 400 });
    return { models: await listModels(id, key, o.deps) };
  }));
  api.post('/setup/test', wrap(async (req) => {
    const id = presetOf(req.body);
    return testModel(id, keyFor(id, req.body), req.body?.model, o.deps);
  }));
  api.post('/setup/save', wrap(async (req) => {
    if (configured) throw Object.assign(new Error('already configured; reload the page'), { status: 409 });
    if (saving) throw Object.assign(new Error('a save is already in progress'), { status: 409 });
    saving = true;
    try {
      const id = presetOf(req.body);
      const key = keyFor(id, req.body);
      // The server repeats the test itself: nothing is saved on the browser's word that it passed.
      const t = await testModel(id, key, req.body?.model, o.deps);
      if (!t.ok) throw Object.assign(new Error(`the model did not answer: ${t.error}`), { status: 400 });
      const saved = saveSetup(o.home, id, key, req.body?.model, presets);
      if (saved.keyEnv && key) env[saved.keyEnv] = key;
      await o.onSaved();
      configured = true;
      return { ok: true, test: t };
    } finally {
      saving = false;
    }
  }));
  app.use('/api', api);
  return app;
}
