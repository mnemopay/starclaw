import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import type { AddressInfo } from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as dotenv from 'dotenv';
import express from 'express';
import { HttpApprover, MIN_API_KEY_LENGTH } from './channels/http';
import type { StarClawEngine } from './engine';
import { createGateway } from './server';
import type { SetupDeps } from './setup';
import { createSetupApp } from './setupServer';

/**
 * `starclaw app`: the local console for people who do not live in a terminal (what the installer launches).
 *
 * The app home is an ordinary StarClaw project directory: `.env`, `starclaw.policy.json`, `.starclaw/` (keys,
 * audit log) and the workspace all live there, so the CLI tools work on it too. The console key is generated on
 * first run and kept in `<home>/.env`; the browser gets it in the URL FRAGMENT, which browsers never send to a
 * server, and the page removes it from the address bar as soon as it has read it.
 */

export function defaultAppHome(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string {
  if (env.STARCLAW_HOME) return path.resolve(env.STARCLAW_HOME);
  if (platform === 'win32' && env.LOCALAPPDATA) return path.join(env.LOCALAPPDATA, 'StarClaw');
  return path.join(os.homedir(), '.starclaw-app');
}

/**
 * Create the home directory and make sure `<home>/.env` holds a usable STARCLAW_API_KEY. Existing lines are never
 * rewritten; a missing key is appended. A key that is present but too short is an error, not silently replaced.
 */
export function prepareAppHome(home: string): { envFile: string; apiKey: string; created: boolean } {
  fs.mkdirSync(home, { recursive: true });
  const envFile = path.join(home, '.env');
  const existing = fs.existsSync(envFile) ? fs.readFileSync(envFile, 'utf8') : '';
  const current = dotenv.parse(existing).STARCLAW_API_KEY;
  if (current !== undefined) {
    if (current.length < MIN_API_KEY_LENGTH) throw new Error(`STARCLAW_API_KEY in ${envFile} is shorter than ${MIN_API_KEY_LENGTH} characters; fix or delete that line`);
    return { envFile, apiKey: current, created: false };
  }
  const apiKey = randomBytes(32).toString('base64url');
  const sep = existing && !existing.endsWith('\n') ? '\n' : '';
  fs.writeFileSync(envFile, `${existing}${sep}# console key for \`starclaw app\` (generated)\nSTARCLAW_API_KEY=${apiKey}\n`, { mode: 0o600 });
  return { envFile, apiKey, created: true };
}

/** Open a URL in the default browser without a shell (nothing in the URL is ever parsed as a command). */
export function openInBrowser(url: string, platform: NodeJS.Platform = process.platform): void {
  const [cmd, args] =
    platform === 'win32' ? ['rundll32.exe', ['url.dll,FileProtocolHandler', url]]
    : platform === 'darwin' ? ['open', [url]]
    : ['xdg-open', [url]];
  const child = spawn(cmd, args, { detached: true, stdio: 'ignore', shell: false });
  child.on('error', () => console.error(`could not open a browser; open this address yourself:\n  ${url}`));
  child.unref();
}

export interface StartAppOptions {
  apiKey: string;
  /** A running agent. Omit it (and pass `setup`) to start on the guided model setup page instead. */
  engine?: StarClawEngine;
  approver?: HttpApprover;
  /** Setup mode: `boot` starts the agent once a tested model has been saved; the same port then serves the console. */
  setup?: { home: string; boot: () => Promise<{ engine: StarClawEngine; approver: HttpApprover }>; deps?: SetupDeps; env?: NodeJS.ProcessEnv };
  /** 0 (default) = a free port. */
  port?: number;
  /** Called with the console URL (key in the fragment). Default: open the browser. */
  open?: ((url: string) => void) | false;
}

/** The console keeps its conversation next to the agent's other state (`<stateDir>/console`). */
function gatewayOptions(engine: StarClawEngine) {
  return engine.stateDir ? { transcriptDir: path.join(engine.stateDir, 'console') } : {};
}

/** Start the gateway on 127.0.0.1 only. Resolves once listening; `url` carries the key in its fragment. */
export async function startApp(o: StartAppOptions): Promise<{ url: string; port: number; mode: () => 'setup' | 'agent'; close: () => Promise<void> }> {
  if (!o.engine && !o.setup) throw new Error('startApp needs an engine or setup options');
  let mode: 'setup' | 'agent' = o.engine ? 'agent' : 'setup';
  let current: express.RequestHandler = o.engine
    ? createGateway(o.engine, o.approver ?? new HttpApprover(), o.apiKey, gatewayOptions(o.engine))
    : createSetupApp({
        apiKey: o.apiKey,
        home: o.setup!.home,
        deps: o.setup!.deps,
        env: o.setup!.env,
        onSaved: async () => {
          const b = await o.setup!.boot();
          current = createGateway(b.engine, b.approver, o.apiKey, gatewayOptions(b.engine));
          mode = 'agent';
        },
      });
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => current(req, res, next));
  const server = await new Promise<import('node:http').Server>((resolve, reject) => {
    const s = app.listen(o.port ?? 0, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
  const port = (server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}/#key=${encodeURIComponent(o.apiKey)}`;
  if (o.open !== false) (o.open ?? openInBrowser)(url);
  return { url, port, mode: () => mode, close: () => new Promise((r) => server.close(() => r())) };
}
