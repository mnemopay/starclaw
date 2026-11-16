'use strict';
/**
 * StarClaw sandbox runner. Runs INSIDE the isolated child: either a `node --permission` process (IPC transport)
 * or a locked-down container (stdio transport, because no IPC fd crosses a container boundary).
 *
 * It is plain CommonJS on purpose: it is executed directly with read access to this single file. It speaks to the
 * parent only over the transport. Every capability beyond pure computation is a brokered call that the parent
 * routes through the Governor.
 *
 * The JS-level hardening below is defence in depth, NOT the security boundary: the boundaries are the container
 * (when used) and Node's permission model. The parent probes the combination at startup and refuses to run code
 * if it does not hold.
 *
 * Stdio transport: frames are lines `@sc:<nonce>:<json>` on stdout; the nonce arrives in the first stdin line
 * and lives only in this closure. See frames.ts for the forgery analysis.
 */

const fs = require('node:fs');
const vm = require('node:vm');
const origExit = process.exit.bind(process);
const writeSync = fs.writeSync.bind(fs);

const stdioMode = typeof process.send !== 'function';
const ipcSend = stdioMode ? null : process.send.bind(process);
let nonce = null; // stdio mode only

function writeAll(fd, str) {
  const buf = Buffer.from(str, 'utf8');
  let off = 0;
  while (off < buf.length) {
    try {
      off += writeSync(fd, buf, off, buf.length - off);
    } catch (e) {
      if (e && e.code === 'EAGAIN') continue; // non-blocking pipe full: retry
      throw e;
    }
  }
}

function send(obj, cb) {
  if (!stdioMode) return ipcSend(obj, cb);
  // Leading newline: guarantees the frame starts a line even if generated code left a partial line on stdout.
  writeAll(1, '\n@sc:' + nonce + ':' + JSON.stringify(obj) + '\n');
  if (cb) cb();
}

function hardenProcess(enabled) {
  if (!enabled) return;
  // process.kill() and process._debugProcess() are NOT blocked by --permission (both verified on Node 25.9 / Windows):
  // they can signal, or switch on the inspector of, any same-user process. Node's docs also list _debugProcess as ungated.
  const deny = () => {
    const e = new Error('process.kill is disabled in the StarClaw sandbox');
    e.code = 'ERR_ACCESS_DENIED';
    throw e;
  };
  for (const k of ['kill', '_kill', '_debugProcess']) {
    try {
      Object.defineProperty(process, k, { value: deny, writable: false, configurable: false });
    } catch {
      /* ignore */
    }
  }
  if (!stdioMode) {
    try {
      Object.defineProperty(process, 'send', { value: undefined, writable: false, configurable: false });
    } catch {
      /* ignore */
    }
  }
}

let nextId = 1;
const waiting = new Map();

function call(name, args) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    waiting.set(id, { resolve, reject });
    send({ type: 'call', id, name, args });
  });
}

function onMessage(msg) {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'result') {
    const w = waiting.get(msg.id);
    if (!w) return;
    waiting.delete(msg.id);
    if (msg.ok) w.resolve(msg.value);
    else {
      const e = new Error(String(msg.error || 'broker call failed'));
      e.code = msg.code || 'ERR_BROKER';
      w.reject(e);
    }
    return;
  }
  if (msg.type === 'run') {
    if (stdioMode) {
      if (nonce !== null) return; // only the first run message (it carries the nonce) is honoured
      if (typeof msg.nonce !== 'string' || msg.nonce.length < 16) {
        process.stderr.write('runner: missing nonce\n');
        origExit(2);
      }
      nonce = msg.nonce;
    }
    run(msg).catch((e) => finish({ ok: false, error: String((e && e.stack) || e) }));
  }
}

function safeJson(v) {
  try {
    const s = JSON.stringify(v === undefined ? null : v);
    return s === undefined ? 'null' : s;
  } catch (e) {
    return JSON.stringify(String(v));
  }
}

let finished = false;
function finish(payload) {
  if (finished) return;
  finished = true;
  const out = { type: 'done', ok: !!payload.ok };
  if (payload.ok) out.value = safeJson(payload.value);
  else out.error = String(payload.error || 'error').slice(0, 4000);
  try {
    send(out, () => origExit(0));
  } catch {
    origExit(1);
  }
  // Safety net if the IPC flush callback never fires.
  setTimeout(() => origExit(0), 2000).unref();
}

async function run(msg) {
  hardenProcess(!msg.skipHardening);
  const tools = Object.create(null);
  for (const name of msg.tools || []) {
    tools[name] = (args) => call(name, args === undefined ? {} : args);
  }
  Object.freeze(tools);
  const module_ = { exports: {} };
  // Generated code contract: define `async function execute()` and export it via module.exports.
  const wrapper = new vm.Script('(function (module, exports, tools, require) {\n' + msg.code + '\n;return module.exports;\n})', {
    filename: 'generated.js',
  });
  const fn = wrapper.runInThisContext();
  const exported = fn(module_, module_.exports, tools, require);
  let target = exported && typeof exported.execute === 'function' ? exported.execute : null;
  if (!target && typeof module_.exports === 'function') target = module_.exports;
  if (!target) throw new Error('generated code must export an async function `execute` via module.exports = { execute }');
  const value = await target();
  finish({ ok: true, value });
}

process.on('uncaughtException', (e) => finish({ ok: false, error: String((e && e.stack) || e) }));
process.on('unhandledRejection', (e) => finish({ ok: false, error: String((e && e.stack) || e) }));

if (stdioMode) {
  // Parent -> child frames: one JSON object per line on stdin. The very first line is the run message.
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      onMessage(msg);
    }
  });
  process.stdin.on('end', () => {
    if (nonce === null) origExit(3);
  });
} else {
  process.on('message', onMessage);
  send({ type: 'ready' });
}
