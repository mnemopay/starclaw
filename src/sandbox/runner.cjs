'use strict';
/**
 * StarClaw sandbox runner. This file runs INSIDE the permission-restricted child process.
 *
 * It is plain CommonJS on purpose: it is executed directly by `node --permission` with read access to this
 * single file. It speaks to the parent only over the IPC channel. Every capability beyond pure computation
 * is a brokered call that the parent routes through the Governor.
 *
 * The JS-level hardening below is defence in depth, NOT the security boundary: the boundary is Node's
 * permission model. The parent probes the combination at startup and refuses to run code if it does not hold.
 */

const send = process.send ? process.send.bind(process) : null;
if (!send) {
  process.stderr.write('runner: no IPC channel\n');
  process.exit(2);
}

// Capture what we need, then remove ambient routes to things the permission model does not cover.
const vm = require('node:vm');
const path = require('node:path');
const origExit = process.exit.bind(process);

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
  try {
    Object.defineProperty(process, 'send', { value: undefined, writable: false, configurable: false });
  } catch {
    /* ignore */
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

process.on('message', (msg) => {
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
    run(msg).catch((e) => finish({ ok: false, error: String((e && e.stack) || e) }));
  }
});

function safeJson(v) {
  try {
    const s = JSON.stringify(v === undefined ? null : v);
    return s === undefined ? 'null' : s;
  } catch (e) {
    return JSON.stringify(String(v));
  }
}

function finish(payload) {
  const sendFn = send;
  const out = { type: 'done', ok: !!payload.ok };
  if (payload.ok) out.value = safeJson(payload.value);
  else out.error = String(payload.error || 'error').slice(0, 4000);
  sendFn(out, () => origExit(0));
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
send({ type: 'ready' });
