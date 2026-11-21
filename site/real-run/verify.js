'use strict';
// Verifies the real run's signed audit log in the browser: record hashes, the chain,
// Ed25519 signatures and the signed checkpoint. Same checks as the StarClaw CLI.
const encoder = new TextEncoder();
const statusEl = document.querySelector('#verify-status');
const verifyBtn = document.querySelector('#verify-real');
const tamperBtn = document.querySelector('#tamper-real');
const bytesFromHex = hex => new Uint8Array(hex.match(/../g).map(b => parseInt(b, 16)));
const bytesFromBase64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
const hashHex = async text => [...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)))].map(b => b.toString(16).padStart(2, '0')).join('');
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
}
async function verifyRun(run, publicKeyHex) {
  const key = await crypto.subtle.importKey('raw', bytesFromHex(publicKeyHex), 'Ed25519', false, ['verify']);
  let previous = '0'.repeat(64);
  for (let i = 0; i < run.records.length; i++) {
    const record = run.records[i];
    if (record.seq !== i || record.prev !== previous) throw new Error(`Record ${i}: chain or sequence mismatch`);
    const body = { v: record.v, seq: record.seq, ts: record.ts, prev: record.prev, type: record.type, data: record.data };
    if (await hashHex(canonicalize(body)) !== record.hash) throw new Error(`Record ${i}: content does not match its hash`);
    if (!await crypto.subtle.verify('Ed25519', key, bytesFromBase64(record.sig), encoder.encode(record.hash))) throw new Error(`Record ${i}: invalid signature`);
    previous = record.hash;
  }
  if (!run.records.length || run.head.seq !== run.records.length - 1 || run.head.hash !== previous) throw new Error('Signed checkpoint does not match the log');
  const message = `starclaw-audit-head:${run.head.seq}:${run.head.hash}`;
  if (!await crypto.subtle.verify('Ed25519', key, bytesFromBase64(run.head.sig), encoder.encode(message))) throw new Error('Invalid checkpoint signature');
}
let data;
async function check(tamper) {
  verifyBtn.disabled = tamperBtn.disabled = true;
  statusEl.dataset.result = '';
  try {
    if (!data) data = await fetch('../editorial/real-run.json').then(r => { if (!r.ok) throw new Error('Could not load the run'); return r.json(); });
    if (!crypto.subtle) throw Object.assign(new Error('unsupported'), { name: 'NotSupportedError' });
    const run = structuredClone(data.runs.real);
    if (tamper) {
      const record = run.records.find(r => r.type === 'decision.result' && r.data.decisionId === run.approval.id);
      record.data.allowed = !record.data.allowed;
    }
    statusEl.textContent = tamper ? 'Changing a copy of the approval, then checking…' : 'Checking the signed log…';
    await verifyRun(run, data.publicKey);
    statusEl.textContent = tamper ? 'Unexpected: the changed log passed.' : `Verified: ${run.records.length} signed records and the signed checkpoint.`;
    statusEl.dataset.result = tamper ? 'error' : 'verified';
  } catch (error) {
    if (error.name === 'NotSupportedError') statusEl.textContent = 'This browser cannot verify Ed25519 signatures. Download the run and check it with `starclaw audit verify`.';
    else statusEl.textContent = tamper ? `Changed record rejected. ${error.message}.` : `Verification failed. ${error.message}.`;
    statusEl.dataset.result = tamper ? 'rejected' : 'error';
  } finally {
    verifyBtn.disabled = tamperBtn.disabled = false;
  }
}
verifyBtn.addEventListener('click', () => check(false));
tamperBtn.addEventListener('click', () => check(true));
