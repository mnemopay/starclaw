'use strict';

const tabs = [...document.querySelectorAll('[data-stage]')];
const mobileTabs = matchMedia('(max-width:560px)');
const updateTabOrientation = () => document.querySelector('.run-steps').setAttribute('aria-orientation', mobileTabs.matches ? 'horizontal' : 'vertical');
updateTabOrientation();
mobileTabs.addEventListener('change', updateTabOrientation);
let example;
let outcome = 'approve';
let verificationEpoch = 0;
const status = document.querySelector('#verification-status');
const verifyButton = document.querySelector('#verify-log');
const tamperButton = document.querySelector('#test-tamper');

function showStage(stage, focus = false) {
  tabs.forEach(tab => {
    const selected = tab.dataset.stage === stage;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    document.getElementById(tab.getAttribute('aria-controls')).hidden = !selected;
    if (selected && focus) tab.focus({ preventScroll: true });
  });
}

tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => showStage(tab.dataset.stage));
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else return;
    event.preventDefault();
    showStage(tabs[next].dataset.stage, true);
  });
});
document.querySelectorAll('[data-go-approval]').forEach(button => button.addEventListener('click', () => showStage('approval', true)));

function displayOutcome(answer) {
  if (!example) return;
  outcome = answer;
  verificationEpoch++;
  const run = example.runs[answer];
  const decision = run.records.find(record => record.type === 'decision.result' && record.data.decisionId === run.approval.id);
  if (!decision) throw new Error('The recorded decision is missing');
  const approved = decision.data.allowed;
  document.querySelector('#receipt-title').textContent = approved ? 'Write approved.' : 'Write denied.';
  document.querySelector('#receipt-description').textContent = approved
    ? 'The engine wrote launch-brief.md after the scripted approval. Both the decision and the write result are in the log.'
    : 'The scripted approver denied the request. The engine did not create launch-brief.md. The denial is in the log.';
  document.querySelector('#receipt-decision').textContent = approved ? 'Approved by scripted approver' : 'Denied by scripted approver';
  document.querySelector('#receipt-file').textContent = run.output === null ? 'No' : 'Yes';
  document.querySelector('#receipt-hash').textContent = decision.hash;
  document.querySelector('#signed-record').textContent = JSON.stringify(decision, null, 2);
  document.querySelector('.receipt-icon').textContent = approved ? '✓' : '×';
  document.querySelector('#panel-receipt').dataset.outcome = approved ? 'approved' : 'denied';
  status.textContent = 'The verifier checks record hashes, the chain, Ed25519 signatures, and the signed checkpoint.';
  status.dataset.result = '';
  verifyButton.disabled = false;
  tamperButton.disabled = false;
}

document.querySelectorAll('[data-decision]').forEach(button => button.addEventListener('click', () => {
  displayOutcome(button.dataset.decision);
  showStage('receipt');
  document.querySelector('#receipt-title').setAttribute('tabindex', '-1');
  document.querySelector('#receipt-title').focus({ preventScroll: true });
}));

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
}
const encoder = new TextEncoder();
const bytesFromHex = hex => Uint8Array.from(hex.match(/.{2}/g), pair => parseInt(pair, 16));
const bytesFromBase64 = base64 => Uint8Array.from(atob(base64), char => char.charCodeAt(0));
const hashHex = async text => [...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)))].map(byte => byte.toString(16).padStart(2, '0')).join('');

async function verifyRun(run, publicKeyHex) {
  if (!crypto.subtle) throw new Error('Browser cryptographic verification is unavailable');
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

async function checkExample(tamper) {
  if (!example) return;
  const epoch = ++verificationEpoch;
  const run = structuredClone(example.runs[outcome]);
  if (tamper) {
    const record = run.records.find(record => record.type === 'decision.result' && record.data.decisionId === run.approval.id);
    record.data.allowed = !record.data.allowed;
  }
  verifyButton.disabled = true;
  tamperButton.disabled = true;
  status.textContent = tamper ? 'Changing a copy of the decision, then checking the log…' : 'Checking the recorded log…';
  status.dataset.result = '';
  try {
    await verifyRun(run, example.publicKey);
    if (epoch !== verificationEpoch) return;
    status.textContent = tamper ? 'Unexpected result: the changed log passed.' : `Verified: ${run.records.length} signed records and the signed checkpoint.`;
    status.dataset.result = tamper ? 'error' : 'verified';
  } catch (error) {
    if (epoch !== verificationEpoch) return;
    if (error.name === 'NotSupportedError' || !crypto.subtle) {
      status.textContent = 'This browser cannot verify Ed25519. Download the example and verify it with the StarClaw CLI.';
      status.dataset.result = 'unavailable';
    } else {
      status.textContent = tamper ? `Changed record rejected. ${error.message}.` : `Verification failed. ${error.message}.`;
      status.dataset.result = tamper ? 'rejected' : 'error';
    }
  } finally {
    if (epoch === verificationEpoch) { verifyButton.disabled = false; tamperButton.disabled = false; }
  }
}
verifyButton.addEventListener('click', () => checkExample(false));
tamperButton.addEventListener('click', () => checkExample(true));

async function loadExample() {
  try {
    const response = await fetch('example-run.json');
    if (!response.ok) throw new Error('Recorded example unavailable');
    example = await response.json();
    if (example.format !== 1 || !example.runs.approve || !example.runs.deny) throw new Error('Unrecognized example format');
    document.querySelector('#recorded-goal').textContent = example.goal;
    document.querySelector('#recorded-input').textContent = example.input;
    document.querySelector('#recorded-code').textContent = example.code;
    document.querySelector('#proposed-content').textContent = example.runs.approve.approval.action.detail;
    document.querySelector('#approval-request').textContent = JSON.stringify(example.runs.approve.approval, null, 2);
    displayOutcome('approve');
    document.querySelectorAll('[data-decision]').forEach(button => { button.disabled = false; });
  } catch {
    document.querySelector('#example-provenance').textContent = 'The recorded example could not be loaded. Read the source or try again later.';
    document.querySelector('#recorded-input').textContent = 'Recorded data unavailable. No approval or verification can be replayed.';
    document.querySelector('#proposed-content').textContent = 'Recorded data unavailable.';
  }
}
loadExample();
