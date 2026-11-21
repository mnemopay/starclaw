// Drives one real StarClaw run through starclaw-server's HTTP API.
// Approvals are NOT automatic: each pending request is written to
// approvals-pending.json and waits until the operator writes a decision
// into decisions.json ({ "<id>": "approve" | "deny" }).
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';

const PORT = 3123;
const KEY = randomBytes(24).toString('hex');
const base = `http://127.0.0.1:${PORT}/api`;
const H = { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' };
const goal = fs.readFileSync('goal.txt', 'utf8').trim();
const log = (o) => fs.appendFileSync('run-events.jsonl', JSON.stringify({ at: new Date().toISOString(), ...o }) + '\n');

const srv = spawn(process.execPath, ['node_modules/starclaw/dist/server.js'], {
  env: { ...process.env, STARCLAW_API_KEY: KEY, PORT: String(PORT), STARCLAW_POLICY: 'starclaw.policy.json' },
  stdio: ['ignore', fs.openSync('server.log', 'a'), fs.openSync('server.log', 'a')],
});
fs.writeFileSync('server.pid', String(srv.pid));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const api = async (path, opts = {}) => (await fetch(base + path, { headers: H, ...opts })).json();

for (let i = 0; ; i++) {
  try { await api('/status'); break; } catch { if (i > 60) throw new Error('server did not start'); await sleep(1000); }
}
const { id } = await api('/goal', { method: 'POST', body: JSON.stringify({ goal }) });
log({ event: 'goal_submitted', jobId: id, goal });

const seen = new Set();
const decided = new Set();
let job;
while (true) {
  const { approvals } = await api('/approvals');
  for (const a of approvals) if (!seen.has(a.id)) { seen.add(a.id); log({ event: 'approval_requested', ...a }); }
  fs.writeFileSync('approvals-pending.json', JSON.stringify(approvals, null, 2));
  let decisions = {};
  try { decisions = JSON.parse(fs.readFileSync('decisions.json', 'utf8')); } catch {}
  for (const a of approvals) {
    const d = decisions[a.id];
    if (d && !decided.has(a.id)) {
      decided.add(a.id);
      const r = await api(`/approvals/${a.id}`, { method: 'POST', body: JSON.stringify({ decision: d }) });
      log({ event: 'approval_decided', id: a.id, decision: d, decidedBy: 'operator (Claude acting for the maintainer)', response: r });
    }
  }
  job = await api(`/jobs/${id}`);
  fs.writeFileSync('job.json', JSON.stringify(job, null, 2));
  if (job.status === 'done') break;
  await sleep(2000);
}
log({ event: 'job_done', jobId: id });
srv.kill();
