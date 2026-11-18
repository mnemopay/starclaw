#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import express from 'express';
import * as dotenv from 'dotenv';
import { createEngine } from './bootstrap';
import { approvalRouter, bearerAuth, HttpApprover } from './channels/http';
import { isSessionId, Transcript } from './channels/transcript';
import type { GoalResult, StarClawEngine } from './engine';

interface Job {
  id: string;
  goal: string;
  status: 'queued' | 'running' | 'done';
  logs: string[];
  result?: GoalResult;
}

/**
 * HTTP gateway. EVERYTHING under /api requires the bearer key (constant-time compare; construction throws if no
 * key is configured). The static page is public but contains no secrets and no way to act without the key.
 * Whoever holds the key is the owner: goals submitted here run with origin "owner" and approvals can be answered.
 */
export interface GatewayOptions {
  /** Where the console conversation is kept (`<stateDir>/console`). Without it, no transcript is written. */
  transcriptDir?: string;
}

/** Text shown in the chat for a finished goal: the reply, else output/result, else the failure. */
export function replyText(r: GoalResult | undefined, logs: string[]): { kind: 'agent' | 'error' | 'denied'; text: string } {
  if (!r) return { kind: 'error', text: logs[logs.length - 1] ?? 'the goal did not finish' };
  if (r.denied) return { kind: 'denied', text: `Not allowed: ${r.error ?? 'denied by policy'}` };
  if (!r.success) return { kind: 'error', text: `Failed: ${r.error ?? 'unknown error'}` };
  const parts = [r.reply, r.stdout?.trimEnd(), r.result !== undefined && r.result !== null ? (typeof r.result === 'string' ? r.result : JSON.stringify(r.result, null, 2)) : undefined].filter((s) => s);
  return { kind: 'agent', text: parts.join('\n\n') || 'Done.' };
}

export function createGateway(engine: StarClawEngine, approver: HttpApprover, apiKey: string | undefined, gopts: GatewayOptions = {}) {
  const auth = bearerAuth(apiKey); // throws ConfigError without a key
  const app = express();
  app.disable('x-powered-by');
  const jobs = new Map<string, Job>();
  let chain: Promise<void> = Promise.resolve();
  const transcript = gopts.transcriptDir ? new Transcript(gopts.transcriptDir) : undefined;

  // Live events for the console: an authenticated fetch() stream (not EventSource, so the key stays in a header).
  const streams = new Set<express.Response>();
  const emit = (event: string, data: unknown) => {
    const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const s of streams) s.write(frame);
  };
  const status = () => ({ tainted: engine.tainted, auditRecords: engine.audit.length, pendingApprovals: approver.pendingCount, sessionId: transcript?.sessionId ?? null });
  approver.subscribe?.(() => {
    emit('approvals', approver.list());
    emit('status', status());
  });

  app.use((_req, res, next) => {
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", 'Cache-Control': 'no-store' });
    next();
  });
  app.use(express.static(path.join(__dirname, '..', 'public')));

  const api = express.Router();
  api.use(auth);
  api.use(approvalRouter(approver));
  api.get('/status', (_req, res) => res.json({ tainted: engine.tainted, auditRecords: engine.audit.length, pendingApprovals: approver.pendingCount }));
  api.get('/stream', (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.flushHeaders();
    streams.add(res);
    res.write(`event: status\ndata: ${JSON.stringify(status())}\n\n`);
    res.write(`event: approvals\ndata: ${JSON.stringify(approver.list())}\n\n`);
    const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
    req.on('close', () => {
      clearInterval(ping);
      streams.delete(res);
    });
  });
  api.get('/transcript', (_req, res) => res.json({ sessionId: transcript?.sessionId ?? null, entries: transcript?.read() ?? [] }));
  api.get('/sessions', (_req, res) => res.json({ sessions: transcript?.sessions() ?? [] }));
  api.get('/sessions/:id', (req, res) => {
    const id = String(req.params.id);
    if (!transcript || !isSessionId(id)) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    res.json({ sessionId: id, readOnly: true, entries: transcript.read(id) });
  });
  api.post('/session/new', (_req, res) => {
    if (engine.newSession() === false) {
      res.status(409).json({ error: 'A goal is active or queued. Wait for it to finish before starting a new session.' });
      return;
    }
    transcript?.rotate();
    emit('session', { sessionId: transcript?.sessionId ?? null });
    emit('status', status());
    res.json({ ok: true });
  });
  api.post('/goal', express.json({ limit: '64kb' }), (req, res) => {
    const goal = req.body?.goal;
    if (typeof goal !== 'string' || !goal.trim() || goal.length > 8000) {
      res.status(400).json({ error: 'goal must be a non-empty string up to 8000 chars' });
      return;
    }
    const job: Job = { id: randomUUID(), goal, status: 'queued', logs: [] };
    jobs.set(job.id, job);
    const userEntry = transcript?.append('user', goal, { jobId: job.id });
    emit('message', userEntry ?? { at: new Date().toISOString(), kind: 'user', text: goal, jobId: job.id });
    chain = chain.then(async () => {
      job.status = 'running';
      emit('job', { jobId: job.id, status: job.status });
      try {
        job.result = await engine.executeGoal(goal, {
          origin: 'owner',
          originRef: 'http',
          onLog: (m) => {
            job.logs.push(m);
            emit('log', { jobId: job.id, line: m });
          },
        });
      } catch (e: any) {
        job.logs.push(`error: ${e.message}`);
      }
      job.status = 'done';
      const r = replyText(job.result, job.logs);
      const tainted = job.result?.tainted;
      const entry = transcript?.append(r.kind, r.text, { jobId: job.id, tainted }) ?? { at: new Date().toISOString(), kind: r.kind, text: r.text, jobId: job.id, tainted };
      emit('message', entry);
      emit('job', { jobId: job.id, status: job.status });
      emit('status', status());
    });
    res.status(202).json({ id: job.id });
  });
  api.get('/jobs/:id', (req, res) => {
    const j = jobs.get(String(req.params.id));
    if (!j) {
      res.status(404).json({ error: 'not found' });
      return;
    }
    res.json(j);
  });
  app.use('/api', api);
  return app;
}

async function main() {
  dotenv.config({ quiet: true } as any);
  const apiKey = process.env.STARCLAW_API_KEY;
  bearerAuth(apiKey); // fail closed on a missing/weak key BEFORE touching anything else
  const approver = new HttpApprover();
  const engine = createEngine({ policy: process.env.STARCLAW_POLICY }, approver);
  const app = createGateway(engine, approver, apiKey); // fails closed here
  await engine.boot();
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.STARCLAW_HOST ?? '127.0.0.1';
  app.listen(port, host, () => console.log(`starclaw-server: http://${host}:${port} (bearer auth required for /api)`));
}

if (require.main === module) main().catch((e) => { console.error(`starclaw-server: ${e.message}`); process.exit(1); });
