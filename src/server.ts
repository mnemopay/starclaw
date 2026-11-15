#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import express from 'express';
import * as dotenv from 'dotenv';
import { createEngine } from './bootstrap';
import { approvalRouter, bearerAuth, HttpApprover } from './channels/http';
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
export function createGateway(engine: StarClawEngine, approver: HttpApprover, apiKey: string | undefined) {
  const auth = bearerAuth(apiKey); // throws ConfigError without a key
  const app = express();
  app.disable('x-powered-by');
  const jobs = new Map<string, Job>();
  let chain: Promise<void> = Promise.resolve();

  app.use((_req, res, next) => {
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'", 'Cache-Control': 'no-store' });
    next();
  });
  app.use(express.static(path.join(__dirname, '..', 'public')));

  const api = express.Router();
  api.use(auth);
  api.use(approvalRouter(approver));
  api.get('/status', (_req, res) => res.json({ tainted: engine.tainted, auditRecords: engine.audit.length, pendingApprovals: approver.pendingCount }));
  api.post('/session/new', (_req, res) => {
    engine.newSession();
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
    chain = chain.then(async () => {
      job.status = 'running';
      try {
        job.result = await engine.executeGoal(goal, { origin: 'owner', originRef: 'http', onLog: (m) => job.logs.push(m) });
      } catch (e: any) {
        job.logs.push(`error: ${e.message}`);
      }
      job.status = 'done';
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
