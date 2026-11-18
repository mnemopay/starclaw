import { createHash, timingSafeEqual } from 'node:crypto';
import express, { NextFunction, Request, Response, Router } from 'express';
import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from '../governance/types';

export class ConfigError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'ConfigError';
  }
}

export const MIN_API_KEY_LENGTH = 16;

/** Constant-time comparison independent of input length: compare SHA-256 digests with timingSafeEqual. */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** Express middleware. Throws ConfigError at construction if no (or a weak) key is configured: fail closed. */
export function bearerAuth(apiKey: string | undefined) {
  if (!apiKey || apiKey.length < MIN_API_KEY_LENGTH) {
    throw new ConfigError(`an API key of at least ${MIN_API_KEY_LENGTH} characters must be configured (STARCLAW_API_KEY); refusing to start without authentication`);
  }
  return (req: Request, res: Response, next: NextFunction) => {
    const h = req.headers.authorization;
    const m = typeof h === 'string' ? /^Bearer (.+)$/.exec(h) : null;
    if (!m || !safeEqual(m[1], apiKey)) {
      res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'unauthorized' });
      return;
    }
    next();
  };
}

interface PendingEntry {
  req: ApprovalRequest;
  resolve: (a: ApprovalAnswer) => void;
}

/** Approver whose pending requests are exposed by approvalRouter(). */
export class HttpApprover implements Approver {
  readonly name = 'http';
  private pending = new Map<string, PendingEntry>();
  private listeners = new Set<() => void>();

  /** Called whenever the pending set changes (new request, decision, expiry). Returns an unsubscribe function. */
  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  private changed() {
    for (const fn of this.listeners) {
      try {
        fn();
      } catch {
        /* a broken listener must not affect approvals */
      }
    }
  }

  request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    return new Promise<ApprovalAnswer>((resolve) => {
      this.pending.set(req.id, { req, resolve });
      signal.addEventListener('abort', () => {
        if (this.pending.delete(req.id)) {
          resolve('deny');
          this.changed();
        }
      });
      this.changed();
    });
  }

  list() {
    return [...this.pending.values()].map(({ req }) => ({
      id: req.id,
      class: req.action.class,
      target: req.action.target,
      summary: req.action.summary,
      cents: req.action.cents,
      tainted: req.provenance.tainted,
      taintSources: req.provenance.sources.map((s) => `${s.kind}: ${s.ref}`),
      escalatedByTaint: req.escalatedByTaint,
      expiresAt: req.expiresAt,
      description: describeRequest(req),
    }));
  }

  decide(id: string, answer: ApprovalAnswer): boolean {
    const e = this.pending.get(id);
    if (!e) return false;
    this.pending.delete(id);
    e.resolve(answer);
    this.changed();
    return true;
  }
  get pendingCount() {
    return this.pending.size;
  }
}

/** Mount under /api. Requires auth to be applied by the caller (see createGateway). */
export function approvalRouter(approver: HttpApprover): Router {
  const r = Router();
  r.get('/approvals', (_req, res) => {
    res.json({ approvals: approver.list() });
  });
  r.post('/approvals/:id', express.json({ limit: '1kb' }), (req, res) => {
    const decision = req.body?.decision;
    if (decision !== 'approve' && decision !== 'deny') {
      res.status(400).json({ error: 'decision must be "approve" or "deny"' });
      return;
    }
    const id = String(req.params.id);
    if (!approver.decide(id, decision)) {
      res.status(404).json({ error: 'no such pending approval' });
      return;
    }
    res.json({ ok: true });
  });
  return r;
}
