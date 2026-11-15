import * as fs from 'node:fs';
import * as path from 'node:path';
import { IdentityRegistry } from '@mnemopay/sdk';

/**
 * Authority that decides whether money may move. The Governor consults it OUTSIDE the generated code,
 * before and after any human approval; a human approval can never override a refusal here.
 *
 * Amounts are integer cents everywhere in StarClaw. The SDK's token API is unit-less, so we use
 * cents as its unit consistently (verified by reading node_modules/@mnemopay/sdk/dist/identity.js:
 * validateToken compares `amount` against maxAmount / maxTotalSpend numerically, with no unit conversion).
 */
export interface SpendAuthority {
  /** Throws nothing; returns ok:false with a reason when the spend is not permitted. */
  check(cents: number, payee: string): { ok: boolean; reason?: string };
  /** Reserve (count) the spend. Must be called before the rail is charged. */
  reserve(cents: number, payee: string): void;
  /** Undo a reservation when the rail charge failed. */
  release(cents: number): void;
  readonly totalReservedCents: number;
}

export function isValidCents(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0;
}

export interface SpendLimits {
  maxPerActionCents: number;
  maxTotalCents: number;
  tokenMinutes: number;
}

/** Spend authority backed by @mnemopay/sdk IdentityRegistry capability tokens. */
export class MnemoPaySpendAuthority implements SpendAuthority {
  private readonly registry = new IdentityRegistry();
  private readonly tokenId: string;
  private reserved = 0;

  /**
   * @param opts.ledgerFile  persists the running total per UTC day, so restarting the process does NOT reset the total cap
   *   (the SDK's token registry itself is in-memory only). Editable by anyone who can write that file: see SECURITY.md.
   */
  constructor(
    agentId: string,
    private readonly limits: SpendLimits,
    private readonly opts: { ownerEmail?: string; ledgerFile?: string; today?: () => string } = {},
  ) {
    const ownerEmail = opts.ownerEmail ?? 'owner@starclaw.invalid';
    this.registry.createIdentity(agentId, 'owner', ownerEmail);
    // Both caps are always set: the SDK treats an undefined cap as "unlimited".
    const token = this.registry.issueToken(agentId, ['charge'], {
      maxAmount: limits.maxPerActionCents,
      maxTotalSpend: limits.maxTotalCents,
      expiresInMinutes: limits.tokenMinutes,
      issuedBy: 'starclaw-governor',
    });
    this.tokenId = token.id;
    const prior = this.loadLedger();
    if (prior > 0) {
      this.registry.recordSpend(this.tokenId, prior);
      this.reserved = prior;
    }
  }

  private day() {
    return (this.opts.today ?? (() => new Date().toISOString().slice(0, 10)))();
  }
  private loadLedger(): number {
    const f = this.opts.ledgerFile;
    if (!f || !fs.existsSync(f)) return 0;
    try {
      const j = JSON.parse(fs.readFileSync(f, 'utf8'));
      return j.day === this.day() && Number.isSafeInteger(j.cents) && j.cents > 0 ? j.cents : 0;
    } catch {
      return this.limits.maxTotalCents; // unreadable ledger: fail closed (treat the cap as used up)
    }
  }
  private saveLedger() {
    const f = this.opts.ledgerFile;
    if (!f) return;
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, JSON.stringify({ day: this.day(), cents: this.reserved }));
  }

  check(cents: number, payee: string) {
    if (!isValidCents(cents)) return { ok: false, reason: 'amount must be a positive integer number of cents' };
    if (cents > this.limits.maxPerActionCents) {
      return { ok: false, reason: `exceeds per-action cap (${cents} > ${this.limits.maxPerActionCents} cents)` };
    }
    // Our own running total in addition to the SDK's: two independent counters must both agree.
    if (this.reserved + cents > this.limits.maxTotalCents) {
      return { ok: false, reason: `exceeds total spend cap (${this.reserved + cents} > ${this.limits.maxTotalCents} cents)` };
    }
    const v = this.registry.validateToken(this.tokenId, 'charge', cents, payee);
    if (!v.valid) return { ok: false, reason: `capability token refused: ${v.reason}` };
    return { ok: true };
  }

  reserve(cents: number, _payee: string) {
    this.registry.recordSpend(this.tokenId, cents);
    this.reserved += cents;
    this.saveLedger();
  }

  release(cents: number) {
    // recordSpend accepts any number; a negative value rolls the reservation back.
    this.registry.recordSpend(this.tokenId, -cents);
    this.reserved -= cents;
    this.saveLedger();
  }

  get totalReservedCents() {
    return this.reserved;
  }
}

/** A payment rail moves real money. The engine never calls one directly: only Governor.spend() does. */
export interface PaymentRail {
  readonly name: string;
  charge(req: { cents: number; payee: string; memo: string; idempotencyKey: string }): Promise<{ id: string }>;
}

/** Default rail: there is no money movement unless the embedding application provides a real rail. */
export class NoPaymentRail implements PaymentRail {
  readonly name = 'none';
  async charge(): Promise<{ id: string }> {
    throw new Error('no payment rail is configured');
  }
}
