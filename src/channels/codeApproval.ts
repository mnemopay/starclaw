import { randomInt } from 'node:crypto';
import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from '../governance/types';

/** No 0/O, 1/I/L: codes are typed by a person on a phone. */
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export const CODE_RE = /^\s*(yes|y|approve|no|n|deny)\s+([A-Za-z2-9]{6})\s*$/i;

export function newApprovalCode(): string {
  let s = '';
  for (let i = 0; i < 6; i++) s += ALPHABET[randomInt(ALPHABET.length)];
  return s;
}

/**
 * Approvals for channels without buttons (Signal, email). Each request gets a random 6-character code that is sent ONLY to
 * the owner; the owner answers "yes CODE" or "no CODE". The caller decides whether a reply really came from the owner
 * (Signal: the verified sender number; email: owner address AND the provider's DKIM/DMARC pass). A code works once; a
 * timeout is a deny. Nothing else in a message can approve anything.
 */
export class CodeApprover implements Approver {
  /** Reaches the owner away from the terminal: unattended runs may use it. */
  readonly async = true;
  private pending = new Map<string, { id: string; resolve: (a: ApprovalAnswer) => void }>();

  constructor(readonly name: string, private readonly send: (text: string, subject: string) => Promise<void>, private readonly maxChars = 3500) {}

  async request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    let code = newApprovalCode();
    while (this.pending.has(code)) code = newApprovalCode();
    const footer = `\n\nReply "yes ${code}" to approve or "no ${code}" to deny.\nAuto-deny at ${new Date(req.expiresAt).toISOString()}.`;
    const text = describeRequest(req).slice(0, this.maxChars - footer.length) + footer;
    return new Promise<ApprovalAnswer>((resolve) => {
      // Registered before sending, so a fast reply cannot arrive for a code we do not know yet.
      this.pending.set(code, { id: req.id, resolve });
      const expire = () => {
        if (this.pending.delete(code)) resolve('deny');
      };
      if (signal.aborted) return expire();
      signal.addEventListener('abort', expire);
      this.send(text, `StarClaw approval ${code}: ${req.action.class} ${req.action.target}`.slice(0, 150)).catch(() => {
        // Could not reach the owner: nobody can approve, so it is a deny.
        if (this.pending.delete(code)) resolve('deny');
      });
    });
  }

  /**
   * Feed every message here with `fromOwner` decided by the channel. Returns 'answered' (it resolved a request),
   * 'not-pending' (an owner code that is unknown or already used), 'ignored' (not an approval reply / not the owner).
   */
  handleReply(text: string, fromOwner: boolean): 'answered' | 'not-pending' | 'ignored' {
    const m = CODE_RE.exec(text);
    if (!m || !fromOwner) return 'ignored';
    const code = m[2].toUpperCase();
    const entry = this.pending.get(code);
    if (!entry) return 'not-pending';
    this.pending.delete(code);
    entry.resolve(/^(yes|y|approve)$/i.test(m[1]) ? 'approve' : 'deny');
    return 'answered';
  }

  get pendingCount() {
    return this.pending.size;
  }
}
