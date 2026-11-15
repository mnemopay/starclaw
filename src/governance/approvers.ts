import { ApprovalAnswer, ApprovalRequest, Approver, describeRequest } from './types';

/** Denies everything. Equivalent to having no approver, but explicit. */
export class DenyAllApprover implements Approver {
  readonly name = 'deny-all';
  async request(): Promise<ApprovalAnswer> {
    return 'deny';
  }
}

export type Ask = (prompt: string, signal: AbortSignal) => Promise<string>;

/**
 * Terminal approver. `ask` is injected so the CLI can reuse its single readline interface.
 * Only an explicit "y" / "yes" approves; empty input, EOF, abort and anything else deny.
 */
export class CliApprover implements Approver {
  readonly name = 'cli';
  constructor(private readonly ask: Ask, private readonly print: (s: string) => void = (s) => console.log(s)) {}

  async request(req: ApprovalRequest, signal: AbortSignal): Promise<ApprovalAnswer> {
    this.print('\n' + '='.repeat(72) + '\n' + describeRequest(req) + '\n' + '='.repeat(72));
    const secs = Math.max(1, Math.round((req.expiresAt - Date.now()) / 1000));
    try {
      const answer = (await this.ask(`Approve? [y/N] (auto-deny in ${secs}s) `, signal)).trim().toLowerCase();
      return answer === 'y' || answer === 'yes' ? 'approve' : 'deny';
    } catch {
      return 'deny';
    }
  }
}
