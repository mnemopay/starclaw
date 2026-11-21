# StarClaw real run: alpha.13 fix, default Groq (2026-11-21)

Same repo, bug and goal as `demo/real-run-alpha10` / `-alpha11` / the alpha.12 run: `mnemopay/mnemopay-sdk` at
`5366c69`, `verifyBundle()` accepts a bundle whose last event was duplicated (odd event count). Goal text: `groq/goal.txt`.

**Build:** packed from commit `5d08182` (branch `fix/alpha13`, merged to main as `7d0e887`). Its package.json still said
2.0.0-alpha.12; the code is the alpha.13 fix. **Provider:** default Groq (`openai/gpt-oss-120b`, classification
`openai/gpt-oss-20b`), with the new default `llm.requestTokenLimit` of 7000. **Attempts:** 1 (the only one run).

## Result: no 413 any more, but the bug was not fixed

| | alpha.12 (same goal) | this run |
|---|---|---|
| Read both files before editing | yes | yes (one read-only program, approved) |
| Replan request after the reads | 9,665 tokens, **HTTP 413** from Groq | fitted to 7000: **6,399 chars of the observation trimmed** (head + tail kept, marker added), request accepted |
| Next program | none (413) | written, but **does not parse**: `Identifier 'AuditChain' has already been declared`, still broken after 2 repair attempts (one repair waited 11 s on a Groq 429) |
| Files written | none | none |
| Job result | `success: false` | `success: false` (`generated code does not parse after 2 repair attempts`) |
| Memory note proposed | none | none |
| LLM cost | 1 cent | 1 cent (ceiling) |

The size problem is fixed: the trim is visible in the audit log as `llm.retry {kind: "context-trimmed", limitTokens:
7000, omittedChars: 6399, what: "replan"}`. What still fails is the model: Groq's free `gpt-oss-120b` produced a
program that redeclares an identifier and could not repair it. For code changes, use a stronger model; on
alpha.10, Claude Sonnet 5.5 via OpenRouter fixed this bug and wrote the test in one attempt.

## Approvals

One approval request: an `exec` of a 670-character read-only program (reads `src/governance/audit-chain.ts` and
`tests/audit-chain.test.ts`, returns them as an observation). Approved by the operator (**Claude acting for the
maintainer**, not Jeremiah) after reading the full payload, which was shown whole with its sha256.

## Signed log

`groq/signed-log/audit.jsonl` (+ `.head`, `audit.pub`):

- `starclaw audit verify --pubkey <audit.pub> audit.jsonl` → `OK: 27 records verified (chain, signatures, head checkpoint); key pinned`
- Changing the approval decision (line 9, `approve` → `deny`) → `FAILED: line 9: hash mismatch: record content was modified`
