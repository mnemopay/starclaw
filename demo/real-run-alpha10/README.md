# A real StarClaw run on alpha.10 (2026-11-19/20)

Same bug and same SDK commit as `demo/real-run` (alpha.9). This directory is a second run on `starclaw@2.0.0-alpha.10`. The model calls were not repeated after the fact. Nothing here was edited to look better.

| | |
|---|---|
| Repo | `mnemopay/mnemopay-sdk` at `5366c69` (v1.17.0). The clone stayed in the run directory and is not in this commit. |
| Bug | `verifyBundle()` accepts a bundle whose last event is duplicated when the event count is odd. The Merkle tree pads an odd layer by repeating the last leaf, so the root does not change. |
| StarClaw | `starclaw@2.0.0-alpha.10` from npm. Not published again for this demo. |
| Sandbox | process layer only. Docker was not used. |
| Approver | the operator, **Claude acting for the maintainer**, through `decisions.json`. Not the maintainer. This package was assembled afterward by Grok from those artifacts. |

## Against the alpha.9 run

Alpha.9 (`demo/real-run`) used 7 attempts. The agent wrote a source fix and did not add the test. Its own cost ceilings summed to 36 cents. The fix reused the existing `root_mismatch` reason.

Alpha.10 used 3 attempts. Cost ceilings: 1 + 1 + 10 cents.

| # | Setup | What happened |
|---|---|---|
| 1 | default `llm.provider: groq` (alpha.10's built-in Groq models; the policy does not name one) | Failed before any work. Groq HTTP 400 `tool_use_failed`: "Tool choice is none, but model called a tool". Job `036718e4-27ea-4757-8541-bec586df46ae`. `llmCostCentsCeil` 1. Not tainted. |
| 2 | same Groq default, run again | Same failure before any work. Job `50266c39-db79-44ea-af43-a65b7c8a4502`. Ceiling 1 cent. |
| 3 | OpenRouter, `anthropic/claude-sonnet-5.5` | Wrote the source fix and the test (`agent-patch.diff`). Four steps were approved. The operator then denied a Docker test step. Job `8ca53ed7-f21d-4fd8-a91b-897376c5e33a` ended `success: false`, error "Denied (human): denied by approver", tainted, ceiling 10 cents. |

The default Groq provider no longer dies with `model_not_found` the way alpha.9's first attempt did. It still cannot complete a goal: both runs died on `tool_use_failed` before a file was read.

## What the patch does

`agent-patch.diff` adds a sequence check after the Merkle root check. If `sequence` is not consecutive from the first event, `verifyBundle` returns `{ ok: false, reason: "sequence_mismatch", index }`. The root computation is unchanged. The new test is `verifyBundle duplicated-last-event tampering` in `tests/audit-chain.test.ts`.

Operator checks after that patch, on the same tree:

* `tsc --noEmit` exited 0 (`tsc.txt`).
* `npm run build` exited 0 (`build.txt`). Alpha.9's suite never had a `dist/`.
* The first `vitest` of `tests/audit-chain.test.ts` failed before any test: npm's optional dependency `@rollup/rollup-win32-x64-msvc` was missing (`targeted-after.txt`). After `npm install @rollup/rollup-win32-x64-msvc --no-save` in the SDK workspace, the same file passed 14/14 (`targeted-pass.txt`, 21:59:32 local).

The full SDK suite then passed: 1454 passed, 3 skipped, 0 failed, in 2070.62s (`full-suite-summary.txt`, process exit 0). Alpha.9's 4 failures were the unbuilt `dist/` tests; this tree was built first, and the patch added 2 tests.

## Signed logs

The two providers used two audit keys. Both logs verify offline.

```bash
npx starclaw audit verify demo/real-run-alpha10/signed-log/audit.jsonl --pubkey-file demo/real-run-alpha10/signed-log/audit.pub
# OK: 61 records verified (chain, signatures, head checkpoint); key pinned
```

That 61-record log is the OpenRouter attempt (`verify.txt`). Flipping `"allowed":true` to `false` on line 10 and verifying the copy fails with `line 10: hash mismatch: record content was modified` (`tamper-verify.txt`). The tamper check also warns that the `.head` file was not copied beside the tampered log, so tail truncation cannot be ruled out on that copy. The original log was not modified.

`signed-log/article12/` is the Article 12 export of the OpenRouter log (`export.txt`). Recomputed from those file bytes, the bundle sha256 is `678e073eb827039c356a5958332f34e9edd800f087ef76a9e11234849b660a4b`. The manifest's audit digest is `47877f7319958705c81bfb515d907f2f0bdefb117c69b99a696a90676168c0dc`. `mission.json` records LLM spend of `$0.096774` from `llm.usage` microcents in this log (the 10 cent ceiling is the job's cap, not this sum).

The Groq attempts are a separate 14-record log, different public key (`signed-log/groq/`, `verify-groq.txt`).

The private keys, `keys.sh`, `node_modules`, and the SDK workspace are not in this commit.
