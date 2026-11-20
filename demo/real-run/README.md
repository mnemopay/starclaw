# A real StarClaw run on a real bug (2026-11-19/20)

Unlike `site/editorial/example-run.json` (real engine, **scripted** model and approver), this run used a
**real model** on a **real open defect**, with a person-in-the-loop approving each step after reading it.
Nothing here was edited to look better: all 7 attempts, including the 6 failures, are in `attempts/`, and
one signed audit chain (`audit/`) covers every attempt.

| | |
|---|---|
| Repo | `mnemopay/mnemopay-sdk` at `5366c69` (v1.17.0), fresh clone in `./workspace/mnemopay-sdk` |
| Bug | `verifyBundle()` accepts a bundle whose last event is duplicated when the event count is odd: the Merkle tree pads odd layers by repeating the last leaf, so the root does not change. mnemopay.com/docs already admits it ("does not catch a duplicated last event"). No GitHub issue was open for it. |
| StarClaw | `starclaw@2.0.0-alpha.9` from npm, driven through `starclaw-server`'s HTTP API (`runner.mjs`) |
| Model | `anthropic/claude-sonnet-5.5` via OpenRouter (`llm.provider: openai-compat`), attempts 4-7 |
| Sandbox | process layer (Node permission model); Docker was not running, so no container layer |
| Approver | the operator: **Claude acting for the maintainer**, deciding through `POST /api/approvals/:id` after reading each request's exact payload. Not the maintainer himself. |
| Cost | 36 cents total, the sum of StarClaw's own per-job ceiling `llmCostCentsCeil` (1+1+1+8+7+13+5; `attempts/*/job.json`) |

## Result

**The agent wrote a correct, minimal fix for the bug. It did not manage to add the test.**

* The approved patch (`agent-patch.diff`, +8 lines in `src/governance/audit-chain.ts`) adds a check after the
  root check: event `sequence` numbers must be consecutive, otherwise `{ ok: false, reason: "root_mismatch", index }`.
  The root computation is unchanged, so roots already anchored on-chain still verify.
  It reuses the existing `root_mismatch` reason instead of adding a new one (no type/API change). A maintainer
  might prefer a dedicated reason; that is a review comment, not a defect.
* `tsc --noEmit`: clean (`tsc.txt`).
* Operator-written check (not by the agent), same 3-event bundle plus a copied last event:
  **before the patch the tampered bundle verifies** (`dupcheck-before.txt`: `expected true to be false`);
  **after the patch it is rejected and the original still verifies** (`dupcheck-after.txt`: 1 passed).
* Full SDK suite on the patched tree: **1448 passed, 4 failed, 3 skipped** (1455 tests, 98 files). The 4 failures
  all load `dist/index.js` (this clone was never built) and fail identically on the unpatched tree, so none is
  caused by the patch (`full-suite-summary.txt`).
* The agent's two tries at adding the test failed: attempt 6 returned a program without
  `module.exports = { execute }` (rejected by the runner after it had already asked to write the test),
  and attempt 7 called `tools.editFile` with `old_string`/`new_string` instead of `find`/`replace`
  (rejected by StarClaw's schema check before anything was written).

## The attempts, honestly

| # | Setup | What happened |
|---|---|---|
| 1 | default policy, provider `groq` | Failed before any work: StarClaw's built-in Groq models (`llama-3.3-70b-versatile`, `llama-3.1-8b-instant`) **no longer exist on Groq** (404 model_not_found). |
| 2 | Groq via openai-compat, `openai/gpt-oss-120b` | Failed: the model emitted a native tool call; Groq returned 400 `tool_use_failed`. |
| 3 | OpenRouter, Sonnet 5.5 + Haiku 5.5 as `smallModel` | Failed with "no choices[0].message.content" before any step, most likely in intent classification: probed separately, Haiku 5.5 at a 5-token cap returns `finish_reason: length` and `content: null`, and the classifier allows 10. |
| 4 | OpenRouter, Sonnet 5.5 only | Read step approved; step 2 program did not parse after 2 repairs (truncated). |
| 5 | same, unchanged goal | Read step approved; step 2 returned no content (hit the output cap). |
| 6 | goal v2: "use small `editFile` steps" | Reads approved; **source fix proposed, approved as a diff, written**; test step failed (program shape). |
| 7 | follow-up goal: add only the test | Two programs approved; both used the wrong `editFile` argument names; schema check refused. |

## What this says about StarClaw (found by this run)

1. **First-run blocker:** the default `groq` provider is dead on arrival. `GroqLLM` hard-codes two models that Groq
   has retired, and `llm.model` is ignored for `provider: groq`. Every new user on the default config fails at the first goal.
2. **1500-token output cap per step** (`generateCode`/`fixCode` in `BackendLLM`) makes whole-file edits impossible;
   attempts 4 and 5 died on it. Real users will hit this on any non-trivial patch.
3. **No `content` on `finish_reason: "length"`** from Claude 5.5 via OpenRouter becomes an opaque
   "no choices[0].message.content string" error; the classifier's 10-token budget is too tight for some models.
4. **Weak tool-argument grounding:** the model guessed `old_string`/`new_string`. The governance held (schema check,
   nothing written), but the agent wasted two approved steps.
5. What worked as designed: every action asked first and showed the exact payload; file writes were shown as a
   diff with the pre-edit sha256; reading repo files marked the session **tainted** and the approvals said so;
   the signed log verifies and a one-field edit is caught.

## Verify it yourself

```bash
npx starclaw audit verify demo/real-run/audit/audit.jsonl --pubkey-file demo/real-run/audit/audit.pub
# OK: 155 records verified (chain, signatures, head checkpoint); key pinned
```

Flipping `"allowed":true` to `false` on line 119 (the approval of the source write) gives
`FAILED: line 119: hash mismatch: record content was modified` (`tamper-verify.txt`).
`audit/article12/` is the EU AI Act Article 12 export of the same log (`starclaw audit export`, `export.txt`).

`real-run.json` uses the same shape as `site/editorial/example-run.json` (`format`, `provenance`, `publicKey`,
`goal`, `input`, `code`, `runs.<name>.{result, approval, output, records, head}`) with one run, `real`,
holding the whole 155-record chain. It is not wired into the site; Codex owns the Signal Room page.
