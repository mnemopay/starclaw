# The same real run, on StarClaw 2.0.0-alpha.10 (2026-11-20)

A re-run of [`../real-run/`](../real-run/README.md) (alpha.9) after the alpha.10 fixes (current Groq
defaults, `llm.maxOutputTokens` default 8192, clear output-limit errors). Same repo, same bug, the **original**
goal text (`goal.txt` = alpha.9's `goal-v1`, without the "work in small steps" workaround alpha.9 needed),
run once on each provider. Every attempt is in `*/attempts/`; nothing was retried silently.

| | |
|---|---|
| Repo | `mnemopay/mnemopay-sdk` at `5366c69` (v1.17.0), fresh clone from GitHub per provider |
| Bug | `verifyBundle()` accepts a bundle whose last event is duplicated when the event count is odd (Merkle padding repeats the last leaf, so the root is unchanged) |
| StarClaw | `2.0.0-alpha.10`, packed from the `v2.0.0-alpha.10` tag (npm still had alpha.9; nothing was published) and driven through `starclaw-server`'s HTTP API (`runner.mjs`, unchanged from alpha.9) |
| Sandbox | process layer only; Docker was deliberately not started |
| Approver | the operator: **Claude acting for the maintainer**, deciding each request through `POST /api/approvals/:id` (`decide.sh`). Not the maintainer himself. |

## alpha.9 vs alpha.10

| | alpha.9 (`../real-run`) | alpha.10, default Groq | alpha.10, OpenRouter Sonnet 5.5 |
|---|---|---|---|
| Attempts | 7 (goal rewritten once, then a follow-up goal) | 2, both failed identically | **1** |
| Source fix written | yes (attempt 6) | no | **yes** |
| Test written | never | no | **yes, in the same step** |
| Approvals | 9 approve, 0 deny | none reached | 4 approve, 1 deny |
| LLM cost (StarClaw's ceiling) | 36 cents | 1 + 1 cents | 10 cents |

## Default Groq (`groq/`)

`llm: { "provider": "groq" }`, so alpha.10's new defaults (`openai/gpt-oss-120b` / `openai/gpt-oss-20b`).
**Both attempts failed before any step**, with the same Groq error:

```
HTTP 400 tool_use_failed: "Tool choice is none, but model called a tool"
failed_generation: {"name": "tools.listDir", "arguments": {"path": "./mnemopay-sdk"}}
```

gpt-oss reads the prompt's `tools.listDir(...)` API and emits a *native* tool call instead of a JavaScript
program; Groq rejects it because the request sends no tools. alpha.9's attempt 2 hit the same thing with
`gpt-oss-120b` set by hand. So alpha.10 fixed the 404 (retired models) but **the default Groq configuration still
cannot complete an agent job**: a new user who picks Groq in setup fails on the first goal.
The signed log for both attempts verifies (`groq/verify.txt`: 14 records).

## OpenRouter, Claude Sonnet 5.5 (`openrouter/`)

Same policy as alpha.9's final attempts (`attempts/1/starclaw.policy.json`).

1. **exec** (read the two files): approved.
2. **exec** (one 4,491-char program doing both edits): approved. See the truncation finding below.
3. **fs.write** `src/governance/audit-chain.ts`: approved. +12/-1: a new `sequence_mismatch` reason and a check,
   after the unchanged root check, that event `sequence` numbers are consecutive.
4. **fs.write** `tests/audit-chain.test.ts`: approved. +30: one test that a duplicated-last-event bundle has the
   *same root* and is now rejected with `sequence_mismatch`, one that untampered bundles of 1, 2, 3, 4, 5, 7 events
   and a custom `sequence_start` still verify.
5. **shell.exec** (run vitest in the container): **denied**, because Docker was intentionally off. A denial ends the
   job by design, so the job reports `success: false`; both files were already written.

Checks run by the operator, not the agent (`agent-patch.diff` is the exact change):

* `tsc --noEmit`: clean (`tsc.txt`). `npm run build`: clean (`build.txt`), so this time `dist/` exists.
* The agent's test **against the unpatched source**: `1 failed | 13 passed` (`expected true to be false`;
  `targeted-before.txt`). **With the patch**: `14 passed` (`targeted-after.txt`). The test catches the bug.
* Full SDK suite without `tests/stress/**`: **88 files passed, 1 skipped; 1423 tests passed, 3 skipped, 0 failed** (`full-suite-nostress.txt`).
* Signed log: `OK: 61 records verified (chain, signatures, head checkpoint); key pinned` (`verify.txt`).
  Flipping `"allowed":true` to `false` in the human approval of the source write (line 47) gives
  `line 47: hash mismatch: record content was modified` (`tamper-verify.txt`).
* Article 12 export with the pinned key: 61 events, bundle sha256 `a6c098e9…` (`export.txt`, `signed-log/article12/`).

Stress tests: in a first full-suite run, `stress-300k/500k/1m` failed only on `expect(p99).toBeLessThan(500)`
(p99 670-800 ms on a heavily loaded 8 GB laptop running other agents) and took ~30 minutes, so that run was cut off
by a timeout. Those files never import the audit chain. The suite was re-run without `tests/stress/**`.

## StarClaw findings from this run (not fixed here)

1. **Default Groq still fails** (above): gpt-oss emits native tool calls and Groq returns 400. Either send a
   system message that forbids tool calls / handle `tool_use_failed`, or pick a default Groq model that follows the
   program format.
2. **Approval text is cut at 3,000 characters** (`dist/governance/types.js`: `... [N more chars not shown]`).
   The approver saw only the first 3,000 of the 4,491-char program in step 2. Alpha.10's larger output cap makes
   programs longer, so this now matters.
3. **Whole-file writes show the start of the file, not a diff.** Steps 3 and 4 used `writeFile`; each approval
   showed the first 3,000 bytes of the new file, so the actual change (near the end) was not visible on the
   approval screen. The operator approved step 3 because the exact edit was visible in the step 2 program,
   and checked both writes with `git diff` right after approving. alpha.9's `editFile` path did show a diff.
   Approval screens should show a diff for `fs.write` when the file already exists.
4. Denying a single step ends the whole job. That is safe, but the agent cannot continue after "no, don't run
   that", for example to skip running tests.

## Reproduce

```bash
npx starclaw audit verify demo/real-run-alpha10/openrouter/signed-log/audit.jsonl \
  --pubkey-file demo/real-run-alpha10/openrouter/signed-log/audit.pub
```
