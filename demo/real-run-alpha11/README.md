# The same real run, on StarClaw 2.0.0-alpha.11 with the default Groq setup (2026-11-20)

A re-run of [`../real-run-alpha10/`](../real-run-alpha10/README.md) with the **default Groq provider** (`"llm": { "provider": "groq" }`, no model set) after the alpha.11 fixes. Same repo and bug (`mnemopay/mnemopay-sdk` at `5366c69`: `verifyBundle()` accepts a bundle whose last event is duplicated when the event count is odd), same goal text (`goal.txt`), same policy and runner (`runner.mjs`, driving `starclaw-server`'s HTTP API). Every attempt is in `groq/attempts/`; nothing was retried silently.

| | |
|---|---|
| StarClaw | packed from commit `02c9452` (branch `fix/alpha11`, merged as #29). Its code is identical to the `v2.0.0-alpha.11` tag; the package still said `2.0.0-alpha.10` because the version bump came in the release PR (#30). |
| Model | Groq defaults: `openai/gpt-oss-120b` (code), `openai/gpt-oss-20b` (classification) |
| Approver | the operator: **Claude acting for the maintainer**, deciding each request through `POST /api/approvals/:id` (`decide.sh`). Not the maintainer himself. |
| Sandbox | process layer only (Docker off) |

## Result

| | alpha.10, default Groq | alpha.11, default Groq |
|---|---|---|
| Reaches step 1 | no: `400 tool_use_failed` (2/2 attempts) | **yes** (2/2 attempts) |
| Approvals | none reached | per attempt: `exec` approved, `memory.write` denied |
| Program shown to the approver | n/a | **whole program** (4,372 and 4,675 chars) with `Payload: N chars, sha256 <full>`; alpha.10 cut at 3,000 |
| Fix + test landed | no | **no**: both programs guessed the file's structure without reading it first, found nothing to patch, wrote nothing |
| Cost | 1 + 1 cents | 1 + 1 cents (StarClaw's per-job ceiling) |

* **Attempt 1:** the program searched `audit-chain.ts` with a regex for a one-line `function verifyBundle(...) {` signature. The real signature spans several lines (`export function verifyBundle(` at line 226), so it returned `{ success: false, reason: "verifyBundle not found" }`. Its fix idea was also wrong: it only checked when the event count was odd, but a duplicated bundle has an even count.
* **Attempt 2:** a sounder fix (require consecutive `sequence` numbers), but it looked for a `const events = bundle.events;` line that does not exist and stopped before writing.
* In both attempts StarClaw then proposed a `memory.write` labelled `Completed: ...` with the failed outcome. The operator denied it: it would have recorded a failed run as completed.
* The job's top-level result says `success: true` while the program's own result says `success: false`. Recorded as a StarClaw finding (not fixed in alpha.11).
* Neither attempt used the `continue` / observation step to read the file before writing code. That is the model's choice; the prompt allows it.

**Conclusion:** alpha.11 fixes the plumbing (no `tool_use_failed`, full payloads, hash-bound approvals). It does not make Groq's free models good at this multi-step code change. For code changes, use a stronger model: on alpha.10, Claude Sonnet 5.5 via OpenRouter fixed the bug and added a test that catches it in one attempt (`../real-run-alpha10/openrouter`).

## Signed log

`groq/signed-log/` holds the server's audit log for both attempts (36 records). `groq/verify.txt`:

```
OK: 36 records verified (chain, signatures, head checkpoint); key pinned
```

The `decision.request` records for the two `exec` approvals carry `detailChars` 4372 / 4675 and the SHA-256 of the full program (seq 7 and 25), so each decision is bound to the full payload. Flipping one `"allowed":true` to `false` in a copy gives `line 9: hash mismatch: record content was modified`.

```bash
npx starclaw audit verify demo/real-run-alpha11/groq/signed-log/audit.jsonl \
  --pubkey-file demo/real-run-alpha11/groq/signed-log/audit.pub
```

## Runner change

`waitnext.sh` and `decide.sh` now open their JSON files as UTF-8. On Windows the default codepage could not decode the model's emoji, so the helper printed nothing; the runner itself was unaffected.
