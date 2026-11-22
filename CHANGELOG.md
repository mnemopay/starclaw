# Changelog

## 2.0.0-alpha.14 (2026-11-22)

### Added
* **`starclaw audit export` also writes `chain-bundle.json`**, a MnemoPay AuditChain `ChainBundle` v1 built from the verified signed log. Its `merkle_root` is what `verifyBundle` from `@mnemopay/sdk/governance/audit-chain` recomputes, and what on-chain anchoring sinks take (the Article 12 bundle is sealed by a manifest digest, which those sinks can't use). The CLI prints the root and the file's sha256; `meta.article12_bundle_sha256` links it to the Article 12 bundle written alongside.
* The bundle is deterministic: event `id` is derived from the record hash, `sequence` = seq, `occurred_at` = ts, `built_at` = the last record's ts, and the original seq/prev/hash/sig are carried in each event's payload so the Ed25519 signatures can still be checked from the bundle. The export is refused unless the SDK's `verifyBundle` accepts it, and an unverified log is refused as before. The StarClaw signed log stays the record of truth; this is an export.
* Shared fixture `tests/fixtures/starclaw-chainbundle/v1` (signed log, pinned root and sha256). Context: mnemopay/mnemopay-sdk#19.

### Tests
* 12 new or changed (`tests/chainBundle.test.ts`, `tests/article12.test.ts`): verifyBundle accepts; changing, removing or reordering an event, or the root, fails with `root_mismatch`; signatures re-verify from the bundle; same log gives the same root; fixture matches byte for byte. Also checked against @mnemopay/sdk 1.17.0 (what a fresh install resolves). Not tested against a live anchoring sink.

## 2.0.0-alpha.13 (2026-11-21)

**This is the first npm release since alpha.11: 2.0.0-alpha.12 was tagged and released on GitHub but never published to npm, so its changes (below) reach npm users with this version.**

### Fixed
* **Requests fit the provider's per-request limit.** On Groq's free tier (which counts input + `max_tokens` against ~8,000 tokens per minute) the replan after two file reads was 9,665 tokens and Groq answered HTTP 413 (alpha.12 real run). Each request is now fitted before it is sent: the largest earlier messages are shortened first, keeping head + tail around an explicit marker (`[N chars omitted to fit the model's request limit; re-read with tools.readFile({ path, startLine, endLine }) ...]`). The system prompt, the current instruction and the note after an observation (denials) are never cut. The output cap is lowered to what is left.
* **HTTP 413 is recovered once.** A 413 (or a 400 `context_length_exceeded`) is a new `LlmError` kind `request-too-large`: the request is shrunk to 80% of the provider's stated limit and resent once; a second one fails with a message that names `llm.requestTokenLimit`.

### Added
* **`llm.requestTokenLimit`** (policy, optional, 2,000 to 2,000,000): most tokens (input estimate + max output) one request may carry. Default **7000 for provider `groq`**, no limit for other providers. Raise it on a paid Groq tier.
* **`tools.readFile({ path, startLine, endLine })`**: 1-based inclusive line ranges, returning `totalLines`, so the model can fetch what a trim left out. Without a range it behaves as before.
* Trims and resends are audited as `llm.retry` with `kind` `context-trimmed` / `request-too-large`, `omittedChars` and `limitTokens`.

### Real run (default Groq, same goal, 1 attempt; branch `demo/real-run-alpha13`)
* No more 413: the replan was fitted to 7000 tokens (6,399 chars of the observation trimmed) and accepted. The bug was still not fixed: Groq's `gpt-oss-120b` then wrote a program that does not parse (`Identifier 'AuditChain' has already been declared`) and could not repair it in 2 attempts; nothing was written, `success: false`, no memory note. Signed log: 27 records verify with the pinned key; changing the approval decision fails with `hash mismatch`. For code changes, use a stronger model.

### Tests
* 14 new (`tests/alpha13.test.ts`). Full suite 617/617 without Docker; the Docker container suites were not re-run for this release.

## 2.0.0-alpha.12 (2026-11-20, GitHub release only; never published to npm)

### Fixed
* **The top-level result is honest.** A program that returns `{ success: false }`, or a step that had a denied action (even one the program caught), is no longer reported as a successful goal; the program's result is kept on the failure. Sub-agents keep their contract (the parent receives the child's full result and decides). `ok: false` is deliberately not read as failure, because tool results such as `tools.spawnAgent`'s carry an `ok` field and are often returned verbatim.
* **No "Completed:" memory for failed runs.** Only a successful run reaches the memory step, so a failed run proposes no memory note.
* **LLM retries are visible.** `tool_use_failed` and HTTP 429 retries are returned with each LLM result and recorded in the audit log as `llm.retry` (`what`, `kind`, `waitSeconds`). alpha.11 could not show whether its retry fired.

### Added
* **Read before edit** (`agent.requireReadBeforeEdit`, default `true`). `writeFile` / `editFile` / `applyPatch` on an EXISTING file that the job has not read (or written itself) is refused before any approval or write, audited as `agent.edit-unread`, and the model is told to call `tools.readFile` first. The code-generation prompt says the same for every provider. New files are unaffected.
* **Deny-continue, opt-in** (`agent.continueAfterDeny`, default `false`, so a denial still ends the job unless you turn it on). When on, a denied step is returned to the model as feedback and the job may replan within `agent.maxSteps`; the identical action (same payload hash, or the same program) is refused automatically if proposed again, never shown to a human twice; every new action still goes through approval. Audited as `agent.denied-replan` / `agent.denied-repeat`.

### Changed
* Behaviour change for callers that read `success`: runs whose final step had a caught denial now report `success: false` with `denied` set (four existing tests were updated accordingly).

### Real run (default Groq, same goal as `demo/real-run-alpha11`, 1 attempt)
* The model now read both files before editing (alpha.11 guessed their structure). It still did not fix the bug: after the reads, the replan request (9,665 tokens) exceeded Groq's free-tier limit of 8,000 tokens per minute and Groq answered HTTP 413; the job ended `success: false` and proposed no memory note. On Groq's free tier a multi-file code change does not fit; use a stronger or higher-tier model for code changes.

### Known, not fixed
* Observations sent back to the model are not trimmed to the provider's per-request token limit, so small free tiers (Groq on-demand, 8k TPM) can reject the replan after a large file read (HTTP 413, not retried).
* Tests: 13 new (`tests/alpha12.test.ts`) plus retry assertions in `tests/llm.test.ts`. Full suite 603/603 without Docker; the Docker container suites were not re-run for this release.



## 2.0.0-alpha.11 (2026-11-20)

### Fixed
* **Default Groq no longer dies before step 1.** On alpha.10, `openai/gpt-oss-120b` answered the tool documentation in the code-generation prompt with a *native* tool call (`tools.listDir`), which Groq rejects with HTTP 400 `tool_use_failed` because no tools are declared. The prompt now says plainly that there is no native function calling, and the OpenAI-compatible backend (Groq included) retries once after `tool_use_failed` with a correction; the rejected call's input is counted (as roughly the retry's input, an over-estimate) so LLM budgets stay conservative. A second `tool_use_failed` is an error.
* **HTTP 429 is retried.** Groq's free tier limits tokens per minute, and StarClaw's prompt is large enough that the next call inside a minute was refused. OpenAI-compatible providers now wait for `Retry-After` (default 20 s, each wait capped at 60 s) and retry up to `llm.rateLimitRetries` times (new policy field, default 3, 0 to 10).
* **Approvals show the whole action.** The plain-text approval cut every payload at 3,000 characters, so an approver saw only part of a 4,491-character program (alpha.10 real run). Payloads are now shown up to 20,000 characters, always with `Payload: N chars, sha256 <hash of the FULL payload>`; anything longer ends with an explicit `[N more chars HIDDEN here ...]` notice saying where to see all of it. `GET /api/approvals` returns the full `detail` and `detailSha256`. The audit log records `detailChars` and `detailSha256` for every decision, so a decision is bound to the full payload even where the stored copy is cut (16,000 chars).
* **`fs.write` approvals show a diff.** Replacing an existing text file now shows a unified diff (old -> new) instead of the start of the new file, so a change near the end of a long file is visible; new files (and non-text content) show the full new content.

### Changed
* **Setup prefers what you already have; Groq is not "the default".** `starclaw app` setup now recommends, in order: an Anthropic key, an OpenRouter key, an OpenAI key (in the environment or the app's `.env`), a running Ollama / LM Studio server with models, an existing Groq key. That choice is preselected and explained. With nothing found, Groq is only *suggested* as the free option, never silently chosen. The policy schema default is still `provider: "groq"`, so existing policies keep working. The README now recommends a strong model for code changes and reports the real-run evidence.

### Real run (branch `demo/real-run-alpha11`)
* Default Groq on this build ran the alpha.10 demo goal end to end with approvals: 2 attempts, no `tool_use_failed`, full 4,372- and 4,675-character programs shown for approval. Neither attempt fixed the bug: each program guessed the file's structure without reading it first, found nothing to patch and wrote nothing (it failed safely). For code changes use a stronger model (alpha.10: Claude Sonnet 5.5 via OpenRouter, one attempt).

### Known, not fixed
* A denial still ends the job. A job whose program returns `{ success: false }` is reported `success: true` at the top level, and a memory note labelled "Completed:" is proposed for it (the approver can deny it, as in the real run).
* Tests: 16 new (`tests/llm.test.ts`, `tests/approvals-alpha11.test.ts`, `tests/setup.test.ts`). Full suite 590/590 without Docker; container + sandbox suites 102 with Docker (2 timing-based shell write-back race tests failed once under load and passed 17/17 when re-run alone).

## 2.0.0-alpha.10 (2026-11-20)



### Fixed

* **The default Groq setup works again.** Groq no longer serves `llama-3.3-70b-versatile` or `llama-3.1-8b-instant` on its on-demand tier (404 `model_not_found`, checked against Groq's live model list on 2026-11-19), so every install on the default `groq` provider failed on its first goal, and `llm.model` was ignored for `groq`. Groq now runs through the same OpenAI-compatible backend as the other providers: defaults `openai/gpt-oss-120b` (code) and `openai/gpt-oss-20b` (intent classification) at Groq's list prices on 2026-11-19 (15/60 and 8/30 cents per million tokens; the 20b input price of $0.075 is rounded up). `llm.model`, `llm.smallModel` and `llm.prices` override them; a model with no known or configured price uses the conservative placeholder. `groq-sdk` is no longer a dependency.

* **Output cap per step: 1500 -> 8192 tokens, and configurable.** New policy field `llm.maxOutputTokens` (default 8192, 256 to 131072) for code generation and repair. 1500 cut whole-file edits off mid-program.

* **Clear error when a model hits the cap.** A response that stops at the length limit (`finish_reason: "length"`, Anthropic `stop_reason: "max_tokens"`) with code cut off or no text at all is now an `LlmError` of kind `output-limit` that names the cap and how to raise it (or that the run's LLM budget limited it), instead of "no choices[0].message.content string". Truncated code is never run. Intent classification gets 256 tokens (reasoning models spent 31 to 84 tokens answering one word and returned nothing at 10) and falls back to `task`, the governed path, if it is still cut off. Chat keeps partial text.

* Tests: 10 new in `tests/llm.test.ts` (Groq defaults and overrides, the cap and its policy bound, truncation for both providers). Full suite 619/619 with Docker. Checked live against Groq with the default policy: classification, code generation and chat.



## 2.0.0-alpha.9 (2026-11-18)



### Added

* **Guided model setup** in `starclaw app`. With no usable model (for example no key yet, as on a fresh install) the app opens a setup page instead of exiting; `--setup` forces it. The page detects Ollama and LM Studio running on this PC (with their models), takes a key for Groq, Anthropic, OpenAI or OpenRouter (with a link to get one), lists the models that key can use live from the provider (no model names are baked in except Groq's built-in one), and **runs a real test call before anything can be saved**. Saving repeats the test on the server, validates the policy, writes the key to `<home>/.env` and the model to `<home>/starclaw.policy.json` (other policy fields and `.env` lines are kept; local models are priced at 0), then starts the agent on the same port: the page lands in the console, already signed in. Setup only offers fixed providers: the browser never supplies a URL, so the setup API cannot be used to make this PC call an arbitrary host. Everything under `/api` needs the console key. A broken policy file is still an error, not a reason to open setup.

* Tests: `tests/setup.test.ts` (6, against a fake OpenAI-compatible server, including key scrubbing from provider errors and "nothing saved when the model does not answer"); `tests/app.test.ts` updated (the CLI opens setup instead of exiting; a broken policy still exits 1). Checked by hand in a real browser against a fake Ollama: detect, test, save, console.

* **Chat console.** `starclaw app` now opens a conversation instead of a one-goal form: your messages and StarClaw's replies, live progress while it works, and approvals as cards in the conversation the moment they are asked (Allow once / Deny). Live updates come over `/api/stream`, read with `fetch()` so the console key stays in a header. The conversation is kept per session in `<stateDir>/console/*.jsonl` (owner-only); **New session** starts a fresh one and **History** shows earlier sessions read-only. Earlier sessions are deliberately NOT fed back into the agent: content it read before (tainted) cannot slip into a clean session. Replies built from untrusted content are marked. The signed audit log stays the record of what the agent did.
* Tests: `tests/console.test.ts` (5: transcript files and id validation, live event order, approvals appearing and clearing, auth on every new endpoint). Checked in a real browser: send, reply, new session, history.
* **Governed MCP.** `tools.mcpList({ server? })` and `tools.mcpCall({ server, tool, args })` for MCP servers **the owner declares** in the new policy block `mcp` (disabled by default; stdio or http; the agent can never add a server). Every call is the new action class `mcp.call` (default `ask`; target `server/tool`, so rules like `{ class: "mcp.call", target: "github/list_*", verdict: "allow" }` work; never auto-allowed when tainted or unattended): the approver sees server, tool and the exact arguments, and the decision and result size are audited (never the result text). Results and tool lists are untrusted and taint the session, because tool descriptions are a known injection channel ("tool poisoning"). Optional per-server `tools` allow-list (others hidden and refused before anyone is asked), `timeoutSeconds`, `maxResultChars`. stdio servers start with a minimal environment (the MCP SDK's safe defaults plus only the env var NAMES you list), so your model keys and tokens are not inherited; they still run on your PC outside the sandbox, and `starclaw doctor` says so. http servers: https only (http to localhost), optional bearer token from a named env var, redirects refused. Sub-agents and registry skills get the tools only when `mcp.call` is in their capabilities. `@modelcontextprotocol/sdk` is now a direct dependency.
* Tests: `tests/mcp.test.ts` (10) against a real stdio MCP server built with the official SDK (`tests/fixtures/mcp-server.js`, including a poisoned tool description). Three deliberate bugs (no taint after a call, inherited environment, no allow-list check) were each confirmed to fail a test.
* **WhatsApp, Signal and email channels** (all disabled by default; any of them can be `channels.ownerChannel`, so approvals and `notifyOwner` go there). **WhatsApp** uses Meta's official Cloud API: webhooks on the existing loopback listener are checked against `X-Hub-Signature-256` (HMAC of the raw body with the app secret) with a replay guard, plus Meta's one-time GET verification; stale and redelivered messages are dropped; only the owner's number counts (others ignored, or TAINTED non-owner goals with `allowPublic`); approvals are Approve/Deny buttons that only resolve when pressed from the owner's number on a pending request. Graph API version is configurable (default v25.0, supported until 2028-07-29 per Meta). WhatsApp only delivers to the owner within 24 h of their last message, and `doctor` says so. **Signal** goes through a signal-cli-rest-api bridge you run on this PC (loopback only; it reports Signal-verified sender numbers). **Email** is IMAP in / SMTP out (TLS). Because anyone can forge From:, a message counts as the owner's only when the TOPMOST `Authentication-Results` header from YOUR provider (`email.authservId`) says `dmarc=pass` for the owner's domain; headers a sender adds lower down are ignored. Signal and email approvals are one-time 6-character codes sent only to the owner ("yes CODE" / "no CODE"): a code works once, only from the verified owner, and a timeout denies. New dependencies: `imapflow`, `nodemailer`, `mailparser` (loaded only when email is enabled).
* Tests: `tests/channels-more.test.ts` (14), including a forged From with the right approval code, a sender-added fake Authentication-Results header, replayed and unsigned webhooks, and a stranger pressing Approve. Four deliberate bugs (trusting the last header, skipping DMARC, accepting codes from anyone, skipping the WhatsApp signature) were each confirmed to fail a test. NOT tested against the real WhatsApp, Signal or a real mailbox: only against fakes.
* **Conversation search.** History in the console has a search box over every earlier session (all words must match, newest first, each hit shown with the messages around it). The agent gets `tools.searchConversations({ query })` for "like we did last time": if a hit came from a reply built on untrusted content, the session becomes tainted (same rule as tainted memory), so old untrusted text cannot come back clean; the audit log records the query length and hit count, never the query. Registry skills cannot declare the tool, and it is on the list of tools no sub-agent can ever hold (it reads your private history).
* Tests: `tests/search.test.ts` (4); removing the taint step was confirmed to fail a test.
* **macOS and Linux installer**: `curl -fsSL https://starclaw.dev/install.sh | bash` (`site/install.sh`). No sudo (refuses to run as root), nothing outside your home directory. Uses your Node if it is 25.9 or newer, otherwise downloads the official Node 25.9.0 build and checks it against nodejs.org's SHASUMS256.txt before use; installs StarClaw from npm with `--omit=dev --omit=optional` into `~/.starclaw-runtime`; adds `starclaw` and `starclaw-app` to `~/.local/bin`. Reinstalling keeps your data (`~/.starclaw-app`). Workflow `unix-installer` proves it on clean Ubuntu and macOS runners: verified Node download, the setup page and its key-protected API answer, a reinstall keeps data, and running as root is refused. `.gitattributes` keeps shell scripts LF.

## 2.0.0-alpha.8 (2026-11-18)

### Reliability and security
* Integrated registry skills with the subagent-capable engine. Registry skills cannot delegate; shell use requires explicit whole-workspace consent.
* Added bounded observation/replanning, read-only runtime recovery, and per-goal deduplication of successful mutations from earlier steps. Saved code is reused only for its exact original goal; completion memory includes the outcome.
* Serialized owner runs and refused session resets during active/queued work. Late approvals cannot revive actions from an exited sandbox, including nested invocations.
* Bound file provenance to clean content hashes. Unknown/changed files, editing and directory results propagate untrusted provenance. Hardened approval-time file checks, hard-link handling, atomic writes and conflict detection.
* Built-in model backends reserve estimated request cost before dispatch, adjust output limits to funds, reconcile usage, and fail closed on corrupt/locked daily ledgers. Provider errors retain their reservations. Estimates still depend on configured prices and provider accounting.
* Container termination waits for exact-name removal and handles Docker auto-removal races.
* Added adversarial and multi-step regression tests. See `docs/competitive-roadmap.md` for boundaries and remaining product work.

### Added
* **`starclaw audit export <log> --out <dir>`**: an EU AI Act Article 12 bundle in MnemoPay's format (`mission.json`, `events.json`, `events.csv`, `chain.txt`, `manifest.json`), written with `buildArticle12Bundle` from `@mnemopay/sdk`. The StarClaw log is verified first (chain, signatures, head checkpoint; `--pubkey`/`--pubkey-file` to pin the key) and the export is **refused** if it fails. Every event keeps the original record's `seq/prev/hash/sig` and timestamp, and event 0 is the `audit.open` with the public key, so the bundle's signatures can be re-checked without the original log. Existing bundle files are never overwritten. `spentUsd` counts LLM usage only; the budget cap is stated only if given (`--budget-usd`). The StarClaw log remains the record of truth: MnemoPay's `MerkleAudit` is in-memory and unsigned, so it is used for the export format, not as the log.
* Tests: `tests/article12.test.ts`.
* **`starclaw app`**: the local console in your browser, the part the coming Windows installer launches. It runs in an app home directory (`%LOCALAPPDATA%\StarClaw` on Windows, `~/.starclaw-app` elsewhere, or `STARCLAW_HOME`/`--home`) that is an ordinary StarClaw project (`.env`, `starclaw.policy.json`, `.starclaw/`, workspace). On first run it writes a random 256-bit console key to `<home>/.env` (an existing short key is refused, never replaced). It listens on 127.0.0.1 only, on a free port, and opens the console with the key in the URL fragment; browsers do not send the fragment to the server, and the page removes it from the address bar and that history entry. Without a model key it exits and names the `.env` file to put it in. Tests: `tests/app.test.ts` (6, including two that run the CLI end to end); checked in a real browser that the key is filled in and gone from the URL.
* **Windows installer** (`installer/windows`, workflow `windows-installer`): `StarClaw-Setup-<version>.exe`, per-user (no admin prompt), into `%LOCALAPPDATA%\Programs\StarClaw`. It bundles the official Node 25.9.0 (zip hash checked against nodejs.org `SHASUMS256.txt`) and StarClaw from its npm tarball, adds Start-menu and optional desktop shortcuts that run `starclaw app`, and has an optional page for the Groq key (written to `%LOCALAPPDATA%\StarClaw\.env` only if no key is there; `/GROQKEY=` for silent installs). Uninstalling keeps the user data (keys, audit log, workspace). CI builds it on a clean Windows VM, installs it silently, starts the console from the installed files, checks the API answers only with the generated key, uninstalls, and checks the data survived. The installer is NOT code-signed yet, so Windows SmartScreen will warn.
* Governed click and type for the MnemoPay browser tab: `tools.browseClick({ selector })` and `tools.browseType({ selector, text, submit? })`, on the control API's `POST /v1/tabs/{id}/click` and `/type`.
  * New action class `browser.click`: default `allow` like `browser.navigate`, escalated to a human once the session is tainted (opening a page taints it, so in practice a click after a page load asks).
  * New action class `browser.type`: default `ask`; never auto-allowed in a tainted session or an unattended run, whatever the policy says (typing hands data to a website, so it is an exfiltration path).
  * New policy field `browser.allowInput` (default `false`). When true, the tab is opened with envelope `allow_input: true` (the field is not sent when false, so older browser builds keep working). When false, `browseType` is refused and audited before any request or approval prompt, and the browser also refuses typing (403 `forbidden`).
  * Selector and text are checked locally with the browser's limits before anything else: selector 1..512 characters, not blank, no control characters; text at most 4096 characters, no control characters except newline and tab, no lone surrogates. Lengths are counted in Unicode code points, like the browser.
  * The approver sees the selector, the page host, the text length, its SHA-256, whether the form will be submitted, and the exact text (new `Action.approverOnly`, rendered near the top of every approval message and never written to the audit log). Audit records get only the selector, host, text length and SHA-256. A failed `browseType` reports a fixed message built from a known error code and the HTTP status; the server's own message is dropped because a server could echo the text. Request ids that contain the text are dropped.
  * Click and type results are untrusted and taint the session, count against `browser.maxActions`, and go through the same final-host check on `data.url` (for `browseType` the error does not name the host). The broker now remembers the last page host the browser reported and uses it as the action target and host, so policy rules, sub-agent domain scopes and registry-skill domain scopes apply to clicks and typing.
  * `starclaw doctor` shows the click verdict and whether typing is on, and warns when `defaults["browser.type"]` is `allow`. Prompt docs and `DEFAULT_TOOL_NAMES` list both tools; sub-agent and registry tool-to-class maps include them; a registry skill that requires `browseType` will not run while `browser.allowInput` is false.
* Tests in `tests/browser.test.ts` (13 new), against the local fake control server. The fake now also enforces the real server's click/type body rules, the envelope field list and the `allow_input` 403. They include a control test showing that without the broker's error sanitising, an echoing server does put the text in the audit log, and seven deliberate-bug mutations were each confirmed to fail a test.

### Not verified
* The real MnemoPay browser was not used: these changes were tested only against the fake. The browser's own click/type behaviour was checked by that project (see its `docs/CONTROL_API.md`), not here.
* The generated code is itself audited (`exec`), so a text the model writes as a literal in its code is in the audit log through that record. Only the browser records leave it out.
* Docker was stopped, so container-layer tests self-skipped; the engine test ran on the process layer only.

## 2.0.0-alpha.7

### Added
* **Signed skills registry** (`src/skills/registry`), deliberately NOT an open store: no catalogue, no search, no auto-install, and **no network fetch at all** (bundles are local `.starclaw-skill` files you point to). Policy block `skillsRegistry` (strict, **disabled by default**; when disabled, `skills install` and running a registry skill are refused and nothing else changes).
  * A skill runs only if (1) it is signed (Ed25519, the existing signer code) by a publisher key YOU pinned in the local keyring (unknown publisher = refuse); (2) the manifest verifies against that signature and every member's sha256 and size matches the signed manifest (any tamper = refuse, fail closed); (3) it **declares** its capabilities (tool names, domains, workspace path scopes, `spendCents` = 0 by default) and runs **attenuated** to the intersection of those and the current policy, never wider (an undeclared tool or scope is refused and audited; a REQUIRED tool the policy denies means it will not run); (4) you approved the install after seeing publisher fingerprint, version, declared capabilities, file hashes and a code and capability diff against any installed version (new action class `skill.install`: ALWAYS asks whatever the policy says, never in unattended runs, no approver = deny); (5) it is not revoked or expired, checked on **every load and every run**; (6) it is not an unflagged rollback or publisher swap (`--allow-rollback` / `--allow-publisher-change`, and a fresh approval that says so).
  * Revocation: owner-managed (`skills revoke <id> [--version v]`) and signed lists from a pinned publisher (`skills revoke --list file`, rising serial per issuer). There is no CLI to AUTHOR a signed list yet (`signRevocationList` in the API only).
  * Bundle format: one self-describing JSON file with flat, name-validated text members, capped by `skillsRegistry.maxBundleBytes/maxFiles/maxFileBytes`. No archive library, no decompression, nothing is extracted by member name, no new dependency.
  * Registry state (keyring, installs, revocations) is signed with the engine's audit key: editing it on disk makes the registry refuse everything.
  * CLI: `starclaw skills keys add|list|remove`, `keygen` and `sign` (publisher side; key file is created 0600 and never overwritten; a group/other-readable key is refused on POSIX), `verify`, `install`, `list`, `revoke`; `starclaw doctor` prints a Skills registry line. Engine API: `engine.installRegistrySkill(file)`, `engine.runRegistrySkill(id)`.
  * Agent-authored skills (`--learn-skills`) are unchanged: hash-pinned, `skill.save` approval-gated, NOT signed, and not part of the registry. Taint semantics are unchanged.
* Tests: `tests/skills-registry.test.ts` (48 tests, including controls that prove the signature check is what rejects a tampered bundle).

### Changed
* NOT verified: behaviour on Linux/macOS (the POSIX key-file permission test only runs off Windows); any real publisher workflow; registry skills inside the Docker container layer (container tests self-skip when Docker is stopped; only the process layer was exercised).

## 2.0.0-alpha.6 (unreleased)

### Added
* Governed sub-agents: `tools.spawnAgent({ goal, capabilities: { tools, domains?, readPaths?, writePaths?, spendCents?, llmCents?, ttlSeconds?, maxActions? } })`. The child is a separate run (own Governor, taint, LLM budget, spend slice, broker, history) whose authority is its parent's INTERSECTED with the request. Anything wider than the parent holds is rejected before a child exists (all reasons listed; nothing is clipped). Off by default.
* Policy block `subagents` (strict): `enabled` (false), `maxDepth` (1: children cannot spawn), `maxConcurrent` (2), `maxTotalPerRun` (4), `maxSeconds` (300), `maxActionsPerChild` (50), `maxLlmCentsPerChild` (10), `maxSpendCentsPerChild` (0: children cannot spend unless the owner raises it), `maxResultChars` (4000). Action class `agent.spawn` (default `ask`; taint-escalated; never auto-allowed in an unattended run).
* Budget slicing: a child's LLM budget and spend are CARVED from the parent's remaining budget/cap (`LlmBudget.carve`, `SpendPool`/`SpendSlice`); the slice is unavailable to the parent and to other children while the child lives, the child is charged exactly what it used, the rest returns, and concurrent children cannot jointly exceed the parent. A child abandoned at its deadline is charged its whole LLM slice.
* Taint: a child starts with its parent's taint; every child answer is untrusted data (`untrusted: true`) and marks the parent session tainted (`subagent-result`), clean child or not.
* Approvals: requests from a child carry `subagent` (chain root run > ... > child, depth, goal) and say `SUB-AGENT` in the text every approver shows; no approver = deny; unattended runs keep deny-by-default and their children stay unattended.
* Audit: `subagent.spawn` (full scope, hash, decision id) is written after the spawn decision and BEFORE the child exists; every record a child writes carries `runId`/`parentRunId`/`subagentDepth` in the same signed chain (`scopedAudit`); `subagent.result` is written after; `subagent.rejected` for refusals.
* `host.exec` and `schedule.create` are never available to a child (hard rule in the Governor, and not grantable by a request); `spawnAgent` is only grantable when `maxDepth` allows another level. A child has no memory (no recall, no write, no skills) and reaches only the workspace directories it was granted (real paths compared, so links do not widen it); the state dir stays hard-denied.
* `starclaw doctor` prints a Sub-agents line (and warns on `agent.spawn: allow` or `maxDepth > 1`). Prompt docs list `tools.spawnAgent`, and a sub-agent's prompt lists exactly what it holds.
* Tests: `tests/subagents.scope.test.ts` (attenuation property tests, budget/spend slicing, Governor/Broker scope) and `tests/subagents.engine.test.ts` (engine end to end with a fake model, process sandbox, fake rail).

### Changed
* The Governor's run deadline now applies to sub-agent runs too (it was scheduled-only); `Governor.audit` is typed as `AuditSink`; the engine's spend authority is wrapped in a `SpendPool` (no behaviour change until a slice is carved).
* A child's wall-clock life is also capped by `sandbox.timeoutSeconds`, because it runs inside its parent's sandbox call. Broker calls from one run are serialised by the sandbox, so one parent's children run one after another unless several runs (or direct API calls) spawn at once.

### Not verified
* Container sandbox layer (Docker was stopped on purpose): sub-agent tests run on the process layer only. Real LLM providers, real payment rails and the Telegram/HTTP approvers were not exercised with sub-agents.

## 2.0.0-alpha.5 (unreleased)

### Added
* Slack and Discord channels, off by default. Goals, asynchronous approvals (so scheduled jobs can ask you too) and `tools.notifyOwner` over a signed webhook, with no new dependency (Node built-ins only).
  * One listener on **127.0.0.1 only** (policy `channels.port`, default 8787; there is no option to bind elsewhere). Slack and Discord can only reach it through a tunnel or reverse proxy that you run.
  * Slack: Events API (`message.im` direct messages) at `/slack/events` and button clicks at `/slack/interactions`. `X-Slack-Signature` (HMAC-SHA256 over `v0:timestamp:rawBody`) is checked in constant time, with a timestamp window (`channels.timestampToleranceSeconds`, default 300) and a replay cache. Redelivered event ids are processed once.
  * Discord: the `/starclaw goal:<text>` slash command and Approve/Deny buttons at `/discord/interactions`. Ed25519 signature over `timestamp + rawBody`, same window and replay cache. No gateway connection and no message-content intent.
  * Owner only: the sender id must equal the configured owner id. Anyone else is ignored (Slack) or refused with a bare "Not authorised." (Discord), or, with `slack.allowPublic` / `discord.allowPublic`, runs as a **tainted non-owner goal** exactly like `TELEGRAM_ALLOW_PUBLIC=1`.
  * Approvals: sent to the owner's DM with the job/goal request id; only the owner's click on that very message counts (user id AND channel AND message id); foreign clicks, replays and late clicks do nothing; expiry is a deny.
  * Policy blocks `slack`, `discord`, `channels` (strict). Secrets and ids come only from the environment variables whose NAMES the policy holds (defaults `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_OWNER_ID`, `DISCORD_BOT_TOKEN`, `DISCORD_PUBLIC_KEY`, `DISCORD_APPLICATION_ID`, `DISCORD_OWNER_ID`). `channels.ownerChannel` (`telegram` by default) picks which channel carries approvals and notifyOwner.
  * `starclaw slack status`, `starclaw discord status`, `starclaw discord register [--guild <id>]`; `starclaw doctor` prints a line per channel (variable names and set/NOT set only).
  * Slack/Discord bot tokens are added to the audit-log redaction patterns; the API clients keep the token in a private field, never follow redirects, and scrub it from errors.
* `GoalQueue`: one bounded queue for goals from every chat channel (they share one engine session and one taint state).

### Changed
* `starclaw daemon` starts the Telegram gateway only when Telegram is the owner channel (`channels.ownerChannel`, the default). Existing setups are unchanged.
* The Telegram handler now uses the shared `GoalQueue`, which is bounded (20 pending goals; further goals get "Busy").
* Tests: local fakes only. NOT verified against real Slack or Discord.

## 2.0.0-alpha.4 (unreleased)

### Added
* Governed browser tools for the MnemoPay Native Browser control API (`mnemopay-control/v1`): `tools.browseOpen/browseNavigate/browseReadText/browseReadLinks/browseClose`. Off by default. Policy block `browser` (`enabled`, `allowedDomains` required non-empty, `maxActions`, `budgetCents`, `ttlSeconds`, read caps), strict schema.
* Action classes `browser.open` (a human ALWAYS decides, whatever the policy says; never auto in unattended runs), `browser.navigate` (escalates to a human once the session is tainted) and `browser.read`.
* Every page-derived result is untrusted and taints the session like `fetchUrl`/`search`. The control token lives only in the host-side client; discovery file is read by the broker and is a hard-denied path for the file tools; token never reaches audit records, approver requests, prompts or errors. Allow-list, loopback and port checks run before any request; content is withheld if the tab ends on a host outside the list.
* `starclaw doctor` prints a Browser line (policy state, discovery file, control API health).
* Tests against a local fake of the control API. NOT verified against the real browser.

## 2.0.0-alpha.3 (unreleased)

### Added
* `tools.shell` and `starclaw shell build|status|clean`: commands run in a locked-down, network-less container against a COPY of the workspace; changes come back through a defensive tar parser and the broker's write rules (see SECURITY.md 1b for the bind-mount/junction experiment that decided this).
* Scheduler: `starclaw schedule add|list|remove|pause|resume`, `starclaw daemon`, heartbeat jobs, a per-run Governor with origin `scheduled`, daily and per-run caps, backoff and auto-pause.
* Asynchronous approvals for unattended runs through Telegram (`scheduled.defaultVerdictForAsk: ask-async`); unapproved or expired means denied.
* `tools.notifyOwner` (owner-only, rate-limited, governed) and `tools.scheduleCreate` (always asks).
* Policy sections `shell`, `scheduled`, `notify`; action classes `shell.exec`, `host.exec`, `schedule.create`, `notify.owner`.

### Changed
* BREAKING: `tools.runCommand` is now action class `host.exec` (was `exec`). Policy rules for `exec` no longer cover it. It is denied with no approver and in every scheduled run, even if the policy allows it.
* `starclaw-telegram` now also runs the scheduler.

## 2.0.0-alpha.2

Model providers, governed file editing, web search and readable fetch. Every new tool goes through the broker and the governor (audit before run).

### Added
* `llm` policy block: `anthropic` and `openai-compat` (OpenAI, OpenRouter, Ollama, LM Studio) next to Groq. Keys come from environment variables only; plain http is allowed for loopback only; no model name is baked in. Missing `llm.prices` uses a conservative placeholder, flagged in the audit log and in `starclaw doctor`.
* `tools.editFile` and `tools.applyPatch`: exact find/replace and strict single-file unified diffs. The approver sees the diff; sha256, symlink and file-changed-since-approval checks run again after approval; atomic write; line endings and BOM preserved.
* `tools.search` (SearXNG or Brave, off by default) and `tools.fetchUrl({ format: 'text' })` readable extraction. Results taint the session.

### Fixed
* Readable extraction had a quadratic path on floods of unterminated tags (100k `<a ` took ~100 s); it now has a hard work budget.

## 2.0.0-alpha.1

Container layer for generated code. The 2.0.0-alpha.0 process sandbox is unchanged and remains the fallback.

### Added
* `ContainerSandbox`: generated code runs in `docker run` with no network, a read-only root, all capabilities dropped, no new privileges, memory and pid caps, a non-root user, and no mounts. The workspace is reached only through the broker.
* Startup probe with one control per removed protection. `--require-container` refuses to run generated code if that probe fails.
* `starclaw sandbox build`, `starclaw sandbox status`, and `starclaw sandbox clean`. Clean removes only containers labelled `starclaw.sandbox=1` whose names start with `starclaw-sbx-`.

### Known gaps
See README "Known limits" and SECURITY.md. Containers share the kernel. An alternate OCI runtime is untested.

## 2.0.0-alpha.0

Rewrite around a Governor. Everything claimed in the 1.0.0 package that was not real has been removed or replaced.

### Removed (were not real controls)
* `vm2` sandbox (which also granted `fs`, `child_process`, `http(s)`, `os`) and the system prompt advice to use `child_process`.
* `mnemopaySpend` stub that returned success; hard-coded credit-score inputs; the unused canary; `verifyIntegrity` (`return signature.length > 0`);
  the Fly.io "cloud sandbox" that returned `{success:true}` without running anything; the simulated swarm and fake QA loop.
* Unused dependencies: `better-sqlite3`, `axios`, `cheerio`, `cors`, `ws`, `node-telegram-bot-api`, `@anthropic-ai/sdk`, `boxen`, `chalk`, `ora`.
* `fast_path` routing that skipped the ledger; auto-skill synthesis; the AutoPruner; the sample goals that ran on `import`.

### Added
* `ProcessSandbox` (Node `--permission`, scrubbed env, caps) with a fail-closed startup probe and `starclaw doctor`.
* `Governor`: policy engine (zod schema, fail-closed), approvers (CLI, Telegram, HTTP), taint tracking, spend authority on `@mnemopay/sdk` capability tokens, LLM budgets.
* Tamper-evident audit log with `starclaw audit verify`.
* Signed, hash-chained memory on built-in `node:sqlite`; hash-pinned skills.
* SSRF-guarded fetch; broker with hard path rules.
* 130 tests including adversarial sandbox, injection scenarios, tamper tests and controls.

### Changed
* Requires Node >= 25.9.0 (network denial under `--permission` was only observed from 25.x).
* `server` now requires `STARCLAW_API_KEY`; `telegram` requires `TELEGRAM_OWNER_ID`. Both fail closed.
* The web console no longer renders generated HTML in an iframe and no longer loads third-party fonts.

### Known gaps
See README "Known limits" and SECURITY.md.
