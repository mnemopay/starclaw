# Changelog

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
