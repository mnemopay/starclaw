# Changelog

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
