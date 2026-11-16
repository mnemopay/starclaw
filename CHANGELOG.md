# Changelog

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
