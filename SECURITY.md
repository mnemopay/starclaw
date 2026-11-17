# StarClaw security model

Version `2.0.0-alpha.1`. Everything below states what was exercised by the test suite or by manual runs on
**Windows 11 x64, Node 25.9.0** (plus probe runs on Node 24.22.3 and 22.23.5). Anything not exercised is marked
*unverified*. Report vulnerabilities privately to the maintainer; do not file public issues for exploits.

## Threat model

**Assets:** the host (files, processes, network position), money, secrets in the environment and `.env`, the
integrity of memory and of the record of what the agent did.

**Adversaries considered**
1. *Hostile content* (web pages, files, other users' messages) that tries to steer the model: prompt injection.
2. *A misbehaving or compromised model* emitting arbitrary code.
3. *A local attacker with write access to the state directory but without the signing key*, tampering with logs/memory.

**Not considered:** a local attacker who can read `.starclaw/audit.key` or run code as your user outside StarClaw;
a malicious maintainer/dependency (see Dependencies); physical access; side channels.

**Core assumption:** the model is untrusted. Its output is input to the Governor, never a decision. Prompt
injection is **not prevented**; the design limits the blast radius and makes actions provable.

## Controls, with verified limits

### 1. Process sandbox (`src/sandbox`)
Generated code runs in a child started with `node --permission --allow-fs-read=<runner.cjs>` only, a scrubbed
environment (no inherited variables; Windows adds non-secret defaults such as `PATH` and `USERPROFILE`),
`--max-old-space-size`, a wall-clock timeout, an output cap and a per-run cap on brokered calls.

Verified denied on Node 25.9.0 / Windows (each by the child's error *and* an independent side-effect check by
the parent: marker files, a TCP and UDP listener that must see nothing, a live victim process):
`child_process` (execFileSync, spawn, via `import()`, via `Function`+`process.mainModule`, via `eval`),
`process.binding`, `worker_threads`, native addons, WASI, raw TCP, `http`, `fetch`, `dns`, `dgram`, filesystem
reads/writes outside the allow-list (absolute, `../`, system files), creating symlinks, reading/writing through a
pre-existing junction, `inspector.open`.

**Findings from my own testing that shaped the design**
* `process.kill(pid)` is **not** blocked by `--permission`: sandboxed code killed a same-user process.
* `process._debugProcess(pid)` is **not** gated either (Node's docs say so too); it switched on the inspector of
  another Node process. Both are neutralised by JS-level hardening in `runner.cjs`; the probe checks the effect.
  This is defence in depth, not a proof that no other un-gated API exists.
* Giving the child direct read/write on the workspace is **unsafe on Windows**: a junction inside the workspace
  let it read and write outside. Therefore the child gets **no** filesystem access at all and all file access is
  brokered (the broker resolves real paths before deciding). Direct access exists only as a test-only control.
* Under `--permission`, Node 24.22.3 and 22.23.5 still allow outbound network. StarClaw requires 25.9.0 and the
  probe fails closed on anything that does not deny it.

**Limits.** Node documents the permission model as a "seat belt" that "does not provide security guarantees in
the presence of malicious code". A model that finds a bypass is outside what this layer protects. This layer
has no OS-level isolation of its own (no job object, seccomp or AppContainer). CPU can be burned until the timeout.
Disk can be filled via brokered writes (5 MB each, up to the call cap). Only Windows was tested. When Docker is
available, the container layer below is the outer boundary. Without it, a bypass gives the code the user's rights.

### 1a. Container sandbox (`src/sandbox/ContainerSandbox.ts`)

When `sandbox.mode` is `auto` (the default) and the container probe passes, generated code runs inside `docker run`
instead of the process layer. Mode `container` requires that image. Mode `process` never starts Docker.
`--require-container` (or `sandbox.requireContainer`) refuses to run generated code if the container probe fails.
There is no process fallback in that case.

The default `docker run` is `--rm -i --pull never`, a unique name `starclaw-sbx-*`, label `starclaw.sandbox=1`,
`--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`, equal
`--memory` and `--memory-swap`, `--cpus 1`, `--user 65534:65534`, a `tmpfs` on `/tmp` mounted `noexec,nosuid`,
`--ipc none`, `--init`, `--log-driver none`, and file-descriptor and core ulimits. No mounts, no environment
passthrough, no published ports, no docker socket. The workspace is not mounted. Files, network and spend exist
only as brokered stdio frames. A timeout inside the container is the host timeout plus 10 seconds. On timeout the
host kills that container by its exact name.

Inside, Node starts with `--permission` and `--allow-fs-read=/sandbox/runner.cjs` only. `process.dlopen` is denied
by that permission model (`ERR_DLOPEN_DISABLED` or `ERR_ACCESS_DENIED`). The image is `node:25.9-slim` pinned by
digest. The image label `starclaw.runner.sha256` must match the packaged runner or the probe reports the image stale.

Verified on Windows 11 x64 with Docker Desktop (Linux containers, WSL2) and Node 25.9.0: the startup probe checks
the live container (uid 65534, zero capabilities, no-new-privileges, seccomp, read-only root, noexec tmpfs, no host
network, no host files, no docker socket, no host environment, memory and pid limits). Each control that removes
one flag makes the matching check fail. `starclaw sandbox clean` removes only containers that carry the label and
the `starclaw-sbx-` name prefix.

**Limits.** Containers share the kernel. On Docker Desktop that kernel is the WSL2 VM's, not a kernel per
container. A container escape is not covered. `sandbox.containerRuntime` can pass an OCI runtime such as `runsc`.
That path is untested. The container does not protect `.starclaw/audit.key` on the host.

### 1b. Shell container (`src/shell`, `tools.shell`)
`tools.shell({ command })` runs `sh -c <command>` in a throwaway container from the `starclaw-shell` image (`starclaw shell build`).
Container flags: no network (there is no policy switch to open it), read-only root, all capabilities dropped,
`no-new-privileges`, default seccomp, uid 65534, memory/pids/cpu caps, `noexec` tmpfs, no env passthrough, no docker
socket, no published ports, no mounts. The container destroys itself after `timeout + 60 s` even if the host dies. One
container exists at a time; `starclaw shell clean` removes only containers labelled `starclaw.shell=1` named `starclaw-sh-*`.

**Why the workspace is copied, not bind-mounted.** Experiment (`tests/shell-container.test.ts`, Windows 11, Docker Desktop
with the WSL2 backend, 2026-11-16):
* A host junction or symlink inside a bind-mounted workspace is exposed to the container as a symlink whose target is a
  translated `/mnt/host/c/...` path. That path does not exist in the container, so the link could not be followed and no
  file outside the workspace was read. **This escape was NOT demonstrated here.** It was tested on one Docker backend only.
  Hyper-V/gRPC-FUSE backends, native Linux Docker and other Docker versions were not tested, so it is not ruled out elsewhere.
* The bind mount is unsafe anyway, and this was demonstrated: the container (root in the experiment) wrote `.env` and
  `.git/*` straight into the host workspace, bypassing the broker's hard rules, and created a symlink that appeared in
  the host directory (a WSL-style reparse point that Node cannot even `lstat`: `EACCES`).

So the design copies instead. **Copy-in:** the workspace is read by the host (never following links; symlinks, junctions,
`.env*`, the state directory and anything `lstat` cannot classify are skipped and reported; caps on files/bytes fail
closed) and streamed as a tar into the container's size-capped tmpfs `/work`. **Copy-out:** after the command, `/work` is
read back as a tar, parsed defensively (checksums, size caps, only plain files/directories; links, devices, fifos, pax size
overrides and malformed headers are refused), turned into an explicit change list, **audited as `shell.writeback.plan`
before anything is applied**, then applied through the broker's write-path hard rules plus: every existing parent must be a
real directory (no link), a file changed on the host while the command ran is a *conflict* and is not overwritten,
Windows-unsafe names (reserved devices, ADS colons, trailing dots/spaces, 8.3 names, case collisions) are refused, caps on
changed/deleted paths, write to temp + rename. A timed-out or killed command writes nothing back. Output and every written
file are tainted (later reads taint the session). Policy class `shell.exec` defaults to `ask`.

*Limits:* the command can read every file that was copied in (everything except `.env*`, links and the state directory)
and print it to the model; it cannot send it anywhere. A background process the command leaves behind may still change
`/work` while it is read back; the result is validated, not trusted. Containers share the kernel (see 1a). Only the above
backend was tested. `apt` packages in the image float at build time.

### 1c. Unattended runs (`src/scheduler`)
Jobs live in `.starclaw/scheduler.json` and run only while `starclaw daemon` (or `starclaw-telegram`) is running. Each run
has its own Governor with origin `scheduled`: its own taint (so it cannot taint or loosen an owner conversation) and a
wall-clock deadline after which every governed action and LLM call is refused. Rules, none relaxable by policy:
a scheduled run can never use `host.exec` or `schedule.create`; a policy `allow` for `spend` is turned into an ask; an `ask`
is **denied at once** unless `scheduled.defaultVerdictForAsk` is `ask-async` AND the approver reaches the owner away from
the terminal (`async`: Telegram). The request then carries the job id and trigger time, expires at
`scheduled.approvalTimeoutSeconds` (capped by the run deadline), and a restart drops pending approvals (late taps get
"no longer pending"): **unapproved means denied**. Limits: runs/day, runs/job/day, LLM cents/day, jobs total, minimum
interval, max run seconds, auto-pause after N consecutive failures with exponential backoff; missed runs are coalesced.
An agent-created job (`tools.scheduleCreate`, class `schedule.create`) is **always** asked, whatever the policy says; a
job proposed from a tainted session starts every run tainted. Jobs you add with `starclaw schedule add` are yours and
are audited (`scheduler.job.created`).

### 1d. Messaging you first (`tools.notifyOwner`)
Messages go only to the configured owner chat; there is no recipient parameter. They are length-capped, rate-limited
(`notify.maxPerHour/maxPerDay`, persisted so a restart does not reset them), governed as `notify.owner` (allowed by
default for a clean session; a tainted session must ask, because a message to you is a phishing/exfiltration channel) and
audited before the send. StarClaw's own notices (e.g. "job paused") use the same limits.

### 1d-bis. Governed browser (`tools.browse*`, classes `browser.open|navigate|read`)
Off unless `browser.enabled` and a non-empty `browser.allowedDomains`. Opening the tab is **always** asked (policy cannot allow it, unattended runs cannot auto-approve it); navigation is allowed by default but escalates to a human once the session is tainted. The host-side client reads the browser discovery file (`control.json`, holds the bearer token) on each call; the file and its directory are hard-denied to every file tool, and the token is scrubbed from anything that leaves the client. Page URLs are checked against the allow-list (no IPs, localhost, credentials or explicit ports) before any request; the browser enforces the same list independently. Everything the page returns is untrusted and taints the session. *Limits:* only tested against a fake of the API; the browser's own loopback isolation is documented by that project as untested on a real desktop; a tab left open is bounded only by `ttlSeconds`/`maxActions`.

### 1e. Legacy host commands (`tools.runCommand`, class `host.exec`)
Still unsandboxed. It is now its own action class, never covered by a rule written for sandboxed `exec`, denied in every
unattended run, and **denied whenever no approver is present (non-interactive), even if a policy rule says `allow`.**
Prefer `tools.shell`.

### 1f. Sub-agents (`tools.spawnAgent`, `src/governance/subagent.ts`)
Off unless `subagents.enabled`. A run can start a child run, and **the child can only ever hold less than its parent**: its
scope is the parent's scope narrowed by what the parent explicitly asks for, computed by one function (`attenuate`). Asking
for anything wider (a tool, host, directory, spend, LLM budget, time or action count the parent does not hold) rejects the
whole request before a child exists; nothing is clipped silently. Scope is checked on top of everything else, never instead
of it: the result is the intersection of the scope and the policy, taint escalation, approvals and spend authority, which
all still apply. Enforcement is in three places: the Governor (action classes implied by the tool list, hosts, a count of
governed actions, the deadline, and a hard denial of `host.exec`/`schedule.create`), the Broker (the tool allow-list, and
workspace directories compared as REAL paths so a link inside a granted directory does not widen it), and the budget/spend
objects (slices are carved, so reserved + carved never exceeds the cap and concurrent children cannot jointly exceed the parent).

* **Limits (policy `subagents`, all hard):** depth (default 1: children cannot spawn), concurrent children, total children per
  run, wall-clock (a child's deadline is the shortest of the request, `maxSeconds`, `sandbox.timeoutSeconds` and what is left of
  its parent's), governed actions, result size. Spend defaults to 0 and is zero unless the owner raises `maxSpendCentsPerChild`.
* **Taint:** the child starts with its parent's taint. Its answer is untrusted data and taints the parent session whether or not
  the child itself was tainted, so a child that was steered cannot hand its parent anything that skips the parent's own approvals.
* **Approvals:** the spawn itself is an `agent.spawn` action whose approval shows the full scope and chain (default `ask`; escalated
  when tainted; never auto-allowed in an unattended run). Anything a child needs a human for reaches the same approver with
  `subagent` chain and depth, labelled `SUB-AGENT` in the text. No approver = deny. A scheduled run's children stay unattended:
  `ask` is denied unless `scheduled.defaultVerdictForAsk` is `ask-async` and the approver reaches the owner away from the terminal.
* **Audit:** `subagent.spawn` (scope, scope hash, decision id, budgets) is written after the spawn decision and before the child
  exists; every record the child writes carries `runId`, `parentRunId` and `subagentDepth`; `subagent.result` is written after.
  All in the one signed chain.
* **Memory and state:** a child recalls nothing, writes no memory and saves no skills. It reaches only granted workspace
  directories; the state directory, `.env*` and the browser discovery file stay hard-denied. `tools.shell` can only be granted
  with whole-workspace read access because it copies the whole workspace into its container.

*Limits:* a sub-agent is a run in the same process and the same sandbox layer as its parent, not a separate trust boundary: if
generated code escapes the sandbox, the scope does not contain it. Taint is still whole-session and coarse. A child that
overruns its deadline is abandoned at the deadline (its whole LLM slice is charged, its spend slice is closed so late spends
fail) but its sandbox process runs until the sandbox timeout. A child's wall-clock time counts against its parent's sandbox
timeout. Domains are matched on the host name of each request and redirect hop, not on the resolved address (the SSRF guard
still applies to that). Verified with a fake model and the process sandbox only (property tests over random requests, mutation
checks that remove each control and watch a test fail); the container layer, real model providers and real payment rails were
not exercised with sub-agents.

### 2. Governor and approvals (`src/governance`)
Every brokered capability is an `Action`; policy returns allow/ask/deny; deny-overrides. Decisions are appended
to the audit log **before** the action runs; results after. No approver configured means every `ask` is a
deny. Approvals time out to deny (enforced by the Governor, not trusted to the approver); an approver that
throws, hangs, or returns anything but `approve` is a deny. Invalid policy files make StarClaw refuse to start.

Hard rules no policy can relax: spend must be a positive safe integer of cents; the broker never reads or writes
the state directory or `.env*`, never writes outside the workspace, and resolves symlinks/junctions before
classifying a path.

*Limits:* approval fatigue and social engineering of the human are out of scope. An approver shows the exact
payload, but a human may not understand it (e.g. an approved `powershell -c ...`). The Telegram approver sends
the request, including code and URLs, through Telegram's servers.

### 3. Taint tracking
Session taint is set by: any `fetchUrl` response; any sub-agent's answer (`subagent-result`); goals from non-owner origins; host-command output (default,
`execOutputTaints`); recalled memories written while tainted; reads of workspace files written while tainted.
While tainted, `exec`, `net.egress`, `spend`, `skill.save` are never auto-allowed. Tested with simulated
injections (a fetched page that instructs exfiltration and payment, mid-run and across turns), each with a
control showing the same actions are auto-allowed when policy allows them and the session is clean.

*Limits:* taint is coarse (whole session) and **incomplete by construction**: it cannot see content a human
pastes into a goal, files written by host commands rather than through the broker, or data the model memorised.
`fs.write` and `memory.write` are not taint-escalated (writes are marked tainted instead). Taint resets on
`/new`, which a careless human can call before reviewing. A tainted action that a human approves is allowed.

### 4. Spend limits
`@mnemopay/sdk` 1.16.0 `IdentityRegistry` tokens (both `maxAmount` and `maxTotalSpend` always set, since the SDK
treats an unset cap as unlimited), plus an independent counter; both must agree. Checked before asking the human,
after approval, and synchronously before reserving. Verified: a human approving over the cap cannot exceed it;
concurrent spends cannot jointly exceed the total; rail failure releases the reservation; floats, negatives,
zero, NaN, Infinity and unsafe integers are refused; default caps are 0.

*Limits:* **no payment rail is shipped**, so real settlement is unimplemented and untested; a rail author must
honour the idempotency key. The SDK registry is in-memory, so the running total is also persisted to
`.starclaw/spend-ledger.json` per UTC day; anyone who can edit that file can reset it. An unreadable ledger fails
closed. LLM cost budgets are soft (checked before each call, overshoot of at most one call), use unverified
default prices, and live in an editable JSON file.

### 5. Audit log
`.starclaw/audit.jsonl`: per record `sha256(canonical{seq,ts,prev,type,data})` signed with Ed25519; signed
`<log>.head` checkpoint. `starclaw audit verify` is offline. Tests modify, delete, reorder and truncate records
and append forgeries: all fail verification; the untouched log passes. Secrets matching common shapes are
redacted before hashing (best-effort; unknown formats are not).

*Limits:* the private key lives in `.starclaw/audit.key` next to the log (mode 0600 on POSIX; on Windows
`chmod` is largely a no-op and the file inherits directory ACLs, *unverified*). Anyone who can read it can forge
a whole log. Without `--pubkey`, verification trusts the key embedded in the log, so a fully re-signed log verifies
(the tool says so). Restoring an older consistent (log, head) pair is a rollback that verification cannot see; copy
the head hash somewhere else if you need that. Single writer only. Missing head = failure unless `--allow-missing-head`.

### 6. Memory
`node:sqlite` (built in; FTS5 verified). Rows are hash-chained and signed, including kind, metadata and taint flag;
recall verifies each row and quarantines modified ones; `verifyAll` also finds deleted rows, a truncated tail
and a missing head. The FTS index is only used to find ids. Skills are SHA-256 pinned.
*Limits:* importance/access counters are not covered; same key caveat as the audit log; `node:sqlite` is
experimental in some Node versions.

### 6b. Signed skills registry (`src/skills/registry`, policy `skillsRegistry`, off by default)
A deliberately closed alternative to open skill stores. Nothing is fetched: the owner points at a local `.starclaw-skill` file. A skill is a bundle of flat text members plus a manifest, signed (Ed25519, the same code as the audit log) by a publisher key the owner pinned in the keyring; trust comes only from the keyring, never from the bundle. Checks, all fail-closed, repeated on **every load and run** (not only at install): publisher pinned; signature over the manifest digest; every member's sha256 and size against the signed manifest (no extra or missing members; names are flat and regex-validated, so there is no path traversal); expiry; revocation (owner list and signed lists with a rising serial); the installed bytes against the hash recorded at approval.

*Attenuation.* The manifest declares tools, domains, workspace path scopes and `spendCents` (default 0). The run uses an `AttenuatedGovernor` and a filtered broker: an undeclared tool is refused, a file/network/spend action outside the declared scopes is denied (and audited), and whatever passes is then judged by the normal policy, taint and approval pipeline. Result: the intersection, never wider. `runCommand` and `scheduleCreate` cannot be declared; `host.exec`, `schedule.create`, `skill.save`, `skill.install` and `memory.write` are never available to a registry skill. A REQUIRED tool whose action class the policy denies makes the skill refuse to run (a class-level probe: it does not evaluate every target-specific rule). The skill's `exec` still goes through the Governor (default `ask`); add a rule such as `{ "class": "exec", "target": "skill:*", "verdict": "allow" }` if you want installed skills to run without a prompt.

*Install.* Class `skill.install` always needs a human (a policy `allow` is overridden, like `browser.open`), is denied in unattended runs and with no approver. The approver sees the publisher fingerprint and label, version, declared capabilities, file hashes, and a code and capability diff against any installed version (the approval prompt truncates its payload at 3000 characters, so the facts come first and a long code diff may be cut: read the bundle before approving large ones). A lower or same-numbered-but-different version needs `--allow-rollback`, a different publisher needs `--allow-publisher-change`, and both still need a fresh approval carrying a ROLLBACK / PUBLISHER CHANGE banner. Revocation and the keyring are re-read after the human answers.

*State.* Keyring, installs and revocations live in one file signed with the engine's audit key; a failed signature refuses everything. Agent-authored skills are not signed and are not in the registry (see 6).

*Limits (read these).* A valid signature proves WHO published, not that the code is safe: pinning a malicious publisher, or approving without reading the diff, defeats it. The registry state is only as safe as `audit.key`; an attacker who can restore an OLD signed state file can un-revoke or roll back (same limit as the audit head). Publisher key-file protection is a 0600 mode on POSIX (a looser file is refused); **on Windows it is only the directory ACL and is not checked**. Keys cannot be rotated in place: pin the new key, re-sign, install with `--allow-publisher-change`. There is no key expiry or transparency log. Registry skills run in the same sandbox layers as generated code; they were tested only in the process layer here (Docker was stopped). A skill that was running when it was revoked is not interrupted; its calls stay governed one by one. No external review or fuzzing of the bundle parser beyond the included hostile-input tests.

### 7. Network egress (parent side)
`fetchUrl` is GET-only, http/https only, no credentials in URLs, SSRF guard on the address actually connected to
(IP literals, decimal/hex/short forms and DNS results; loopback/private/link-local/metadata blocked by default),
manual redirects with each hop authorised separately, size and time caps.
*Limits:* TLS certificate handling is Node's default. Data can still leave in an approved URL; the approver sees
the full URL.

### 8. HTTP and Telegram front ends
HTTP: bearer key, SHA-256 + `timingSafeEqual`; refuses to start with no or a short key; localhost by default; CSP
and no `innerHTML` in the console. No TLS, no rate limiting or lockout (*unverified against brute force*). Telegram:
refuses to start without a numeric owner id; callbacks are accepted only from the owner's user **and** chat.

### 8b. Slack and Discord (`src/channels/slack.ts`, `discord.ts`, `verify.ts`, `server.ts`)
Off by default. When enabled, one HTTP listener is bound to **127.0.0.1 only** (no setting changes that). Making it reachable from Slack/Discord needs a tunnel or reverse proxy the owner runs; **that is outside StarClaw and is the exposed surface**. The listener accepts POST only, caps the body (`channels.maxBodyBytes`), has short header/request timeouts, and never echoes or logs request bodies, headers or secrets (rejections are logged as bare reason codes: missing, malformed, stale, bad-signature, replay).

*Authentication.* Every request is verified before its body is parsed. Slack: HMAC-SHA256 of `v0:<timestamp>:<raw body>` with the signing secret, compared with `timingSafeEqual`. Discord: Ed25519 over `<timestamp><raw body>` with the application public key (`crypto.verify`). Both reject timestamps outside `channels.timestampToleranceSeconds` (default 300 s, either direction), and an accepted signature is remembered for the window so a captured request cannot be replayed (bounded cache; only requests that passed verification are stored). Slack event ids are deduplicated because Slack redelivers events.

*Who may instruct or approve.* The sender id must equal the configured owner id exactly. Slack goals are accepted only from direct messages to the bot; bot messages and message subtypes are ignored so the bot cannot talk to itself. Any other sender is ignored (Slack) or told "Not authorised." (Discord); with `allowPublic` they run as non-owner goals, which mark the whole session tainted exactly as for Telegram. An approval click counts only if the clicking user id is the owner AND the click comes from the exact message we posted (channel and message id/ts); a click for an unknown, expired or already-answered request changes nothing; the first answer stands; expiry or a send failure is a deny. The request is registered before it is sent, so a fast click cannot be lost.

*Secrets.* Policy holds environment variable NAMES only (the name pattern rejects values such as `xoxb-...`). A missing or malformed token, signing secret, public key, application id or owner id makes `starclaw daemon` refuse to start; error messages name the variable, never the value. API clients keep the token in a private field (invisible to `JSON.stringify`/`util.inspect`), send it only in the Authorization header (not on Discord interaction follow-ups), refuse redirects, accept a non-default base URL only as a constructor argument (tests), and scrub the token from errors. Slack/Discord token shapes are added to audit redaction (best-effort). All replies disable mention parsing.

*Limits.* **Verified only against local fakes** (signature maths, the HTTP listener, the owner/approval/taint logic with the real Governor and engine). **Not verified against real Slack or Discord**: payload shapes, scopes, rate limits, retry behaviour and the 3-second interaction deadline come from their documentation. A Discord interaction token lasts 15 minutes, so a longer goal is delivered to the owner by DM (to a non-owner it is lost). The Slack signing secret is shared: anyone holding it can forge requests; the Discord check is asymmetric. Messages, including approval prompts with code and URLs, pass through Slack's/Discord's servers. There is no per-sender rate limit beyond the bounded goal queue (20) and the LLM budgets, so `allowPublic` lets strangers spend your LLM budget. A non-owner goal taints the shared session, which also affects your next owner goal until `/new` (same as Telegram). The audit log records `channels.start` and each goal's origin; individual rejected requests are logged, not audited, so a flood cannot grow the signed log.

## Residual risks, plainly
1. Prompt injection works against the model; StarClaw only gates what it can do. A human who approves is the last line.
2. The process layer is a seat belt. With the container layer active, a Node permission-model bypass stays inside that container. A container or kernel escape is not covered, and containers on Docker Desktop share the WSL2 kernel. Without Docker, a Node bypass would give generated code the user's rights.
3. Approved host commands (`host.exec`) are unsandboxed; prefer `tools.shell`.
4. Key and state files are only as safe as your account; log/memory forgery needs only read access to the key.
5. Only one OS/Node combination was tested; no external review or fuzzing was done.

## Dependencies
`npm audit` reported 0 vulnerabilities at the time of writing (run it again). Direct dependencies: `@mnemopay/sdk`,
`commander`, `dotenv`, `express`, `groq-sdk`, `zod`. Install scripts are not needed. The SDK is trusted for its
token arithmetic only; its source was read for the units and mutability of tokens (`validateToken` returns live
objects, so the registry is never exposed outside the Governor).
# Hardening of multi-step execution

Owner goals and registry skill runs are serialized. A session reset is refused while owner work is
active or queued. Broker actions carry a sandbox invocation lifetime: approvals received after that
invocation exits cannot start its deferred actions. Actions already dispatched to external systems
can still complete; a timeout is not a transaction rollback.

Unknown or externally modified workspace files are untrusted. Clean provenance is bound to the hash
of bytes written through the broker, rather than merely to a path. Corrupt and legacy provenance
state does not establish trust. Reads and edits refuse hard-linked files; shell staging skips them.
Whole-file writes recheck paths and original content after approval and commit atomically. These are
Node-level checks, not a race-free native boundary against a hostile same-user process.

Registry skills declaring shell access must declare whole-workspace paths (`**`); narrower grants
are rejected. They cannot declare delegation. A shell grant includes its staged workspace and
write-back behavior, so only grant it to a skill permitted to operate on that whole workspace.

Multi-step recovery never auto-retries a failed step that attempted a mutation, timed out, or had an
unhandled denial. It cannot turn a denied continuation into another model attempt. Successful
mutations from earlier steps are deduplicated within a goal; this does not survive a process crash.
Real payment rails still require durable transaction idempotency and outcome reconciliation.

Built-in model backends reserve conservative request cost before dispatch. This is based on text
estimates and configured prices, not a guaranteed provider invoice ceiling. Errors and missing usage
retain the reservation; ledger corruption refuses further spending. Custom model implementations
must use the supplied budget option to obtain preflight reservations.
