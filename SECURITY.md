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
Session taint is set by: any `fetchUrl` response; goals from non-owner origins; host-command output (default,
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

## Residual risks, plainly
1. Prompt injection works against the model; StarClaw only gates what it can do. A human who approves is the last line.
2. The process layer is a seat belt. With the container layer active, a Node permission-model bypass stays inside that container. A container or kernel escape is not covered, and containers on Docker Desktop share the WSL2 kernel. Without Docker, a Node bypass would give generated code the user's rights.
3. Approved host commands are unsandboxed.
4. Key and state files are only as safe as your account; log/memory forgery needs only read access to the key.
5. Only one OS/Node combination was tested; no external review or fuzzing was done.

## Dependencies
`npm audit` reported 0 vulnerabilities at the time of writing (run it again). Direct dependencies: `@mnemopay/sdk`,
`commander`, `dotenv`, `express`, `groq-sdk`, `zod`. Install scripts are not needed. The SDK is trusted for its
token arithmetic only; its source was read for the units and mutability of tokens (`validateToken` returns live
objects, so the registry is never exposed outside the Governor).
