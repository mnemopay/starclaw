# StarClaw

An autonomous assistant for research, code changes, and recurring work, with explicit permissions,
spending controls, and verifiable action receipts. Run it locally and give it goals through the CLI,
web console, Telegram, Slack, or Discord.

StarClaw generates JavaScript, runs it in an isolated sandbox, and can inspect results before planning
the next step. **Capabilities pass through a policy engine** that allows, asks a human, or denies,
with a signed, hash-chained audit record written before an approved action runs.

> **Status: `2.0.0-alpha.9`, an alpha, on npm (`latest` and `next`); not yet recommended for customers.** See
> [Known limits](#known-limits) and [SECURITY.md](SECURITY.md) first. Install: the Windows installer from
> [GitHub Releases](https://github.com/mnemopay/starclaw/releases), `curl -fsSL https://starclaw.dev/install.sh | bash` on
> macOS/Linux, or `npm install -g starclaw` (Node 25.9+). Developed on Windows 11 x64; the installers are tested in CI
> on Windows, Ubuntu and macOS. The old `starclaw@1.0.0` on npm is deprecated and broken; a plain install no longer resolves to it.

StarClaw does **not** prevent prompt injection. It assumes the model *will* sometimes be steered by hostile
content and limits what that can cost you: risky actions need a human, who is shown the exact action and where
the untrusted content came from, and everything is provable afterwards.

## Install

Requires **Node.js >= 25.9.0** (see [why](#why-node-259)).

```bash
npm install -g starclaw       # 2.0.0-alpha.9 (latest); the macOS/Linux and Windows installers above bundle Node for you
export GROQ_API_KEY=...        # the bundled LLM backend is Groq; the LLM is an interface, bring your own
npx starclaw sandbox build    # optional but recommended: builds the Docker sandbox image (needs Docker)
npx starclaw doctor           # probes every isolation layer and prints what is blocked, which layer is ACTIVE and why
```

## Quick start

```bash
npx starclaw policy init                    # writes the conservative default policy to ./starclaw.policy.json
npx starclaw run "summarise the headlines on https://example.com"
npx starclaw                                 # interactive session
npx starclaw app                             # console in your browser (127.0.0.1 only; key generated in the app home)
npx starclaw audit verify .starclaw/audit.jsonl --pubkey-file .starclaw/audit.pub
npx starclaw audit export .starclaw/audit.jsonl --pubkey-file .starclaw/audit.pub --out article12/   # EU AI Act Article 12 bundle (MnemoPay format)
```

### Tasks with multiple steps

The model can return `{ __starclaw: "continue", observation: ... }` to inspect an intermediate result
and generate the next program. Ordinary return values finish the task. Observations are untrusted:
they preserve provenance and never grant additional permissions. Example goals:

* Research a company using the configured search provider, inspect the sources, and write a sourced brief.
* Inspect workspace files, prepare a patch, then use the container shell to run the project's checks.
* Create a scheduled monitor and notify the owner when a checked condition needs attention.

Limits are configurable through `agent: { maxSteps: 4, maxRuntimeRetries: 1, maxSeconds: 300 }`.
Runtime recovery is allowed only when the failed step attempted no side effects, did not time out,
and encountered no policy denial. Identical successful file writes, payments, owner messages and
schedule creation from an earlier step are deduplicated within the same goal. This is an in-memory
guard, not durable payment idempotency or automatic crash recovery. Multi-step programs are not
saved as single reusable skills. Saved programs are reused only for the exact goal that created them.

Starting a new session while owner work is running or queued is refused; wait for it to finish.
See [the implementation notes and product roadmap](docs/competitive-roadmap.md) for current boundaries.

With the default policy StarClaw **asks you before** running code, writing a file, touching the network,
saving memory, saving a skill or spending money. The only thing it does silently is read files inside
`./workspace`. In a non-interactive run (no TTY, or `--non-interactive`) anything that would need approval is
**denied**.

Other front ends (both fail closed without credentials):

| Command | Needs | Notes |
|---|---|---|
| `starclaw-telegram` | `TELEGRAM_BOT_TOKEN`, numeric `TELEGRAM_OWNER_ID` | Approve/Deny inline buttons, owner only, timeout = deny. Messages from others are ignored, or (with `TELEGRAM_ALLOW_PUBLIC=1`) run as tainted non-owner goals. |
| `starclaw daemon` + policy `slack.enabled` | `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_OWNER_ID` (names configurable in the policy) | Owner-only goals by DM, Approve/Deny buttons, `notifyOwner`. Signed webhook on `127.0.0.1:8787` (you run the tunnel). See [Slack and Discord](#slack-and-discord). |
| `starclaw daemon` + policy `discord.enabled` | `DISCORD_BOT_TOKEN`, `DISCORD_PUBLIC_KEY`, `DISCORD_APPLICATION_ID`, `DISCORD_OWNER_ID` | `/starclaw` slash command (owner only), Approve/Deny buttons, `notifyOwner`. Same listener. |
| `starclaw-server` | `STARCLAW_API_KEY` (16+ chars) | HTTP API + small web console on `127.0.0.1:3000`. Every `/api` route needs `Authorization: Bearer <key>`. No TLS: put it behind your own proxy if you expose it. |

## Slack and Discord

Both are **off by default** and are configured in the policy; secrets and ids are read only from the environment variables the policy names:

```json
{ "version": 1,
  "slack":    { "enabled": true },
  "discord":  { "enabled": false },
  "channels": { "port": 8787, "ownerChannel": "slack" } }
```

* `starclaw slack status` / `starclaw discord status` check the configuration (names and set/NOT set, never values). `starclaw daemon` refuses to start if an enabled channel is misconfigured.
* **Listener.** `starclaw daemon` listens on **127.0.0.1 only** (`channels.port`). Slack and Discord cannot reach loopback: you must run a tunnel or reverse proxy (cloudflared, ngrok, nginx...) that forwards HTTPS to it. That proxy is then your exposed surface; StarClaw authenticates callers by signature, not by network position.
* **Slack app** (least privilege): bot scopes `chat:write` and `im:history`; Event Subscriptions -> `https://<tunnel>/slack/events` with bot event `message.im`; Interactivity -> `https://<tunnel>/slack/interactions`. Set `SLACK_OWNER_ID` to your member id (`U...`). Direct messages from you become goals; replies and approval buttons come back in that DM. *Scopes and settings are from Slack's documentation and were not exercised against a real workspace.*
* **Discord app**: Interactions Endpoint URL -> `https://<tunnel>/discord/interactions`; copy the application's public key into `DISCORD_PUBLIC_KEY`; run `starclaw discord register` once (uploads the `/starclaw` command using the bot token); set `DISCORD_OWNER_ID` to your numeric user id. Use `/starclaw goal:<text>`; replies are ephemeral. Approval prompts arrive as a DM from the bot. *Not exercised against real Discord.*
* **Who counts.** Only the configured owner id. Others are ignored/refused, unless `allowPublic` is set, in which case their goals run **tainted** (exec, network, spend and skill-save then need your approval). A non-owner can never answer an approval.
* `channels.ownerChannel` chooses where approvals and `tools.notifyOwner` go (default `telegram`; the Telegram gateway runs only when it is the owner channel).

## Signed skills (optional, off by default)

Not a marketplace. Set `skillsRegistry.enabled` in the policy, pin the publishers **you** trust, and install `.starclaw-skill` files from disk:

```bash
npx starclaw skills keygen publisher.key                         # publisher: prints the public key + fingerprint
npx starclaw skills sign ./my-skill --key publisher.key --out my-skill.starclaw-skill   # ./my-skill has skill.json + code files
npx starclaw skills keys add <publicKeyHex> --label "Acme"        # owner: pin the publisher (check the fingerprint out of band)
npx starclaw skills verify my-skill.starclaw-skill               # signature, hashes, expiry, revocation; installs nothing
npx starclaw skills install my-skill.starclaw-skill              # shows publisher, version, capabilities, diff; you approve
npx starclaw skills list | revoke <id> | keys list | keys remove <fingerprint>
```

A skill declares the tools, domains, workspace paths and spend it needs; it runs only with the **intersection** of that and your policy, and is re-verified (signature, hashes, expiry, revocation) on every run. Unsigned skills the agent writes itself (`--learn-skills`) are unchanged. Details and limits: [SECURITY.md](SECURITY.md) section 6b.

## Governed browser (optional, off by default)

The `tools.browse*` tools drive one tab of the MnemoPay Native Browser through its loopback control API. Start the browser with `MNEMOPAY_CONTROL_API=1`, then enable it in the policy:

```json
{ "version": 1,
  "browser": { "enabled": true, "allowedDomains": ["docs.example.com"], "maxActions": 20, "allowInput": false } }
```

* `browseOpen` always asks you. `browseNavigate`, `browseReadText`, `browseReadLinks` and `browseClick` are allowed in a clean session. Navigating and clicking ask you once the session is tainted, and opening a page taints it.
* `browseType({ selector, text, submit? })` types into a text field. It is refused unless `browser.allowInput` is `true`. It always asks in a tainted session or a scheduled run, and by default it asks every time. The approval shows you the exact text. The audit log keeps only its length and SHA-256.
* Everything a page returns is untrusted data. `starclaw doctor` prints a Browser line. Details and limits are in [SECURITY.md](SECURITY.md) section 1d-bis. These tools were tested against a local fake of the control API, not the real browser.

## See it work (2 minutes, offline)

```bash
git clone https://github.com/mnemopay/starclaw && cd starclaw && npm install && npm run build
node dist/cli.js sandbox build    # needs Docker; builds the container image from YOUR copy of the runner
npm run demo                      # no API key, no network, no real money
```

Without Docker (or without the image) the demo still runs, on the Node-permission-model layer only; the first
lines of its output say which layer is active and why.

A scripted model plays an agent that obeys instructions hidden in a web page. You watch StarClaw stop it from
leaking data and from paying an attacker (even though the owner's policy *allows* web access and spending),
verify the signed audit log, then see verification fail after one record is edited. The sandbox, Governor,
taint tracking, approval flow and audit log in the demo are the real code; only the model and the payment rail
are fakes. What it proves: injected instructions cannot spend or leak without a human who is shown where the
content came from. What it does **not** prove: that a real model can't be steered (it can), or that the code is
free of bugs. Narration script for recording it: [demo/README.md](demo/README.md).

## How it works

```
goal ──> LLM writes code ──> Governor: exec? ──(ask/allow/deny)──> sandbox:  [ Docker container ──> node --permission ]   (or node --permission alone)
                                                                        │ tools.* calls over a frame protocol (stdio / IPC)
                                      ┌─────────────────────────────────┘
                                      v
                       Broker ──> Governor ──> policy ──> taint check ──> approver ──> audit (before) ──> action ──> audit (after)
```

* **Layered isolation** (`src/sandbox`), outermost first:
  1. **Container** (`ContainerSandbox`): `docker run --rm -i --network none --read-only --cap-drop ALL --security-opt
     no-new-privileges --pids-limit 64 --memory 256m --memory-swap 256m --cpus 1 --user 65534:65534
     --tmpfs /tmp:rw,noexec,nosuid,size=16m --ipc none --init`, unique name, label `starclaw.sandbox=1`, **no mounts, no
     env passthrough, no docker socket**. The container cannot see the workspace at all; files, network and spend only
     exist as brokered calls over a stdio frame protocol (forged frames are harmless: see SECURITY.md).
  2. **Node permission model** inside the container (and alone when no container is available): no child_process,
     workers, addons, WASI, network or filesystem, plus JS-level hardening.
  3. **Governor/broker**: every brokered call is policy-checked, taint-checked, approved and audited.
  `sandbox.mode` is `auto` (default: container if its probe passes, else process, else refuse), `container` or `process`;
  `--require-container` (or `sandbox.requireContainer`) means generated code runs **only** if the container probe passes.
  **At startup each layer is probed by attempting forbidden operations through the same code path and checking the
  side effects from the host; if the selected layer fails its probe, StarClaw refuses to run generated code.**
  `starclaw doctor` shows both probes, the active layer and why.
* **Governor** (`src/governance`): action classes `exec`, `fs.read`, `fs.write`, `net.egress` (per host),
  `spend` (integer cents), `skill.save`, `memory.write`; verdicts `allow | ask | deny`; JSON policy with a
  strict schema (invalid policy = refuse to start). Approvers: terminal, Telegram, Slack, Discord (owner only), HTTP (bearer
  auth, constant-time compare). Timeout, error or any answer other than the exact string `approve` = deny.
* **Taint tracking**: content from the web, from non-owner messages, from host-command output, and from
  memories/files that were themselves written while tainted marks the session tainted. While tainted,
  `exec`, `net.egress`, `spend` and `skill.save` can never be auto-allowed by policy: they escalate to a human
  whose prompt shows the tainted provenance. A human starts a clean session with `/new`.
* **Spend limits**: `@mnemopay/sdk` capability tokens (`IdentityRegistry`) issued with a per-action cap and a
  total cap, enforced by the Governor *outside* the generated code. A human approval cannot exceed them
  (re-checked after approval and again immediately before money moves). Integer cents only. The total is
  persisted per UTC day so a restart does not reset it. **No payment rail ships**: without one, spending is
  impossible. LLM cost is accounted separately against per-run and per-day budgets.
* **Audit log** (`.starclaw/audit.jsonl`): JSONL, each record hash-chained to the previous one and Ed25519-signed,
  plus a signed head checkpoint. `starclaw audit verify` checks it offline and detects edits, deletions,
  reordering and tail truncation (all covered by tests).
* **Sub-agents** (`tools.spawnAgent`, off by default; policy block `subagents`): a run can start a child run that holds
  **strictly less** authority than it does. The child's scope is the parent's, narrowed by what the parent explicitly asks
  for (tools, hosts, workspace directories, spend carved from the parent's remaining cap, LLM budget carved from its
  remaining budget, a shorter deadline, fewer actions); a request for MORE than the parent holds is rejected before a child
  exists, never clipped. Depth, concurrent and total children are capped (default: children cannot spawn). A child inherits
  its parent's taint, its answer comes back as untrusted data and taints the parent, anything it needs a human for reaches
  the owner flagged as a sub-agent with the full chain, `host.exec` / `schedule.create` are never available to it, it gets
  no memory, and every record it writes names its parent in the same audit chain. See SECURITY.md 1f.
* **Memory** (`node:sqlite`, FTS5; no native add-on): every memory is hash-chained and signed; recall verifies
  rows and quarantines any that were modified. Skills are pinned by SHA-256 and refused if the file changed.

## What is and is not protected (short version)

| Threat | Result |
|---|---|
| Generated code spawns processes, loads addons/workers/WASI, opens sockets, reads/writes outside the workspace, signals other processes | Blocked and probe-verified on Node 25.9.0 / Windows, in the process layer and (when available) again by the container layer (details: `starclaw doctor`) |
| Generated code tries to reach the host (files, network, docker socket, environment, other processes) | Container layer: no mounts, no network, no capabilities, non-root, read-only root, memory/pids caps; probe-verified from the host side on Docker Desktop (WSL2) |
| Injected text makes the agent exfiltrate, run commands or spend | **Not prevented.** Requires human approval once the session is tainted; the human sees the provenance |
| You approve something harmful | Nothing stops you. Approved host commands run with your full privileges |
| Someone edits the audit log or memory without the signing key | Detected |
| Someone who can read `.starclaw/audit.key` | Can forge both. The key sits next to the data |
| Malicious code that finds a Node permission-model bypass | With the container layer: confined by the container instead. Without it: **not covered** (Node documents the model as a "seat belt") |
| Malicious code that finds a Linux kernel / container-runtime escape | **Not covered.** Containers share the kernel (on Docker Desktop: the WSL2 VM's). For hostile multi-tenant use put gVisor/Kata/Firecracker underneath |

## Known limits

* Only Windows 11 x64 + Node 25.9.0 was tested. Linux/macOS are untested (the probe will tell you).
* Containers are not VMs: they share the host kernel (Docker Desktop: the WSL2 VM kernel, not one VM per container).
  `sandbox.containerRuntime` passes an OCI runtime (e.g. `runsc`) to `docker --runtime`; **that path is untested**.
* The container does not protect `.starclaw/audit.key` if the host itself is compromised: the key lives on the host.
* Without Docker, the process layer is Node's permission model plus JS-level hardening plus a probe: a seat belt, not a VM.
* Docker was only tested on Windows 11 + Docker Desktop (Linux containers, WSL2). Linux and macOS hosts are untested.
* No payment rail is included. Real money movement is unimplemented and untested.
* `tools.runCommand` runs approved commands unsandboxed on the host.
* Sub-agents are runs inside the same process and the same sandbox layer as their parent, not a separate trust boundary:
  the scope is enforced by the Governor and Broker, so a sandbox escape is not contained by it. A child that overruns its
  deadline is abandoned (and charged its whole LLM slice) but its sandbox process runs until the sandbox timeout. Tested
  with a fake model and the process sandbox only; the container layer was not exercised.
* Memory and audit integrity are only as strong as the secrecy of the key in `.starclaw/`.

### Why Node >= 25.9

Under `--permission`, Node 25.9.0 denies network access (`--allow-net`). I ran the same probe on Node 24.22.3 and
22.23.5: they deny everything else but still allow outbound network, so the probe fails and StarClaw refuses
to run generated code there. Node 25.0 to 25.8 were not tested; the runtime probe decides.

## Compared with OpenClaw

I have not audited OpenClaw and make no claims about its current behaviour. The design differences StarClaw
aims for are: no ambient authority for generated code (everything is brokered and governed), approval gates by
default, taint-based escalation for actions that follow untrusted input, hard spend caps enforced outside the
model's reach, and an offline-verifiable audit trail. Each is implemented and tested here; none is a claim that
StarClaw is safe for production use today.

## Development

```bash
npm run build && npm test && npm run typecheck
```

Tests use a fake LLM and fake payment rail: nothing in the suite calls a real provider. Security tests come
with *controls* that show the test fails when the protection is removed (e.g. sandbox without the permission
model, memory without verification, a permissive spend authority).

License: Apache-2.0. Copyright (c) 2026 Jeremiah Omiagbo / J&B Enterprise LLC.
