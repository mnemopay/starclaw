# StarClaw

A governed autonomous agent. You give it a goal; a language model writes JavaScript to achieve it; StarClaw
runs that code in an isolated sandbox (a locked-down Docker container, with Node's permission model inside it) where **every capability is brokered through a policy
engine** that can allow, ask a human, or deny, and that writes a **signed, hash-chained audit record before
anything runs**.

> **Status: `2.0.0-alpha.3`. Not published, not yet recommended for customers.** See [Known limits](#known-limits)
> and [SECURITY.md](SECURITY.md) first. Tested on Windows 11 x64 with Node 25.9.0 only.

StarClaw does **not** prevent prompt injection. It assumes the model *will* sometimes be steered by hostile
content and limits what that can cost you: risky actions need a human, who is shown the exact action and where
the untrusted content came from, and everything is provable afterwards.

## Install

Requires **Node.js >= 25.9.0** (see [why](#why-node-259)).

```bash
npm install starclaw          # once published; until then: npm install ./starclaw-2.0.0-alpha.3.tgz
export GROQ_API_KEY=...        # the bundled LLM backend is Groq; the LLM is an interface, bring your own
npx starclaw sandbox build    # optional but recommended: builds the Docker sandbox image (needs Docker)
npx starclaw doctor           # probes every isolation layer and prints what is blocked, which layer is ACTIVE and why
```

## Quick start

```bash
npx starclaw policy init                    # writes the conservative default policy to ./starclaw.policy.json
npx starclaw run "summarise the headlines on https://example.com"
npx starclaw                                 # interactive session
npx starclaw audit verify .starclaw/audit.jsonl --pubkey-file .starclaw/audit.pub
```

With the default policy StarClaw **asks you before** running code, writing a file, touching the network,
saving memory, saving a skill or spending money. The only thing it does silently is read files inside
`./workspace`. In a non-interactive run (no TTY, or `--non-interactive`) anything that would need approval is
**denied**.

Other front ends (both fail closed without credentials):

| Command | Needs | Notes |
|---|---|---|
| `starclaw-telegram` | `TELEGRAM_BOT_TOKEN`, numeric `TELEGRAM_OWNER_ID` | Approve/Deny inline buttons, owner only, timeout = deny. Messages from others are ignored, or (with `TELEGRAM_ALLOW_PUBLIC=1`) run as tainted non-owner goals. |
| `starclaw-server` | `STARCLAW_API_KEY` (16+ chars) | HTTP API + small web console on `127.0.0.1:3000`. Every `/api` route needs `Authorization: Bearer <key>`. No TLS: put it behind your own proxy if you expose it. |

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
  strict schema (invalid policy = refuse to start). Approvers: terminal, Telegram (owner only), HTTP (bearer
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
