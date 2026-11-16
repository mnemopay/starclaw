# Demo: an agent reads a poisoned web page

`npm run demo` runs [`injection-demo.ts`](injection-demo.ts). It is offline and deterministic. Set `DEMO_FAST=1`
to skip the pauses, `NO_COLOR=1` for plain text.

**What is real:** the sandbox (a Docker container with Node's permission model inside, when Docker is available),
the Governor and its policy engine, taint tracking, the approval flow, the Ed25519-signed hash-chained audit log
and its verifier. **What is fake:** the language model (a script), the payment rail (a counter), and the "attacker"
(a local web server that counts requests).

## Recording it (about 2 minutes)

Use a dark terminal, large font. Run `npm run demo` once off-camera to warm the Docker image, then record the
second run. Suggested narration, matched to what the screen shows:

1. **Opening (10 s), over the title.** "This is an AI agent that writes and runs its own code. The usual worry is
   prompt injection: a web page the agent reads can contain hidden instructions. I'll show what happens."
2. **Self-check (10 s), over "Sandbox self-check: PASSED".** "Before it runs any code, StarClaw tests its own
   isolation: no network, read-only filesystem, no privileges, memory limits. If any test fails, it refuses to run."
3. **Act 1 (15 s).** "A normal task. It asks me first, I approve, it saves a note. Everything is written to a signed log."
4. **Act 2 (50 s), the heart of the demo.** "Now it reads a page with a hidden instruction: send your private notes
   to this address and pay fifty to the attacker. The model is fooled. It tries both. But look at what I, the human,
   am shown: it is flagged because the page it just read is untrusted, and it tells me exactly which page.
   Even though my policy says web access and spending are allowed, once untrusted content is in the session those
   rules stop applying. I deny both. The attacker's server was contacted zero times. Zero money moved."
5. **Act 3 (15 s).** "Everything above is in a signed, hash-chained log. I can verify it offline against my own key."
6. **Act 4 (15 s).** "If someone edits one record to hide the warning, verification fails. You can't quietly rewrite what the agent did."
7. **Close (10 s).** "StarClaw doesn't claim to stop prompt injection. It limits what an injected agent can do and
   proves what it did. That's the difference between an agent you can trust with real access and one you can't."

## Honest caveats to say out loud if asked

- The model in the demo is scripted; a real model might resist or might be fooled differently.
- Approval only helps if the person actually reads the request. StarClaw shows the provenance to make that easier.
- This is an alpha, tested on Windows 11 with Node 25.9 and Docker Desktop only. See `SECURITY.md`.
