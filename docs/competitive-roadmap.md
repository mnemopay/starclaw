# StarClaw: reliability and security improvements

This branch integrates the signed registry with main's browser, scheduler, channels and subagents.
It adds a bounded observation/replanning loop while preserving policy enforcement on each step.

## Implemented

* Configurable step, runtime-retry and wall-clock limits. Runtime retries stop after attempted
  side effects, timeouts or unhandled denials. A caught denial can be returned as a final result,
  but cannot trigger automatic replanning to work around it.
* Per-goal deduplication of identical successful mutations from earlier steps. Calls repeated
  within one step remain independent operations, so spend limits still apply to every payment.
* Serialized owner execution, including registry skills. Session reset refuses active/queued work.
  Late approvals cannot revive tool calls from an exited sandbox.
* File provenance bound to hashes of clean broker writes. Imported files, externally changed
  files, legacy provenance lists and corrupt/missing provenance state are untrusted. Editing and
  directory listings propagate taint too. File content is not sanitized into trusted instructions.
* Post-approval path checks, refusal of hard-linked read/edit targets, atomic file replacement,
  exclusive creation and conflict detection for whole-file writes. Shell staging skips hard links.
* Registry shell use requires an explicit `**` whole-workspace grant. Registry skills cannot spawn
  agents. Narrow shell scopes are intentionally rejected until scoped staging exists.
* Built-in LLM backends reserve estimated prompt/output cost before dispatch, reduce output limits
  to available funds, and reconcile valid provider usage. Daily ledger updates use exclusive locks
  and atomic replacement. Corruption/lock contention fails closed. Failed requests retain their
  reservation because provider billing may have occurred. Missing usage is an error.
* Useful final outcomes stored with completion memories. Saved programs reused only for exact goals.
* Container termination waits for removal of the exact named container before resolving.

## Limits that remain

These changes do not certify the project as secure. Host execution still runs with the owner's
privileges. Filesystem checks are implemented in Node and do not establish a race-free native
filesystem boundary against a hostile local process. Signing keys remain on the host.

LLM reservation depends on conservative text-token estimates and configured prices. It cannot
guarantee a third-party invoice, especially for hidden reasoning tokens, provider-specific billing,
or stale prices. Custom LLM implementations must accept the budget option or use their own preflight
reservation; the compatibility path still accounts usage after calls. A crashed process can leave
a budget lock that requires operator investigation. Do not automatically delete another writer's lock.

The model decides when to request another observation and when to finish. Completion is not an
independent semantic proof. Deduplication and progress are not durable across process crashes.
Browser tools currently navigate and read; interactive form filling is still a product gap.

## Next product work, in order

1. Durable task records, cancellation, checkpoints and explicit resume. Use durable idempotency keys
   for external mutations, and reconcile ambiguous outcomes before retrying them.
2. Governed MCP connectors with scoped credentials and per-tool schemas. Start with the integrations
   required by actual pilot users; never execute arbitrary servers with inherited host privileges.
3. Browser interactions with isolated sessions, authenticated-origin controls, preview/commit approval
   for submissions, and bounded credential access.
4. Typed, parameterized skills with explicit applicability checks, outcome validation and versioned
   learning. Exact-goal reuse is the conservative interim behavior.
5. Expiring task grants for named resources/actions, with explicit budgets and action counts. Keep
   sensitive writes, publication and payments reviewable without prompting for every harmless read.
6. An installer/onboarding flow that checks the runtime and sandbox, configures a provider, and gets
   a user through the first successful task.

## Product evaluation

Use the same goals, model, limits and environment when comparing agents. Run clean and injected
variants of these workflows:

| Workflow | Completion evidence | Security evidence |
| --- | --- | --- |
| Company research | A saved report with working source links and supported claims | Injected sources cannot leak workspace secrets or create unauthorized actions |
| Repository maintenance | Correct patch plus relevant passing project checks | Host/state secrets remain inaccessible; refused actions stay refused during recovery |
| Recurring monitoring | Persisted schedule, correct trigger behavior, useful owner notification | Unattended approvals, notification limits and task budgets remain enforced |

Measure verified completion rate, task correctness, cost, elapsed time, recovery success, human
interruptions and unauthorized side effects. Report failures and environment limitations alongside
successes. Deterministic fake-model regression tests validate controls; they are not market benchmarks
or evidence of real-model task completion rates.
