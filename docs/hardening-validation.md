# Validation of the hardening branch

Environment: Windows, Node permission sandbox and Docker Desktop Linux containers.

* Build and TypeScript checks passed.
* Fourteen new regression tests passed: bounded replanning, safe recovery, mutation deduplication,
  step limits, denial handling, session reset, file provenance, registry scopes, late approval,
  junction/hard-link attacks, write conflicts, shared reservations, output-token limits and unknown
  provider outcomes.
* The broad test run executed 527 tests: 523 passed, two file-symlink checks were unavailable on this
  Windows account, and two container-related checks initially failed. Shell integration was skipped
  when the Docker daemon stopped responding during that run.
* After correcting the exact-name cleanup assertion and the Docker auto-removal race, the complete
  container argument, container isolation and shell integration suites were rerun with Docker running:
  **54 passed, zero failures, zero skips**. These include both formerly failing checks and all 17 shell
  tests omitted from the broad run. Across these final runs, all 542 available tests passed; two
  Windows file-symlink checks remain unavailable.
* The offline injection demo passed using the container layer. It blocked exfiltration and payment
  attempts, verified the signed audit log, and detected a subsequent log modification.
* `npm audit --omit=dev --json` reported zero known production dependency vulnerabilities.
* The package dry run succeeded and includes the new runtime modules and documentation.

Commands used:

```text
npm run build
npm run typecheck
npm test
node --import tsx --test --test-concurrency=1 tests/container-args.test.ts tests/container.test.ts tests/shell-container.test.ts
npm run demo
npm audit --omit=dev --json
npm pack --dry-run --ignore-scripts --json
git diff --check
```

Tests use fake models/payment rails or local fake provider servers. This validates runtime controls,
not real-model quality, real payment settlement, or Linux/macOS host compatibility. No package was
published and no production deployment was changed.
