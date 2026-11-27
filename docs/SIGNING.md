# Code signing policy

**Status: planned, not active.** StarClaw plans to apply to the SignPath Foundation's free code signing program for
open-source projects. Until that application is approved and this page says otherwise, **every StarClaw Windows
installer is unsigned**, and Windows SmartScreen will warn about it. Check each download against the release's
`SHA256SUMS.txt`.

When the application is approved, Windows releases will be signed as follows:

> Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by
> [SignPath Foundation](https://signpath.org/).

## What is signed

Only `StarClaw-Setup-<version>.exe`, the Windows installer built by
[`.github/workflows/windows-installer.yml`](../.github/workflows/windows-installer.yml) from this repository, on
GitHub-hosted runners. Nothing is signed on a developer's machine.

Not signed with this project's certificate, because it is not this project's code:

* `node\node.exe` inside the installer is the official Node.js build downloaded from nodejs.org (its hash is checked
  against nodejs.org's `SHASUMS256.txt` during the build). It already carries the OpenJS Foundation's signature.
* npm dependencies (JavaScript, installed from the npm registry with production dependencies only).
* `unins000.exe`, the uninstaller Inno Setup writes at install time, is currently not signed (see Limits).

## How a release gets signed

1. A maintainer pushes a version tag (`v*`).
2. The workflow builds the installer, installs it on a clean Windows runner, starts the console from the installed
   files, checks its API, and uninstalls it. If any of that fails, nothing is signed or released.
3. The exact file that passed is uploaded as a GitHub Actions artifact and submitted to SignPath with the official
   [`submit-signing-request`](https://github.com/SignPath/github-action-submit-signing-request) action (pinned to a
   commit). SignPath checks that the artifact came from a GitHub-hosted workflow run of this repository.
4. **An approver must approve the signing request in SignPath by hand.** The workflow waits up to one hour.
5. The workflow checks that the returned file has a valid, timestamped Authenticode signature, then publishes it to
   the GitHub prerelease with a fresh `SHA256SUMS.txt`. If signing fails, is rejected, or times out, the release job
   does not run: an unsigned file is never published in place of a signed one.

## Team roles

| Role | Who |
|---|---|
| Committers and reviewers | [Jeremiah Omiagbo (@t49qnsx7qt-kpanks)](https://github.com/t49qnsx7qt-kpanks), owner of the [mnemopay](https://github.com/mnemopay) organization |
| Approvers (approve each signing request) | [Organization owners](https://github.com/orgs/mnemopay/people?query=role%3Aowner) |

StarClaw currently has a single maintainer. Pull requests from anyone else are reviewed by the maintainer before
merging. Every maintainer must use multi-factor authentication on GitHub and on SignPath.

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the
user or the person installing or operating it.

In practice: StarClaw sends your prompts and the content you ask it to work on to the AI model provider **you
configure** (Groq by default, or Anthropic, OpenRouter, OpenAI, or a local Ollama/LM Studio server), and to the
services you enable in your policy (for example Telegram, Slack, Discord, email or a search API). Those providers'
own privacy policies apply to what you send them. StarClaw has no telemetry, analytics or update check. Its console
listens on `127.0.0.1` only.

## Limits

* A signature tells you the file was built by this repository's CI and has not been changed since. It does not
  mean the software is free of bugs or safe for any particular use; see [SECURITY.md](../SECURITY.md).
* A newly signed file can still trigger a SmartScreen prompt until it has built download reputation.
* The uninstaller (`unins000.exe`) is not signed yet. Inno Setup can embed a signed uninstaller
  (`SignedUninstaller`), which needs a second signing round trip in CI; that is planned, not done.

## For maintainers: turning signing on

Signing is off until **all four** of these exist in the repository settings (Settings > Secrets and variables >
Actions). With any of them missing, the workflow builds and releases unsigned exactly as before, and prints a warning
if only some are set.

| Name | Kind | Value |
|---|---|---|
| `SIGNPATH_API_TOKEN` | **secret** | API token of a SignPath user with *submitter* rights on the project (a CI user, not a person's login) |
| `SIGNPATH_ORGANIZATION_ID` | variable (or secret) | SignPath organization ID (a GUID) |
| `SIGNPATH_PROJECT_SLUG` | variable (or secret) | e.g. `starclaw` |
| `SIGNPATH_POLICY_SLUG` | variable (or secret) | `release-signing` (or `test-signing` while trying it out) |

In SignPath, the project needs the trusted build system *GitHub.com* linked, and the artifact configuration from
[`.signpath/artifact-configurations/windows-installer.xml`](../.signpath/artifact-configurations/windows-installer.xml)
set as its default. Signing runs on version tags and on manual runs (`workflow_dispatch`), never on pull requests.

If the first signing request is refused for metadata (product name/version), compare the setup.exe's version
resource (Properties > Details) with the restriction in that XML: `starclaw.iss` sets `VersionInfoProductName` and
`VersionInfoProductTextVersion`, but which version field SignPath compares was not confirmed before the first real
request.
