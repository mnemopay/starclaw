# Editorial direction: show the product's behavior

The page keeps the ivory, ink, vermilion and serif/grotesk typography, with a recorded task as its main visual.

`example-run.json` contains two executions of the same task using the real StarClaw engine, a scripted model and a scripted approver. They ran through the process permission sandbox. One approval allowed a file write; the other denied it. No external model API, network access or payments were involved. Public fixture paths do not contain user account names. The generated private signing key is not published.

The page is a replay, not an agent service. Its buttons do not write files. Verification uses browser Web Crypto to check the canonical record body hash, previous-record chain, sequence, Ed25519 signature, and signed head checkpoint. The tamper control changes only an in-memory copy of the decision. Browsers without Ed25519 support receive an explicit fallback message. The example's public key ships alongside the records; this is a verification demonstration, not an independent trust anchor or a security certification.

To regenerate from the repository root, with dependencies installed and a compatible Node runtime:

```text
node --import tsx scripts/record-site-example.ts
```

The recorder creates a unique temporary directory (at the drive root on Windows, to keep user paths out of the public log), verifies both runs, exports the example, and removes only its own generated directory.

Validation: approval and denial logs verified in Chromium; changing a decision was rejected; task tabs worked by keyboard; no page overflow at 1440, 768, 390 or 320 pixels; no browser runtime errors. The example request and output are downloadable and inspectable. All rendering uses text nodes for recorded data.
