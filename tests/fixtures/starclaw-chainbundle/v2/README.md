# starclaw-chainbundle fixture v2

The same signed StarClaw audit log as `v1/`, with `chain-bundle.json` rebuilt by
StarClaw 2.0.0-alpha.15 and later, which add `meta.event_count` (the number of events,
here 5). Anchoring sinks such as AgentAudit's can record the event count from `meta`
instead of defaulting to 1.

**`v1/` is frozen.** AgentAudit's CI pins `v1/chain-bundle.json` byte for byte, so it is
never regenerated. New consumers should use v2.

| File | Contents |
|---|---|
| `audit.jsonl` | 5 signed StarClaw records (identical to `v1/audit.jsonl`) |
| `audit.jsonl.head` | Signed head checkpoint (identical to v1) |
| `pubkey.txt` | The Ed25519 public key to pin (identical to v1) |
| `chain-bundle.json` | The ChainBundle v1 built from the log, now with `meta.event_count` (no Article 12 link in meta) |
| `expected.json` | Pinned `merkle_root`, `event_count` and sha256 of `chain-bundle.json` |

## Pinned values

- `merkle_root`: `35a592434300017e903062fbff4488a2f3322479626289c37e78984fb54ddd04`, **equal to v1's**. The root is rolled from the events only; `event_count` is in `meta`, which is not a leaf.
- sha256(`chain-bundle.json`): `df1e3f662f1663103cd97aa9af4c8c578e722e3d6628cca3007ad344e072ac6e` (v1: `54f963b6...4824abfc`)
- `meta.event_count`: `5`

## What changed from v1

Only one line of `chain-bundle.json`: `meta` gains `"event_count": 5` after `key_pinned`.
Events, `built_at`, `merkle_root`, the other `meta` fields and their order are unchanged.
The ChainBundle `version` (1) and `meta.format` (`starclaw-chainbundle/1`) are unchanged:
the field is additive. Event mapping and tree construction are as described in `v1/README.md`.
Bytes are LF only; `.gitattributes` keeps them verbatim.

Checked by `tests/chainBundle.test.ts` (byte-exact rebuild, sha256, `verifyBundle` ok,
root equal to v1's).
