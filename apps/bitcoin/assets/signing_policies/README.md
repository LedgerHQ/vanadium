# Signing policy images

This directory holds the **built** signing-policy images shipped with the app: one `.vpol` file per
example policy, plus a `hashes.txt` recording each image's hash. They are data, not source: the
integration tests `include_bytes!` them, and the client CLI reads them verbatim at runtime.

The corresponding **source** lives in `apps/bitcoin/policies/<name>/`, one Rust crate per policy.

The format of a `.vpol` image, and everything a policy program can do, is specified in
[../../docs/SIGNING_POLICIES.md](../../docs/SIGNING_POLICIES.md).

## Every byte counts

A key is bound to a policy by the SHA-256 of

```
engine_id (0x02) ‖ engine_version (0x00) ‖ compact_size(len) ‖ image bytes
```

and the first 124 bits of that hash become the key's derivation path. So the *exact* bytes of a
`.vpol` file determine which key enforces it. A different compiler version, a different optimization
level, or a stray byte in the header produces a different hash, a different key, a different account
ID and a different proof of registration.

Treat a published image as immutable. To change a policy, build a new image and register a new
account; there is no way to update a policy in place, by design.

## Building

```
cargo vnd policy build apps/bitcoin/policies/<name>
```

writes `<name>.vpol` here. `hashes.txt` must be regenerated in the same commit; CI rebuilds every
policy and fails if an image or its hash has drifted, which is what makes the committed images
trustworthy enough to test against.

Reproducible builds are a requirement here rather than a nicety: the whole security story rests on a
user being able to independently derive the hash of a policy from its source. See
[Auditability](../../docs/SIGNING_POLICIES.md#auditability). Until that is solved, treat the
committed images as the authoritative artifacts and the crates as their documentation.

## The example policies

| Image | What it does |
|-------|--------------|
| `fee-cap.vpol` | Refuses to sign if the fee exceeds 10% of the total input amount. Otherwise defers to the normal confirmation flow. |
| `consolidation-only.vpol` | Signs silently, but only for transactions that send nothing outside the account, reduce the number of UTXOs, and keep the fee under 1%. A service holding this key can tidy up the account and cannot move a satoshi out of it. |
| `vault-covenant.vpol` | Simulates BIP-443 `OP_CHECKCONTRACTVERIFY` in `CCV_MODE_CHECK_OUTPUT`: every vault input's amount must be preserved into the vault output, which must itself be the same vault. Exercises per-input invocation, the shared state, and the accelerated taproot tweak. |

The first two are convenience examples. `vault-covenant` is the one that exercises the parts of the
engine that a simple limit policy does not, and it should be kept working as the engine evolves.

## A warning about silent approval

A policy that returns `ApproveSilently` disables every on-device check for the transactions it
approves: no amounts, no addresses, no fee, no confirmation. That is the point of the feature, and it
is why the hash the device shows at registration matters more than anything else in this directory.

Note also what each example deliberately ignores. `fee-cap` bounds the fee and nothing else — it
happily signs a transaction that sends everything to an attacker, as long as the fee is reasonable.
Composing a policy out of the checks it *does* make is the author's job; the device makes none of
them on the policy's behalf.
