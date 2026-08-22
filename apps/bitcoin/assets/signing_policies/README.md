# Signing policies

Ready-to-use **signing programs** for the Bitcoin V-App. A signing program is a tiny script that a
key of a wallet policy commits to: before signing with that key, the device evaluates the program
against the transaction and either refuses to sign, signs after the usual confirmation, or signs
without asking at all.

The language, the binding between a program and a key, and the PSBT encoding are specified in
[docs/PSBT.md](../../docs/PSBT.md#signing-policies). This folder is the practical counterpart: a
handful of policies that are worth running, and that double as worked examples of the language.

## The `.plc` format

A `.plc` file is the **raw source** of a program — no header, no encoding, no metadata. The client
reads it verbatim and wraps it with the engine id (`0x01`, the built-in language) and version (`0`)
before hashing it.

Two consequences worth internalizing:

- **Every byte counts.** Comments, indentation and the trailing newline are all part of the hash.
  Reformatting a file changes its hash, which changes the derivation path of any key bound to it,
  which changes the account id and invalidates its proof of registration. Treat a published `.plc`
  file as immutable: to change a policy, add a new file and register a new account.
- **The extension is checked, case-sensitively.** `fee-cap.plc` works, `fee-cap.PLC` is rejected.

## The policies

| File | What it enforces | Outcome |
|------|------------------|---------|
| [always-approve.plc](always-approve.plc) | Nothing. Signs whatever the wallet policy allows | always silent |
| [never-sign.plc](never-sign.plc) | The key is inert: addresses can still be derived, but this key never signs | always refused |
| [fee-cap.plc](fee-cap.plc) | The fee may not exceed 10% of the total input amount | refused above the cap, normal confirmation below |
| [single-recipient.plc](single-recipient.plc) | At most one external recipient and one change output — no batching | refused if batched, normal confirmation otherwise |
| [small-spend-auto-approve.plc](small-spend-auto-approve.plc) | Payments up to 0.001 BTC need no confirmation | silent up to the threshold, normal confirmation above |
| [self-transfer-only.plc](self-transfer-only.plc) | Nothing may leave the wallet, and the fee stays under 1% | silent for self-transfers, refused otherwise |
| [consolidation-only.plc](consolidation-only.plc) | Self-transfers that also reduce the number of UTXOs, fee under 1% | silent for consolidations, refused otherwise |
| [spending-limits.plc](spending-limits.plc) | Hard cap at 0.05 BTC, fee cap at 5%, silent below 0.001 BTC | all three outcomes, depending on the amount |

⚠️ `always-approve.plc` disables every on-device check for the key bound to it. It is meant for
demos and tests, or for a key whose safety comes from elsewhere (for instance one participant of a
multisig whose cosigners do the reviewing). `small-spend-auto-approve.plc` and
`single-recipient.plc` deliberately check one thing each, and in particular ignore the fee — a
small payment can still be an expensive transaction. `spending-limits.plc` is the example of a
policy that combines several checks.

A few things a program *cannot* do in this version: it sees only transaction-wide aggregates (see
the [`context` fields](../../docs/PSBT.md#the-context-object)), never individual addresses,
scripts, or anything about the past. There is no state, so "spend at most X per day" is out of
reach — the limits above are per transaction.

## Using them from the CLI

The commands below are typed at the interactive prompt of the Bitcoin client
(`cargo run -- --native` from `apps/bitcoin/client`, or see
[the app README](../../README.md#run-the-v-app) for the other transports). Paths are resolved
relative to the directory the client was started from, so from `apps/bitcoin/client` a policy is
`../assets/signing_policies/<name>.plc`.

**1. Get the hash and the binding path.** A program is bound to a key purely through a BIP-32
derivation path derived from the program hash:

```text
signing_policy_hash --policy ../assets/signing_policies/fee-cap.plc
```

```text
hash: <64 hex chars>
path: 1347175257'/1'/0'/p1/p2/p3/p4
```

`--coin_type` (default `1`, testnet) and `--account` (default `0`) pick the two hardened indices;
`p1..p4` are computed from the hash.

**2. Fetch the device's key at that path**, and use it — with the very same origin — in a wallet
policy:

```text
get_pubkey --tree standard --path "1347175257'/1'/0'/p1/p2/p3/p4"
```

**3. Register the account**, supplying the program itself. The device recomputes `p1..p4` from it
and refuses the registration if they don't match the origin path:

```text
register_account --name "Fee-capped account" --descriptor_template "wpkh(@0/**)" --keys_info "[f5acc2fd/1347175257'/1'/0'/p1/p2/p3/p4]tpub..." --signing-policy ../assets/signing_policies/fee-cap.plc
```

**4. Sign**, supplying the program again so the client can insert it into the PSBT's global map:

```text
sign_psbt --psbt "$BASE64_PSBT" --signing-policy ../assets/signing_policies/fee-cap.plc
```

`--signing-policy` is repeatable (once per distinct program used by the account's keys); identical
programs are deduplicated by hash. If a policy-bound key is missing its program, signing fails
closed.

⚠️ At registration the device shows the policy's **hash**, not its source: it has no way to tell
you what the policy means. Compute the hash of the exact file bytes on another trusted machine —
`signing_policy_hash` on a second host, or any SHA-256 of `01 00 <compact-size len> <file bytes>` —
and compare it with the hash on screen before approving.

## Writing your own

Start from the closest file here and keep in mind:

- The first action reached wins, so refusals must come before approvals.
- Anything the engine dislikes — a parse error, a type error, an overflow, a division by zero, a
  program over 2048 bytes or nested deeper than 32 levels — makes the device refuse to sign.
- `approve()` is only honored when *every* key signing the transaction approves silently, and when
  all input amounts could be verified; otherwise the normal confirmation flow is used.

Every file in this folder is compiled by the app's unit tests
(`policy::test_assets::shipped_policies_compile`), and a few of them are used by the
`register_account` and `sign_psbt` tests, which read them from here rather than restating the
source. A new `.plc` file is picked up by adding it to
[`app/src/policy/test_assets.rs`](../../app/src/policy/test_assets.rs).
