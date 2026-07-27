This document details the specifications of extensions to the PSBT format used by the Vanadium Bitcoin app.

Three extensions are currently defined:

- **Accounts**: The signing flow uses BIP-388 wallet policies (or other account abstractions) to identify inputs and outputs that belong to known accounts. The PSBT contains the necessary information to easily verify that UTXOs belong to the claimed accounts.
- **Authenticated outputs**: Outputs that do not belong to known accounts can be *authenticated* by attaching a signature from a pubkey with an established Root of Trust.
- **Signing policies**: Wallet-policy keys can commit to programs that inspect transaction aggregates and decide whether the key may sign.

# Accounts and coordinates

An _account_ identifies a collection of outputs/addresses that logically belong to the same accounting unit. For signers with an account-based signing flow, the account information is the primary mechanism to ensure clear signing on the flow of money in and out of accounts. For each transaction, the UX will clearly show how much money is being spent, or going into, each of the accounts involved in the transaction.

For each account, the corresponding _coordinates_ identify the exact an output/address.

The specifications of each account type must detail how the account description and the coordinates are serialized.

Each of the different types of accounts has a single `account_tag`, implemented as a single unsigned byte.

The additional fields are defined using the proprietary fields defined by the [PSBT](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) (with key types `PSBT_{GLOBAL,IN,OUT}_PROPRIETARY` in the global, per-input or per-output maps, respectively), using the proprietary identifier `ACCOUNT` (all capital letters).

## Account types
### Wallet policy ([BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki))

`account_tag` is 0 for wallet policies (and their coordinates).

- Account: A valid BIP-388 wallet policy
- Coordinates: a `(is_change, address_index)` pair, where `is_change` is a boolean, and `address_index` is a number between 0 and 2147483647.

The wallet policy is serialized as the concatenation of:
- The compact-size length of the descriptor template
- The descriptor template
- The compact size number _n_ of key expressions
- Repeat for each of the _n_ keys
  - If there is no key origin information, a single byte 0, followed by a 78-byte serialized xpub
  - If there is ordinary key origin information, the concatenation of
    - a single byte 1
    - 4 bytes: key fingerprint, big-endian
    - compact-size length _k_ of the key origin derivation
    - 4 * _k_ bytes: the concatenation of each derivation step, each represented as a 4-byte little-endian number
    - a 78-byte serialized xpub
  - If there is key origin information with a signing-policy commitment, the concatenation of
    - a single byte 2
    - 4 bytes: key fingerprint, big-endian
    - compact-size length _k_ of the key origin derivation
    - 4 * _k_ bytes: the concatenation of each derivation step, each represented as a 4-byte little-endian number
    - the 32-byte signing-policy hash
    - a 78-byte serialized xpub whose chaincode equals that hash

The coordinates are serialized as:
- a single byte 0 if not change, 1 if change
- followed by 4 byte little-endian address index.

### Silent Payments Address ([BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki))

TODO

## Global subkey types

| Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeytype>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>` Description | `<valuedata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<valuedata>`&nbsp;Description&nbsp;&nbsp; | Versions Requiring Inclusion | Versions Requiring Exclusion | Versions Allowing Inclusion | Parent BIP |
|-----------------------|-------------------------------------------------|-----------------------------|----------------|-------------------------------------|---------------------------------------------------------------------------------------|------|-|------|--------|
| Account Description   | `PSBT_ACCOUNT_GLOBAL_ACCOUNT_DESCRIPTOR = 0x00` | `<compact size account ID>` | The account ID | `<byte account_tag> <bytes serialized account>`        | The single byte account tag, followed by the full description of the account, serialized as per the rules of that account type | 0, 2 | | 0, 2 | No BIP |
| Account Name          | `PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME = 0x01`       | `<compact size account ID>` | The account ID | `<compact size name length> <name>` | The non-zero length of the name, followed by the name of the account                  |      | | 0, 2 | No BIP |
| Proof of Registration | `PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR = 0x02`        | `<compact size account ID>` | The account ID | `<bytes>`                           | If required by the signer, the _Proof of Registration_ for the account                |      | | 0, 2 | No BIP |


### Per-input subkey types

| Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeytype>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>` Description | `<valuedata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<valuedata>`&nbsp;Description&nbsp;&nbsp; | Versions Requiring Inclusion | Versions Requiring Exclusion | Versions Allowing Inclusion | Parent BIP |
|---------------------|--------------------------------------|-----------------------------|----------------|----------------------------------|---------------------------------------------------------------------|-|-|------|--------|
| Account Coordinates | `PSBT_ACCOUNT_IN_COORDINATES = 0x00` | None | No subkey data | `<compact size account ID> <byte account_tag> <bytes serialized coordinates>` | The compact size account id, followed by a single byte account tag, followed by the coordinates, serialized as per the specification of the account | | | 0, 2 | No BIP |


### Per-output subkey types

| Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeytype>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>` Description | `<valuedata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<valuedata>`&nbsp;Description&nbsp;&nbsp; | Versions Requiring Inclusion | Versions Requiring Exclusion | Versions Allowing Inclusion | Parent BIP |
|---------------------|---------------------------------------|-----------------------------|----------------|----------------------------------|---------------------------------------------------------------------|-|-|------|--------|
| Account Coordinates | `PSBT_ACCOUNT_OUT_COORDINATES = 0x00` | None | No subkey data | `<compact size account ID> <byte account_tag> <bytes serialized coordinates>` | The compact size account id, followed by a single byte account tag, followed by the coordinates, serialized as per the specification of the account | | | 0, 2 | No BIP |


# Identity keys and output authentication

Identity keys can be included in the global section of the PSBT. Those keys can therefore be used to sign for the output scripts of the transaction.

The specs for the signature over the output script as specified in [identity.md](identity.md). If trust in the identity pubkey can be established, then when signing a transaction, the Vanadium Bitcoin app can show authentication information for each authenticated external output, mitigating a large class of risks like address replacement and address poisoning.

Authentication data is carried in proprietary PSBT fields (`PSBT_OUT_PROPRIETARY`), using proprietary identifier `IDAUTH` (all capital letters).

## Authentication types

Each output authentication proof has an `auth_tag`, implemented as a single unsigned byte.

### Identity-based signature for output scripts

`auth_tag` is 0 for identity-based signatures.


## Global subkey types

| Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeytype>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>` Description | `<valuedata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<valuedata>`&nbsp;Description&nbsp;&nbsp; | Versions Requiring Inclusion | Versions Requiring Exclusion | Versions Allowing Inclusion | Parent BIP |
|---------------------------|-----------------------------------------|-----------------------------------|-----------------------------|----------------------|-------------------------------------------------------------------------------------|-|-|------|--------|
| Identity Key | `PSBT_IDAUTH_GLOBAL_REGISTERED_IDENTITY_KEY = 0x00` | `<33-byte identity pubkey>` | The compressed secp256k1 public key of the identity key | `<1-byte name length> <name> <32-byte proof of registration>` | The non-zero length of the registered name, followed by the name, followed by the 32-byte proof of registration for this identity key | | | 0, 2 | No BIP |

## Per-output subkey types

| Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeytype>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<subkeydata>` Description | `<valuedata>`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| `<valuedata>`&nbsp;Description&nbsp;&nbsp; | Versions Requiring Inclusion | Versions Requiring Exclusion | Versions Allowing Inclusion | Parent BIP |
|---------------------------|-----------------------------------------|-----------------------------------|-----------------------------|----------------------|-------------------------------------------------------------------------------------|-|-|------|--------|
| Output Authentication Signature | `PSBT_IDAUTH_OUT_SIGNATURE = 0x00` | `<byte auth_tag> <33-byte identity pubkey>` | The authentication type and identity pubkey used for this proof | `<64-byte signature>` | Schnorr signature over the output script | | | 0, 2 | No BIP |

For each output, a signer should verify each provided proof against that output's `scriptPubKey`.

- If a proof is well-formed and valid, it may be used for UX authentication if the pubkey is trusted.
- If a proof is malformed or invalid, signing should be aborted.


# Signing policies

A key used in a wallet policy can carry an enforceable **signing program**: a tiny script the
device evaluates against the transaction before signing with that key. The program can refuse to
sign, or authorize signing without user confirmation.

## Binding a program to a key

A policy-bound key carries the same 32-byte program hash in two places:

- An explicit extension to the BIP-388 key origin, serialized with discriminator `2` as described
  above.
- The chaincode of that key's xpub, replacing its canonical BIP-32 chaincode.

The textual key-information syntax appends the lowercase hexadecimal hash to the origin path:

```text
[fingerprint/path/<64 lowercase hex characters>]xpub
```

Parsing this syntax replaces the xpub chaincode with the decoded hash. The explicit origin hash
and xpub chaincode must agree; a chaincode mismatch without an explicit origin hash is not treated
as an implicit policy commitment.

Because the wallet policy (including its xpubs) is committed by the registration proof, binding a
program to a key changes the account ID and proof of registration. When signing, the device derives
the signing key using the synthetic chaincode as a pseudo-root, so any produced signature is
cryptographically bound to the program hash.

Account registration receives the full programs separately from the wallet policy. For each
policy-bound key controlled by the device, registration requires the matching full program,
recomputes its hash, and validates that the selected engine can compile it. One program may satisfy
multiple keys that reference the same hash. An unbound internal key must retain its canonical
BIP-32 chaincode. Policy-bound internal keys are not supported in `musig(...)` expressions.

The device does not display policy source or a policy summary during registration. Users should
verify the exact policy bytes and hash independently on another trusted device before registering
the account.

## Global subkey type

Programs are carried in proprietary PSBT global fields (`PSBT_GLOBAL_PROPRIETARY`), using
proprietary identifier `SIGNING_POLICY` (all capital letters).

| Name | `<subkeytype>` | `<subkeydata>` | `<subkeydata>` Description | `<valuedata>` | `<valuedata>` Description | Versions Allowing Inclusion | Parent BIP |
|------|----------------|----------------|----------------------------|---------------|---------------------------|-----------------------------|------------|
| Signing Policy Program | `PSBT_SIGNING_POLICY_GLOBAL_SCRIPT = 0x00` | `<32-byte hash>` | `SHA-256` of the value bytes; must equal both the explicit origin hash and the chaincode of the bound xpub | `<byte engine_id> <byte engine_version> <compact size len> <program bytes>` | The engine identifier and version, then the length-prefixed program source | 0, 2 | No BIP |

`engine_id = 0x01` selects the built-in program language described below (`0x00` is reserved). The
`engine_id` and `engine_version` are part of the hashed value, so bumping the version invalidates
previously-registered programs by design.

## The program language

An infix, Rust-like language that runs for its side effects. It is deliberately minimal:
non-Turing-complete (no loops or functions) and dynamically typed over `Int` (`i64`, satoshis)
and `Bool`. It supports immutable, block-scoped `let` bindings for naming subexpressions.

Statements run top to bottom. The first **action** reached is terminal:

- `fail();` → refuse to sign with this key.
- `approve();` → sign **without** user confirmation (honored only if every signing key approves
  silently).
- Falling off the end (no action) → sign with the **normal** user-confirmation flow.

Any parse error, runtime type error, arithmetic overflow, divide-by-zero, or exceeded limit causes
the device to **fail closed** (refuse to sign).

```text
program  := stmt*
stmt     := let_stmt | if_stmt | action ";"
let_stmt := "let" ident "=" expr ";"
if_stmt  := "if" expr block ("else" (block | if_stmt))?
block    := "{" stmt* "}"
action   := ("fail" | "approve") "(" ")"
expr     := or ; or := and ("||" and)* ; and := cmp ("&&" cmp)*
cmp      := add (cmp_op add)?              ; comparisons are non-associative
add      := mul (("+"|"-") mul)* ; mul := unary (("*"|"/") unary)*
unary    := ("!"|"-") unary | primary
primary  := int | "true" | "false" | "context" "." ident | ident | "(" expr ")"
cmp_op   := "==" | "!=" | "<" | "<=" | ">" | ">="
```

`// line comments` are supported. Programs are capped at 2048 source bytes and 32 levels of
nesting.

A `let` binding is immutable and **block-scoped**: it is visible from its declaration to the end
of the enclosing `{}` block. A `let` may not shadow a name already in scope, may not reference
itself, and may not use a reserved name (`fail`, `approve`). A bare identifier in an expression
(`primary := ident`) refers to an in-scope binding; an unknown name is a compile error
(fail-closed).

### The `context` object

A program reads the transaction only through a fixed set of aggregate fields (there is no
per-input / per-output access in this version). All amounts are in satoshis.

| Field | Type | Meaning |
|-------|------|---------|
| `context.inputs_total` | Int | Sum of all input amounts |
| `context.outputs_total` | Int | Sum of all output amounts |
| `context.internal_in_total` | Int | Sum of inputs belonging to a recognized account (currently equals `inputs_total`) |
| `context.external_out_total` | Int | Sum of outputs not belonging to a recognized account (external recipients) |
| `context.change_total` | Int | Sum of change / internal outputs |
| `context.fee` | Int | `inputs_total - outputs_total` |
| `context.fee_percent` | Int | Fee as an integer percentage of `inputs_total`, floored |
| `context.input_count` | Int | Number of inputs |
| `context.output_count` | Int | Number of outputs |
| `context.external_out_count` | Int | Number of external outputs |
| `context.change_count` | Int | Number of change / internal outputs |
| `context.tx_version` | Int | Transaction version |
| `context.locktime` | Int | Transaction fallback locktime (0 if unset) |

The `context` values are only trustworthy after the account-coordinate script checks are verified;
the device gates silent signing on that verification succeeding.

### Examples

```rust
// Spending cap: sign silently for small external spends, else ask the user.
if context.external_out_total <= 100000 { approve(); }

// Fee cap: refuse if the absolute fee or the fee percentage is too high.
if context.fee > 50000 || context.fee_percent > 10 { fail(); }

// Self-transfer only: silent if fully internal, else refuse.
if context.external_out_total == 0 { approve(); } else { fail(); }

// Refuse over a hard cap; silent when small; else normal user confirmation.
if context.fee > 50000               { fail(); }
if context.external_out_total > 5000000 { fail(); }
if context.external_out_total <= 100000 { approve(); }

// `let` names a value once and reuses it.
let cap = 100000;
if context.fee > cap / 10 { fail(); }
if context.external_out_total <= cap { approve(); }
```

Signing policies are not supported for MuSig2 keys in this version.
