This document details the specifications of extensions to the PSBT format used by the Vanadium Bitcoin app.

Two extensions are currently defined:

- **Accounts**: The signing flow uses BIP-388 wallet policies (or other account abstractions) to identify inputs and outputs that belong to known accounts. The PSBT contains the necessary information to easily verify that UTXOs belong to the claimed accounts.
- **Authenticated outputs**: Outputs that do not belong to known accounts can be *authenticated* by attaching a signature from a pubkey with an established Root of Trust.

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
  - If there is key origin information, the concatenation of
    - a single byte 1
    - 4 bytes: key fingerprint
    - 1 byte: length _k_ of the key origin derivation
    - 4 * _k_ bytes: the concatenation of each derivation step, each represented as a 4-byte little-endian number.

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
