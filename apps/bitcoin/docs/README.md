This is the Bitcoin application for Vanadium. It (will be) a next-generation application that generalizes the functionality of the [Ledger Bitcoin application](https://github.com/LedgerHQ/app-bitcoin-new) with more general signing flows, and advanced use cases.

It is also based around the [PSBT standard](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki), but fully implements the signing model based on _accounts_, represented initially with [BIP-388 wallet policies](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki) - more account types (like [silent payment addresses](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)) may be added in the future.

In the future, experimenting with features like _signed addresses_, _known contacts_, _identity_, etc is planned, in order to further enhance the UX and avoid users from having to manually check addresses whenever possible.

*Remark*: the current implementation targets Bitcoin testnet only (extended public keys are serialized with the testnet version bytes, and the displayed coin ticker is `TEST`). Mainnet support is planned.

# Features and supported standards

The bitcoin app implements standards to guarantee interoperability, security and clear signing for bitcoin transactions, from the simpler to the more advanced use cases:
- [BIP-370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki) PSBTs Version 2 are used to describe transactions to the application.
- [BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki) wallet policies build on top of descriptors ([BIP-380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) and related BIPs) to describe standardized *wallet accounts* that work for any kind of spending conditions, including using [miniscript](https://github.com/bitcoin/bips/blob/master/bip-0379.md).

## PSBT-level extensions
PSBT-level extensions via *Proprietary Use Types* are used to carry account information, proofs of registration and identity-based output authentication.

They are documented in [PSBT.md](PSBT.md).


## Experimental/advanced features

- **Cleartext registration of wallet policies**: when registering a wallet policy, show a cleartext, human-readable description of the spending paths to the user, instead of (or in addition to) the raw BIP-388 descriptor template. Falls back to the raw template when the descriptor template's confusion score exceeds the safe threshold.
- **Identity-based authentication** ([identity.md](identity.md)): identity keys are derived from the device, can be registered with a user-chosen name, and used to sign for xpubs and for output `scriptPubkey`s. During PSBT signing, external outputs carrying a valid signature from a registered identity key are displayed alongside the corresponding name, enabling clear signing of known counterparts.
- **Authenticated cosigner xpubs**: when registering a multi-key wallet policy, each cosigner xpub can be accompanied by a Schnorr signature from a registered identity key, so the device labels the key with the cosigner's name during the registration review.
- **Multi-account spends**: a single PSBT can spend from multiple known wallet policies; the review shows the net amount spent or received for each affected account.
- **Resident keys**: BIP-32 keys derived from a seed generated and stored inside the app and never exported. Resident keys can be used as keys in wallet policies, and the app supports PSBT signing with them.

## Planned features

- [BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) MuSig2 support
- [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) Silent Payments support. Silent Payment addresses can be added as a new type of account - but they could also be used as *identity pubkeys*. This would allow a DNS-based Root of Trust that doesn't require an explicit registration step.
- DNSSEC-based authentication for identity pubkeys. Similar to [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) but for identity pubkeys.
- Signing policies: derive keys that will only sign transactions (and possibly auto-sign) if they satisfy certain spending policies.

# Commands

This is a draft of the specs of the app.

Throughout the commands, the `tree` parameter selects which BIP-32 key hierarchy to use:
- `Standard`: keys derived from the device's master seed (the same seed shared with other apps).
- `Resident`: keys derived from a seed that is generated inside the app on first use and stored in the app's persistent storage. The resident seed never leaves the device and cannot be exported.

## `get_master_fingerprint`

**Inputs:** A `tree` selector (Standard or Resident).\
**Outputs:** The fingerprint of the master public key as defined in [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), for the chosen tree.

No interaction with the user is required.

## `get_extended_pubkey`

**Inputs:** A `tree` selector; a BIP-32 derivation path; a boolean `display` parameter; an optional `identity_index` (only valid when `tree == Standard`).\
**Outputs:** The [serialized extended public key](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format) as a 78-byte array for the given derivation path, plus an optional Schnorr signature over that xpub from the `identity_index`-th identity key (see [identity.md](identity.md)).

If `display == True`, the public key (encoded in base58check) is shown to the user for confirmation, and the command returns only after the user approves. When the path is recognized as an identity-key path (see [identity.md](identity.md)), the value shown is the identity key itself (root xpub or compressed pubkey in hex) and the prompt is adapted accordingly.

TBD: What paths should allow `display == False`?

## `register_identity_key`

**Inputs:** A name, and a 33-byte compressed secp256k1 public key.\
**Outputs:** A registration id and the corresponding *Proof-of-Registration* (HMAC) for this identity key.

Shows the identity key and its name to the user for confirmation. After approval, the device computes a proof-of-registration that can later be presented to the device to vouch that this pubkey was registered under this name (e.g. during `register_account` for cosigner authentication, or in PSBTs for output authentication).

## `register_account`

**Inputs:** The account name and description; an optional list of registered identity keys with their proofs of registration; an optional list of per-key identity signatures over the cosigner xpubs; a boolean `show_cleartext` flag.\
**Outputs:** The account id and the *Proof-of-Registration* of the account (HMAC).

Shows an account for inspection to the user; after confirmation, returns the proof of registration. When `show_cleartext` is true (and the descriptor template is considered "safe enough" to be summarized), the device shows a human-readable description of each spending path instead of the raw descriptor template.

For each cosigner key in the wallet policy, the device labels it on screen as:
- the name of a registered identity key, if a valid signature over its xpub from that key is provided;
- `our key`, if the key matches a public key derived from the standard or resident tree on this device;
- `dummy`, if the key matches the BIP-341 unspendable NUMS point;
- otherwise, no label.

*Remark*: this is similar to the `REGISTER_WALLET` command of the Ledger Bitcoin app. The proof of registration allows the device to recognize in the future that this account was registered with the chosen name.

*Remark*: registering *external* accounts (for which the device is not a cosigner) is supported, in order to enable recognizing their addresses among the outputs during `sign_psbt` even if not spending from them in the inputs.


## `get_address`

**Inputs:** An optional account name; the account description; the proof of registration (`por`); the coordinates of the specific address; a boolean `display` parameter; an optional `identity_index`.\
**Outputs:** The address of the account, plus an optional Schnorr signature over the output `scriptPubkey` from the `identity_index`-th identity key.

Initially, only BIP-388 wallet policies are supported as accounts; the coordinates are `(is_change: bool, address_index: 0..2**31-1)`.

The provided proof of registration is validated against the (name, account) pair. Default accounts (no name and no proof of registration) are not yet supported.

## `sign_psbt`

**Inputs:** A PSBTv2 filled with all the necessary information to sign the transaction, including account information for each affected input and output (see [PSBT.md](PSBT.md)).\
**Outputs:** Partial signatures (or any other object the signer intends to add to the psbt).

Processes (and, if appropriate, signs) a PSBT, after validating the action with the user.

The transaction is analyzed in an account-centric manner: for each of the affected accounts in the inputs, shows how much money is spent/received in total.

Account info and coordinates are also used to identify external outputs belonging to known accounts (allowing the user to validate the destination account, rather than the actual address). External outputs that are not associated with any known account may be authenticated by attaching a Schnorr signature, from a registered identity key, over the output `scriptPubkey` (see [PSBT.md](PSBT.md)); if the signature is valid, the corresponding name is displayed alongside the address during review.

The device also shows extra warnings before the transaction review when:
- the segwit-v0 inputs cannot be fully verified because the non-witness UTXO is missing;
- the transaction fee exceeds a configured fraction of the total input amount (high-fee warning).

Both the standard tree or the resident tree are supported during signing.

*Remark*: The Ledger bitcoin app also takes the `wallet_policy` (and its *Proof-of-Registration* if needed) as a separate input. Here, the account information and the coordinates are included in the PSBT itself, for each affected input/output of the transaction.