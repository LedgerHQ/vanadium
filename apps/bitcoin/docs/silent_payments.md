# Silent payments

[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) silent payment addresses are static addresses that never appear on chain: the sender derives a fresh taproot output for each payment, from the recipient's code and from the transaction's own inputs.

The app can **pay to silent payment addresses** from its accounts, following the signer role of [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki), with the DLEQ proofs of [BIP-374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki). It also has **silent payment accounts**, which receive to silent payment addresses; spending what they receive ([BIP-376](https://github.com/bitcoin/bips/blob/master/bip-0376.mediawiki)) is not supported yet.

## Paying to a silent payment address

The host describes the payment as an output with `PSBT_OUT_SP_V0_INFO`, the recipient's code `B_scan || B_m`, and no `PSBT_OUT_SCRIPT`: the script depends on the whole transaction, so the signer computes it. Such an output is always external: the review shows the `tsp1…` address of the code.

`sign_psbt` then works in four steps:

1. **Before the review**, the app checks everything that needs no private key, so that the user is never asked to approve a transaction that can't be signed:
   - no input spends a segwit version above 1, and no taproot input asks for `SIGHASH_DEFAULT` explicitly: when a sighash type is specified, BIP-375 requires `SIGHASH_ALL`, which is the only other type the app accepts in any transaction. Without one, the device signs with `SIGHASH_ALL`; for taproot inputs it uses `SIGHASH_DEFAULT`, which BIP-341 defines to commit to exactly what `SIGHASH_ALL` commits to, with a signature one byte shorter. BIP-375 only rules out the types that let the outputs change after signing;
   - at least one input is *eligible*, and the device holds the private key of each one (see below);
   - the PSBT has no ECDH share or DLEQ proof that the device wouldn't compute: no per-input ones, and no global ones for a scan key that no output pays to;
   - the outputs to codes carry no identity-key proof and no account coordinates: both are about a script, which these outputs don't have yet.
2. **The review**, during which the usual deferred checks prove that each input belongs to its account.
3. **After the approval**, the app computes the sum `a` of the private keys of the eligible inputs, and for each scan key the global ECDH share `a·B_scan` with its DLEQ proof, then the script of each output to a code. If the PSBT already has a global share or a script, it must be the one the device computes, and a global share must come with a valid DLEQ proof: this lets the host send again a PSBT in which it merged a previous response.
4. **The signatures**, over the transaction with those scripts.

The response carries the shares (`sp_shares`) and the scripts (`sp_output_scripts`) next to the signatures. The host must set them in the PSBT, as `PSBT_GLOBAL_SP_ECDH_SHARE`, `PSBT_GLOBAL_SP_DLEQ` and `PSBT_OUT_SCRIPT`, and set `PSBT_GLOBAL_TX_MODIFIABLE` to 0, as BIP-375's reference validator requires: the signatures commit to the scripts, which depend on all the inputs. The client does all this in `SignedPsbtResponse::merge_into`.

### Eligible inputs, and which ones the device can use

BIP-352 takes a key from each input that it calls eligible, whatever its account:

| Inputs | Key |
|---|---|
| `pkh()`, `wpkh()`, `sh(wpkh())` | the input's key |
| `tr()`, spent by any path | the taproot *output* key: the internal key, tweaked with the tap tree |
| others, like `wsh()` | none: the input is not eligible, and doesn't affect the outputs |

The app computes a single global share for each scan key, so it needs the private key of *every* eligible input. It fails with `SilentPaymentInputNotHeld` for:

- a `tr()` input whose internal key is a `musig()`: each cosigner only holds part of the key;
- a `tr()` input whose internal key belongs to a cosigner, even if one of the device's keys is in a leaf of the tap tree;
- a `tr()` input whose internal key is derived from a NUMS xpub, as wallet policies do to disable the key path. BIP-352 only excludes the inputs whose internal key is exactly the NUMS point H, which a derived key never is, so no sender can ever use such inputs to pay a silent payment address. Wallets must leave these coins out of such payments.

BIP-375 also lets each signer add the shares of its own inputs, with a DLEQ proof per input; supporting that would need another round, and verifying the proofs of the other signers.

### The order of the outputs to the same scan key

The `k` of each output among the outputs to the same scan key counts them in **output order**, as the reference validator and the test vectors of BIP-375 v0.1.2 do. The text of BIP-375 instead asks to sort the codes of each scan key lexicographically, but its own test vectors only pass in output order. The rule is in `common::silent_payments::recipients`, the one place to change should BIP-375 settle on its text.

## Silent payment accounts

A silent payment account is the BIP-352 account `n` of the device, with its two keys, in the standard tree:

| Key | Path |
|---|---|
| scan key `b_scan` | `m/352'/1'/n'/1'/0` |
| spend key `b_spend` | `m/352'/1'/n'/0'/0` |

The account holds the account index, the scan *private* key and the spend *public* key `B_spend`: the keys of a [BIP-392](https://github.com/bitcoin/bips/blob/master/bip-0392.mediawiki) `tspscan` key, which is what a wallet needs to find the account's payments. The spend private key, which spends them, never leaves the device.

### Setting up an account

1. `export_silent_payment_scan_key` returns the `tspscan` key of the account `n`. The user always confirms the export, after a warning: the scan key reveals every payment to the account, though it can't spend them.
2. The host builds the account from it, and registers it with `register_account`. The device checks that the keys are its own for the account index, and shows the name, the index and the account's address. The proof of registration then vouches for the keys, so the device never derives them again to compute the account's addresses.

### Addresses, labels and change

`get_address` returns the account's silent payment address, `tsp1…`, or the address of one of its labels `m`, whose spend key is `B_m = B_spend + hash(b_scan || m)·G` (BIP-352). A wallet must scan for each label that it hands out.

Label 0 is the change label of BIP-352: `get_address` never returns it, so that every payment to it is the account's own change.

### Destinations

Like any account, a silent payment account tells which inputs and outputs are its own by computing their *destination* from its coordinates:

- the coordinates of an address are its label, if any, and the destination is the account's code `(B_scan, B_m)`: in a PSBT, an output to a code has `PSBT_OUT_SP_V0_INFO` and no script, as the script of each payment depends on the whole transaction;
- the coordinates of an output that the account received are its tweak, as in `PSBT_IN_SP_TWEAK` (BIP-376), the label's included, and the destination is that output's script, `OP_1 x(B_spend + tweak·G)`.

The transactions that spend from silent payment accounts, or send change to them, will use these destinations.
