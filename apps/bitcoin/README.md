This is the Bitcoin app for Vanadium. It is composed of the following crates:

- [app](app) contains the V-app.
- [client](client) contains the client of the V-app.
- [common](common) contains the code shared between the V-App and the client.

The `client` is a library crate (see [lib.rs](client/src/lib.rs)), but it also has a test executable ([main.rs](client/src/main.rs)) to interact with the app from the command line.

## Project Status

### ✅ Implemented Features
- Support for all legacy, SegWit, and Taproot transaction types
- Support for [Miniscript wallet policies](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki)
- Support for transactions spending/receiving to an arbitrary number of accounts

### 🚧 Work in Progress / Planned
- [Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- Identity-based output authentication
- ...anything you can think of

### 🐛 Known Issues & Limitations
- Performance still needs major work
- ⚠️ Not audited, only use on testnets! :)

## Build the V-App

### Risc-V

In order to build the app for the Risc-V target, enter the `app` folder and run:

   ```sh
   cargo build --release --target=riscv32imac-unknown-none-elf
   ```

### Native

In order to build the app for the native target, enter the `app` folder and run:

   ```sh
  cargo build --release
   ```

## Run the V-App

### Native target

Make sure you built the V-App for the native target.

On a terminal in the `app` folder, simply run:

   ```sh
   cargo run
   ```

On a different terminal in the `client` folder, run:

   ```sh
   cargo run -- --native
   ```

Note: you can customize the hostname and port of the app by setting the `VAPP_ADDRESS` environment variable.

### RISC-V target

Make sure you built the V-App for the RISC-V target.

Launch Vanadium on speculos. Then execute:

From the `client` folder

   ```sh
   cargo run
   ```

If you want to run the V-app on a real device, execute instead:

   ```sh
   cargo run -- --hid
   ```

## CLI usage

The executable client is a Command Line Interface to the features of the Bitcoin V-App, featuring autocomplete and command history.

Once the CLI interface is running, press TAB to see the existing command and their arguments.

### Signing policies (`.plc` files)

Some commands take a *signing program*: a small script that a key of a wallet policy commits to,
and that the device evaluates before signing with that key — it can refuse to sign, or authorize
signing without confirmation. Programs are passed as files with the (case-sensitive) `.plc`
extension; a set of ready-to-use ones lives in
[assets/signing_policies](assets/signing_policies).

Paths are resolved relative to the directory the client was started from, so from the `client`
folder a policy is `../assets/signing_policies/<name>.plc`.

A full round-trip, at the CLI prompt:

```text
signing_policy_hash --policy ../assets/signing_policies/fee-cap.plc
get_pubkey --tree standard --path "1347175257'/1'/0'/p1/p2/p3/p4"
register_account --name "Fee-capped account" --descriptor_template "wpkh(@0/**)" --keys_info "[f5acc2fd/1347175257'/1'/0'/p1/p2/p3/p4]tpub..." --signing-policy ../assets/signing_policies/fee-cap.plc
sign_psbt --psbt "$BASE64_PSBT" --signing-policy ../assets/signing_policies/fee-cap.plc
```

`signing_policy_hash` prints the program's hash and the BIP-32 path that binds a key to it (the
`p1..p4` chunks are derived from the hash); `get_pubkey` fetches the device's key at that path,
which is then used — with the same origin — in the wallet policy. Both `register_account` and
`sign_psbt` need the program itself, and accept `--signing-policy` more than once when the account
uses several. A policy-bound key whose program is missing produces no signature.

The device only displays the policy's *hash* when registering the account, so verify it against the
hash of the exact file bytes computed elsewhere before approving. See
[assets/signing_policies/README.md](assets/signing_policies/README.md) for what each shipped policy
does, and [docs/PSBT.md](docs/PSBT.md#signing-policies) for the language and the PSBT encoding.
