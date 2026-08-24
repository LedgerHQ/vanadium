//! Fixtures shared by the `sign_psbt` unit tests.

use alloc::vec;
use alloc::vec::Vec;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::{
    bip32::{ChainCode, ChildNumber, Xpub},
    psbt::Psbt,
};
use common::{
    bip388::WalletPolicy,
    por::{ProofOfRegistration, Registerable},
    psbt::prepare_psbt,
};
use sdk::curve::{Curve, EcfpPrivateKey, ToPublicKey};

/// rust-bitcoin doesn't support PSBTv2, so we use this helper for conversion.
pub(super) fn serialize_as_psbtv2(psbt: &Psbt) -> Vec<u8> {
    common::psbt::psbt_v0_to_v2(&psbt.serialize()).expect("Failed to convert PSBTv0 to PSBTv2")
}

/// A legacy `pkh(@0/**)` transaction: one 1_000_000 sat input, whose non-witness
/// UTXO carries two outputs and which spends vout 1, paying a single external
/// output of 999_800 sat — so the fee is 200 sat.
pub(super) fn legacy_pkh_psbt() -> Psbt {
    let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
    let mut psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "pkh(@0/**)",
        vec![
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "My legacy account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    psbt
}

/// A `wpkh(@0/**)` transaction: one SegWit v0 input carrying both a witness UTXO and
/// the non-witness UTXO that backs it.
pub(super) fn segwit_wpkh_psbt() -> Psbt {
    let psbt_b64 = "cHNidP8BAHQCAAAAAXoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////AqC7DQAAAAAAGXapFDRKD0jKFQ7CuQOBdmC5tosTpnAmiKx0OCMAAAAAABYAFOs4+puBKPgfJule2wxf+uqDaQ/kAAAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxGESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXKGWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAAAAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAAAACICAinsR3JxMe0liKIMRu2pq7fapvSf1Quv5wucWqaWHE7MGPWswv1UAACAAQAAgAAAAIABAAAACgAAAAA=";
    let mut psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "wpkh(@0/**)",
        vec![
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "My segwit account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    psbt
}

/// BIP-32 path a device-controlled xpub claims to live at. Any path will do; the
/// device just needs to be able to re-derive it locally from its master seed.
pub(super) const DEVICE_PATH: [u32; 4] = [0x80000030, 0x80000001, 0x80000000, 0x80000002];

/// Builds the device's xpub at [`DEVICE_PATH`] by re-deriving from the host-side SDK's
/// master.
pub(super) fn device_xpub() -> Xpub {
    let node = sdk::curve::Secp256k1::derive_hd_node(&DEVICE_PATH).unwrap();
    let compressed = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*node.privkey)
        .to_public_key()
        .to_compressed();
    Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: 4,
        parent_fingerprint: bitcoin::bip32::Fingerprint::default(),
        child_number: ChildNumber::Hardened { index: 2 },
        public_key: bitcoin::secp256k1::PublicKey::from_slice(&compressed).unwrap(),
        chain_code: ChainCode::from(node.chaincode),
    }
}
