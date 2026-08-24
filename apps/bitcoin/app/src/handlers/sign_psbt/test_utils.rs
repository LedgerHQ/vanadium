//! Fixtures shared by the `sign_psbt` unit tests.

use alloc::vec;
use alloc::vec::Vec;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::psbt::Psbt;
use common::{
    bip388::WalletPolicy,
    por::{ProofOfRegistration, Registerable},
    psbt::prepare_psbt,
};

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
