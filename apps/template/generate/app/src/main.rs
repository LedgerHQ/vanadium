#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

use core::str::from_utf8;

use alloc::{vec, vec::Vec};
use sdk::{
    curve::{Curve, EcfpPrivateKey},
    hash::Hasher,
    ux::Icon,
    App, AppBuilder,
};

use client::Command;

sdk::bootstrap!();

const H: u32 = 0x80000000u32;

// Shows the message to the user and asks for confirmation to sign
#[cfg(not(test))]
fn show_message_ui(app: &mut App, msg: &str) -> bool {
    use alloc::format;

    let approved = app.show_confirm_reject(
        "Sign message",
        &format!("Message: {}", msg),
        "Sign message",
        "Reject",
    );

    approved
}

#[cfg(test)]
fn show_message_ui(_app: &mut App, _msg: &str) -> bool {
    true
}

fn process_sign_message(app: &mut App, msg: &[u8]) -> Vec<u8> {
    let msg_str = match from_utf8(msg) {
        Ok(m) => m,
        Err(_) => return vec![],
    };

    if show_message_ui(app, msg_str) {
        let path: Vec<u32> = [H + 9999].to_vec();
        let hd_node = sdk::curve::Secp256k1::derive_hd_node(&path).expect("This shouldn't happen");
        let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> = EcfpPrivateKey::new(
            hd_node
                .privkey
                .as_slice()
                .try_into()
                .expect("invalid privkey"),
        );
        let msg_hash = sdk::hash::Sha256::hash(&msg);
        let sig = privkey.ecdsa_sign_hash(&msg_hash).expect("Signing failed");

        app.show_info(Icon::Success, "Message signed");

        sig
    } else {
        app.show_info(Icon::Failure, "Signing cancelled");
        vec![]
    }
}

fn process_message(app: &mut App, msg: &[u8]) -> Vec<u8> {
    if msg.is_empty() {
        sdk::exit(0);
    }

    let command: Command = match postcard::from_bytes(msg) {
        Ok(cmd) => cmd,
        Err(_) => return vec![], // Return an empty response on error
    };

    match command {
        Command::SignMessage { msg } => process_sign_message(app, &msg),
    }
}

pub fn main() {
    AppBuilder::new("Template", env!("CARGO_PKG_VERSION"), process_message)
        .description("Template App")
        .run();
}

#[cfg(test)]
mod tests {
    use sdk::curve::ToPublicKey;

    use super::*;

    #[test]
    fn test_e2e() {
        let mut app = App::singleton();

        let msg = b"Hello, Vanadium!";
        let msg_hash = sdk::hash::Sha256::hash(msg);
        let sig = process_sign_message(&mut app, msg);

        let path: Vec<u32> = [H + 9999].to_vec();
        let hd_node = sdk::curve::Secp256k1::derive_hd_node(&path).expect("This shouldn't happen");
        let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> = EcfpPrivateKey::new(
            hd_node
                .privkey
                .as_slice()
                .try_into()
                .expect("invalid privkey"),
        );
        let pubkey = privkey.to_public_key();

        pubkey.ecdsa_verify_hash(&msg_hash, &sig).unwrap();
    }
}
