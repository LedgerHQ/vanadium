use alloc::vec::Vec;

use common::{errors::Error, message::Response};

use crate::constants::BIP32_TESTNET_PUBKEY_VERSION;
use crate::resident_key::get_or_init_resident_public_key;

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_resident_pubkey(app: &mut sdk::App, xpub: &str, index: u16) -> bool {
    use alloc::{string::ToString, vec};
    use sdk::ux::{Icon, TagValue};

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Verify resident\nextended public key", "")
    } else {
        ("Verify resident", "extended public key")
    };

    let approved = app
        .review_pairs(
            intro_text,
            intro_subtext,
            &vec![
                TagValue {
                    tag: "Index".into(),
                    value: index.to_string(),
                },
                TagValue {
                    tag: "Public key".into(),
                    value: xpub.into(),
                },
            ],
            "Verify public key",
            "Confirm",
            false,
        )
        .await;
    if approved {
        app.show_info(Icon::Success, "Public key verified");
    } else {
        app.show_info(Icon::Failure, "Public key rejected");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_resident_pubkey(_app: &mut sdk::App, _xpub: &str, _index: u16) -> bool {
    true
}

pub async fn handle_get_resident_pubkey(
    app: &mut sdk::App,
    index: u16,
    display: bool,
) -> Result<Response, Error> {
    let pubkey = get_or_init_resident_public_key()?;
    let pubkey_bytes = pubkey.as_ref().to_bytes();

    // Chaincode: 30 zero bytes followed by the index encoded as big-endian u16.
    let mut chaincode = [0u8; 32];
    let index_be = index.to_be_bytes();
    chaincode[30] = index_be[0];
    chaincode[31] = index_be[1];

    // Serialise as a standard 78-byte extended public key structure.
    let mut xpub = Vec::with_capacity(78);
    xpub.extend_from_slice(&BIP32_TESTNET_PUBKEY_VERSION.to_be_bytes()); // 4 bytes version
    xpub.push(0u8); // depth = 0 (no BIP32 derivation)
    xpub.extend_from_slice(&[0u8; 4]); // parent fingerprint = 0
    xpub.extend_from_slice(&[0u8; 4]); // child number = 0
    xpub.extend_from_slice(&chaincode); // 32 bytes chaincode
    xpub.push(pubkey_bytes[64] % 2 + 0x02); // compressed pubkey prefix (02 or 03)
    xpub.extend_from_slice(&pubkey_bytes[1..33]); // x coordinate

    if display {
        let xpub_base58 = bitcoin::base58::encode_check(&xpub);
        if !display_resident_pubkey(app, &xpub_base58, index).await {
            return Err(Error::UserRejected);
        }
    }

    Ok(Response::ResidentPubkey(xpub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resident_key::set_resident_key;

    const KNOWN_KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, 0x20,
    ];

    fn get_xpub(index: u16, display: bool) -> Vec<u8> {
        set_resident_key(KNOWN_KEY).unwrap();
        let resp = sdk::executor::block_on(handle_get_resident_pubkey(
            &mut sdk::App::singleton(),
            index,
            display,
        ))
        .unwrap();
        let Response::ResidentPubkey(xpub) = resp else {
            panic!("Expected ResidentPubkey response");
        };
        xpub
    }

    #[test]
    fn test_xpub_structure() {
        let xpub = get_xpub(0, false);

        assert_eq!(xpub.len(), 78, "xpub must be 78 bytes");

        // Version bytes (testnet: 0x043587CF)
        assert_eq!(
            &xpub[0..4],
            &BIP32_TESTNET_PUBKEY_VERSION.to_be_bytes(),
            "version mismatch"
        );

        // Depth = 0
        assert_eq!(xpub[4], 0, "depth must be 0");

        // Parent fingerprint = 0
        assert_eq!(&xpub[5..9], &[0u8; 4], "parent fingerprint must be zero");

        // Child number = 0
        assert_eq!(&xpub[9..13], &[0u8; 4], "child number must be zero");

        // Chaincode: first 30 bytes are zero
        assert_eq!(&xpub[13..43], &[0u8; 30], "first 30 chaincode bytes must be zero");

        // Compressed pubkey prefix is 0x02 or 0x03
        assert!(
            xpub[45] == 0x02 || xpub[45] == 0x03,
            "pubkey prefix must be 0x02 or 0x03"
        );
    }

    #[test]
    fn test_chaincode_encodes_index() {
        let xpub0 = get_xpub(0, false);
        let xpub1 = get_xpub(1, false);
        let xpub42 = get_xpub(42, false);
        let xpub_max = get_xpub(u16::MAX, false);

        // Chaincode index bytes are at positions 43-44 (offset 30-31 within the 32-byte chaincode
        // that starts at byte 13).
        assert_eq!(&xpub0[43..45], &0u16.to_be_bytes());
        assert_eq!(&xpub1[43..45], &1u16.to_be_bytes());
        assert_eq!(&xpub42[43..45], &42u16.to_be_bytes());
        assert_eq!(&xpub_max[43..45], &u16::MAX.to_be_bytes());
    }

    #[test]
    fn test_pubkey_is_deterministic() {
        // Same key and index should always produce the same xpub.
        let xpub_a = get_xpub(7, false);
        let xpub_b = get_xpub(7, false);
        assert_eq!(xpub_a, xpub_b);
    }

    #[test]
    fn test_different_indices_differ_only_in_chaincode() {
        let xpub0 = get_xpub(0, false);
        let xpub1 = get_xpub(1, false);

        // The public key portion (bytes 45-77) must be identical.
        assert_eq!(&xpub0[45..], &xpub1[45..], "public key must not depend on index");

        // But the full xpub (including chaincode) must differ.
        assert_ne!(xpub0, xpub1);
    }

    #[test]
    fn test_display_true_returns_ok() {
        // In test / autoapprove mode the UI is skipped, so display=true must still succeed.
        let xpub_no_display = get_xpub(3, false);
        let xpub_display = get_xpub(3, true);
        assert_eq!(xpub_no_display, xpub_display);
    }
}

