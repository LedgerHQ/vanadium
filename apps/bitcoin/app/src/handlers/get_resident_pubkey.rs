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
