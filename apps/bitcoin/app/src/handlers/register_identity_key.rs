use common::{
    errors::Error,
    identity::IdentityKey,
    message::Response,
    por::{ProofOfRegistration, Registerable},
};

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_register_identity_key(app: &mut sdk::App, name: &str, pubkey_hex: &str) -> bool {
    use alloc::vec::Vec;
    use sdk::ux::{Icon, TagValue};

    let mut pairs = Vec::with_capacity(2);

    pairs.push(TagValue {
        tag: "Name".into(),
        value: name.into(),
    });
    pairs.push(TagValue {
        tag: "Public key".into(),
        value: pubkey_hex.into(),
    });

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Register\nidentity key", "")
    } else {
        ("Register", "identity key")
    };
    let approved = app
        .review_pairs(
            intro_text,
            intro_subtext,
            &pairs,
            "Confirm registration",
            "Register",
            false,
        )
        .await;

    if approved {
        app.show_info(Icon::Success, "Identity key registered");
    } else {
        app.show_info(Icon::Failure, "Registration cancelled");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_register_identity_key(
    _app: &mut sdk::App,
    _name: &str,
    _pubkey_hex: &str,
) -> bool {
    true
}

pub async fn handle_register_identity_key(
    app: &mut sdk::App,
    name: &str,
    pubkey: &[u8],
) -> Result<Response, Error> {
    use alloc::{format, string::String};

    let compressed: [u8; 33] = pubkey.try_into().map_err(|_| Error::InvalidKey)?;
    let identity_key = IdentityKey::new(compressed).map_err(|_| Error::InvalidKey)?;

    let pubkey_hex: String = identity_key
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    if !display_register_identity_key(app, name, &pubkey_hex).await {
        return Err(Error::UserRejected);
    }

    let id = identity_key.registration_id(name);
    let por = ProofOfRegistration::new(&id);

    Ok(Response::IdentityKeyRegistered {
        key_id: *id.as_bytes(),
        hmac: por.dangerous_as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        identity::IdentityKey,
        message::Response,
        por::{ProofOfRegistration, Registerable},
    };

    #[test]
    fn test_register_identity_key() {
        // A valid compressed public key (0x02 prefix + 32 bytes)
        let compressed = [
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];

        let name = "My Identity";
        let identity_key = IdentityKey::new(compressed).unwrap();
        let expected_id = identity_key.registration_id(name);

        let resp = sdk::executor::block_on(handle_register_identity_key(
            &mut sdk::App::singleton(),
            name,
            &compressed,
        ));

        assert_eq!(
            resp,
            Ok(Response::IdentityKeyRegistered {
                key_id: *expected_id.as_bytes(),
                hmac: ProofOfRegistration::new(&expected_id).dangerous_as_bytes(),
            })
        );
    }

    #[test]
    fn test_register_identity_key_invalid_prefix() {
        // Invalid prefix (0x05)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x05;

        let resp = sdk::executor::block_on(handle_register_identity_key(
            &mut sdk::App::singleton(),
            "Bad Key",
            &compressed,
        ));

        assert_eq!(resp, Err(Error::InvalidKey));
    }

    #[test]
    fn test_register_identity_key_wrong_length() {
        let short = [0x02; 20];

        let resp = sdk::executor::block_on(handle_register_identity_key(
            &mut sdk::App::singleton(),
            "Short Key",
            &short,
        ));

        assert_eq!(resp, Err(Error::InvalidKey));
    }
}
