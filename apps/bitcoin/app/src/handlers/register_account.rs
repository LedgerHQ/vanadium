use alloc::string::String;
use common::{
    bip388,
    errors::Error,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_XPUB},
    message::{self, Response},
    por::{ProofOfRegistration, Registerable},
};
use sdk::curve::{EcfpPublicKey, Secp256k1};

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_wallet_policy(
    app: &mut sdk::App,
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
    key_auth_names: &[Option<String>],
) -> bool {
    use alloc::{format, string::ToString, vec::Vec};
    use sdk::ux::{Icon, TagValue};

    let mut pairs = Vec::with_capacity(2 + wallet_policy.key_information.len());

    pairs.push(TagValue {
        tag: "Account".into(),
        value: name.into(),
    });
    pairs.push(TagValue {
        tag: "Descriptor template".into(),
        value: wallet_policy.descriptor_template_raw().to_string(),
    });

    for (i, key_info) in wallet_policy.key_information.iter().enumerate() {
        let tag = match key_auth_names.get(i).and_then(Option::as_ref) {
            Some(signer) => format!("Key #{} ({})", i, signer),
            None => format!("Key #{}", i),
        };
        pairs.push(TagValue {
            tag,
            value: key_info.to_string(),
        });
    }

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Register Bitcoin\naccount", "")
    } else {
        ("Register Bitcoin", "account")
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
        app.show_info(Icon::Success, "Account registered");
    } else {
        app.show_info(Icon::Failure, "Registration cancelled");
    }

    approved
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_wallet_policy(
    _app: &mut sdk::App,
    _name: &str,
    _wallet_policy: &bip388::WalletPolicy,
    _key_auth_names: &[Option<String>],
) -> bool {
    true
}

pub async fn handle_register_account(
    app: &mut sdk::App,
    name: &str,
    account: &message::Account,
    registered_identities: Option<&[message::RegisteredIdentityEntry]>,
    key_signatures: Option<&[Option<message::IdentitySignature>]>,
) -> Result<Response, Error> {
    use alloc::{string::String, vec::Vec};

    let wallet_policy: bip388::WalletPolicy =
        account.try_into().map_err(|_| Error::InvalidWalletPolicy)?;

    // Verify PoRs for registered identity keys and build a (pubkey ==> name) lookup table.
    let identity_key_names: Vec<([u8; 33], String)> = match registered_identities {
        Some(identities) => {
            let mut names = Vec::with_capacity(identities.len());
            for entry in identities {
                let pubkey: [u8; 33] = entry
                    .pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidIdentitySignature)?;
                let ik = IdentityKey::new(pubkey).map_err(|_| Error::InvalidIdentitySignature)?;
                let por_bytes: [u8; 32] = entry
                    .por
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidProofOfRegistrationLength)?;
                let expected_por =
                    ProofOfRegistration::<IdentityKey>::new(&ik.registration_id(&entry.name));
                let actual_por = ProofOfRegistration::<IdentityKey>::from_bytes(por_bytes);
                if actual_por != expected_por {
                    return Err(Error::InvalidProofOfRegistration);
                }
                names.push((pubkey, entry.name.clone()));
            }
            names
        }
        None => Vec::new(),
    };

    // Verify Schnorr signatures over cosigner xpubs and resolve signer names per key.
    let n = wallet_policy.key_information.len();
    let mut key_auth_names: Vec<Option<String>> = Vec::with_capacity(n);
    for _ in 0..n {
        key_auth_names.push(None);
    }
    if let Some(signatures) = key_signatures {
        for (i, sig_opt) in signatures.iter().enumerate() {
            if i >= n {
                break;
            }
            if let Some(sig) = sig_opt {
                let identity_pubkey: [u8; 33] = sig
                    .identity_pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidIdentitySignature)?;
                let signature: [u8; 64] = sig
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidIdentitySignature)?;
                let ecfp_pubkey = EcfpPublicKey::<Secp256k1, 32>::from_compressed(&identity_pubkey)
                    .map_err(|_| Error::InvalidIdentitySignature)?;
                let xpub_bytes = wallet_policy.key_information[i].pubkey.encode();
                let msg = build_identity_message(MSG_TYPE_XPUB, &xpub_bytes)
                    .map_err(|_| Error::InvalidIdentitySignature)?;
                ecfp_pubkey
                    .schnorr_verify(&msg, &signature)
                    .map_err(|_| Error::InvalidIdentitySignature)?;
                key_auth_names[i] = identity_key_names
                    .iter()
                    .find(|(pk, _)| *pk == identity_pubkey)
                    .map(|(_, nm)| nm.clone());
            }
        }
    }

    // TODO: necessary sanity checks on the wallet policy

    // TODO:
    // distinguish internal keys (after checking the derivation is correct) and external ones
    // We should also clearly mark any resident key among the internal keys
    if !display_wallet_policy(app, name, &wallet_policy, &key_auth_names).await {
        return Err(Error::UserRejected);
    }

    let id = wallet_policy.registration_id(name);
    let por = ProofOfRegistration::new(&id);

    Ok(Response::AccountRegistered {
        account_id: *id.as_bytes(),
        hmac: por.dangerous_as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        account::KeyInformation,
        bip388,
        message::{self, Response},
        por::{ProofOfRegistration, Registerable},
    };

    fn ki(key_info_str: &str) -> message::PubkeyInfo {
        let info = KeyInformation::try_from(key_info_str).unwrap();

        let origin = info.origin_info.map(|info| message::KeyOrigin {
            fingerprint: info.fingerprint,
            path: message::Bip32Path(
                info.derivation_path
                    .iter()
                    .map(|step| u32::from(*step))
                    .collect(),
            ),
        });

        message::PubkeyInfo {
            pubkey: info.pubkey.encode().to_vec(),
            origin,
        }
    }

    #[test]
    fn test_register_account() {
        let account_name = "My Test Account";
        let account = message::Account::WalletPolicy(message::WalletPolicy {
            template: "wpkh(@0/**)".into(),
            keys_info: vec![ki(
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
            )],
        });

        let wallet_policy: bip388::WalletPolicy = (&account).try_into().unwrap();
        let expected_account_id = wallet_policy.registration_id(account_name);

        let resp = sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            account_name,
            &account,
            None,
            None,
        ));

        assert_eq!(
            resp,
            Ok(Response::AccountRegistered {
                account_id: *expected_account_id.as_bytes(),
                // can't really test the hmac here, so we duplicate the app's logic
                hmac: ProofOfRegistration::new(&expected_account_id).dangerous_as_bytes(),
            })
        );
    }
}
