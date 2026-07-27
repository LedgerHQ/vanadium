use alloc::{string::String, vec, vec::Vec};
use common::{
    bip388,
    errors::Error,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_XPUB},
    message::{self, Response},
    por::{ProofOfRegistration, Registerable},
    psbt::signing_policy::SigningPolicy,
};
use sdk::curve::{EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey};

use crate::{bip32::KeyTree, constants::NUMS_COMPRESSED_PUBKEY};

async fn display_wallet_policy(
    app: &mut sdk::App,
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
    key_auth_names: &[Option<String>],
    show_cleartext: bool,
) -> bool {
    use alloc::{format, string::ToString, vec::Vec};
    use common::bip388::{ClearText, MAX_CONFUSION_SCORE};
    use sdk::ux::TagValue;

    let mut pairs = Vec::with_capacity(2 + wallet_policy.key_information().len());

    pairs.push(TagValue {
        tag: "Account".into(),
        value: name.into(),
    });

    let use_cleartext = show_cleartext
        && wallet_policy.descriptor_template().confusion_score() <= MAX_CONFUSION_SCORE;

    if use_cleartext {
        let (descriptions, _all_have_cleartext) =
            wallet_policy.descriptor_template().to_cleartext();
        for (i, desc) in descriptions.iter().enumerate() {
            let tag = format!("Spending path #{}", i + 1);
            pairs.push(TagValue {
                tag,
                value: desc.clone(),
            });
        }
    } else {
        pairs.push(TagValue {
            tag: "Descriptor template".into(),
            value: wallet_policy.descriptor_template_raw().to_string(),
        });
    }

    for (i, key_info) in wallet_policy.key_information().iter().enumerate() {
        let tag = match key_auth_names.get(i).and_then(Option::as_ref) {
            Some(signer) => format!("Key @{} ({})", i, signer),
            None => format!("Key @{}", i),
        };
        pairs.push(TagValue {
            tag,
            value: key_info.to_string(),
        });
    }

    let approved: bool;

    #[cfg(not(any(test, feature = "autoapprove")))]
    {
        let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
            ("Register Bitcoin\naccount", "")
        } else {
            ("Register Bitcoin", "account")
        };

        approved = app
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
            app.show_info(sdk::ux::Icon::Success, "Account registered");
        } else {
            app.show_info(sdk::ux::Icon::Failure, "Registration cancelled");
        }
    }

    #[cfg(any(test, feature = "autoapprove"))]
    {
        let _ = app;
        approved = true;
    }

    approved
}

pub async fn handle_register_account(
    app: &mut sdk::App,
    name: &str,
    account: &message::Account,
    signing_policies: &[SigningPolicy],
    registered_identities: Option<&[message::RegisteredIdentityEntry]>,
    key_signatures: Option<&[Option<message::IdentitySignature>]>,
    show_cleartext: bool,
) -> Result<Response, Error> {
    app.show_spinner("Processing...");

    let message::Account::WalletPolicy(wallet_policy) = account;

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
    let n = wallet_policy.key_information().len();
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
                let xpub_bytes = wallet_policy.key_information()[i].pubkey.encode();
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

    // Validate policy commitments and label keys as "dummy" or "our key".
    let standard_fpr = crate::bip32::master_fingerprint(KeyTree::Standard)?;
    let resident_fpr = crate::bip32::master_fingerprint(KeyTree::Resident)?;
    let mut policy_bound_internal = vec![false; n];
    for (i, key_info) in wallet_policy.key_information().iter().enumerate() {
        let xpub_chaincode: [u8; 32] = *key_info.pubkey.chain_code.as_ref();
        if let Some(hash) = key_info
            .origin_info
            .as_ref()
            .and_then(|origin| origin.signing_policy_hash)
        {
            if xpub_chaincode != hash {
                return Err(Error::InvalidSigningPolicy);
            }
        }

        let compressed_pubkey = key_info.pubkey.public_key.serialize();

        if compressed_pubkey == NUMS_COMPRESSED_PUBKEY {
            if key_auth_names[i].is_none() {
                key_auth_names[i] = Some(String::from("dummy"));
            }
            continue;
        }

        // Keys without origin info are always considered external.
        let Some(ref origin) = key_info.origin_info else {
            continue;
        };

        let path: Vec<u32> = origin
            .derivation_path
            .iter()
            .map(|step| u32::from(*step))
            .collect();

        let tree = if origin.fingerprint == standard_fpr {
            Some(KeyTree::Standard)
        } else if origin.fingerprint == resident_fpr {
            Some(KeyTree::Resident)
        } else {
            None
        };
        let hd_node = tree.and_then(|t| crate::bip32::derive_hd_node(t, &path).ok());

        if let Some(hd_node) = hd_node {
            let derived_pubkey = EcfpPrivateKey::<Secp256k1, 32>::new(*hd_node.privkey)
                .to_public_key()
                .to_compressed();
            if compressed_pubkey != derived_pubkey {
                continue;
            }

            if let Some(hash) = origin.signing_policy_hash {
                let signing_policy = signing_policies
                    .iter()
                    .find(|policy| policy.hash() == hash)
                    .ok_or(Error::SigningPolicyMissing)?;
                crate::policy::validate_policy(&signing_policy.as_entry())?;
                policy_bound_internal[i] = true;
            } else if xpub_chaincode != hd_node.chaincode {
                return Err(Error::InvalidSigningPolicy);
            }

            if key_auth_names[i].is_none() {
                key_auth_names[i] = Some(String::from("our key"));
            }
        }
    }

    for (key_expression, _) in wallet_policy.descriptor_template().placeholders() {
        if !key_expression.is_musig() {
            continue;
        }
        let key_indices = key_expression
            .musig_key_indices()
            .expect("key expression must be musig after is_musig() returned true");
        if key_indices
            .iter()
            .any(|index| policy_bound_internal[*index as usize])
        {
            return Err(Error::SigningPolicyUnsupportedForMusig);
        }
    }

    if !display_wallet_policy(app, name, &wallet_policy, &key_auth_names, show_cleartext).await {
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
    use alloc::format;
    use bitcoin::bip32::ChainCode;
    use common::{
        account::KeyInformation,
        bip388,
        message::{self, Response},
        por::{ProofOfRegistration, Registerable},
        psbt::signing_policy::{SigningPolicy, ENGINE_ID_PROGRAM},
    };

    const INTERNAL_XPUB: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
    const EXTERNAL_XPUB: &str = "tpubDFWK5mCX28dt6hfy74Bc51jjbWrimXow1bTxCMpJrWqesK3AeZiYn8tcLFW3VoBiHhM9FjKdLWaC3GZVVX5PfGNG3zfbM14bMb1SLym36nN";
    const RESIDENT_XPUB: &str = "tpubDD7URPdwnhN6XNWRkMLhaGvhp1xaZNTAqgn8qULdENfMrUbCUcV4Kd4FQzVSHkKx9nmU7sNjBMPa96b9g3KTSJTAvTsTcT5mYDz97fUppvd";

    fn make_account(template: &str, keys_info_strs: &[&str]) -> message::Account {
        let keys = keys_info_strs
            .iter()
            .map(|s| KeyInformation::try_from(*s).unwrap())
            .collect();
        message::Account::WalletPolicy(bip388::WalletPolicy::new(template, keys).unwrap())
    }

    fn wallet_policy_of(account: &message::Account) -> &bip388::WalletPolicy {
        let message::Account::WalletPolicy(wp) = account;
        wp
    }

    fn policy(engine_id: u8, engine_version: u8, script: &[u8]) -> SigningPolicy {
        SigningPolicy::new(engine_id, engine_version, script.to_vec())
    }

    fn policy_bound_key(origin: &str, xpub: &str, policy: &SigningPolicy) -> String {
        format!("[{}/{}]{}", origin, hex::encode(policy.hash()), xpub)
    }

    fn account_from_keys(template: &str, keys: Vec<KeyInformation>) -> message::Account {
        message::Account::WalletPolicy(bip388::WalletPolicy::new(template, keys).unwrap())
    }

    fn register(
        account: &message::Account,
        signing_policies: &[SigningPolicy],
    ) -> Result<Response, Error> {
        sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            "Policy account",
            account,
            signing_policies,
            None,
            None,
            false,
        ))
    }

    #[test]
    fn test_register_policy_bound_internal_key() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &signing_policy);
        let account = make_account("wpkh(@0/**)", &[&key]);

        assert!(register(&account, &[signing_policy]).is_ok());
    }

    #[test]
    fn test_register_policy_bound_resident_key() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let resident_fpr = crate::bip32::master_fingerprint(KeyTree::Resident).unwrap();
        let origin = format!("{:08x}/44'/1'/0'", resident_fpr);
        let key = policy_bound_key(&origin, RESIDENT_XPUB, &signing_policy);
        let account = make_account("wpkh(@0/**)", &[&key]);

        assert!(register(&account, &[signing_policy]).is_ok());
    }

    #[test]
    fn test_register_shared_and_repeated_signing_policy() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &signing_policy);
        let account = make_account("wsh(multi(2,@0/**,@1/**))", &[&key, &key]);

        assert!(register(&account, &[signing_policy.clone(), signing_policy]).is_ok());
    }

    #[test]
    fn test_register_multiple_signing_policies() {
        let first_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let second_policy = policy(ENGINE_ID_PROGRAM, 0, b"if true { approve(); }");
        let first_key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &first_policy);
        let second_key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &second_policy);
        let account = make_account("wsh(multi(2,@0/**,@1/**))", &[&first_key, &second_key]);

        assert!(register(&account, &[first_policy, second_policy]).is_ok());
    }

    #[test]
    fn test_register_rejects_missing_or_mismatched_program() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &signing_policy);
        let account = make_account("wpkh(@0/**)", &[&key]);

        assert_eq!(register(&account, &[]), Err(Error::SigningPolicyMissing));
        assert_eq!(
            register(
                &account,
                &[policy(ENGINE_ID_PROGRAM, 0, b"if true { approve(); }")],
            ),
            Err(Error::SigningPolicyMissing)
        );
    }

    #[test]
    fn test_register_rejects_invalid_programs() {
        let invalid_source = policy(ENGINE_ID_PROGRAM, 0, b"if { fail(); }");
        let invalid_key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &invalid_source);
        let invalid_account = make_account("wpkh(@0/**)", &[&invalid_key]);
        assert_eq!(
            register(&invalid_account, &[invalid_source]),
            Err(Error::PolicyExecutionFailed)
        );

        let unsupported = policy(0xff, 0, b"approve();");
        let unsupported_key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &unsupported);
        let unsupported_account = make_account("wpkh(@0/**)", &[&unsupported_key]);
        assert_eq!(
            register(&unsupported_account, &[unsupported]),
            Err(Error::UnsupportedPolicyEngine)
        );

        let unsupported_version = policy(ENGINE_ID_PROGRAM, 1, b"approve();");
        let unsupported_version_key =
            policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &unsupported_version);
        let unsupported_version_account = make_account("wpkh(@0/**)", &[&unsupported_version_key]);
        assert_eq!(
            register(&unsupported_version_account, &[unsupported_version]),
            Err(Error::UnsupportedPolicyEngine)
        );
    }

    #[test]
    fn test_register_allows_external_hashes_and_extra_programs() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let external_key =
            policy_bound_key("d5365b22/48'/1'/0'/2'", EXTERNAL_XPUB, &signing_policy);
        let external_account = make_account("wpkh(@0/**)", &[&external_key]);
        assert!(register(&external_account, &[]).is_ok());

        let ordinary_account = make_account(
            "wpkh(@0/**)",
            &[&format!("[f5acc2fd/84'/1'/0']{}", INTERNAL_XPUB)],
        );
        assert!(register(&ordinary_account, &[signing_policy]).is_ok());
    }

    #[test]
    fn test_register_rejects_invalid_chaincode_commitments() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let bound_key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &signing_policy);
        let mut mismatched_key = KeyInformation::try_from(bound_key.as_str()).unwrap();
        mismatched_key.pubkey.chain_code = ChainCode::from([0x55; 32]);
        let mismatched_account = account_from_keys("wpkh(@0/**)", vec![mismatched_key]);
        assert_eq!(
            register(&mismatched_account, &[signing_policy]),
            Err(Error::InvalidSigningPolicy)
        );

        let mut undeclared_key =
            KeyInformation::try_from(format!("[f5acc2fd/84'/1'/0']{}", INTERNAL_XPUB).as_str())
                .unwrap();
        undeclared_key.pubkey.chain_code = ChainCode::from([0x66; 32]);
        let undeclared_account = account_from_keys("wpkh(@0/**)", vec![undeclared_key]);
        assert_eq!(
            register(&undeclared_account, &[]),
            Err(Error::InvalidSigningPolicy)
        );
    }

    #[test]
    fn test_register_rejects_policy_bound_internal_musig_key() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, b"approve();");
        let internal_key = policy_bound_key("f5acc2fd/84'/1'/0'", INTERNAL_XPUB, &signing_policy);
        let account = make_account("tr(musig(@0,@1)/**)", &[&internal_key, EXTERNAL_XPUB]);

        assert_eq!(
            register(&account, &[signing_policy]),
            Err(Error::SigningPolicyUnsupportedForMusig)
        );
    }

    #[test]
    fn test_register_account() {
        let account_name = "My Test Account";
        let account = make_account(
            "wpkh(@0/**)",
            &["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"],
        );
        let expected_account_id = wallet_policy_of(&account).registration_id(account_name);

        let resp = sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            account_name,
            &account,
            &[],
            None,
            None,
            false,
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

    #[test]
    fn test_register_account_simple_inheritance() {
        let account_name = "Simple inheritance";
        let account = make_account(
            "tr(@0/<0;1>/*,and_v(v:pk(@1/<0;1>/*),older(52596)))",
            &[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "[d5365b22/48'/1'/0'/2']tpubDFWK5mCX28dt6hfy74Bc51jjbWrimXow1bTxCMpJrWqesK3AeZiYn8tcLFW3VoBiHhM9FjKdLWaC3GZVVX5PfGNG3zfbM14bMb1SLym36nN",
            ],
        );
        let expected_account_id = wallet_policy_of(&account).registration_id(account_name);

        let resp = sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            account_name,
            &account,
            &[],
            None,
            None,
            false,
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

    #[test]
    fn test_register_account_simple_inheritance2() {
        let account_name = "Simple inheritance";
        let account = make_account(
            "tr(@0/<0;1>/*,{and_v(v:pk(@1/<2;3>/*),older(4383)),and_v(v:pk(@2/<0;1>/*),pk(@1/<0;1>/*))})",
            &[
                "tpubD6NzVbkrYhZ4XUBKWaWfdn2icbaEDfaUgkCCbKPm31LTLRfaaEJRDAF3XXbvTaKLHATytZPGoWpVxnMnrRbn4519fP6nhZDDFtJimcZWBGC",
                "[41e8dfb4/48'/1'/0'/2']tpubDE6DKS5H4uEZwjGqvSujs1GMKY3PZKuEvsVFbvCStYs3yNjo93aeVqEGT3gsFtAPHdj19oTZCjoKarMz1Ve6bKdzh6gNaFsfH1FudHTxGrB",
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        );
        let expected_account_id = wallet_policy_of(&account).registration_id(account_name);

        let resp = sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            account_name,
            &account,
            &[],
            None,
            None,
            true,
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

    #[test]
    fn test_register_account_expanding_multisig() {
        let account_name = "Expanding multisig";
        let account = make_account(
            "tr(@0/<0;1>/*,{and_v(v:pk(@1/<2;3>/*),older(4383)),and_v(v:pk(@2/<0;1>/*),pk(@1/<0;1>/*))})",
            &[
                "tpubD6NzVbkrYhZ4YWFESthNwVXM9BnBbB81mYcR4Y2B1cn7H2877iHruRir4JtbC4h4gDueD7WcHayskdKpHowgWiQs8AQFWgas79gF5Nc2UG7",
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "[7a88647b/48'/1'/0'/2']tpubDFfCoyA3T5WhDyLUwiyy1mHm1Kmm1DRTkW3iiGWu9q8Xi3rXNsQdDq6ujG1HzKu87HmS6dimVSAgWsnH2hdeAZ5WV99yg86BiU2RtJcPVHL",
            ],
        );
        let expected_account_id = wallet_policy_of(&account).registration_id(account_name);

        let resp = sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            account_name,
            &account,
            &[],
            None,
            None,
            true,
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
