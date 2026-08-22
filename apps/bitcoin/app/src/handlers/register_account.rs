use alloc::{string::String, vec::Vec};
use common::{
    bip388,
    errors::Error,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_XPUB},
    message::{self, Response},
    por::{ProofOfRegistration, Registerable},
    psbt::signing_policy::{parse_signing_policy_path, signing_policy_chunks, SigningPolicy},
};
use sdk::curve::{EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey};

use crate::{bip32::KeyTree, constants::NUMS_COMPRESSED_PUBKEY};

/// Builds the tag/value pairs shown when reviewing an account registration.
///
/// `key_policy_hashes[i]` is `Some(hash)` if key `@i` is bound to a signing
/// policy; the policy's full hash is then shown right after the key itself.
fn account_review_pairs(
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
    key_auth_names: &[Option<String>],
    key_policy_hashes: &[Option<[u8; 32]>],
    show_cleartext: bool,
) -> Vec<sdk::ux::TagValue> {
    use alloc::{format, string::ToString};
    use common::bip388::{ClearText, MAX_CONFUSION_SCORE};
    use sdk::ux::TagValue;

    let mut pairs = Vec::with_capacity(2 + 2 * wallet_policy.key_information().len());

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

        if let Some(policy_hash) = key_policy_hashes.get(i).and_then(Option::as_ref) {
            pairs.push(TagValue {
                tag: format!("Key @{} signing policy", i),
                value: policy_hash.iter().map(|b| format!("{:02x}", b)).collect(),
            });
        }
    }

    pairs
}

async fn display_wallet_policy(
    app: &mut sdk::App,
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
    key_auth_names: &[Option<String>],
    key_policy_hashes: &[Option<[u8; 32]>],
    show_cleartext: bool,
) -> bool {
    let pairs = account_review_pairs(
        name,
        wallet_policy,
        key_auth_names,
        key_policy_hashes,
        show_cleartext,
    );

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
        let _ = (app, pairs);
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

    // Validate signing-policy bindings and label keys as "dummy" or "our key".
    // `key_policy_hashes[i]` records the hash of the policy bound to key @i, so
    // that it can be shown next to the key on screen.
    let mut key_policy_hashes: Vec<Option<[u8; 32]>> = alloc::vec![None; n];
    let standard_fpr = crate::bip32::master_fingerprint(KeyTree::Standard)?;
    let resident_fpr = crate::bip32::master_fingerprint(KeyTree::Resident)?;
    for (i, key_info) in wallet_policy.key_information().iter().enumerate() {
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

            // The declared xpub must be the genuine derived node (chaincode
            // included), for both ordinary and signing-policy-bound keys.
            let xpub_chaincode: [u8; 32] = *key_info.pubkey.chain_code.as_ref();
            if xpub_chaincode != hd_node.chaincode {
                return Err(Error::InvalidSigningPolicy);
            }

            // A signing-policy origin path must have its program supplied so we
            // can validate (compile) it now; fail closed otherwise. This applies
            // uniformly to plain and musig keys.
            if let Some((_coin_type, _account, chunks)) = parse_signing_policy_path(&path) {
                let signing_policy = signing_policies
                    .iter()
                    .find(|policy| signing_policy_chunks(&policy.hash()) == chunks)
                    .ok_or(Error::SigningPolicyMissing)?;
                let entry = signing_policy.as_entry();
                crate::policy::validate_policy(&entry)?;
                key_policy_hashes[i] = Some(entry.hash);
            }

            if key_auth_names[i].is_none() {
                key_auth_names[i] = Some(String::from("our key"));
            }
        }
    }

    if !display_wallet_policy(
        app,
        name,
        wallet_policy,
        &key_auth_names,
        &key_policy_hashes,
        show_cleartext,
    )
    .await
    {
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
    use alloc::{format, vec};
    use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
    use bitcoin::secp256k1::PublicKey;
    use common::{
        account::KeyInformation,
        bip388::{self, KeyOrigin},
        message::{self, Response},
        por::{ProofOfRegistration, Registerable},
        psbt::signing_policy::{signing_policy_key_path, SigningPolicy, ENGINE_ID_PROGRAM},
    };

    // Signing programs shipped in `apps/bitcoin/assets/signing_policies`.
    use crate::policy::test_assets::{ALWAYS_APPROVE, FEE_CAP};

    const INTERNAL_XPUB: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
    const EXTERNAL_XPUB: &str = "tpubDFWK5mCX28dt6hfy74Bc51jjbWrimXow1bTxCMpJrWqesK3AeZiYn8tcLFW3VoBiHhM9FjKdLWaC3GZVVX5PfGNG3zfbM14bMb1SLym36nN";

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

    /// Builds a device-controlled [`KeyInformation`] whose origin path is the
    /// signing-policy path for `program_hash` at `account`, deriving the real
    /// xpub from the selected key tree.
    fn device_policy_key_info(
        tree: KeyTree,
        account: u32,
        program_hash: &[u8; 32],
    ) -> KeyInformation {
        // Coin-type is not semantically constrained by the device; use testnet.
        let path = signing_policy_key_path(1, account, program_hash);
        let node = crate::bip32::derive_hd_node(tree, &path).unwrap();
        let compressed = EcfpPrivateKey::<Secp256k1, 32>::new(*node.privkey)
            .to_public_key()
            .to_compressed();
        let fingerprint = crate::bip32::master_fingerprint(tree).unwrap();
        let pubkey = Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: path.len() as u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from(*path.last().unwrap()),
            public_key: PublicKey::from_slice(&compressed).unwrap(),
            chain_code: ChainCode::from(node.chaincode),
        };
        KeyInformation {
            pubkey,
            origin_info: Some(KeyOrigin {
                fingerprint,
                derivation_path: path.iter().map(|&n| ChildNumber::from(n)).collect(),
            }),
        }
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
    fn test_review_pairs_show_full_policy_hash_in_lowercase_hex() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let hash = signing_policy.hash();
        let key = device_policy_key_info(KeyTree::Standard, 0, &hash);
        let external_key = KeyInformation::try_from(EXTERNAL_XPUB).unwrap();
        let account = account_from_keys("wsh(multi(2,@0/**,@1/**))", vec![key, external_key]);

        let pairs = account_review_pairs(
            "Policy account",
            wallet_policy_of(&account),
            &[Some(String::from("our key")), None],
            &[Some(hash), None],
            false,
        );

        // The policy hash is shown right after the key it is bound to, as all
        // 32 bytes in lowercase hexadecimal.
        let expected_hex: String = hash
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .map(|nibble| char::from(b"0123456789abcdef"[nibble as usize]))
            .collect();
        let key_pos = pairs
            .iter()
            .position(|p| p.tag == "Key @0 (our key)")
            .expect("the policy-bound key should be shown");
        assert_eq!(pairs[key_pos + 1].tag, "Key @0 signing policy");
        assert_eq!(expected_hex.len(), 64);
        assert_eq!(pairs[key_pos + 1].value, expected_hex);

        // Keys without a policy get no such pair.
        let external_pos = pairs
            .iter()
            .position(|p| p.tag == "Key @1")
            .expect("the external key should be shown");
        assert_eq!(external_pos, pairs.len() - 1);
    }

    #[test]
    fn test_register_policy_bound_internal_key() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let key = device_policy_key_info(KeyTree::Standard, 0, &signing_policy.hash());
        let account = account_from_keys("wpkh(@0/**)", vec![key]);

        assert!(register(&account, &[signing_policy]).is_ok());
    }

    #[test]
    fn test_register_policy_bound_resident_key() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let key = device_policy_key_info(KeyTree::Resident, 0, &signing_policy.hash());
        let account = account_from_keys("wpkh(@0/**)", vec![key]);

        assert!(register(&account, &[signing_policy]).is_ok());
    }

    #[test]
    fn test_register_shared_and_repeated_signing_policy() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let key0 = device_policy_key_info(KeyTree::Standard, 0, &signing_policy.hash());
        let key1 = device_policy_key_info(KeyTree::Standard, 1, &signing_policy.hash());
        let account = account_from_keys("wsh(multi(2,@0/**,@1/**))", vec![key0, key1]);

        assert!(register(&account, &[signing_policy.clone(), signing_policy]).is_ok());
    }

    #[test]
    fn test_register_multiple_signing_policies() {
        let first_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let second_policy = policy(ENGINE_ID_PROGRAM, 0, FEE_CAP);
        let first_key = device_policy_key_info(KeyTree::Standard, 0, &first_policy.hash());
        let second_key = device_policy_key_info(KeyTree::Standard, 0, &second_policy.hash());
        let account = account_from_keys("wsh(multi(2,@0/**,@1/**))", vec![first_key, second_key]);

        assert!(register(&account, &[first_policy, second_policy]).is_ok());
    }

    #[test]
    fn test_register_rejects_missing_or_mismatched_program() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let key = device_policy_key_info(KeyTree::Standard, 0, &signing_policy.hash());
        let account = account_from_keys("wpkh(@0/**)", vec![key]);

        // No program supplied for the policy-bound key.
        assert_eq!(register(&account, &[]), Err(Error::SigningPolicyMissing));
        // A different program has different path chunks, so it doesn't match.
        assert_eq!(
            register(&account, &[policy(ENGINE_ID_PROGRAM, 0, FEE_CAP)]),
            Err(Error::SigningPolicyMissing)
        );
    }

    #[test]
    fn test_register_rejects_invalid_programs() {
        let invalid_source = policy(ENGINE_ID_PROGRAM, 0, b"if { fail(); }");
        let invalid_key = device_policy_key_info(KeyTree::Standard, 0, &invalid_source.hash());
        let invalid_account = account_from_keys("wpkh(@0/**)", vec![invalid_key]);
        assert_eq!(
            register(&invalid_account, &[invalid_source]),
            Err(Error::PolicyExecutionFailed)
        );

        let unsupported = policy(0xff, 0, ALWAYS_APPROVE);
        let unsupported_key = device_policy_key_info(KeyTree::Standard, 0, &unsupported.hash());
        let unsupported_account = account_from_keys("wpkh(@0/**)", vec![unsupported_key]);
        assert_eq!(
            register(&unsupported_account, &[unsupported]),
            Err(Error::UnsupportedPolicyEngine)
        );

        let unsupported_version = policy(ENGINE_ID_PROGRAM, 1, ALWAYS_APPROVE);
        let unsupported_version_key =
            device_policy_key_info(KeyTree::Standard, 0, &unsupported_version.hash());
        let unsupported_version_account =
            account_from_keys("wpkh(@0/**)", vec![unsupported_version_key]);
        assert_eq!(
            register(&unsupported_version_account, &[unsupported_version]),
            Err(Error::UnsupportedPolicyEngine)
        );
    }

    #[test]
    fn test_register_allows_external_keys_and_extra_programs() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        // A purely external key ignores any supplied programs.
        let external_account = make_account(
            "wpkh(@0/**)",
            &[&format!("[d5365b22/48'/1'/0'/2']{}", EXTERNAL_XPUB)],
        );
        assert!(register(&external_account, &[signing_policy.clone()]).is_ok());

        // An ordinary device key with an extra (unused) program is fine.
        let ordinary_account = make_account(
            "wpkh(@0/**)",
            &[&format!("[f5acc2fd/84'/1'/0']{}", INTERNAL_XPUB)],
        );
        assert!(register(&ordinary_account, &[signing_policy]).is_ok());
    }

    #[test]
    fn test_register_rejects_tampered_chaincode() {
        // A device key whose declared xpub chaincode doesn't match the value
        // derived from its origin path is rejected.
        let mut key =
            KeyInformation::try_from(format!("[f5acc2fd/84'/1'/0']{}", INTERNAL_XPUB).as_str())
                .unwrap();
        key.pubkey.chain_code = ChainCode::from([0x66; 32]);
        let account = account_from_keys("wpkh(@0/**)", vec![key]);
        assert_eq!(register(&account, &[]), Err(Error::InvalidSigningPolicy));
    }

    #[test]
    fn test_register_allows_policy_bound_musig_key() {
        let signing_policy = policy(ENGINE_ID_PROGRAM, 0, ALWAYS_APPROVE);
        let internal_key = device_policy_key_info(KeyTree::Standard, 0, &signing_policy.hash());
        let external_key = KeyInformation::try_from(EXTERNAL_XPUB).unwrap();
        let account = account_from_keys("tr(musig(@0,@1)/**)", vec![internal_key, external_key]);

        assert!(register(&account, &[signing_policy]).is_ok());
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
