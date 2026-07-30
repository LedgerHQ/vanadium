use alloc::{string::String, vec::Vec};
use common::{
    bip388,
    errors::Error,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_XPUB},
    message::{self, Response},
    por::{ProofOfRegistration, Registerable},
    psbt::signing_policy::{
        parse_signing_policy_path, signing_policy_chunks, SigningPolicy, SigningPolicyEntry,
    },
};
use sdk::curve::{EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey};

use crate::{bip32::KeyTree, constants::NUMS_COMPRESSED_PUBKEY};

/// The image's self-declared label, if it parses and has one.
///
/// Validation has already succeeded by the time this is called, so a parse failure
/// here is impossible; returning `None` rather than propagating keeps the display
/// path infallible.
fn policy_label(entry: &SigningPolicyEntry<'_>) -> Option<String> {
    use crate::policy::engine::riscv::image::Image;

    let image = Image::parse(entry.program).ok()?;
    let label = image.label();
    if label.is_empty() {
        return None;
    }
    core::str::from_utf8(label).ok().map(String::from)
}

/// Build the rows shown during the registration review.
///
/// Split out from [`display_wallet_policy`] so the policy rows can be tested without
/// driving the UX.
fn account_review_pairs(
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
    key_auth_names: &[Option<String>],
    key_policies: &[Option<PolicyDisplay>],
    show_cleartext: bool,
) -> alloc::vec::Vec<sdk::ux::TagValue> {
    use alloc::{format, string::ToString, vec::Vec};
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

        // A policy-bound key gets a second row. The device can only show the
        // program's hash and its self-declared label — it has no way to tell the
        // user what the program means. See docs/SIGNING_POLICIES.md#auditability.
        if let Some(policy) = key_policies.get(i).and_then(Option::as_ref) {
            pairs.push(TagValue {
                tag: format!("Key @{} signing policy", i),
                value: policy.describe(),
            });
        }
    }

    pairs
}

/// What the review shows for a policy-bound key.
pub(crate) struct PolicyDisplay {
    pub hash: [u8; 32],
    /// The image's self-declared label, if it has one.
    pub label: Option<String>,
}

impl PolicyDisplay {
    fn describe(&self) -> String {
        use alloc::{format, string::ToString};

        let hex: String = self.hash.iter().map(|b| format!("{:02x}", b)).collect();
        match &self.label {
            // The label is committed by the hash but written by whoever wrote the
            // program, so it is marked as self-declared rather than presented as
            // a fact about behaviour.
            Some(label) => format!("{} (self-declared: {})", hex, label),
            None => hex.to_string(),
        }
    }
}

async fn display_wallet_policy(
    app: &mut sdk::App,
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
    key_auth_names: &[Option<String>],
    key_policies: &[Option<PolicyDisplay>],
    show_cleartext: bool,
) -> bool {
    let pairs = account_review_pairs(
        name,
        wallet_policy,
        key_auth_names,
        key_policies,
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
        let _ = (app, &pairs);
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

    // Label keys as "dummy" or "our key", and bind signing policies.
    //
    // Unlike the labelling pass this replaces, keys that already carry an identity
    // label are not skipped: policy binding must be checked for every key, or a
    // cosigner-authenticated key could carry an unvalidated policy.
    let standard_fpr = crate::bip32::master_fingerprint(KeyTree::Standard)?;
    let resident_fpr = crate::bip32::master_fingerprint(KeyTree::Resident)?;
    let mut key_policies: Vec<Option<PolicyDisplay>> = Vec::with_capacity(n);
    for _ in 0..n {
        key_policies.push(None);
    }
    for (i, key_info) in wallet_policy.key_information().iter().enumerate() {
        let xpub_bytes = key_info.pubkey.encode();
        let compressed_pubkey = &xpub_bytes[45..78];

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
        let Some(hd_node) = tree.and_then(|t| crate::bip32::derive_hd_node(t, &path).ok()) else {
            continue;
        };

        let derived = EcfpPrivateKey::<Secp256k1, 32>::new(*hd_node.privkey)
            .to_public_key()
            .to_compressed();
        if compressed_pubkey != derived {
            // A fingerprint collision, not one of our keys.
            continue;
        }

        // The pubkey is ours, so the declared chaincode must be the genuine one:
        // it governs the change/address child derivation, and a policy-bound key
        // derives its children from this node. A mismatch is a client lying about
        // our own key rather than an external key, so it is fatal.
        if xpub_bytes[13..45] != hd_node.chaincode {
            return Err(Error::InvalidSigningPolicy);
        }

        // A key whose origin path has the signing-policy shape must have its program
        // supplied here, so it can be validated before the account is registered.
        // Fail closed otherwise, uniformly for plain and musig keys.
        if let Some((_coin_type, _account, chunks)) = parse_signing_policy_path(&path) {
            let policy = signing_policies
                .iter()
                .find(|p| signing_policy_chunks(&p.hash()) == chunks)
                .ok_or(Error::SigningPolicyMissing)?;
            let entry = policy.as_entry();
            crate::policy::validate_policy(&entry)?;
            key_policies[i] = Some(PolicyDisplay {
                hash: entry.hash,
                label: policy_label(&entry),
            });
        }

        if key_auth_names[i].is_none() {
            key_auth_names[i] = Some(String::from("our key"));
        }
    }

    if !display_wallet_policy(
        app,
        name,
        &wallet_policy,
        &key_auth_names,
        &key_policies,
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
    use common::{
        account::KeyInformation,
        bip388,
        message::{self, Response},
        por::{ProofOfRegistration, Registerable},
    };

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

#[cfg(test)]
mod policy_tests {
    use super::*;

    use alloc::vec;
    use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
    use common::{
        account::KeyInformation,
        bip388::{self, KeyOrigin},
        message::{self, Response},
        psbt::signing_policy::{signing_policy_key_path, SigningPolicy, ENGINE_ID_RISCV},
    };
    use sdk::curve::Curve as _;
    use crate::policy::engine::riscv::image::test_util::{exit_image, exit_image_labeled};

    fn policy(image: Vec<u8>) -> SigningPolicy {
        SigningPolicy::new(ENGINE_ID_RISCV, 0, image)
    }

    /// A `wpkh(@0/**)` account whose key is the device key at the policy path.
    ///
    /// `tamper_chaincode` substitutes a chaincode the device did not derive, which
    /// must be rejected outright rather than treated as an external key.
    fn policy_bound_account(
        policy_hash: &[u8; 32],
        tamper_chaincode: bool,
    ) -> message::Account {
        let path = signing_policy_key_path(1, 0, policy_hash);
        let node = sdk::curve::Secp256k1::derive_hd_node(&path).unwrap();
        let compressed = EcfpPrivateKey::<Secp256k1, 32>::new(*node.privkey)
            .to_public_key()
            .to_compressed();
        let mut chaincode = node.chaincode;
        if tamper_chaincode {
            chaincode[0] ^= 0xFF;
        }
        let xpub = Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: path.len() as u8,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::Normal { index: path[6] },
            public_key: bitcoin::secp256k1::PublicKey::from_slice(&compressed).unwrap(),
            chain_code: ChainCode::from(chaincode),
        };
        let key_info = KeyInformation {
            pubkey: xpub,
            origin_info: Some(KeyOrigin {
                fingerprint: crate::bip32::master_fingerprint(KeyTree::Standard).unwrap(),
                derivation_path: path.iter().map(|&n| ChildNumber::from(n)).collect(),
            }),
        };
        message::Account::WalletPolicy(
            bip388::WalletPolicy::new("wpkh(@0/**)", vec![key_info]).unwrap(),
        )
    }

    fn register(
        account: &message::Account,
        policies: &[SigningPolicy],
    ) -> Result<Response, Error> {
        sdk::executor::block_on(handle_register_account(
            &mut sdk::App::singleton(),
            "Policy account",
            account,
            policies,
            None,
            None,
            false,
        ))
    }

    #[test]
    fn registers_a_policy_bound_key() {
        let p = policy(exit_image(2));
        let account = policy_bound_account(&p.hash(), false);
        assert!(register(&account, &[p]).is_ok());
    }

    #[test]
    fn a_policy_bound_key_without_its_program_is_rejected() {
        let p = policy(exit_image(2));
        let account = policy_bound_account(&p.hash(), false);
        assert_eq!(register(&account, &[]), Err(Error::SigningPolicyMissing));
    }

    #[test]
    fn a_program_whose_hash_does_not_match_the_path_is_rejected() {
        let bound = policy(exit_image(2));
        let other = policy(exit_image(0));
        let account = policy_bound_account(&bound.hash(), false);
        // A valid program, but not the one the key's path commits to.
        assert_eq!(register(&account, &[other]), Err(Error::SigningPolicyMissing));
    }

    #[test]
    fn a_malformed_program_is_rejected() {
        let p = policy(b"not a vpol image".to_vec());
        let account = policy_bound_account(&p.hash(), false);
        assert_eq!(
            register(&account, &[p]),
            Err(Error::PolicyExecutionFailed)
        );
    }

    #[test]
    fn a_tampered_chaincode_is_rejected() {
        // The pubkey matches our derivation but the chaincode does not, so the client
        // is lying about our own key: the chaincode governs the child derivation a
        // policy-bound key signs with.
        let p = policy(exit_image(2));
        let account = policy_bound_account(&p.hash(), true);
        assert_eq!(register(&account, &[p]), Err(Error::InvalidSigningPolicy));
    }

    #[test]
    fn extra_unused_programs_are_tolerated() {
        let bound = policy(exit_image(2));
        let unused = policy(exit_image(0));
        let account = policy_bound_account(&bound.hash(), false);
        assert!(register(&account, &[bound, unused]).is_ok());
    }

    #[test]
    fn the_review_shows_the_full_hash_and_marks_the_label_self_declared() {
        let p = policy(exit_image_labeled(2, b"vault v1"));
        let account = policy_bound_account(&p.hash(), false);
        let message::Account::WalletPolicy(wallet_policy) = &account;

        let display = PolicyDisplay {
            hash: p.hash(),
            label: policy_label(&p.as_entry()),
        };
        assert_eq!(display.label.as_deref(), Some("vault v1"));

        let pairs = account_review_pairs(
            "Policy account",
            wallet_policy,
            &[None],
            &[Some(display)],
            false,
        );
        let row = pairs
            .iter()
            .find(|p| p.tag == "Key @0 signing policy")
            .expect("the policy row must be shown");

        let expected_hex: String = p.hash().iter().map(|b| alloc::format!("{:02x}", b)).collect();
        assert!(row.value.starts_with(&expected_hex), "{}", row.value);
        assert!(row.value.contains("self-declared"), "{}", row.value);
    }

    #[test]
    fn a_key_without_a_policy_gets_no_policy_row() {
        let p = policy(exit_image(2));
        let account = policy_bound_account(&p.hash(), false);
        let message::Account::WalletPolicy(wallet_policy) = &account;
        let pairs = account_review_pairs("Policy account", wallet_policy, &[None], &[None], false);
        assert!(!pairs.iter().any(|p| p.tag.contains("signing policy")));
    }
}
