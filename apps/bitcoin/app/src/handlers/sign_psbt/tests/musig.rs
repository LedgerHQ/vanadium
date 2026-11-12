//! MuSig2 accounts: the two-round keypath protocol driven end to end against an
//! off-device cosigner, plus the cases where the device must refuse.

use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    absolute, psbt::Psbt, transaction, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use common::{
    bip388::{KeyInformation, KeyOrigin, WalletPolicy},
    errors::Error,
    message::{MuSig2PartialSignature, MuSig2Pubnonce, Response},
    musig as musig_lib,
    por::{ProofOfRegistration, Registerable},
    script::ToScript,
};
use hex_literal::hex;
use sdk::curve::{Curve, EcfpPrivateKey, EcfpPublicKey, ToPublicKey};

use crate::handlers::musig_signing;

use super::super::handle_sign_psbt;
use super::super::test_utils::{device_xpub_at, prepare_as_psbtv2, DEVICE_PATH};

/// A PSBT for `tr(musig(@0,@1)/**)` whose participant xpubs the device
/// doesn't control. The musig branch should fire (no longer silently
/// skipped) and produce no output — empty `signatures`, `musig_pubnonces`
/// and `musig_partial_sigs`.
///
/// The cosigner xpubs match the C reference app's
/// `tests/test_musig2.py::test_musig2_hotsigner_keypath`; the witness UTXO
/// scriptPubKey at `(is_change=false, address_index=3)` is taken verbatim
/// from the same test.
#[test]
fn test_handle_sign_psbt_musig_no_local_participant() {
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            // P2WPKH to a dummy address — must be an addressable script.
            script_pubkey: ScriptBuf::from_bytes(
                hex!("0014" "00112233445566778899aabbccddeeff00112233").to_vec(),
            ),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    // The previous output: a P2TR locked to the musig aggregate at
    // (is_change=false, address_index=3). The scriptPubKey is the value
    // independently re-derived in `common::script::tests::tr_musig_keypath_to_script`.
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: ScriptBuf::from_bytes(
            hex!("5120c1fdfebed063aa148340c45132e6718d8de81466ae2b90929e3d9328364cd6ed").to_vec(),
        ),
    });
    // BIP-373 tap_bip32_derivation: keyed by the BIP-32-tweaked aggregate
    // x-only key; fingerprint is the synthetic BIP-388 aggregate xpub's
    // BIP-32 fingerprint.
    let agg_xonly = XOnlyPublicKey::from_slice(&hex!(
        "9066461650209f8bbc59b05af5d1615c50f5f79c188d7be742fd932252f68f0c"
    ))
    .unwrap();
    let agg_fpr = Fingerprint::from(hex!("5b8fbc93"));
    let path = DerivationPath::from(vec![
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 3 },
    ]);
    psbt.inputs[0]
        .tap_key_origins
        .insert(agg_xonly, (vec![], (agg_fpr, path)));

    let wallet_policy = WalletPolicy::new(
        "tr(musig(@0,@1)/**)",
        vec![
            "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
                .try_into()
                .unwrap(),
            "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"
                .try_into()
                .unwrap(),
        ],
    )
    .unwrap();

    let account_name = "Musig for my ears";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    let accounts = [(&wallet_policy, account_name, &por)];

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(&psbt, &accounts),
    ))
    .unwrap();

    match response {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
            ..
        } => {
            assert!(
                signatures.is_empty(),
                "no plain placeholders ⇒ no signatures"
            );
            assert!(
                musig_pubnonces.is_empty(),
                "no local participants ⇒ no pubnonces"
            );
            assert!(
                musig_partial_sigs.is_empty(),
                "no local participants ⇒ no partial sigs"
            );
        }
        _ => panic!("Expected PsbtSigned response"),
    }
}

/// Hot cosigner xprv (BIP-32 master) used by these tests. Same key as the
/// C reference's `test_musig2.py::test_musig2_hotsigner_keypath`.
const COSIGNER_XPRV: &str = "tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz";

fn cosigner_xprv() -> Xpriv {
    Xpriv::from_str(COSIGNER_XPRV).unwrap()
}

fn cosigner_xpub(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Xpub {
    Xpub::from_priv(secp, &cosigner_xprv())
}

/// Builds the 2-of-2 keypath wallet policy `tr(musig(@0,@1)/**)` where
/// `@0` is device-controlled (with origin info) and `@1` is the bare hot
/// cosigner xpub. The exact origin path doesn't matter as long as the
/// device can re-derive it locally.
pub(super) fn make_2of2_keypath_policy() -> WalletPolicy {
    make_2of2_keypath_policy_at(&DEVICE_PATH)
}

/// Like [`make_2of2_keypath_policy`], with the device's key at `path`.
fn make_2of2_keypath_policy_at(path: &[u32]) -> WalletPolicy {
    let secp = Secp256k1::new();
    let standard_fpr = sdk::curve::Secp256k1::get_master_fingerprint();
    let key_info_0 = KeyInformation {
        pubkey: device_xpub_at(path),
        origin_info: Some(KeyOrigin {
            fingerprint: standard_fpr,
            derivation_path: path.iter().map(|&n| ChildNumber::from(n)).collect(),
        }),
    };
    let key_info_1 = KeyInformation {
        pubkey: cosigner_xpub(&secp),
        origin_info: None,
    };
    WalletPolicy::new("tr(musig(@0,@1)/**)", vec![key_info_0, key_info_1]).unwrap()
}

/// Constructs a one-input/one-output PSBT for the given wallet policy at
/// `(is_change=false, address_index)`. The output is a dummy P2WPKH. The
/// witness UTXO scriptPubKey is derived via the wallet policy itself so
/// `analyze_transaction` accepts the PSBT.
pub(super) fn build_musig_keypath_psbt(wallet_policy: &WalletPolicy, address_index: u32) -> Psbt {
    build_musig_keypath_psbt_spending(&[(wallet_policy, address_index)])
}

/// Like [`build_musig_keypath_psbt`], with one input for each `(wallet policy, address index)`
/// of `spends`, in order.
fn build_musig_keypath_psbt_spending(spends: &[(&WalletPolicy, u32)]) -> Psbt {
    let secp = Secp256k1::new();

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..spends.len())
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x42; 32]),
                    vout: vout as u32,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            })
            .collect(),
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(
                hex!("0014" "00112233445566778899aabbccddeeff00112233").to_vec(),
            ),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    for (input, (wallet_policy, address_index)) in psbt.inputs.iter_mut().zip(spends) {
        input.witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: wallet_policy.to_script(false, *address_index).unwrap(),
        });

        // Inject the BIP-373 tap_bip32_derivation entry for the BIP-32-tweaked
        // aggregate, keyed by its xonly key and tagged with the aggregate
        // xpub's BIP-32 fingerprint.
        let participant_xpubs: Vec<Xpub> = wallet_policy
            .key_information()
            .iter()
            .map(|ki| ki.pubkey)
            .collect();
        let agg_xpub = musig_lib::aggregate_xpub(&participant_xpubs).unwrap();
        let path = vec![
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal {
                index: *address_index,
            },
        ];
        let agg_child = agg_xpub
            .derive_pub(&secp, &path.iter().copied().collect::<DerivationPath>())
            .unwrap();
        let agg_xonly: [u8; 32] = agg_child.public_key.x_only_public_key().0.serialize();
        input.tap_key_origins.insert(
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&agg_xonly).unwrap(),
            (vec![], (agg_xpub.fingerprint(), DerivationPath::from(path))),
        );
    }

    psbt
}

/// Inserts a BIP-373 `PSBT_IN_MUSIG2_PUB_NONCE` entry into `psbt.inputs[0].unknown`.
/// Key layout (per BIP-373): `0x1B || participant_pk(33) || agg_pk(33)`
/// — leaf_hash is omitted for keypath spends.
fn insert_pubnonce(
    psbt: &mut Psbt,
    participant_pk: &[u8; 33],
    agg_pk: &[u8; 33],
    pubnonce: &[u8; 66],
) {
    insert_pubnonce_at(psbt, 0, participant_pk, agg_pk, pubnonce)
}

/// Like [`insert_pubnonce`], into input `input_index`.
fn insert_pubnonce_at(
    psbt: &mut Psbt,
    input_index: usize,
    participant_pk: &[u8; 33],
    agg_pk: &[u8; 33],
    pubnonce: &[u8; 66],
) {
    let mut keydata = Vec::with_capacity(66);
    keydata.extend_from_slice(participant_pk);
    keydata.extend_from_slice(agg_pk);
    psbt.inputs[input_index].unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0x1B,
            key: keydata,
        },
        pubnonce.to_vec(),
    );
}

/// Off-device emulation of the hot cosigner. Per BIP-388, MuSig2 signing
/// uses the cosigner's *master* xpub (the one listed in `keys_info`); the
/// `(change, address_index)` derivation is applied via session tweaks,
/// not by deriving children.
fn cosigner_master_round1(
    agg_xonly_tweaked: &[u8; 32],
    rand_root: &[u8; 32],
) -> ([u8; 33], musig_lib::SecNonce, musig_lib::PubNonce, [u8; 32]) {
    let secp = Secp256k1::new();
    let xpriv = cosigner_xprv();
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let participant_pk: [u8; 33] = xpub.public_key.serialize();
    let sk: [u8; 32] = xpriv.private_key.secret_bytes();
    let (secnonce, pubnonce) =
        musig_lib::nonce_gen(rand_root, &participant_pk, agg_xonly_tweaked).unwrap();
    (participant_pk, secnonce, pubnonce, sk)
}

/// Full 2-of-2 keypath MuSig2 round trip through `handle_sign_psbt`,
/// finishing with an aggregated 64-byte Schnorr signature that verifies
/// under the BIP-341-tweaked aggregate.
#[test]
fn test_handle_sign_psbt_musig_2of2_keypath_round_trip() {
    musig_signing::reset_storage_for_tests();

    let address_index: u32 = 7;
    let wallet_policy = make_2of2_keypath_policy();
    let account_name = "Musig 2-of-2 keypath";

    let mut psbt = build_musig_keypath_psbt(&wallet_policy, address_index);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    let accounts = [(&wallet_policy, account_name, &por)];

    // ---- Round 1 ----
    let r1 = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(&psbt, &accounts),
    ))
    .unwrap();
    let device_pubnonce = match r1 {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
            ..
        } => {
            assert!(signatures.is_empty());
            assert!(musig_partial_sigs.is_empty());
            assert_eq!(musig_pubnonces.len(), 1, "expected one device pubnonce");
            musig_pubnonces.into_iter().next().unwrap()
        }
        _ => panic!("Expected PsbtSigned"),
    };
    let agg_pk: [u8; 33] = device_pubnonce.aggregate_pubkey;
    // The BIP-340 verifier key is the agg key with even-y prefix (BIP-341).
    let agg_xonly: [u8; 32] = agg_pk[1..].try_into().unwrap();

    // ---- Off-device: compute cosigner's pubnonce ----
    let (cosigner_pk, _cosigner_secnonce, cosigner_pubnonce, cosigner_sk) =
        cosigner_master_round1(&agg_xonly, &[0xAB; 32]);

    // ---- Inject both pubnonces and run Round 2 ----
    insert_pubnonce(
        &mut psbt,
        &device_pubnonce.participant_pk,
        &agg_pk,
        &device_pubnonce.pubnonce,
    );
    insert_pubnonce(&mut psbt, &cosigner_pk, &agg_pk, &cosigner_pubnonce.0);

    let r2 = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(&psbt, &accounts),
    ))
    .unwrap();
    let device_psig = match r2 {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
            ..
        } => {
            assert!(signatures.is_empty());
            assert!(musig_pubnonces.is_empty());
            assert_eq!(musig_partial_sigs.len(), 1);
            musig_partial_sigs.into_iter().next().unwrap()
        }
        _ => panic!("Expected PsbtSigned"),
    };

    // ---- Off-device: cosigner's partial signature ----
    // Reproduce the per-input info to get tweaks/keys/order; the cosigner
    // and device run the exact same protocol, so they share the SessionContext.
    let placeholder = wallet_policy
        .descriptor_template()
        .placeholders()
        .next()
        .unwrap()
        .0
        .clone();
    let info = musig_signing::compute_per_input_info(
        wallet_policy.key_information(),
        &placeholder,
        false,
        address_index,
        musig_signing::SpendPath::Keypath { taptree_hash: None },
    )
    .unwrap();
    let aggnonce = musig_lib::nonce_agg(&[
        musig_lib::PubNonce(device_pubnonce.pubnonce),
        cosigner_pubnonce,
    ])
    .unwrap();
    // Sighash — both sides compute it the same way.
    let prevouts = vec![psbt.inputs[0].witness_utxo.clone().unwrap()];
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    let sighash: [u8; 32] = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap()
        .to_byte_array();

    let tweaks_slice = &info.tweaks[..info.n_tweaks];
    let is_xonly_slice = &info.is_xonly[..info.n_tweaks];
    let sctx = musig_lib::SessionContext {
        aggnonce: &aggnonce,
        pubkeys: &info.keys,
        tweaks: tweaks_slice,
        is_xonly: is_xonly_slice,
        msg: &sighash,
    };
    // The cosigner must hand `nonce_gen` a fresh secnonce, since `sign`
    // consumes it; re-derive deterministically from the same rand_root.
    let (_, cosigner_secnonce_recomputed, _, _) = cosigner_master_round1(&agg_xonly, &[0xAB; 32]);
    let cosigner_psig = musig_lib::sign(cosigner_secnonce_recomputed, &cosigner_sk, &sctx).unwrap();

    // ---- Aggregate the two partial signatures and verify ----
    let final_sig =
        musig_lib::partial_sig_agg(&sctx, &[device_psig.signature, cosigner_psig]).unwrap();
    // The BIP-340 verifier key has prefix 0x02 (even-y) and the x of the
    // taptweaked aggregate.
    let mut verifier_pk = [0u8; 33];
    verifier_pk[0] = 0x02;
    verifier_pk[1..].copy_from_slice(&agg_pk[1..]);
    let pk_for_verify =
        EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(&verifier_pk).unwrap();
    pk_for_verify
        .schnorr_verify(&sighash, &final_sig)
        .expect("aggregated MuSig2 Schnorr signature must verify under the taptweaked aggregate");
}

/// Round 2 without a prior round 1 → the device has no session in
/// persistent storage and must error cleanly.
#[test]
fn test_handle_sign_psbt_musig_round2_without_round1_errors() {
    musig_signing::reset_storage_for_tests();

    let address_index: u32 = 11;
    let wallet_policy = make_2of2_keypath_policy();
    let account_name = "Musig negative test #1";

    let mut psbt = build_musig_keypath_psbt(&wallet_policy, address_index);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    let accounts = [(&wallet_policy, account_name, &por)];

    // Compute what the agg_pk would be so we can inject pubnonces under
    // the right BIP-373 key — the device will *try* to enter round 2.
    let placeholder = wallet_policy
        .descriptor_template()
        .placeholders()
        .next()
        .unwrap()
        .0
        .clone();
    let info = musig_signing::compute_per_input_info(
        wallet_policy.key_information(),
        &placeholder,
        false,
        address_index,
        musig_signing::SpendPath::Keypath { taptree_hash: None },
    )
    .unwrap();
    let agg_pk = info.agg_key_tweaked;
    let agg_xonly: [u8; 32] = agg_pk[1..].try_into().unwrap();

    // Both pubnonces must be present so the handler ENTERS round 2; it
    // then fails because there's no persisted session. We use *master*
    // participant pks (BIP-388 musig signs with master keys).
    let device_master_pk = {
        let n = sdk::curve::Secp256k1::derive_hd_node(&DEVICE_PATH).unwrap();
        EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*n.privkey)
            .to_public_key()
            .to_compressed()
    };
    let (_sn_dev, pn_dev) =
        musig_lib::nonce_gen(&[0xDEu8; 32], &device_master_pk, &agg_xonly).unwrap();
    let (cosigner_pk, _, cosigner_pubnonce, _) = cosigner_master_round1(&agg_xonly, &[0xCDu8; 32]);
    insert_pubnonce(&mut psbt, &device_master_pk, &agg_pk, &pn_dev.0);
    insert_pubnonce(&mut psbt, &cosigner_pk, &agg_pk, &cosigner_pubnonce.0);

    // No prior round 1 ⇒ no session in storage ⇒ MissingMusigSession.
    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(&psbt, &accounts),
    ));
    assert_eq!(result, Err(Error::MissingMusigSession));
}

/// Round 2 with the device's own pubnonce in the PSBT but the cosigner's
/// missing → the device should error with `MissingMusigPubnonce`.
#[test]
fn test_handle_sign_psbt_musig_round2_missing_cosigner_pubnonce_errors() {
    musig_signing::reset_storage_for_tests();

    let address_index: u32 = 13;
    let wallet_policy = make_2of2_keypath_policy();
    let account_name = "Musig negative test #2";

    let mut psbt = build_musig_keypath_psbt(&wallet_policy, address_index);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    let accounts = [(&wallet_policy, account_name, &por)];

    // ---- Round 1 (real) ----
    let r1 = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(&psbt, &accounts),
    ))
    .unwrap();
    let device_pubnonce = match r1 {
        Response::PsbtSigned {
            musig_pubnonces, ..
        } => musig_pubnonces.into_iter().next().unwrap(),
        _ => panic!(),
    };
    let agg_pk = device_pubnonce.aggregate_pubkey;

    // Inject ONLY the device's pubnonce → the device should detect the
    // cosigner's missing and fail.
    insert_pubnonce(
        &mut psbt,
        &device_pubnonce.participant_pk,
        &agg_pk,
        &device_pubnonce.pubnonce,
    );

    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(&psbt, &accounts),
    ));
    assert_eq!(result, Err(Error::MissingMusigPubnonce));
}

/// Another path of a device key, for a second MuSig2 account in the same PSBT.
const OTHER_DEVICE_PATH: [u32; 4] = [0x80000030, 0x80000001, 0x80000001, 0x80000002];

/// Runs `handle_sign_psbt` on `psbt` with `accounts`, and returns the MuSig2 pubnonces and
/// partial signatures of the response.
fn sign_musig(
    psbt: &Psbt,
    accounts: &[(&WalletPolicy, &str, &[u8; 32])],
) -> Result<(Vec<MuSig2Pubnonce>, Vec<MuSig2PartialSignature>), Error> {
    match sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &prepare_as_psbtv2(psbt, accounts),
    ))? {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
            ..
        } => {
            assert!(
                signatures.is_empty(),
                "no plain placeholders ⇒ no signatures"
            );
            Ok((musig_pubnonces, musig_partial_sigs))
        }
        _ => panic!("Expected PsbtSigned"),
    }
}

/// Completes, with the hot cosigner whose round-1 randomness is `cosigner_rand`, the key-path
/// MuSig2 signature of `sighash` for an input of `wallet_policy` at `address_index`, and checks
/// that it verifies under the input's aggregate key.
fn cosign_and_verify(
    wallet_policy: &WalletPolicy,
    address_index: u32,
    sighash: &[u8; 32],
    device_pubnonce: &MuSig2Pubnonce,
    device_psig: &MuSig2PartialSignature,
    cosigner_rand: &[u8; 32],
) {
    let placeholder = wallet_policy
        .descriptor_template()
        .placeholders()
        .next()
        .unwrap()
        .0
        .clone();
    let info = musig_signing::compute_per_input_info(
        wallet_policy.key_information(),
        &placeholder,
        false,
        address_index,
        musig_signing::SpendPath::Keypath { taptree_hash: None },
    )
    .unwrap();
    let agg_xonly: [u8; 32] = info.agg_key_tweaked[1..].try_into().unwrap();
    let (_, cosigner_secnonce, cosigner_pubnonce, cosigner_sk) =
        cosigner_master_round1(&agg_xonly, cosigner_rand);
    let aggnonce = musig_lib::nonce_agg(&[
        musig_lib::PubNonce(device_pubnonce.pubnonce),
        cosigner_pubnonce,
    ])
    .unwrap();
    let sctx = musig_lib::SessionContext {
        aggnonce: &aggnonce,
        pubkeys: &info.keys,
        tweaks: &info.tweaks[..info.n_tweaks],
        is_xonly: &info.is_xonly[..info.n_tweaks],
        msg: sighash,
    };
    let cosigner_psig = musig_lib::sign(cosigner_secnonce, &cosigner_sk, &sctx).unwrap();
    let final_sig =
        musig_lib::partial_sig_agg(&sctx, &[device_psig.signature, cosigner_psig]).unwrap();

    let mut verifier_pk = [0x02; 33];
    verifier_pk[1..].copy_from_slice(&agg_xonly);
    EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(&verifier_pk)
        .unwrap()
        .schnorr_verify(sighash, &final_sig)
        .expect("aggregated MuSig2 Schnorr signature must verify");
}

/// Two MuSig2 accounts in the same PSBT, with interleaved inputs: one signing pass is one session,
/// so every input's pubnonce comes from the same randomness, which round 2 finds again.
#[test]
fn test_handle_sign_psbt_musig_two_accounts_round_trip() {
    musig_signing::reset_storage_for_tests();

    let policy_a = make_2of2_keypath_policy();
    let policy_b = make_2of2_keypath_policy_at(&OTHER_DEVICE_PATH);
    let spends = [(&policy_a, 1), (&policy_b, 2), (&policy_a, 3)];
    let mut psbt = build_musig_keypath_psbt_spending(&spends);
    let por_a = ProofOfRegistration::new(&policy_a.registration_id("Musig A")).dangerous_as_bytes();
    let por_b = ProofOfRegistration::new(&policy_b.registration_id("Musig B")).dangerous_as_bytes();
    let accounts = [
        (&policy_a, "Musig A", &por_a),
        (&policy_b, "Musig B", &por_b),
    ];

    // ---- Round 1 ----
    let (device_pubnonces, psigs) = sign_musig(&psbt, &accounts).unwrap();
    assert!(psigs.is_empty());
    let input_indices: Vec<u32> = device_pubnonces.iter().map(|p| p.input_index).collect();
    assert_eq!(input_indices, [0, 1, 2]);

    let cosigner_rand = |input_index: u32| [0xA0 + input_index as u8; 32];
    for pubnonce in &device_pubnonces {
        let input_index = pubnonce.input_index as usize;
        let agg_pk = &pubnonce.aggregate_pubkey;
        let agg_xonly: [u8; 32] = agg_pk[1..].try_into().unwrap();
        let (cosigner_pk, _, cosigner_pubnonce, _) =
            cosigner_master_round1(&agg_xonly, &cosigner_rand(pubnonce.input_index));
        insert_pubnonce_at(
            &mut psbt,
            input_index,
            &pubnonce.participant_pk,
            agg_pk,
            &pubnonce.pubnonce,
        );
        insert_pubnonce_at(
            &mut psbt,
            input_index,
            &cosigner_pk,
            agg_pk,
            &cosigner_pubnonce.0,
        );
    }

    // ---- Round 2 ----
    let (pubnonces, device_psigs) = sign_musig(&psbt, &accounts).unwrap();
    assert!(pubnonces.is_empty());
    assert_eq!(device_psigs.len(), spends.len());

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect();
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    for (input_index, (device_psig, (wallet_policy, address_index))) in
        device_psigs.iter().zip(&spends).enumerate()
    {
        assert_eq!(device_psig.input_index as usize, input_index);
        let sighash: [u8; 32] = cache
            .taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        cosign_and_verify(
            wallet_policy,
            *address_index,
            &sighash,
            &device_pubnonces[input_index],
            device_psig,
            &cosigner_rand(input_index as u32),
        );
    }
}

/// A signing pass runs a single round: a PSBT with the pubnonces of some inputs only, which would
/// get partial signatures for some inputs and pubnonces for the others, is rejected.
#[test]
fn test_handle_sign_psbt_musig_mixed_rounds_errors() {
    musig_signing::reset_storage_for_tests();

    let wallet_policy = make_2of2_keypath_policy();
    let mut psbt = build_musig_keypath_psbt_spending(&[(&wallet_policy, 1), (&wallet_policy, 2)]);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id("Musig")).dangerous_as_bytes();
    let accounts = [(&wallet_policy, "Musig", &por)];

    let (device_pubnonces, _) = sign_musig(&psbt, &accounts).unwrap();
    assert_eq!(device_pubnonces.len(), 2);

    // Only the first input gets the pubnonces of round 1.
    let pubnonce = &device_pubnonces[0];
    let agg_xonly: [u8; 32] = pubnonce.aggregate_pubkey[1..].try_into().unwrap();
    let (cosigner_pk, _, cosigner_pubnonce, _) = cosigner_master_round1(&agg_xonly, &[0xAB; 32]);
    insert_pubnonce(
        &mut psbt,
        &pubnonce.participant_pk,
        &pubnonce.aggregate_pubkey,
        &pubnonce.pubnonce,
    );
    insert_pubnonce(
        &mut psbt,
        &cosigner_pk,
        &pubnonce.aggregate_pubkey,
        &cosigner_pubnonce.0,
    );

    assert_eq!(
        sign_musig(&psbt, &accounts).err(),
        Some(Error::MixedMusigRounds)
    );
}

/// Round 2 with a device pubnonce in the PSBT that its session did not produce: the device must
/// refuse to sign, as the aggregate nonce would not contain the nonce it signs with.
#[test]
fn test_handle_sign_psbt_musig_round2_foreign_device_pubnonce_errors() {
    musig_signing::reset_storage_for_tests();

    let wallet_policy = make_2of2_keypath_policy();
    let mut psbt = build_musig_keypath_psbt(&wallet_policy, 17);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id("Musig")).dangerous_as_bytes();
    let accounts = [(&wallet_policy, "Musig", &por)];

    // ---- Round 1 (real): the device has a session ----
    let (device_pubnonces, _) = sign_musig(&psbt, &accounts).unwrap();
    let device_pubnonce = &device_pubnonces[0];
    let agg_pk = device_pubnonce.aggregate_pubkey;
    let agg_xonly: [u8; 32] = agg_pk[1..].try_into().unwrap();

    // The PSBT carries another pubnonce for the device's key.
    let (_, foreign_pubnonce) =
        musig_lib::nonce_gen(&[0xDE; 32], &device_pubnonce.participant_pk, &agg_xonly).unwrap();
    assert_ne!(foreign_pubnonce.0, device_pubnonce.pubnonce);
    let (cosigner_pk, _, cosigner_pubnonce, _) = cosigner_master_round1(&agg_xonly, &[0xAB; 32]);
    insert_pubnonce(
        &mut psbt,
        &device_pubnonce.participant_pk,
        &agg_pk,
        &foreign_pubnonce.0,
    );
    insert_pubnonce(&mut psbt, &cosigner_pk, &agg_pk, &cosigner_pubnonce.0);

    assert_eq!(
        sign_musig(&psbt, &accounts).err(),
        Some(Error::MusigPubnonceMismatch)
    );
}
