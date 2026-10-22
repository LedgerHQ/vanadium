//! Transactions involving several accounts.

use bitcoin::{
    bip32::{DerivationPath, Fingerprint, KeySource, Xpub},
    hashes::Hash,
    psbt::Psbt,
    secp256k1::{PublicKey, Secp256k1},
    sighash::SighashCache,
    Amount, EcdsaSighashType, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
};
use common::{
    bip388::WalletPolicy,
    fastpsbt,
    message::Response,
    por::{ProofOfRegistration, Registerable},
    script::ToScript,
};
use sdk::curve::EcfpPublicKey;

use super::super::analyze::analyze_transaction;
use super::super::handle_sign_psbt;
use super::super::test_utils::prepare_as_psbtv2;

const SEGWIT_XPUB: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
const TAPROOT_XPUB: &str = "tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";

/// The key at `/change/index` of `xpub`, which is the device's key at `origin`, with its key
/// origin.
fn child(xpub: &str, origin: &str, change: u32, index: u32) -> (PublicKey, KeySource) {
    let xpub: Xpub = xpub.parse().unwrap();
    let path: DerivationPath = format!("m/{change}/{index}").parse().unwrap();
    let key = xpub
        .derive_pub(&Secp256k1::new(), &path)
        .unwrap()
        .public_key;
    let full_path: DerivationPath = format!("{origin}/{change}/{index}").parse().unwrap();
    (
        key,
        (Fingerprint::from([0xf5, 0xac, 0xc2, 0xfd]), full_path),
    )
}

#[test]
fn test_handle_sign_psbt_transfer_to_another_account() {
    let segwit = WalletPolicy::new(
        "wpkh(@0/**)",
        vec![format!("[f5acc2fd/84'/1'/0']{SEGWIT_XPUB}")
            .as_str()
            .try_into()
            .unwrap()],
    )
    .unwrap();
    let taproot = WalletPolicy::new(
        "tr(@0/**)",
        vec![format!("[f5acc2fd/86'/1'/0']{TAPROOT_XPUB}")
            .as_str()
            .try_into()
            .unwrap()],
    )
    .unwrap();

    // spends from the segwit account, and sends part of the funds to the taproot account
    let spent = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: segwit.to_script(false, 2).unwrap(),
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20])),
            },
            TxOut {
                value: Amount::from_sat(39_000),
                script_pubkey: taproot.to_script(false, 5).unwrap(),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(spent.clone());
    let (key, origin) = child(SEGWIT_XPUB, "m/84'/1'/0'", 0, 2);
    psbt.inputs[0].bip32_derivation.insert(key, origin);
    let (taproot_key, origin) = child(TAPROOT_XPUB, "m/86'/1'/0'", 0, 5);
    psbt.outputs[1]
        .tap_key_origins
        .insert(taproot_key.x_only_public_key().0, (vec![], origin));

    let por = |policy: &WalletPolicy, name| {
        ProofOfRegistration::new(&policy.registration_id(name)).dangerous_as_bytes()
    };
    let (segwit_por, taproot_por) = (por(&segwit, "Segwit"), por(&taproot, "Taproot"));
    let psbt_v2 = prepare_as_psbtv2(
        &psbt,
        &[
            (&segwit, "Segwit", &segwit_por),
            (&taproot, "Taproot", &taproot_por),
        ],
    );

    // the taproot account receives its output, and only the payment is external
    let (summary, _) = analyze_transaction(&fastpsbt::Psbt::parse(&psbt_v2).unwrap()).unwrap();
    assert_eq!(summary.account_spent_amounts, [100_000, -39_000]);
    assert_eq!(summary.external_outputs.len(), 1);
    assert_eq!(summary.external_outputs[0].output_index, 0);

    let response =
        sdk::executor::block_on(handle_sign_psbt(&mut sdk::App::singleton(), &psbt_v2)).unwrap();
    let Response::PsbtSigned { signatures, .. } = response else {
        panic!("Expected PsbtSigned response");
    };
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].input_index, 0);
    assert_eq!(signatures[0].pubkey, key.serialize());

    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .p2wpkh_signature_hash(0, &spent.script_pubkey, spent.value, EcdsaSighashType::All)
        .unwrap();
    let (sighash_type, signature) = signatures[0].signature.split_last().unwrap();
    assert_eq!(*sighash_type, EcdsaSighashType::All as u8);
    // the secp256k1 shim doesn't verify ECDSA signatures
    EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(&key.serialize())
        .unwrap()
        .ecdsa_verify_hash(&sighash.to_byte_array(), signature)
        .expect("Signature verification failed");
}
