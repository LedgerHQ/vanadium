//! Paying to silent payment codes (BIP-375): the device computes an ECDH share and a DLEQ proof
//! for each scan key and the scripts of the outputs, then signs the transaction with them.
//!
//! The positive tests check what the device returns against values computed here: the private
//! keys of the eligible inputs (each checked against the script it spends), the outputs of
//! BIP-352 for their sum, the DLEQ proofs, and the signatures over the final transaction.

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint},
    hashes::{hash160, Hash},
    key::{Keypair, TapTweak},
    psbt::Psbt,
    secp256k1::{PublicKey, Secp256k1},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash, TapNodeHash},
    Amount, EcdsaSighashType, OutPoint, PubkeyHash, ScriptBuf, TapSighashType, Transaction, TxIn,
    TxOut, Txid, WPubkeyHash,
};
use common::{
    bip388::WalletPolicy,
    errors::Error,
    fastpsbt::{self, *},
    message::{PartialSignature, Response, SilentPaymentShare, WalletPolicyCoordinates},
    por::{ProofOfRegistration, Registerable},
    psbt::{
        prepare_psbt, OutputAuthProof, PsbtAccount, PsbtAccountCoordinates, PsbtAccountInputWrite,
        PsbtAccountOutputWrite, PsbtOutputAuthWrite, PsbtV2,
    },
    script::ToScript,
    silent_payments::{
        self as sp, SilentPaymentAccount, SilentPaymentCode, SilentPaymentCoordinates,
    },
};
use sdk::curve::{Curve, EcfpPublicKey, Secp256k1Point, Secp256k1Scalar};

use super::super::analyze::analyze_transaction;
use super::super::display::build_display_pairs;
use super::super::handle_sign_psbt;
use super::musig::{build_musig_keypath_psbt, make_2of2_keypath_policy};

const LEGACY_KEY: &str = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
const SEGWIT_KEY: &str = "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
const TAPROOT_KEY: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";
const MULTISIG_KEY: &str = "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK";
const COSIGNER_KEY: &str = "[d5365b22/48'/1'/0'/2']tpubDFWK5mCX28dt6hfy74Bc51jjbWrimXow1bTxCMpJrWqesK3AeZiYn8tcLFW3VoBiHhM9FjKdLWaC3GZVVX5PfGNG3zfbM14bMb1SLym36nN";
const FOREIGN_KEY: &str = "tpubD6NzVbkrYhZ4XUBKWaWfdn2icbaEDfaUgkCCbKPm31LTLRfaaEJRDAF3XXbvTaKLHATytZPGoWpVxnMnrRbn4519fP6nhZDDFtJimcZWBGC";

fn policy(template: &str, keys: &[&str]) -> WalletPolicy {
    let keys = keys.iter().map(|key| (*key).try_into().unwrap()).collect();
    WalletPolicy::new(template, keys).unwrap()
}

/// The child `/change/index` of key `key_index` of `policy`, with its full key origin if the key
/// has one.
fn child_key(
    policy: &WalletPolicy,
    key_index: usize,
    change: u32,
    index: u32,
) -> (PublicKey, Option<(Fingerprint, DerivationPath)>) {
    let key_info = &policy.key_information()[key_index];
    let steps = [ChildNumber::from(change), ChildNumber::from(index)];
    let key = key_info
        .pubkey
        .derive_pub(&Secp256k1::new(), &steps)
        .unwrap()
        .public_key;
    let origin = key_info.origin_info.as_ref().map(|origin| {
        let path: Vec<ChildNumber> = origin
            .derivation_path
            .iter()
            .chain(&steps)
            .copied()
            .collect();
        (
            Fingerprint::from(origin.fingerprint.to_be_bytes()),
            path.into(),
        )
    });
    (key, origin)
}

/// The device's private key at the key origin `origin`.
fn device_private_key(origin: &(Fingerprint, DerivationPath)) -> [u8; 32] {
    let path: Vec<u32> = origin.1.as_ref().iter().map(|&step| step.into()).collect();
    *sdk::curve::Secp256k1::derive_hd_node(&path)
        .unwrap()
        .privkey
}

/// The code of the scan key `scan·G` and the spend key `spend·G`.
fn code(scan: u32, spend: u32) -> SilentPaymentCode {
    let g = sdk::curve::Secp256k1::get_generator();
    SilentPaymentCode::new(
        &g * &Secp256k1Scalar::from_u32(scan),
        &g * &Secp256k1Scalar::from_u32(spend),
    )
    .unwrap()
}

/// An input of a test transaction: an account, the coordinates it spends from, its amount, and how
/// BIP-352 sees it.
struct Spend<'a> {
    policy: &'a WalletPolicy,
    index: u32,
    amount: u64,
    kind: Kind,
}

enum Kind {
    /// A single-key input of the account's key #0: `pkh()`, `wpkh()` or `sh(wpkh())`.
    SingleKey,
    /// A taproot input whose internal key is the account's key #0, with this tap tree root.
    Taproot(Option<TapNodeHash>),
    /// An input that BIP-352 ignores, whose witness script is the multisig of all the keys.
    Ineligible,
    /// An eligible input that the device can't contribute to.
    NotHeld,
}

/// An input that spends an output that a silent payment account received, with its tweak.
struct SpSpend<'a> {
    account: &'a SilentPaymentAccount,
    tweak: [u8; 32],
    amount: u64,
}

/// The device's private key of an output with tweak `tweak` that the silent payment account
/// `account` received, `b_spend + tweak` (BIP-376), with `b_spend` derived here.
fn received_private_key(account: &SilentPaymentAccount, tweak: &[u8; 32]) -> Secp256k1Scalar {
    let path: DerivationPath = format!("m/352'/1'/{}'/0'/0", account.account_index())
        .parse()
        .unwrap();
    let b_spend = device_private_key(&(Fingerprint::default(), path));
    &Secp256k1Scalar::from_be_bytes(&b_spend).unwrap()
        + &Secp256k1Scalar::from_be_bytes(tweak).unwrap()
}

/// The script of the output with tweak `tweak` that `account` received: `OP_1 x(d·G)`.
fn received_script(account: &SilentPaymentAccount, tweak: &[u8; 32]) -> ScriptBuf {
    let d = received_private_key(account, tweak);
    let key = &sdk::curve::Secp256k1::get_generator() * &d;
    ScriptBuf::from_bytes([&[0x51, 0x20][..], key.x()].concat())
}

enum Out<'a> {
    Code(SilentPaymentCode, u64),
    Script(ScriptBuf, u64),
    /// The change address `index` of a single-key segwit account.
    Change(&'a WalletPolicy, u32, u64),
    /// A code of a silent payment account, with an optional label.
    SilentPaymentChange(&'a SilentPaymentAccount, Option<u32>, u64),
}

/// The code of `account` with label `label`, computed from the device's keys.
fn account_code(account: &SilentPaymentAccount, label: Option<u32>) -> SilentPaymentCode {
    let key = |branch| {
        let path: DerivationPath = format!("m/352'/1'/{}'/{branch}'/0", account.account_index())
            .parse()
            .unwrap();
        Secp256k1Scalar::from_be_bytes(&device_private_key(&(Fingerprint::default(), path)))
            .unwrap()
    };
    let g = sdk::curve::Secp256k1::get_generator();
    let (b_scan, spend) = (key(1), &g * &key(0));
    let spend = match label {
        Some(m) => sp::labeled_spend_key(&spend, &b_scan, m).unwrap(),
        None => spend,
    };
    SilentPaymentCode::new(&g * &b_scan, spend).unwrap()
}

/// A test transaction, as a prepared PSBTv2, with what the tests check the device against.
struct Fixture {
    psbt: PsbtV2,
    /// The unsigned transaction, with a placeholder script for the outputs to codes.
    tx: Transaction,
    prevouts: Vec<TxOut>,
    redeem_scripts: Vec<Option<ScriptBuf>>,
    witness_scripts: Vec<Option<ScriptBuf>>,
    /// The sum of the private keys of the eligible inputs, as they enter BIP-352.
    a: Option<Secp256k1Scalar>,
}

fn fixture(spends: &[Spend], outs: &[Out]) -> Fixture {
    fixture_with(spends, &[], outs)
}

/// A test transaction whose inputs spend `spends`, then `sp_spends`, and whose outputs are `outs`.
fn fixture_with(spends: &[Spend], sp_spends: &[SpSpend], outs: &[Out]) -> Fixture {
    let secp = Secp256k1::new();
    let prevouts: Vec<TxOut> = spends
        .iter()
        .map(|spend| TxOut {
            value: Amount::from_sat(spend.amount),
            script_pubkey: spend.policy.to_script(false, spend.index).unwrap(),
        })
        .chain(sp_spends.iter().map(|spend| TxOut {
            value: Amount::from_sat(spend.amount),
            script_pubkey: received_script(spend.account, &spend.tweak),
        }))
        .collect();
    // a legacy input comes with the whole transaction that it spends, output `i` for input `i`
    let funding_txs: Vec<Option<Transaction>> = prevouts
        .iter()
        .enumerate()
        .map(|(i, prevout)| {
            prevout.script_pubkey.is_p2pkh().then(|| Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn::default()],
                output: (0..i)
                    .map(|_| TxOut::NULL)
                    .chain([prevout.clone()])
                    .collect(),
            })
        })
        .collect();
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: funding_txs
            .iter()
            .enumerate()
            .map(|(i, funding_tx)| TxIn {
                previous_output: OutPoint {
                    // not in the order of the inputs, so that the smallest outpoint isn't the first
                    txid: funding_tx.as_ref().map_or(
                        Txid::from_byte_array([0x30 - i as u8; 32]),
                        Transaction::compute_txid,
                    ),
                    vout: i as u32,
                },
                ..Default::default()
            })
            .collect(),
        output: outs
            .iter()
            .map(|out| match out {
                Out::Code(_, amount) | Out::SilentPaymentChange(_, _, amount) => TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                Out::Script(script, amount) => TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: script.clone(),
                },
                Out::Change(policy, index, amount) => TxOut {
                    value: Amount::from_sat(*amount),
                    script_pubkey: policy.to_script(true, *index).unwrap(),
                },
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    for (output, out) in psbt.outputs.iter_mut().zip(outs) {
        if let Out::Change(policy, index, _) = out {
            let (key, origin) = child_key(policy, 0, 1, *index);
            output.bip32_derivation.insert(key, origin.unwrap());
        }
    }

    let mut redeem_scripts = Vec::new();
    let mut witness_scripts = Vec::new();
    let mut a: Option<Secp256k1Scalar> = None;
    for (i, spend) in spends.iter().enumerate() {
        let prevout = &prevouts[i];
        let input = &mut psbt.inputs[i];
        match &funding_txs[i] {
            Some(funding_tx) => input.non_witness_utxo = Some(funding_tx.clone()),
            None => input.witness_utxo = Some(prevout.clone()),
        }
        let is_taproot = matches!(spend.kind, Kind::Taproot(_))
            || (matches!(spend.kind, Kind::NotHeld) && prevout.script_pubkey.is_p2tr());
        for key_index in 0..spend.policy.key_information().len() {
            let (key, origin) = child_key(spend.policy, key_index, 0, spend.index);
            let Some(origin) = origin else { continue };
            if is_taproot {
                input
                    .tap_key_origins
                    .insert(key.x_only_public_key().0, (vec![], origin));
            } else {
                input.bip32_derivation.insert(key, origin);
            }
        }

        let mut redeem_script = None;
        let mut witness_script = None;
        let key = match spend.kind {
            Kind::SingleKey => {
                let (key, origin) = child_key(spend.policy, 0, 0, spend.index);
                let hash = hash160::Hash::hash(&key.serialize()).to_byte_array();
                let wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash));
                if prevout.script_pubkey.is_p2pkh() {
                    let pkh = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash));
                    assert_eq!(prevout.script_pubkey, pkh);
                } else if prevout.script_pubkey.is_p2sh() {
                    assert_eq!(prevout.script_pubkey, wpkh.to_p2sh());
                    input.redeem_script = Some(wpkh.clone());
                    redeem_script = Some(wpkh);
                } else {
                    assert_eq!(prevout.script_pubkey, wpkh);
                }
                Some(device_private_key(&origin.unwrap()))
            }
            Kind::Taproot(root) => {
                let (_, origin) = child_key(spend.policy, 0, 0, spend.index);
                let internal = device_private_key(&origin.unwrap());
                let keypair = Keypair::from_seckey_slice(&secp, &internal).unwrap();
                let tweaked = keypair.tap_tweak(&secp, root).to_keypair();
                // the output key of the spent script
                assert_eq!(
                    prevout.script_pubkey.as_bytes()[2..],
                    tweaked.x_only_public_key().0.serialize()
                );
                Some(tweaked.secret_bytes())
            }
            Kind::Ineligible => {
                let mut builder = bitcoin::script::Builder::new().push_int(1);
                for key_index in 0..spend.policy.key_information().len() {
                    let (key, _) = child_key(spend.policy, key_index, 0, spend.index);
                    builder = builder.push_slice(key.serialize());
                }
                let script = builder
                    .push_int(spend.policy.key_information().len() as i64)
                    .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
                    .into_script();
                assert_eq!(prevout.script_pubkey, script.to_p2wsh());
                input.witness_script = Some(script.clone());
                witness_script = Some(script);
                None
            }
            Kind::NotHeld => None,
        };
        if let Some(key) = key {
            let key = Secp256k1Scalar::from_be_bytes(&key).unwrap();
            let key = sp::input_private_key(&key, is_taproot);
            // BIP-352 takes the key with an even y-coordinate for taproot: check it is the one
            let point = &sdk::curve::Secp256k1::get_generator() * &key;
            if is_taproot {
                assert_eq!(point.x()[..], prevout.script_pubkey.as_bytes()[2..]);
            }
            a = Some(match a {
                Some(a) => &a + &key,
                None => key,
            });
        }
        redeem_scripts.push(redeem_script);
        witness_scripts.push(witness_script);
    }
    for (i, spend) in sp_spends.iter().enumerate() {
        let i = spends.len() + i;
        psbt.inputs[i].witness_utxo = Some(prevouts[i].clone());
        let key = sp::input_private_key(&received_private_key(spend.account, &spend.tweak), true);
        let point = &sdk::curve::Secp256k1::get_generator() * &key;
        assert_eq!(point.x()[..], prevouts[i].script_pubkey.as_bytes()[2..]);
        a = Some(match a {
            Some(a) => &a + &key,
            None => key,
        });
        redeem_scripts.push(None);
        witness_scripts.push(None);
    }

    // each account once, with a name and its proof of registration
    let mut accounts: Vec<(PsbtAccount, String, [u8; 32])> = Vec::new();
    let mut policies: Vec<&WalletPolicy> = Vec::new();
    for spend in spends {
        if policies.iter().any(|p| core::ptr::eq(*p, spend.policy)) {
            continue;
        }
        policies.push(spend.policy);
        let name = format!("Account {}", accounts.len());
        let por =
            ProofOfRegistration::new(&spend.policy.registration_id(&name)).dangerous_as_bytes();
        accounts.push((spend.policy.into(), name, por));
    }
    let mut sp_accounts: Vec<&SilentPaymentAccount> = Vec::new();
    for spend in sp_spends {
        if sp_accounts.iter().any(|a| core::ptr::eq(*a, spend.account)) {
            continue;
        }
        sp_accounts.push(spend.account);
        let name = format!("Account {}", accounts.len());
        let por =
            ProofOfRegistration::new(&spend.account.registration_id(&name)).dangerous_as_bytes();
        accounts.push((spend.account.into(), name, por));
    }
    let accounts: Vec<(PsbtAccount, &str, &[u8; 32])> = accounts
        .iter()
        .map(|(account, name, por)| (account.clone(), name.as_str(), por))
        .collect();

    let mut psbt = PsbtV2::from_v0(&psbt.serialize()).unwrap();
    for (i, spend) in sp_spends.iter().enumerate() {
        psbt.inputs[spends.len() + i].insert(PSBT_IN_SP_TWEAK, &[], spend.tweak.to_vec());
    }
    for (output, out) in psbt.outputs.iter_mut().zip(outs) {
        if let Out::SilentPaymentChange(account, label, _) = out {
            output.remove(PSBT_OUT_SCRIPT, &[]).unwrap();
            let code = account_code(account, *label);
            output.insert(PSBT_OUT_SP_V0_INFO, &[], code.to_bytes().to_vec());
            if let Some(label) = label {
                output.insert(PSBT_OUT_SP_V0_LABEL, &[], label.to_le_bytes().to_vec());
            }
        }
    }
    prepare_psbt(&mut psbt, &accounts).unwrap();
    for (output, out) in psbt.outputs.iter_mut().zip(outs) {
        if let Out::Code(code, _) = out {
            output.remove(PSBT_OUT_SCRIPT, &[]).unwrap();
            output.insert(PSBT_OUT_SP_V0_INFO, &[], code.to_bytes().to_vec());
        }
    }

    Fixture {
        psbt,
        tx,
        prevouts,
        redeem_scripts,
        witness_scripts,
        a,
    }
}

fn sign(psbt: &PsbtV2) -> Result<Response, Error> {
    sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &psbt.serialize(),
    ))
}

/// The response's signatures and ECDH shares, and the transaction with the computed scripts, once
/// checked against the fixture.
struct Checked {
    signatures: Vec<PartialSignature>,
    shares: Vec<SilentPaymentShare>,
    tx: Transaction,
}

/// Checks the device's response against what BIP-352 and BIP-375 give for `fx`.
fn check(fx: &Fixture, response: Response) -> Checked {
    let Response::PsbtSigned {
        signatures,
        sp_shares,
        sp_output_scripts,
        ..
    } = response
    else {
        panic!("Expected PsbtSigned response");
    };
    let a = fx.a.as_ref().unwrap();
    let g = sdk::curve::Secp256k1::get_generator();

    // the scripts are the outputs of BIP-352 for the sum of the eligible keys
    let raw = fx.psbt.serialize();
    let parsed = fastpsbt::Psbt::parse(&raw).unwrap();
    let recipients = sp::recipients(&parsed).unwrap();
    let outpoints: Vec<OutPoint> = fx
        .tx
        .input
        .iter()
        .map(|txin| txin.previous_output)
        .collect();
    let codes: Vec<SilentPaymentCode> = recipients.iter().map(|r| r.code.clone()).collect();
    let expected = sp::create_outputs(a, &outpoints, &codes).unwrap();
    assert_eq!(sp_output_scripts.len(), recipients.len());
    let mut tx = fx.tx.clone();
    for ((script, recipient), x) in sp_output_scripts.iter().zip(&recipients).zip(&expected) {
        assert_eq!(script.output_index as usize, recipient.output_index);
        assert_eq!(script.script, [&[0x51, 0x20][..], &x[..]].concat());
        tx.output[recipient.output_index].script_pubkey =
            ScriptBuf::from_bytes(script.script.clone());
    }

    // one share per scan key, in the order of the outputs, each a·B_scan with a valid proof
    let mut scan_keys: Vec<Secp256k1Point> = Vec::new();
    for code in &codes {
        if !scan_keys.contains(code.scan()) {
            scan_keys.push(*code.scan());
        }
    }
    assert_eq!(sp_shares.len(), scan_keys.len());
    for (share, scan) in sp_shares.iter().zip(&scan_keys) {
        assert_eq!(share.scan_key, scan.to_compressed().unwrap());
        let c = scan * a;
        assert_eq!(share.share, c.to_compressed().unwrap());
        assert!(sp::verify_proof(
            &(&g * a),
            scan,
            &c,
            &share.dleq_proof,
            &g,
            None
        ));
    }

    // the signatures are valid for the transaction with the computed scripts
    let mut cache = SighashCache::new(&tx);
    for signature in &signatures {
        let i = signature.input_index as usize;
        let prevout = &fx.prevouts[i];
        if prevout.script_pubkey.is_p2tr() {
            // SIGHASH_ALL ends the signature with its byte, SIGHASH_DEFAULT doesn't
            let (schnorr_signature, sighash_type) = match signature.signature.len() {
                65 => {
                    assert_eq!(signature.signature[64], TapSighashType::All as u8);
                    (&signature.signature[..64], TapSighashType::All)
                }
                _ => (&signature.signature[..], TapSighashType::Default),
            };
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&fx.prevouts), sighash_type)
                .unwrap();
            assert_eq!(signature.pubkey, prevout.script_pubkey.as_bytes()[2..]);
            let pubkey = [&[0x02][..], &signature.pubkey].concat();
            EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(
                &pubkey.try_into().unwrap(),
            )
            .unwrap()
            .schnorr_verify(&sighash.to_byte_array(), schnorr_signature)
            .expect("Schnorr signature verification failed");
        } else {
            let sighash = if let Some(script) = &fx.witness_scripts[i] {
                cache
                    .p2wsh_signature_hash(i, script, prevout.value, EcdsaSighashType::All)
                    .unwrap()
                    .to_byte_array()
            } else if prevout.script_pubkey.is_p2pkh() {
                cache
                    .legacy_signature_hash(i, &prevout.script_pubkey, EcdsaSighashType::All as u32)
                    .unwrap()
                    .to_byte_array()
            } else {
                // the wpkh() script, nested in sh() or not
                let wpkh = fx.redeem_scripts[i]
                    .as_ref()
                    .unwrap_or(&prevout.script_pubkey);
                cache
                    .p2wpkh_signature_hash(i, wpkh, prevout.value, EcdsaSighashType::All)
                    .unwrap()
                    .to_byte_array()
            };
            let (sighash_type, der) = signature.signature.split_last().unwrap();
            assert_eq!(*sighash_type, EcdsaSighashType::All as u8);
            // the secp256k1 shim doesn't verify ECDSA signatures
            EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(
                &signature.pubkey.clone().try_into().unwrap(),
            )
            .unwrap()
            .ecdsa_verify_hash(&sighash, der)
            .expect("ECDSA signature verification failed");
        }
    }

    Checked {
        signatures,
        shares: sp_shares,
        tx,
    }
}

fn segwit_policy() -> WalletPolicy {
    policy("wpkh(@0/**)", &[SEGWIT_KEY])
}

/// One segwit input, paying one silent payment code and returning the change.
fn simple_fixture(segwit: &WalletPolicy) -> Fixture {
    fixture(
        &[Spend {
            policy: segwit,
            index: 2,
            amount: 100_000,
            kind: Kind::SingleKey,
        }],
        &[
            Out::Code(code(11, 12), 60_000),
            Out::Change(segwit, 0, 39_000),
        ],
    )
}

/// Inputs of every kind that BIP-352 counts: `pkh()`, `wpkh()`, `sh(wpkh())`, and `tr()` with a
/// tap tree.
#[test]
fn test_pay_to_silent_payment_codes() {
    let legacy = policy("pkh(@0/**)", &[LEGACY_KEY]);
    let segwit = segwit_policy();
    let nested_segwit = policy("sh(wpkh(@0/**))", &[SEGWIT_KEY]);
    let taproot = policy("tr(@0/**,pk(@1/**))", &[TAPROOT_KEY, FOREIGN_KEY]);
    // the tap tree has a single leaf: pk() of the foreign key
    let (leaf_key, _) = child_key(&taproot, 1, 0, 3);
    let leaf_script = bitcoin::script::Builder::new()
        .push_slice(leaf_key.x_only_public_key().0.serialize())
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script();
    let root = TapNodeHash::from(TapLeafHash::from_script(
        &leaf_script,
        LeafVersion::TapScript,
    ));

    let fx = fixture(
        &[
            Spend {
                policy: &segwit,
                index: 2,
                amount: 100_000,
                kind: Kind::SingleKey,
            },
            Spend {
                policy: &taproot,
                index: 3,
                amount: 50_000,
                kind: Kind::Taproot(Some(root)),
            },
            Spend {
                policy: &legacy,
                index: 4,
                amount: 20_000,
                kind: Kind::SingleKey,
            },
            Spend {
                policy: &nested_segwit,
                index: 5,
                amount: 30_000,
                kind: Kind::SingleKey,
            },
        ],
        &[
            // two codes with the same scan key, which get k = 0 and k = 1, and another scan key
            Out::Code(code(11, 12), 40_000),
            Out::Script(
                ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20])),
                30_000,
            ),
            Out::Code(code(11, 13), 30_000),
            Out::Code(code(21, 22), 20_000),
            Out::Change(&segwit, 0, 79_000),
        ],
    );

    // the review shows the addresses of the codes
    let raw = fx.psbt.serialize();
    let parsed = fastpsbt::Psbt::parse(&raw).unwrap();
    let (summary, _) = analyze_transaction(&parsed).unwrap();
    let external: Vec<usize> = summary
        .external_outputs
        .iter()
        .map(|output| output.output_index)
        .collect();
    assert_eq!(external, [0, 1, 2, 3]);
    let pairs = build_display_pairs(&parsed, &summary).unwrap();
    let output_0 = pairs.iter().find(|p| p.tag == "Output 0").unwrap();
    assert_eq!(output_0.value, code(11, 12).to_address("tsp").unwrap());
    assert!(output_0.value.starts_with("tsp1q"));

    let checked = check(&fx, sign(&fx.psbt).unwrap());
    assert_eq!(checked.signatures.len(), 4);
}

/// An input that BIP-352 doesn't count, like a `wsh()` multisig, doesn't enter the shares, and
/// still gets signed.
#[test]
fn test_ineligible_inputs_are_left_out() {
    let segwit = segwit_policy();
    let multisig = policy("wsh(multi(1,@0/**,@1/**))", &[MULTISIG_KEY, COSIGNER_KEY]);
    let fx = fixture(
        &[
            Spend {
                policy: &multisig,
                index: 4,
                amount: 70_000,
                kind: Kind::Ineligible,
            },
            Spend {
                policy: &segwit,
                index: 2,
                amount: 100_000,
                kind: Kind::SingleKey,
            },
        ],
        &[Out::Code(code(11, 12), 160_000)],
    );
    let checked = check(&fx, sign(&fx.psbt).unwrap());
    assert_eq!(checked.signatures.len(), 2);
}

#[test]
fn test_no_eligible_inputs() {
    let multisig = policy("wsh(multi(1,@0/**,@1/**))", &[MULTISIG_KEY, COSIGNER_KEY]);
    let fx = fixture(
        &[Spend {
            policy: &multisig,
            index: 4,
            amount: 70_000,
            kind: Kind::Ineligible,
        }],
        &[Out::Code(code(11, 12), 60_000)],
    );
    assert_eq!(sign(&fx.psbt), Err(Error::SilentPaymentNoEligibleInputs));
}

/// A taproot input counts with its output key even when a script path spends it, so the device
/// needs the private key of the internal key, which a cosigner holds here.
#[test]
fn test_internal_key_not_held() {
    let taproot = policy("tr(@0/**,pk(@1/**))", &[FOREIGN_KEY, TAPROOT_KEY]);
    let fx = fixture(
        &[Spend {
            policy: &taproot,
            index: 3,
            amount: 50_000,
            kind: Kind::NotHeld,
        }],
        &[Out::Code(code(11, 12), 40_000)],
    );
    assert_eq!(sign(&fx.psbt), Err(Error::SilentPaymentInputNotHeld));
}

/// Nobody holds the private key of a `musig()` internal key, so it can't pay to a code.
#[test]
fn test_musig_input_not_held() {
    let musig = make_2of2_keypath_policy();
    let por = ProofOfRegistration::new(&musig.registration_id("Musig")).dangerous_as_bytes();
    let mut psbt = PsbtV2::from_v0(&build_musig_keypath_psbt(&musig, 3).serialize()).unwrap();
    prepare_psbt(&mut psbt, &[(&musig, "Musig", &por)]).unwrap();
    let output = &mut psbt.outputs[0];
    output.remove(PSBT_OUT_SCRIPT, &[]).unwrap();
    output.insert(PSBT_OUT_SP_V0_INFO, &[], code(11, 12).to_bytes().to_vec());
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentInputNotHeld));
}

/// BIP-375: only SIGHASH_ALL, or no sighash type. The explicit SIGHASH_DEFAULT that a taproot input
/// can otherwise ask for is rejected too.
#[test]
fn test_sighash_types() {
    let segwit = segwit_policy();
    let fx = simple_fixture(&segwit);
    let mut psbt = fx.psbt.clone();
    psbt.inputs[0].insert(PSBT_IN_SIGHASH_TYPE, &[], 1u32.to_le_bytes().to_vec());
    check(&fx, sign(&psbt).unwrap());

    let taproot = policy("tr(@0/**)", &[TAPROOT_KEY]);
    let fx = fixture(
        &[Spend {
            policy: &taproot,
            index: 1,
            amount: 50_000,
            kind: Kind::Taproot(None),
        }],
        &[Out::Code(code(11, 12), 40_000)],
    );
    let mut psbt = fx.psbt.clone();
    psbt.inputs[0].insert(PSBT_IN_SIGHASH_TYPE, &[], 1u32.to_le_bytes().to_vec());
    let checked = check(&fx, sign(&psbt).unwrap());
    assert_eq!(checked.signatures[0].signature.len(), 65);
    psbt.inputs[0].insert(PSBT_IN_SIGHASH_TYPE, &[], 0u32.to_le_bytes().to_vec());
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentSighashType));
}

/// BIP-375: no input may spend a segwit version above 1.
#[test]
fn test_segwit_version_above_1() {
    let segwit = segwit_policy();
    let mut fx = simple_fixture(&segwit);
    let utxo = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: ScriptBuf::from_bytes([&[0x52, 0x20][..], &[7; 32]].concat()),
    };
    fx.psbt.inputs[0].insert(
        PSBT_IN_WITNESS_UTXO,
        &[],
        bitcoin::consensus::serialize(&utxo),
    );
    assert_eq!(sign(&fx.psbt), Err(Error::SilentPaymentSegwitVersion));
}

/// A PSBT that already has the device's share and scripts, as after merging its response, gets
/// signed again; shares or scripts the device wouldn't compute are rejected.
#[test]
fn test_existing_shares_and_scripts() {
    let segwit = segwit_policy();
    let fx = simple_fixture(&segwit);
    let first = sign(&fx.psbt).unwrap();
    let Response::PsbtSigned {
        sp_shares,
        sp_output_scripts,
        ..
    } = first.clone()
    else {
        panic!("Expected PsbtSigned response");
    };
    let share = &sp_shares[0];
    let script = &sp_output_scripts[0];

    let mut merged = fx.psbt.clone();
    merged.global.insert(
        PSBT_GLOBAL_SP_ECDH_SHARE,
        &share.scan_key,
        share.share.to_vec(),
    );
    merged.global.insert(
        PSBT_GLOBAL_SP_DLEQ,
        &share.scan_key,
        share.dleq_proof.to_vec(),
    );
    merged.outputs[0].insert(PSBT_OUT_SCRIPT, &[], script.script.clone());
    let again = check(&fx, sign(&merged).unwrap());
    assert_eq!(again.shares[0], *share, "the verified proof is kept");

    // another share for the same scan key
    let mut psbt = merged.clone();
    psbt.global.insert(
        PSBT_GLOBAL_SP_ECDH_SHARE,
        &share.scan_key,
        code(1, 2).to_bytes()[..33].to_vec(),
    );
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentShareMismatch));

    // the device's share, with an invalid proof, or without one
    let mut psbt = merged.clone();
    let mut proof = share.dleq_proof;
    proof[40] ^= 1;
    psbt.global
        .insert(PSBT_GLOBAL_SP_DLEQ, &share.scan_key, proof.to_vec());
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentShareMismatch));
    psbt.global.remove(PSBT_GLOBAL_SP_DLEQ, &share.scan_key);
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentShareMismatch));

    // a proof for a scan key without outputs
    let mut psbt = fx.psbt.clone();
    let other_scan = code(31, 32).to_bytes()[..33].to_vec();
    psbt.global
        .insert(PSBT_GLOBAL_SP_DLEQ, &other_scan, share.dleq_proof.to_vec());
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentShareMismatch));

    // a share for a scan key without outputs
    let mut psbt = fx.psbt.clone();
    psbt.global
        .insert(PSBT_GLOBAL_SP_ECDH_SHARE, &other_scan, share.share.to_vec());
    psbt.global
        .insert(PSBT_GLOBAL_SP_DLEQ, &other_scan, share.dleq_proof.to_vec());
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentShareMismatch));

    // a share of the input
    let mut psbt = fx.psbt.clone();
    psbt.inputs[0].insert(PSBT_IN_SP_ECDH_SHARE, &share.scan_key, share.share.to_vec());
    psbt.inputs[0].insert(PSBT_IN_SP_DLEQ, &share.scan_key, share.dleq_proof.to_vec());
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentShareMismatch));

    // another script
    let mut psbt = fx.psbt.clone();
    let mut wrong = script.script.clone();
    wrong[10] ^= 1;
    psbt.outputs[0].insert(PSBT_OUT_SCRIPT, &[], wrong);
    assert_eq!(sign(&psbt), Err(Error::SilentPaymentOutputScriptMismatch));
}

/// Identity keys sign scripts, which don't apply to an output whose script the device computes,
/// and a wallet policy's coordinates give a script, never the output's code.
#[test]
fn test_unsupported_output_fields() {
    let segwit = segwit_policy();
    let fx = simple_fixture(&segwit);

    // a wallet policy's destinations are scripts, never codes
    let mut psbt = fx.psbt.clone();
    psbt.outputs[0]
        .set_account_coordinates(
            0,
            PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates::new(false, 5)),
        )
        .unwrap();
    assert_eq!(sign(&psbt), Err(Error::OutputScriptMismatch));

    let mut psbt = fx.psbt.clone();
    psbt.outputs[0]
        .add_auth_proof(&OutputAuthProof::IdentitySignature {
            pubkey: code(1, 2).to_bytes()[..33].try_into().unwrap(),
            sig: [1; 64],
        })
        .unwrap();
    assert_eq!(sign(&psbt), Err(Error::UnsupportedSilentPayment));
}

#[test]
fn test_invalid_code() {
    let segwit = segwit_policy();
    let mut fx = simple_fixture(&segwit);
    // no point of secp256k1 has x = 0
    let mut info = code(11, 12).to_bytes();
    info[34..].copy_from_slice(&[0; 32]);
    fx.psbt.outputs[0].insert(PSBT_OUT_SP_V0_INFO, &[], info.to_vec());
    assert_eq!(sign(&fx.psbt), Err(Error::InvalidSilentPayment));
}

/// The device's silent payment account `index`.
fn silent_payment_account(index: u32) -> SilentPaymentAccount {
    crate::sp_keys::account(index).unwrap()
}

/// Spending outputs that a silent payment account received (BIP-376), with an input of a wallet
/// policy: each signature is checked against the key of the output it spends.
#[test]
fn test_spend_from_silent_payment_account() {
    let segwit = segwit_policy();
    let account = silent_payment_account(0);
    let mut fx = fixture_with(
        &[Spend {
            policy: &segwit,
            index: 4,
            amount: 10_000,
            kind: Kind::SingleKey,
        }],
        &[
            SpSpend {
                account: &account,
                tweak: [0x11; 32],
                amount: 50_000,
            },
            SpSpend {
                account: &account,
                tweak: [0x22; 32],
                amount: 30_000,
            },
        ],
        &[Out::Script(
            ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20])),
            89_000,
        )],
    );

    // the review shows what each account spends
    let raw = fx.psbt.serialize();
    let parsed = fastpsbt::Psbt::parse(&raw).unwrap();
    let (summary, _) = analyze_transaction(&parsed).unwrap();
    assert_eq!(summary.account_spent_amounts, [10_000, 80_000]);

    let checked = check(&fx, sign(&fx.psbt).unwrap());
    assert_eq!(checked.signatures.len(), 3);

    // with SIGHASH_ALL
    fx.psbt.inputs[2].insert(PSBT_IN_SIGHASH_TYPE, &[], 1u32.to_le_bytes().to_vec());
    let checked = check(&fx, sign(&fx.psbt).unwrap());
    assert_eq!(checked.signatures[2].signature.len(), 65);
}

/// An input of a silent payment account spends an output by its tweak, which must be its
/// `PSBT_IN_SP_TWEAK`, and the account's script at that tweak must be the spent one.
#[test]
fn test_silent_payment_input_tweak() {
    let account = silent_payment_account(0);
    let fx = fixture_with(
        &[],
        &[SpSpend {
            account: &account,
            tweak: [0x11; 32],
            amount: 50_000,
        }],
        &[Out::Script(
            ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20])),
            49_000,
        )],
    );
    let coords = |coords| PsbtAccountCoordinates::SilentPayment(coords);

    let mut psbt = fx.psbt.clone();
    psbt.inputs[0].remove(PSBT_IN_SP_TWEAK, &[]);
    assert_eq!(sign(&psbt).err(), Some(Error::SilentPaymentTweakMismatch));
    psbt.inputs[0].insert(PSBT_IN_SP_TWEAK, &[], vec![0x12; 32]);
    assert_eq!(sign(&psbt).err(), Some(Error::SilentPaymentTweakMismatch));

    // both are another tweak
    psbt.inputs[0]
        .set_account_coordinates(0, coords(SilentPaymentCoordinates::Tweak([0x12; 32])))
        .unwrap();
    assert_eq!(sign(&psbt).err(), Some(Error::InputScriptMismatch));

    // an input doesn't spend a code
    let mut psbt = fx.psbt.clone();
    psbt.inputs[0]
        .set_account_coordinates(0, coords(SilentPaymentCoordinates::Code { label: None }))
        .unwrap();
    assert_eq!(sign(&psbt).err(), Some(Error::AccountCoordinatesMismatch));
}

/// Paying a silent payment code from a silent payment account and a wallet policy, with the change
/// to the account's change label: the change is the account's, its script is computed like the
/// other's, and scanning with the account's scan key finds it.
#[test]
fn test_silent_payment_change() {
    let segwit = segwit_policy();
    let account = silent_payment_account(1);
    let fx = fixture_with(
        &[Spend {
            policy: &segwit,
            index: 4,
            amount: 20_000,
            kind: Kind::SingleKey,
        }],
        &[SpSpend {
            account: &account,
            tweak: [0x33; 32],
            amount: 60_000,
        }],
        &[
            Out::Code(code(11, 12), 40_000),
            Out::SilentPaymentChange(&account, Some(0), 39_000),
        ],
    );

    // the review shows the payment, and the change in what the account spends
    let raw = fx.psbt.serialize();
    let parsed = fastpsbt::Psbt::parse(&raw).unwrap();
    let (summary, _) = analyze_transaction(&parsed).unwrap();
    assert_eq!(summary.account_spent_amounts, [20_000, 21_000]);
    assert_eq!(summary.external_outputs.len(), 1);
    assert_eq!(summary.external_outputs[0].output_index, 0);

    // one share for the recipient's scan key, one for the account's
    let checked = check(&fx, sign(&fx.psbt).unwrap());
    assert_eq!(checked.signatures.len(), 2);
    assert_eq!(checked.shares.len(), 2);

    let outpoints: Vec<OutPoint> = fx.tx.input.iter().map(|i| i.previous_output).collect();
    let outputs: Vec<[u8; 32]> = checked
        .tx
        .output
        .iter()
        .map(|o| o.script_pubkey.as_bytes()[2..].try_into().unwrap())
        .collect();
    let a_pub = &sdk::curve::Secp256k1::get_generator() * fx.a.as_ref().unwrap();
    let mut labels = sp::Labels::new();
    labels.insert(account.scan_key(), 0).unwrap();
    let found = sp::scan(
        account.scan_key(),
        account.spend_key(),
        &a_pub,
        &outpoints,
        &outputs,
        &labels,
    )
    .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].output_key, outputs[1]);
    // and the account can spend it
    assert_eq!(
        received_script(&account, found[0].tweak.as_be_bytes()),
        checked.tx.output[1].script_pubkey
    );
}

/// An output is the account's only if its code is the account's, at its coordinates; and an output
/// pays to a code, not to the tweak of an output that the account received.
#[test]
fn test_silent_payment_change_is_the_accounts() {
    let account = silent_payment_account(1);
    let fx = fixture_with(
        &[],
        &[SpSpend {
            account: &account,
            tweak: [0x33; 32],
            amount: 60_000,
        }],
        &[
            Out::Code(code(11, 12), 40_000),
            Out::SilentPaymentChange(&account, Some(0), 19_000),
        ],
    );
    assert!(sign(&fx.psbt).is_ok());

    // the code of another label
    let mut psbt = fx.psbt.clone();
    let other = account_code(&account, Some(1));
    psbt.outputs[1].insert(PSBT_OUT_SP_V0_INFO, &[], other.to_bytes().to_vec());
    assert_eq!(sign(&psbt).err(), Some(Error::OutputScriptMismatch));

    let mut psbt = fx.psbt.clone();
    psbt.outputs[1]
        .set_account_coordinates(
            0,
            PsbtAccountCoordinates::SilentPayment(SilentPaymentCoordinates::Tweak([0x33; 32])),
        )
        .unwrap();
    assert_eq!(sign(&psbt).err(), Some(Error::AccountCoordinatesMismatch));
}
