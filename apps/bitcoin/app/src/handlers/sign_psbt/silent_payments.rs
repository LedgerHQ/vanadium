//! Paying to silent payment codes (BIP-352), as BIP-375 asks of a PSBT signer.
//!
//! An output with `PSBT_OUT_SP_V0_INFO` pays to a silent payment code, and its script depends on
//! the whole transaction: on the sum `a` of the private keys of the inputs that BIP-352 calls
//! *eligible*, on the smallest outpoint that the transaction spends, and on the rank `k` of the
//! output among the outputs to the same scan key. So the outputs aren't final when the user
//! reviews the transaction, and signing gets a stage of its own:
//!
//! - [`analyze`] runs before the review, and checks everything that doesn't need a private key, so
//!   that the user isn't asked to approve a transaction that can't be signed.
//! - [`finalize`] runs after the approval and the deferred checks: it computes `a`, then for each
//!   scan key the ECDH share `a·B_scan` with its DLEQ proof, and the scripts of the outputs, which
//!   it sets in the PSBT before anything gets signed.
//!
//! The device must hold the private key of every eligible input, and computes one global share
//! per scan key. BIP-375 also lets each signer contribute shares for its own inputs, which would
//! support inputs of a key that is only partly ours, like a `musig()` internal key: that would need
//! a second round and verifying the others' DLEQ proofs, and isn't supported.
//!
//! The outputs to silent payment codes are always external for now: the device shows the
//! address of the code.

use alloc::vec::Vec;

use bitcoin::{hashes::Hash, OutPoint, ScriptBuf, Txid};
use common::{
    bip388::{DescriptorTemplate, KeyExpression, WalletPolicy},
    errors::Error,
    fastpsbt,
    message::{SilentPaymentOutputScript, SilentPaymentShare, WalletPolicyCoordinates},
    silent_payments::{self as sp, Recipient},
};
use sdk::curve::{Secp256k1, Secp256k1Point, Secp256k1Scalar};

use super::analyze::{input_prevout, TransactionSummary};
use super::context::TaptreeHashes;
use super::key_resolution::{resolve_private_key, KeySource, LocalKeys};
use super::signing::taproot_output_private_key;

/// An eligible input, with the key that BIP-352 takes from it.
struct EligibleInput {
    input_index: usize,
    /// The input's key, or for a taproot input its internal key.
    key_source: KeySource,
    is_taproot: bool,
}

/// What [`analyze`] found out about the outputs to silent payment codes of a PSBT.
pub(super) struct SilentPayments {
    /// The outputs to silent payment codes, in output order.
    outputs: Vec<Recipient>,
    eligible_inputs: Vec<EligibleInput>,
}

/// The key that BIP-352 takes from an input of `wallet_policy`, and whether the input is taproot;
/// `None` if the input isn't eligible.
///
/// Inputs of `pkh()`, `wpkh()` and `sh(wpkh())` are eligible with their key, and inputs of `tr()`
/// with their output key, whatever path spends them; the others, like `wsh()`, aren't. That is
/// decided from the account, whose script the deferred checks prove to be the spent one before
/// [`finalize`] runs. The only `tr()` inputs that BIP-352 excludes are those whose internal key is
/// exactly the NUMS point H, which a key of a wallet policy can't be: it is always derived.
fn eligible_key(wallet_policy: &WalletPolicy) -> Option<(&KeyExpression, bool)> {
    match wallet_policy.descriptor_template() {
        DescriptorTemplate::Pkh(kp) | DescriptorTemplate::Wpkh(kp) => Some((kp, false)),
        DescriptorTemplate::Sh(inner) => match inner.as_ref() {
            DescriptorTemplate::Wpkh(kp) => Some((kp, false)),
            _ => None,
        },
        DescriptorTemplate::Tr(kp, _) => Some((kp, true)),
        _ => None,
    }
}

/// Checks a PSBT with outputs to silent payment codes before the review, and returns `None` if it
/// has none.
///
/// It fails if an input spends a segwit version above 1 or asks for another sighash type than
/// `SIGHASH_ALL`, taproot inputs included, as BIP-375 requires; if no input is eligible; if the
/// device doesn't hold the key of an eligible input, like a `musig()` or a cosigner's internal key;
/// or if the PSBT has ECDH shares or DLEQ proofs the device wouldn't compute: per-input ones, or
/// global ones for another scan key (those for a scan key of the outputs are checked by
/// [`finalize`]).
pub(super) fn analyze(
    psbt: &fastpsbt::Psbt,
    summary: &TransactionSummary,
    local_keys: &mut LocalKeys,
) -> Result<Option<SilentPayments>, Error> {
    let outputs = sp::recipients(psbt).map_err(|_| Error::InvalidSilentPayment)?;
    if outputs.is_empty() {
        return Ok(None);
    }

    let mut eligible_inputs = Vec::new();
    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let prevout = input_prevout(input)?;
        if prevout
            .script_pubkey
            .witness_version()
            .is_some_and(|version| version.to_num() > 1)
        {
            return Err(Error::SilentPaymentSegwitVersion);
        }
        // BIP-375 allows SIGHASH_ALL only, unlike the analysis, which also lets a taproot input ask
        // for SIGHASH_DEFAULT. Without a sighash type, the device signs with SIGHASH_ALL
        // (SIGHASH_DEFAULT for taproot)
        if input
            .sighash_type
            .is_some_and(|sighash_type| sighash_type != 0x01)
        {
            return Err(Error::SilentPaymentSighashType);
        }
        if input.sp_ecdh_shares().next().is_some() || input.sp_dleq_proofs().next().is_some() {
            return Err(Error::SilentPaymentShareMismatch);
        }

        let (account_id, wallet_policy, coords) = summary.input_account(input_index);
        let Some((kp, is_taproot)) = eligible_key(wallet_policy) else {
            continue;
        };
        let key_index = kp
            .plain_key_index()
            .ok_or(Error::SilentPaymentInputNotHeld)?;
        let change_step = if coords.is_change { kp.num2 } else { kp.num1 };
        let key_source = local_keys
            .resolve(
                &wallet_policy.key_information()[key_index as usize],
                (account_id, key_index),
                Some((change_step.into(), coords.address_index.into())),
            )
            .ok_or(Error::SilentPaymentInputNotHeld)?;
        eligible_inputs.push(EligibleInput {
            input_index,
            key_source,
            is_taproot,
        });
    }
    if eligible_inputs.is_empty() {
        return Err(Error::SilentPaymentNoEligibleInputs);
    }

    let shares = psbt.sp_ecdh_shares().map(|(scan_key, _)| scan_key);
    let proofs = psbt.sp_dleq_proofs().map(|(scan_key, _)| scan_key);
    for scan_key in shares.chain(proofs) {
        if !outputs
            .iter()
            .any(|output| output.code.to_bytes()[..33] == scan_key[..])
        {
            return Err(Error::SilentPaymentShareMismatch);
        }
    }

    Ok(Some(SilentPayments {
        outputs,
        eligible_inputs,
    }))
}

/// The private key of an eligible input, as it enters the sum `a`.
fn input_private_key(
    input: &EligibleInput,
    wallet_policy: &WalletPolicy,
    coords: &WalletPolicyCoordinates,
    taptree_hashes: &TaptreeHashes,
) -> Result<Secp256k1Scalar, Error> {
    let hd_node = resolve_private_key(&input.key_source)?;
    let key = if input.is_taproot {
        let taptree_hash = taptree_hashes.get(input.input_index, wallet_policy, coords)?;
        taproot_output_private_key(&hd_node.privkey, taptree_hash)?
    } else {
        hd_node.privkey.clone()
    };
    let key = Secp256k1Scalar::from_be_bytes(&key).ok_or(Error::InvalidKey)?;
    Ok(sp::input_private_key(&key, input.is_taproot))
}

/// The sum `a` of the private keys of the eligible inputs.
fn sum_input_keys(
    summary: &TransactionSummary,
    silent_payments: &SilentPayments,
    taptree_hashes: &TaptreeHashes,
) -> Result<Secp256k1Scalar, Error> {
    let mut a = Secp256k1Scalar::zero();
    for input in &silent_payments.eligible_inputs {
        let (_, wallet_policy, coords) = summary.input_account(input.input_index);
        a = &a + &input_private_key(input, wallet_policy, coords, taptree_hashes)?;
    }
    if a.is_zero() {
        return Err(Error::InvalidSilentPayment);
    }
    Ok(a)
}

/// The outpoints that the transaction spends.
fn outpoints(psbt: &fastpsbt::Psbt) -> Result<Vec<OutPoint>, Error> {
    psbt.inputs
        .iter()
        .map(|input| {
            Ok(OutPoint {
                txid: Txid::from_byte_array(*input.previous_txid.ok_or(Error::InvalidParameter)?),
                vout: input.output_index.ok_or(Error::InvalidParameter)?,
            })
        })
        .collect()
}

/// The global ECDH share of a scan key.
struct Share {
    scan: Secp256k1Point,
    /// `a·B_scan`.
    share: Secp256k1Point,
    response: SilentPaymentShare,
}

/// The global ECDH share of each scan key of the outputs, in the order of the outputs, with its
/// DLEQ proof, from the sum `a` of the private keys of the eligible inputs and `a_pub = a·G`.
///
/// A share that the PSBT already has must be the device's, and come with a valid DLEQ proof, which
/// the response then keeps.
fn ecdh_shares(
    psbt: &fastpsbt::Psbt,
    outputs: &[Recipient],
    a: &Secp256k1Scalar,
    a_pub: &Secp256k1Point,
) -> Result<Vec<Share>, Error> {
    let g = Secp256k1::get_generator();
    let mut shares: Vec<Share> = Vec::new();
    for output in outputs {
        let scan = output.code.scan();
        if shares.iter().any(|share| share.scan == *scan) {
            continue;
        }
        let scan_key = output.code.to_bytes()[..33].try_into().unwrap();
        let share = sp::ecdh_share(a, scan);
        let share_bytes = share.to_compressed().ok_or(Error::InvalidSilentPayment)?;
        let dleq_proof = match (
            psbt.get_sp_ecdh_share(&scan_key),
            psbt.get_sp_dleq_proof(&scan_key),
        ) {
            (None, None) => {
                let aux: [u8; 32] = sdk::rand::random_bytes(32).try_into().unwrap();
                sp::generate_proof(a, scan, &aux, &g, None)
                    .map_err(|_| Error::InvalidSilentPayment)?
            }
            // BIP-375: a signer verifies the global DLEQ proof it is given
            (Some(existing), Some(proof))
                if *existing == share_bytes
                    && sp::verify_proof(a_pub, scan, &share, proof, &g, None) =>
            {
                *proof
            }
            _ => return Err(Error::SilentPaymentShareMismatch),
        };
        shares.push(Share {
            scan: *scan,
            share,
            response: SilentPaymentShare {
                scan_key,
                share: share_bytes,
                dleq_proof,
            },
        });
    }
    Ok(shares)
}

/// The script of each output to a silent payment code, in output order, from the shares of their
/// scan keys. Fails if the PSBT already has a different script.
fn output_scripts(
    psbt: &fastpsbt::Psbt,
    outputs: &[Recipient],
    input_hash: &Secp256k1Scalar,
    shares: &[Share],
) -> Result<Vec<SilentPaymentOutputScript>, Error> {
    let secrets = shares
        .iter()
        .map(|share| {
            let secret = sp::shared_secret(input_hash, &share.share)
                .map_err(|_| Error::InvalidSilentPayment)?;
            Ok((share.scan, secret))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let mut scripts = Vec::new();
    for recipient in outputs {
        let (_, secret) = secrets
            .iter()
            .find(|(scan, _)| scan == recipient.code.scan())
            .expect("every scan key has a share");
        let output_key = sp::output_key(secret, recipient.code.spend(), recipient.k)
            .map_err(|_| Error::InvalidSilentPayment)?;
        // the taproot output whose x-only key is the output key: OP_1 <x>
        let script = [&[0x51, 0x20][..], output_key.x()].concat();
        if psbt.outputs[recipient.output_index]
            .script
            .is_some_and(|existing| existing != script)
        {
            return Err(Error::SilentPaymentOutputScriptMismatch);
        }
        scripts.push(SilentPaymentOutputScript {
            output_index: recipient.output_index as u32,
            script,
        });
    }
    Ok(scripts)
}

/// The ECDH shares and the output scripts that [`finalize`] computed.
#[derive(Default)]
pub(super) struct Finalized {
    pub(super) shares: Vec<SilentPaymentShare>,
    pub(super) output_scripts: Vec<SilentPaymentOutputScript>,
}

/// Computes the ECDH share of each scan key with its DLEQ proof, and the script of each output to
/// a silent payment code, then sets the scripts that the PSBT doesn't have yet in `psbt`. Fails if
/// the PSBT already has a different global share, a global share without a valid DLEQ proof, or a
/// different script.
///
/// Runs after the deferred checks, which prove that the inputs belong to their accounts.
pub(super) fn finalize(
    psbt: &mut fastpsbt::Psbt,
    summary: &TransactionSummary,
    silent_payments: &SilentPayments,
    taptree_hashes: &TaptreeHashes,
) -> Result<Finalized, Error> {
    let a = sum_input_keys(summary, silent_payments, taptree_hashes)?;
    let a_pub = &Secp256k1::get_generator() * &a;
    let input_hash =
        sp::input_hash(&outpoints(psbt)?, &a_pub).map_err(|_| Error::InvalidSilentPayment)?;

    let shares = ecdh_shares(psbt, &silent_payments.outputs, &a, &a_pub)?;
    let output_scripts = output_scripts(psbt, &silent_payments.outputs, &input_hash, &shares)?;

    let new_scripts: Vec<(usize, ScriptBuf)> = output_scripts
        .iter()
        .map(|script| (script.output_index as usize, &script.script))
        .filter(|(output_index, _)| psbt.outputs[*output_index].script.is_none())
        .map(|(output_index, script)| (output_index, ScriptBuf::from_bytes(script.clone())))
        .collect();
    if !new_scripts.is_empty() {
        psbt.set_sp_output_scripts(new_scripts)
            .map_err(|_| Error::InvalidSilentPayment)?;
    }

    Ok(Finalized {
        shares: shares.into_iter().map(|share| share.response).collect(),
        output_scripts,
    })
}
