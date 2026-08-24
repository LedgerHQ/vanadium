//! Sighash computation and taproot-tree helpers shared by the plain-key and MuSig2
//! signing paths. Deliberately kept free of any signing/key-resolution logic so both
//! [`super::signing`] and [`super::musig`] can depend on it without depending on each
//! other.

use alloc::vec::Vec;

use bitcoin::{
    hashes::Hash, sighash::SighashCache, TapLeafHash, TapSighashType, Transaction, TxOut,
};
use common::{
    bip388::DescriptorTemplate,
    errors::Error,
    fastpsbt,
    taproot::{GetTapLeafHash, GetTapTreeHash},
};

/// Computes a 32-byte BIP-341 sighash for the given input. The output goes to
/// either `schnorr_sign` (plain key path) or `musig::sign` (musig path).
pub(super) fn compute_taproot_sighash(
    input_index: usize,
    sighash_cache: &mut SighashCache<&Transaction>,
    prevouts: &[TxOut],
    leaf_hash: Option<TapLeafHash>,
) -> Result<[u8; 32], Error> {
    let sighash_type = TapSighashType::Default;
    let sighash = if let Some(leaf_hash) = leaf_hash {
        sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(prevouts),
                leaf_hash,
                sighash_type,
            )
            .map_err(|_| Error::ErrorComputingSighash)?
    } else {
        sighash_cache
            .taproot_key_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(prevouts),
                sighash_type,
            )
            .map_err(|_| Error::ErrorComputingSighash)?
    };
    Ok(sighash.to_byte_array())
}

fn input_prevout(input: &fastpsbt::Input<'_>) -> Result<TxOut, Error> {
    if let Some(witness_utxo) = input
        .get_witness_utxo()
        .map_err(|_| Error::InvalidWitnessUtxo)?
    {
        return Ok(witness_utxo.clone());
    }

    let non_witness_utxo = input
        .get_non_witness_utxo()
        .map_err(|_| Error::InvalidNonWitnessUtxo)?
        .ok_or(Error::MissingInputUtxo)?;
    let output_index = input
        .output_index
        .ok_or(Error::MissingPreviousOutputIndex)? as usize;
    non_witness_utxo
        .output
        .get(output_index)
        .cloned()
        .ok_or(Error::InvalidNonWitnessUtxo)
}

/// Lazily materializes the prevouts list shared by all taproot sighashes in
/// input order. SegWit inputs use their witness UTXO; legacy inputs fall back to
/// the referenced output in their non-witness UTXO.
pub(super) fn ensure_prevouts<'a>(
    cache: &'a mut Option<Vec<TxOut>>,
    psbt: &fastpsbt::Psbt,
) -> Result<&'a [TxOut], Error> {
    if cache.is_none() {
        *cache = Some(
            psbt.inputs
                .iter()
                .map(input_prevout)
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    cache.as_deref().ok_or(Error::MissingInputUtxo)
}

/// Computes the merkle root of a `tr(...)` wallet policy's script tree at the
/// given coordinates, or `None` for BIP-86 / BIP-386 style policies (no tree).
pub(super) fn taptree_hash_for(
    wallet_policy: &common::bip388::WalletPolicy,
    coords: &common::message::WalletPolicyCoordinates,
) -> Result<Option<[u8; 32]>, Error> {
    match wallet_policy.descriptor_template() {
        DescriptorTemplate::Tr(_, tree) => tree
            .as_ref()
            .map(|t| {
                t.get_taptree_hash(
                    wallet_policy.key_information(),
                    coords.is_change,
                    coords.address_index,
                )
            })
            .transpose()
            .map_err(|_| Error::InvalidWalletPolicy),
        _ => Err(Error::UnexpectedTaprootPolicy),
    }
}

/// Computes the tapleaf hash for a script-path placeholder, or `None` for
/// keypath / non-taproot placeholders.
pub(super) fn leaf_hash_for(
    tapleaf_desc: Option<&DescriptorTemplate>,
    wallet_policy: &common::bip388::WalletPolicy,
    coords: &common::message::WalletPolicyCoordinates,
) -> Result<Option<TapLeafHash>, Error> {
    tapleaf_desc
        .map(|desc| {
            desc.get_tapleaf_hash(
                wallet_policy.key_information(),
                coords.is_change,
                coords.address_index,
            )
        })
        .transpose()
        .map_err(|_| Error::InvalidWalletPolicy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use bitcoin::ScriptBuf;

    // rust-bitcoin doesn't support Psbtv2, so we use this helper for conversion
    fn serialize_as_psbtv2(psbt: &bitcoin::psbt::Psbt) -> Vec<u8> {
        common::psbt::psbt_v0_to_v2(&psbt.serialize()).expect("Failed to convert PSBTv0 to PSBTv2")
    }

    #[test]
    fn ensure_prevouts_supports_mixed_utxo_types() {
        let witness_prevout = TxOut {
            value: bitcoin::Amount::from_sat(60_000),
            script_pubkey: ScriptBuf::new(),
        };
        let legacy_prevout = TxOut {
            value: bitcoin::Amount::from_sat(70_000),
            script_pubkey: ScriptBuf::new(),
        };
        let legacy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![legacy_prevout.clone()],
        };
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0x42; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: legacy_tx.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![],
        };
        let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(witness_prevout.clone());
        psbt.inputs[1].non_witness_utxo = Some(legacy_tx);

        let serialized = serialize_as_psbtv2(&psbt);
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        let mut cache = None;
        assert_eq!(
            ensure_prevouts(&mut cache, &parsed).unwrap(),
            &[witness_prevout, legacy_prevout]
        );
    }
}
