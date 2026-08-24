//! Sighash computation and taproot-tree helpers shared by the plain-key and MuSig2
//! signing paths. Deliberately kept free of any signing/key-resolution logic so both
//! [`super::signing`] and [`super::musig`] can depend on it without depending on each
//! other.

use bitcoin::{
    hashes::Hash, sighash::SighashCache, TapLeafHash, TapSighashType, Transaction, TxOut,
};
use common::{
    bip388::DescriptorTemplate,
    errors::Error,
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

/// Whether the policy is `tr(...)` at all. Only looks at the descriptor's kind, so
/// unlike [`taptree_hash_for`] it costs nothing.
pub(super) fn is_taproot_policy(wallet_policy: &common::bip388::WalletPolicy) -> bool {
    matches!(
        wallet_policy.descriptor_template(),
        DescriptorTemplate::Tr(..)
    )
}

/// Computes the merkle root of a `tr(...)` wallet policy's script tree at the
/// given coordinates, or `None` for BIP-86 / BIP-386 style policies (no tree).
///
/// This walks the entire tree, deriving every leaf's keys — measured at ~18s on a
/// Ledger Flex for a three-leaf tree. Reach it through
/// [`super::context::PlaceholderCtx::taptree_hash`], which computes it at most once per
/// input and only when something actually reads the result.
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
