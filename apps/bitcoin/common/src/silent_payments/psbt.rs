//! The silent payment outputs of a PSBT (BIP-375).

use alloc::vec::Vec;

use crate::fastpsbt::Psbt;

use super::{assign_k, Error, SilentPaymentCode};

/// An output of a PSBT that pays to a silent payment code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// The index of the output.
    pub output_index: usize,
    /// The code in the output's `PSBT_OUT_SP_V0_INFO`.
    pub code: SilentPaymentCode,
    /// The `k` of the output among the outputs to the same scan key.
    pub k: u32,
}

/// The outputs of `psbt` that pay to a silent payment code, in output order, with their `k`.
///
/// `k` counts the outputs to each scan key in output order, as the reference validator and the
/// test vectors of BIP-375 v0.1.2 (bips@927b6de9) do. The text of BIP-375 asks instead to sort the
/// codes of each scan key lexicographically, with ties broken by output index, but its own valid
/// vector "two sp outputs - output 0 uses label=3 / output 1 uses label=1" only passes in output
/// order. Should BIP-375 settle on its text, sort `codes` here before assigning `k`.
pub fn recipients(psbt: &Psbt) -> Result<Vec<Recipient>, Error> {
    let mut output_indices = Vec::new();
    let mut codes = Vec::new();
    for (output_index, output) in psbt.outputs.iter().enumerate() {
        if let Some(info) = output.sp_v0_info {
            output_indices.push(output_index);
            codes.push(SilentPaymentCode::from_bytes(info)?);
        }
    }
    let ks = assign_k(&codes)?;
    Ok(output_indices
        .into_iter()
        .zip(codes)
        .zip(ks)
        .map(|((output_index, code), k)| Recipient {
            output_index,
            code,
            k,
        })
        .collect())
}
