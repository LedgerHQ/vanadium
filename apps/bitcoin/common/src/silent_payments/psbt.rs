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
/// As BIP-375 requires, `k` counts the outputs to each scan key in the order of their codes, sorted
/// lexicographically, with ties broken by output index.
pub fn recipients(psbt: &Psbt) -> Result<Vec<Recipient>, Error> {
    let mut sorted: Vec<(&[u8; 66], usize)> = psbt
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(output_index, output)| output.sp_v0_info.map(|info| (info, output_index)))
        .collect();
    sorted.sort_unstable();
    let codes = sorted
        .iter()
        .map(|(info, _)| SilentPaymentCode::from_bytes(info))
        .collect::<Result<Vec<_>, _>>()?;
    let ks = assign_k(&codes)?;
    let mut recipients: Vec<Recipient> = sorted
        .into_iter()
        .zip(codes)
        .zip(ks)
        .map(|(((_, output_index), code), k)| Recipient {
            output_index,
            code,
            k,
        })
        .collect();
    recipients.sort_unstable_by_key(|recipient| recipient.output_index);
    Ok(recipients)
}
