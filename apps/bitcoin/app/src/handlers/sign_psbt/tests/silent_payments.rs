//! Silent payments, which the signer doesn't support yet.

use common::{errors::Error, fastpsbt::PSBT_OUT_SP_V0_INFO};
use hex_literal::hex;

use super::super::handle_sign_psbt;
use super::super::test_utils::segwit_wpkh_psbt;

#[test]
fn test_handle_sign_psbt_rejects_silent_payment_outputs() {
    // the output keeps its script, which the device would have to check against the code
    const G: [u8; 33] = hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let mut psbt = segwit_wpkh_psbt();
    psbt.outputs[0].insert(PSBT_OUT_SP_V0_INFO, &[], [G, G].concat());

    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &psbt.serialize(),
    ));
    assert_eq!(result, Err(Error::UnsupportedSilentPayment));
}
