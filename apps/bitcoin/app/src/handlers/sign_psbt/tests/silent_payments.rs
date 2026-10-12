//! Silent payments, which the signer doesn't support yet.

use bitcoin::psbt::raw;
use common::errors::Error;
use hex_literal::hex;

use super::super::handle_sign_psbt;
use super::super::test_utils::{segwit_wpkh_psbt, serialize_as_psbtv2};

#[test]
fn test_handle_sign_psbt_rejects_silent_payment_outputs() {
    // the output keeps its script, which the device would have to check against the code
    const G: [u8; 33] = hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let mut psbt = segwit_wpkh_psbt();
    let sp_v0_info = raw::Key {
        type_value: 0x09,
        key: vec![],
    };
    psbt.outputs[0].unknown.insert(sp_v0_info, [G, G].concat());

    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ));
    assert_eq!(result, Err(Error::UnsupportedSilentPayment));
}
