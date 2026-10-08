//! Conformance tests for the ECALLs' own contract.
//!
//! Every test makes raw ECALLs through the Sadik V-App, bypassing the SDK's wrappers, and checks
//! the exact status and output. The same expectations run against the native target
//! (`--features native-tests`) and against the VM on Speculos (`--features speculos-tests`), so
//! passing on both means that the two implementations agree. An ECALL must never kill the V-App
//! on invalid input: it returns 0.
#![cfg(any(feature = "speculos-tests", feature = "native-tests"))]

use common::{RawEcall, RawEcallResult};
use vnd_sadik_client::SadikClient;

mod setup;
use setup::setup;

/// Makes `call`, failing the test if the V-App does not survive it.
async fn ecall(client: &mut SadikClient, call: RawEcall) -> RawEcallResult {
    match client.raw_ecall(call.clone()).await {
        Ok(res) => res,
        Err(e) => panic!("the V-App did not survive {call:?}: {e}"),
    }
}

#[tokio::test]
async fn test_raw_ecall_harness() {
    let mut setup = setup().await;

    let res = ecall(
        &mut setup.client,
        RawEcall::BnModm {
            n: vec![0, 0, 0, 11],
            m: vec![0, 0, 0, 7],
        },
    )
    .await;
    assert_eq!(
        res,
        RawEcallResult {
            status: 1,
            output: vec![0, 0, 0, 4]
        }
    );
}

/// Makes `call` and checks its exact status and output. On failure, the ECALL must not have
/// written the output buffer, which the V-App zero-initializes.
async fn check(client: &mut SadikClient, call: RawEcall, status: u32, output: Vec<u8>) {
    let res = ecall(client, call.clone()).await;
    assert_eq!(res, RawEcallResult { status, output }, "for {call:?}");
}

/// `x` as a big-endian integer of `len` bytes.
fn be(x: u64, len: usize) -> Vec<u8> {
    let mut res = vec![0u8; len];
    let bytes = x.to_be_bytes();
    let n = len.min(8);
    res[len - n..].copy_from_slice(&bytes[8 - n..]);
    res
}

const SECP256K1_N: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

#[tokio::test]
async fn test_bn_modm() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let modm = |n: Vec<u8>, m: Vec<u8>| RawEcall::BnModm { n, m };

    check(c, modm(be(11, 1), be(7, 1)), 1, be(4, 1)).await;
    // lengths that are not a multiple of 16
    check(c, modm(be(100, 17), be(13, 17)), 1, be(9, 17)).await;
    check(c, modm(be(100, 17), be(13, 3)), 1, be(9, 17)).await;
    // the largest operand: (2^4096 - 1) mod 7 = 1
    check(c, modm(vec![0xff; 512], be(7, 1)), 1, be(1, 512)).await;

    // len_m > len
    check(c, modm(be(11, 2), be(7, 3)), 0, be(0, 2)).await;
    // zero modulus, also when empty
    check(c, modm(be(11, 4), be(0, 4)), 0, be(0, 4)).await;
    check(c, modm(vec![], vec![]), 0, vec![]).await;
    // too long
    check(c, modm(vec![1; 513], be(7, 1)), 0, be(0, 513)).await;
}

#[tokio::test]
async fn test_bn_addm_subm_multm() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let addm = |a: Vec<u8>, b: Vec<u8>, m: Vec<u8>| RawEcall::BnAddm { a, b, m };
    let subm = |a: Vec<u8>, b: Vec<u8>, m: Vec<u8>| RawEcall::BnSubm { a, b, m };
    let multm = |a: Vec<u8>, b: Vec<u8>, m: Vec<u8>| RawEcall::BnMultm { a, b, m };

    check(c, addm(be(3, 1), be(5, 1), be(7, 1)), 1, be(1, 1)).await;
    check(c, subm(be(3, 1), be(5, 1), be(7, 1)), 1, be(5, 1)).await;
    check(c, multm(be(3, 1), be(5, 1), be(7, 1)), 1, be(1, 1)).await;

    // addition and subtraction accept an even modulus; multiplication does not
    check(c, addm(be(5, 4), be(5, 4), be(8, 4)), 1, be(2, 4)).await;
    check(c, subm(be(1, 4), be(2, 4), be(4, 4)), 1, be(3, 4)).await;
    check(c, multm(be(3, 4), be(5, 4), be(8, 4)), 0, be(0, 4)).await;

    // modulus 1: every operand is 0, and so is the result
    check(c, addm(be(0, 2), be(0, 2), be(1, 2)), 1, be(0, 2)).await;
    check(c, subm(be(0, 2), be(0, 2), be(1, 2)), 1, be(0, 2)).await;
    check(c, multm(be(0, 2), be(0, 2), be(1, 2)), 1, be(0, 2)).await;

    // 33-byte operands: 2^256 * 2 mod (2^257 - 1) = 1
    let mut two_256 = vec![0u8; 33];
    two_256[0] = 1;
    let mut m = vec![0xffu8; 33];
    m[0] = 1;
    check(c, multm(two_256, be(2, 33), m), 1, be(1, 33)).await;

    for op in [addm, subm, multm] {
        // operands must be smaller than the modulus
        check(c, op(be(7, 1), be(1, 1), be(7, 1)), 0, be(0, 1)).await;
        check(c, op(be(1, 1), be(9, 1), be(7, 1)), 0, be(0, 1)).await;
        // zero modulus
        check(c, op(be(0, 4), be(0, 4), be(0, 4)), 0, be(0, 4)).await;
        check(c, op(vec![], vec![], vec![]), 0, vec![]).await;
        // too long
        check(c, op(be(1, 513), be(1, 513), be(7, 513)), 0, be(0, 513)).await;
    }
}

#[tokio::test]
async fn test_bn_powm() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let powm = |a: Vec<u8>, e: Vec<u8>, m: Vec<u8>| RawEcall::BnPowm { a, e, m };

    check(c, powm(be(3, 1), be(4, 1), be(7, 1)), 1, be(4, 1)).await;
    // 2^(2^512 - 1) mod 7 = 1
    check(c, powm(be(2, 3), vec![0xff; 64], be(7, 3)), 1, be(1, 3)).await;
    // a^0 = 1, whether the exponent is empty or zero
    check(c, powm(be(3, 1), vec![], be(7, 1)), 1, be(1, 1)).await;
    check(c, powm(be(3, 1), be(0, 2), be(7, 1)), 1, be(1, 1)).await;
    check(c, powm(be(0, 1), be(0, 1), be(7, 1)), 1, be(1, 1)).await;
    check(c, powm(be(0, 1), be(5, 1), be(7, 1)), 1, be(0, 1)).await;
    // modulus 1
    check(c, powm(be(0, 1), be(5, 1), be(1, 1)), 1, be(0, 1)).await;
    check(c, powm(be(0, 1), vec![], be(1, 1)), 1, be(0, 1)).await;

    // even or zero modulus
    check(c, powm(be(3, 1), be(2, 1), be(8, 1)), 0, be(0, 1)).await;
    check(c, powm(be(0, 1), be(2, 1), be(0, 1)), 0, be(0, 1)).await;
    // base not smaller than the modulus
    check(c, powm(be(7, 1), be(2, 1), be(7, 1)), 0, be(0, 1)).await;
    // too long
    check(c, powm(be(3, 1), vec![1; 513], be(7, 1)), 0, be(0, 1)).await;
    check(c, powm(be(3, 513), be(1, 1), be(7, 513)), 0, be(0, 513)).await;
}

#[tokio::test]
async fn test_bn_modinv_prime() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let modinv = |a: Vec<u8>, p: Vec<u8>| RawEcall::BnModinvPrime { a, p };

    check(c, modinv(be(3, 1), be(7, 1)), 1, be(5, 1)).await;
    check(
        c,
        modinv(be(2, 32), SECP256K1_N.to_vec()),
        1,
        hex_literal::hex!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1").to_vec(),
    )
    .await;

    // zero has no inverse
    check(c, modinv(be(0, 1), be(7, 1)), 0, be(0, 1)).await;
    // a must be smaller than p
    check(c, modinv(be(7, 1), be(7, 1)), 0, be(0, 1)).await;
    check(c, modinv(be(8, 1), be(7, 1)), 0, be(0, 1)).await;
    // even or zero modulus
    check(c, modinv(be(1, 1), be(2, 1)), 0, be(0, 1)).await;
    check(c, modinv(be(1, 1), be(0, 1)), 0, be(0, 1)).await;
    check(c, modinv(vec![], vec![]), 0, vec![]).await;
    // too long
    check(c, modinv(be(1, 513), be(7, 513)), 0, be(0, 513)).await;
}
