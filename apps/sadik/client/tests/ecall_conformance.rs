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

/// The digest of `msg` for the composite hash identifier, computed on the host.
fn host_digest(hash_id: u32, msg: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    fn d<H: Digest>(msg: &[u8]) -> Vec<u8> {
        H::digest(msg).to_vec()
    }
    match (hash_id >> 16, hash_id & 0xffff) {
        (1, 20) => d::<ripemd::Ripemd160>(msg),
        (3, 32) => d::<sha2::Sha256>(msg),
        (4, 48) => d::<sha2::Sha384>(msg),
        (5, 64) => d::<sha2::Sha512>(msg),
        (6, 28) => d::<sha3::Keccak224>(msg),
        (6, 32) => d::<sha3::Keccak256>(msg),
        (6, 48) => d::<sha3::Keccak384>(msg),
        (6, 64) => d::<sha3::Keccak512>(msg),
        (7, 28) => d::<sha3::Sha3_224>(msg),
        (7, 32) => d::<sha3::Sha3_256>(msg),
        (7, 48) => d::<sha3::Sha3_384>(msg),
        (7, 64) => d::<sha3::Sha3_512>(msg),
        _ => unreachable!(),
    }
}

/// Every supported (algorithm, output size) pair, as composite hash identifiers.
const HASH_IDS: [u32; 12] = [
    1 << 16 | 20,
    3 << 16 | 32,
    4 << 16 | 48,
    5 << 16 | 64,
    6 << 16 | 28,
    6 << 16 | 32,
    6 << 16 | 48,
    6 << 16 | 64,
    7 << 16 | 28,
    7 << 16 | 32,
    7 << 16 | 48,
    7 << 16 | 64,
];

/// What a successful `RawEcall::Hash` returns: the digest, in a zero-padded 64-byte buffer.
fn hash_result(hash_id: u32, msg: &[u8]) -> Vec<u8> {
    let mut out = host_digest(hash_id, msg);
    out.resize(64, 0);
    out
}

#[tokio::test]
async fn test_hash() {
    let mut setup = setup().await;
    let c = &mut setup.client;

    let msg: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
    // Cuts the message so that the updates end before, at and after the block boundaries of every
    // algorithm (64 and 128 bytes, and the SHA-3 rates 72, 104, 136 and 144), with an empty update.
    let cuts = [0, 1, 64, 64, 71, 72, 105, 136, 137, 144, 200, 256, 300];
    let chunks: Vec<Vec<u8>> = cuts.windows(2).map(|w| msg[w[0]..w[1]].to_vec()).collect();

    for hash_id in HASH_IDS {
        // the empty message
        let call = RawEcall::Hash { hash_id, chunks: vec![], tamper: None };
        check(c, call, 1, hash_result(hash_id, &[])).await;

        // the message in one update, and split in many
        let call = RawEcall::Hash { hash_id, chunks: vec![msg.clone()], tamper: None };
        check(c, call, 1, hash_result(hash_id, &msg)).await;
        let call = RawEcall::Hash { hash_id, chunks: chunks.clone(), tamper: None };
        check(c, call, 1, hash_result(hash_id, &msg)).await;
    }

    // unsupported identifiers fail at initialization
    for hash_id in [
        0,
        2 << 16 | 32,       // not an algorithm
        8 << 16 | 32,       // not an algorithm
        3 << 16 | 64,       // SHA-256 with the wrong size
        5 << 16 | 65,       // SHA-512 with a size above the largest digest
        6 << 16 | 20,       // Keccak with an unsupported size
        7 << 16,            // SHA-3 with an empty output
        1 << 24 | 3 << 16 | 32, // reserved bits set
    ] {
        let call = RawEcall::Hash { hash_id, chunks: vec![msg.clone()], tamper: None };
        check(c, call, 0, vec![]).await;
    }
}

/// The VM must never trust the hash context that the V-App holds between ECALLs. Only the VM's
/// context layout is known, so this runs on Speculos only.
#[cfg(feature = "speculos-tests")]
#[tokio::test]
async fn test_hash_tampered_context() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let msg = b"The quick brown fox jumps over the lazy dog".to_vec();
    let sha256 = 3 << 16 | 32;
    let sha3_256 = 7 << 16 | 32;

    // The `info` function pointer, at offset 0, is ignored: the digest is still right.
    for offset in 0..4 {
        let call = RawEcall::Hash {
            hash_id: sha256,
            chunks: vec![msg.clone()],
            tamper: Some((offset, 0x41)),
        };
        check(c, call, 1, hash_result(sha256, &msg)).await;
    }
    // SHA-3's output size and block size (offsets 8 and 12) are not taken from the context either.
    for offset in [8, 12] {
        let call = RawEcall::Hash {
            hash_id: sha3_256,
            chunks: vec![msg.clone()],
            tamper: Some((offset, 0xff)),
        };
        check(c, call, 1, hash_result(sha3_256, &msg)).await;
    }

    // A buffered length (`blen`, at offset 8 for SHA-256 and 16 for SHA-3) beyond the block is
    // rejected rather than used to index the block.
    let call = RawEcall::Hash { hash_id: sha256, chunks: vec![msg.clone()], tamper: Some((8, 64)) };
    check(c, call, 0, vec![]).await;
    let call = RawEcall::Hash { hash_id: sha3_256, chunks: vec![msg.clone()], tamper: Some((17, 1)) };
    check(c, call, 0, vec![]).await;
}

#[tokio::test]
async fn test_get_random_bytes() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let rng = |size: u32| RawEcall::GetRandomBytes { size };

    check(c, rng(0), 1, vec![]).await;
    for size in [1, 32, 256] {
        let first = ecall(c, rng(size)).await;
        let second = ecall(c, rng(size)).await;
        assert_eq!((first.status, first.output.len()), (1, size as usize));
        assert_eq!((second.status, second.output.len()), (1, size as usize));
        if size >= 32 {
            assert_ne!(first.output, second.output);
        }
    }

    check(c, rng(257), 0, vec![0; 257]).await;
    check(c, rng(4096), 0, vec![0; 4096]).await;
}
