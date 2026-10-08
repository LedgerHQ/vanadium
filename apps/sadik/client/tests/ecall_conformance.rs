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

const SECP256K1: u32 = 0x21;

/// The seed of Speculos' default mnemonic, which the native target uses too.
const DEFAULT_SEED: [u8; 64] = hex_literal::hex!("b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564");

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// BIP-32 derivation from `DEFAULT_SEED`, computed on the host: `privkey || chain_code`.
fn host_bip32(path: &[u32]) -> Vec<u8> {
    use k256::elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint};
    let node = hmac_sha512(b"Bitcoin seed", &[&DEFAULT_SEED]);
    let (mut key, mut chain_code) = (
        k256::Scalar::reduce(k256::U256::from_be_slice(&node[..32])),
        node[32..].to_vec(),
    );
    for &step in path {
        let data = if step >= 0x8000_0000 {
            let mut d = vec![0u8];
            d.extend_from_slice(&key.to_bytes());
            d
        } else {
            let point = (k256::ProjectivePoint::GENERATOR * key).to_affine();
            point.to_encoded_point(true).as_bytes().to_vec()
        };
        let i = hmac_sha512(&chain_code, &[&data, &step.to_be_bytes()]);
        key += k256::Scalar::reduce(k256::U256::from_be_slice(&i[..32]));
        chain_code = i[32..].to_vec();
    }
    let mut res = key.to_bytes().to_vec();
    res.extend_from_slice(&chain_code);
    res
}

/// Vanadium's SLIP-21 node for `labels`, computed on the host. Its master node is derived from
/// the standard SLIP-21 key at m/"VANADIUM".
fn host_slip21(labels: &[&[u8]]) -> Vec<u8> {
    let child = |node: &[u8; 64], label: &[u8]| hmac_sha512(&node[..32], &[&[0u8], label]);
    let standard_master = hmac_sha512(b"Symmetric key seed", &[&DEFAULT_SEED]);
    let vanadium_seed = child(&standard_master, b"VANADIUM");
    let mut node = hmac_sha512(b"Symmetric key seed", &[&vanadium_seed[32..]]);
    for label in labels {
        node = child(&node, label);
    }
    node.to_vec()
}

/// Encodes SLIP-21 labels, each prefixed by its length.
fn encode_labels(labels: &[&[u8]]) -> Vec<u8> {
    let mut res = Vec::new();
    for label in labels {
        res.push(label.len() as u8);
        res.extend_from_slice(label);
    }
    res
}

#[tokio::test]
async fn test_derive_hd_node() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let derive = |curve: u32, path: Vec<u32>| RawEcall::DeriveHdNode { curve, path };
    let h = 0x8000_0000u32;

    for path in [
        vec![],
        vec![h + 84, h + 1, h],
        vec![h + 86, h + 1, h, 0, 5],
        (0..16u32).map(|i| if i % 2 == 0 { h + i } else { i }).collect(),
    ] {
        let expected = host_bip32(&path);
        check(c, derive(SECP256K1, path), 1, expected).await;
    }

    // too long
    check(c, derive(SECP256K1, vec![h; 17]), 0, vec![0; 64]).await;
    check(c, derive(SECP256K1, vec![0; 256]), 0, vec![0; 64]).await;
    // unsupported curve
    check(c, derive(0x22, vec![h]), 0, vec![0; 64]).await;
}

#[tokio::test]
async fn test_get_master_fingerprint() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::Digest;

    let mut setup = setup().await;
    let c = &mut setup.client;

    let master = host_bip32(&[]);
    let key = k256::SecretKey::from_slice(&master[..32]).unwrap();
    let pk = key.public_key().to_encoded_point(true);
    let hash160 = ripemd::Ripemd160::digest(sha2::Sha256::digest(pk.as_bytes()));

    check(c, RawEcall::GetMasterFingerprint { curve: SECP256K1 }, 1, hash160[..4].to_vec()).await;
    check(c, RawEcall::GetMasterFingerprint { curve: 0x22 }, 0, vec![0; 4]).await;
}

#[tokio::test]
async fn test_derive_slip21_node() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let slip21 = |labels: Vec<u8>| RawEcall::DeriveSlip21Node { labels };

    let longest = [b'x'; 252];
    for labels in [
        vec![],
        vec![&b""[..]],
        vec![&b"SLIP-0021"[..]],
        vec![&b"SLIP-0021"[..], &b"Master encryption key"[..]],
        vec![&longest[..]],
    ] {
        check(c, slip21(encode_labels(&labels)), 1, host_slip21(&labels)).await;
    }

    // a label longer than 252 bytes
    check(c, slip21(encode_labels(&[&[b'x'; 253]])), 0, vec![0; 64]).await;
    // a truncated label
    check(c, slip21(vec![3, b'a', b'b']), 0, vec![0; 64]).await;
    // a buffer longer than 256 bytes
    check(c, slip21(vec![0; 257]), 0, vec![0; 64]).await;
}

const INFINITY: [u8; 65] = [0u8; 65];

/// The uncompressed encoding of `k * G`, or 65 zero bytes for infinity.
fn point_kg(k: u64) -> Vec<u8> {
    point_to_bytes(&(k256::ProjectivePoint::GENERATOR * k256::Scalar::from(k)))
}

fn point_to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    use k256::elliptic_curve::{group::Group, sec1::ToEncodedPoint};
    if bool::from(p.is_identity()) {
        INFINITY.to_vec()
    } else {
        p.to_affine().to_encoded_point(false).as_bytes().to_vec()
    }
}

/// The generator with its y-coordinate incremented: not on the curve.
fn off_curve_point() -> Vec<u8> {
    let mut p = point_kg(1);
    p[64] = p[64].wrapping_add(1);
    p
}

#[tokio::test]
async fn test_ecfp_add_point() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let add = |p: Vec<u8>, q: Vec<u8>| RawEcall::EcfpAddPoint { curve: SECP256K1, p, q };
    let neg_g = point_to_bytes(&-k256::ProjectivePoint::GENERATOR);

    check(c, add(point_kg(1), point_kg(2)), 1, point_kg(3)).await;
    // doubling
    check(c, add(point_kg(5), point_kg(5)), 1, point_kg(10)).await;
    // P + (-P) is infinity
    check(c, add(point_kg(1), neg_g.clone()), 1, INFINITY.to_vec()).await;
    // infinity is the identity
    check(c, add(INFINITY.to_vec(), point_kg(7)), 1, point_kg(7)).await;
    check(c, add(point_kg(7), INFINITY.to_vec()), 1, point_kg(7)).await;
    check(c, add(INFINITY.to_vec(), INFINITY.to_vec()), 1, INFINITY.to_vec()).await;

    // invalid encodings, also next to infinity
    let mut compressed_prefix = point_kg(1);
    compressed_prefix[0] = 0x02;
    let mut bad_infinity = INFINITY.to_vec();
    bad_infinity[64] = 1;
    let mut x_too_large = point_kg(1);
    x_too_large[1..33].copy_from_slice(&hex_literal::hex!(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    ));
    for invalid in [compressed_prefix, bad_infinity, x_too_large, off_curve_point()] {
        check(c, add(invalid.clone(), point_kg(2)), 0, INFINITY.to_vec()).await;
        check(c, add(point_kg(2), invalid.clone()), 0, INFINITY.to_vec()).await;
        check(c, add(INFINITY.to_vec(), invalid.clone()), 0, INFINITY.to_vec()).await;
        check(c, add(invalid, INFINITY.to_vec()), 0, INFINITY.to_vec()).await;
    }

    // unsupported curve
    let call = RawEcall::EcfpAddPoint { curve: 0x22, p: point_kg(1), q: point_kg(2) };
    check(c, call, 0, INFINITY.to_vec()).await;
}

#[tokio::test]
async fn test_ecfp_scalar_mult() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let mul = |p: Vec<u8>, k: Vec<u8>| RawEcall::EcfpScalarMult { curve: SECP256K1, p, k };
    let n_minus = |d: u8| {
        let mut k = SECP256K1_N.to_vec();
        k[31] -= d;
        k
    };

    check(c, mul(point_kg(1), be(3, 32)), 1, point_kg(3)).await;
    check(c, mul(point_kg(7), be(1, 32)), 1, point_kg(7)).await;
    check(c, mul(point_kg(7), be(5, 32)), 1, point_kg(35)).await;
    // scalars shorter than 32 bytes, including the empty scalar 0
    check(c, mul(point_kg(1), be(3, 1)), 1, point_kg(3)).await;
    check(c, mul(point_kg(1), be(0x0102, 2)), 1, point_kg(0x0102)).await;
    check(c, mul(point_kg(1), vec![]), 1, INFINITY.to_vec()).await;
    // zero, and the largest scalar: (n - 1) * G = -G
    check(c, mul(point_kg(1), be(0, 32)), 1, INFINITY.to_vec()).await;
    check(
        c,
        mul(point_kg(1), n_minus(1)),
        1,
        point_to_bytes(&-k256::ProjectivePoint::GENERATOR),
    )
    .await;
    // infinity
    check(c, mul(INFINITY.to_vec(), be(5, 32)), 1, INFINITY.to_vec()).await;

    // scalars that are not smaller than n, or too long
    check(c, mul(point_kg(1), SECP256K1_N.to_vec()), 0, INFINITY.to_vec()).await;
    let mut n_plus_1 = SECP256K1_N.to_vec();
    n_plus_1[31] += 1;
    check(c, mul(point_kg(1), n_plus_1), 0, INFINITY.to_vec()).await;
    check(c, mul(point_kg(1), vec![0xff; 32]), 0, INFINITY.to_vec()).await;
    check(c, mul(point_kg(1), be(1, 33)), 0, INFINITY.to_vec()).await;

    // invalid points, even with the scalars 0 and 1
    for k in [be(0, 32), be(1, 32), vec![]] {
        check(c, mul(off_curve_point(), k), 0, INFINITY.to_vec()).await;
    }
    let mut compressed_prefix = point_kg(1);
    compressed_prefix[0] = 0x03;
    check(c, mul(compressed_prefix, be(1, 32)), 0, INFINITY.to_vec()).await;

    // unsupported curve
    let call = RawEcall::EcfpScalarMult { curve: 0x22, p: point_kg(1), k: be(1, 32) };
    check(c, call, 0, INFINITY.to_vec()).await;
}

const ECDSA_RFC6979: u32 = 3 << 9;
const SHA256_ID: u32 = 3;

/// The DER-encoded RFC 6979 signature of `msg_hash`, reduced modulo n, computed on the host.
fn host_ecdsa_sign(privkey: &[u8; 32], msg_hash: &[u8; 32]) -> Vec<u8> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use k256::elliptic_curve::{ops::Reduce, PrimeField};
    let reduced = k256::Scalar::reduce(k256::U256::from_be_slice(msg_hash)).to_repr();
    let key = SigningKey::from_bytes(privkey.into()).unwrap();
    let sig: Signature = key.sign_prehash(&reduced).unwrap();
    sig.to_der().as_bytes().to_vec()
}

/// The high-S twin of a DER-encoded signature: same r, with s replaced by n - s.
fn high_s(der: &[u8]) -> Vec<u8> {
    let sig = k256::ecdsa::Signature::from_der(der).unwrap();
    let (r, s) = sig.split_scalars();
    let twin = k256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    twin.to_der().as_bytes().to_vec()
}

fn privkey(k: u64) -> [u8; 32] {
    be(k, 32).try_into().unwrap()
}

#[tokio::test]
async fn test_ecdsa_sign() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let sign = |privkey: [u8; 32], msg_hash: [u8; 32]| RawEcall::EcdsaSign {
        curve: SECP256K1,
        mode: ECDSA_RFC6979,
        hash_id: SHA256_ID,
        privkey: privkey.to_vec(),
        msg_hash: msg_hash.to_vec(),
    };
    let n_minus_1: [u8; 32] = {
        let mut k = SECP256K1_N;
        k[31] -= 1;
        k
    };
    let hash = [0x42u8; 32];

    for (key, msg_hash) in [
        (privkey(1), hash),
        (privkey(0xdeadbeef), [0u8; 32]),
        (n_minus_1, hash),
        // hashes that are not smaller than n are reduced
        (privkey(7), SECP256K1_N),
        (privkey(7), [0xff; 32]),
    ] {
        let expected = host_ecdsa_sign(&key, &msg_hash);
        check(c, sign(key, msg_hash), expected.len() as u32, expected).await;
    }

    // invalid private keys
    check(c, sign(privkey(0), hash), 0, vec![]).await;
    check(c, sign(SECP256K1_N, hash), 0, vec![]).await;
    check(c, sign([0xff; 32], hash), 0, vec![]).await;

    // unsupported curve, mode and hash
    for (curve, mode, hash_id) in [
        (0x22, ECDSA_RFC6979, SHA256_ID),
        (SECP256K1, 0, SHA256_ID),
        (SECP256K1, ECDSA_RFC6979, 5),
    ] {
        let call = RawEcall::EcdsaSign {
            curve,
            mode,
            hash_id,
            privkey: privkey(1).to_vec(),
            msg_hash: hash.to_vec(),
        };
        check(c, call, 0, vec![]).await;
    }
}

#[tokio::test]
async fn test_ecdsa_verify() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let verify = |pubkey: Vec<u8>, msg_hash: [u8; 32], signature: Vec<u8>| RawEcall::EcdsaVerify {
        curve: SECP256K1,
        pubkey,
        msg_hash: msg_hash.to_vec(),
        signature,
    };

    let key = privkey(0x1234);
    let pubkey = point_kg(0x1234);
    let hash = [0x42u8; 32];
    let sig = host_ecdsa_sign(&key, &hash);

    check(c, verify(pubkey.clone(), hash, sig.clone()), 1, vec![]).await;
    // high-S signatures are valid
    check(c, verify(pubkey.clone(), hash, high_s(&sig)), 1, vec![]).await;
    // wrong message or key
    check(c, verify(pubkey.clone(), [0x43; 32], sig.clone()), 0, vec![]).await;
    check(c, verify(point_kg(0x1235), hash, sig.clone()), 0, vec![]).await;

    // a hash that is not smaller than n verifies like its reduction
    let big_hash = [0xffu8; 32];
    let big_sig = host_ecdsa_sign(&key, &big_hash);
    check(c, verify(pubkey.clone(), big_hash, big_sig.clone()), 1, vec![]).await;
    let mut reduced = [0u8; 32];
    reduced[15] = 1;
    reduced[16..].copy_from_slice(&hex_literal::hex!("4551231950b75fc4402da1732fc9bebe"));
    check(c, verify(pubkey.clone(), reduced, big_sig), 1, vec![]).await;

    // signatures that are not strict DER
    let mut padded = sig.clone();
    padded[1] += 1;
    padded.push(0);
    let mut wrong_tag = sig.clone();
    wrong_tag[0] = 0x31;
    for bad in [vec![], sig[..sig.len() - 1].to_vec(), padded, wrong_tag, vec![0x30; 73]] {
        check(c, verify(pubkey.clone(), hash, bad), 0, vec![]).await;
    }

    // invalid public keys
    let mut compressed_prefix = pubkey.clone();
    compressed_prefix[0] = 0x02;
    for bad in [INFINITY.to_vec(), off_curve_point(), compressed_prefix] {
        check(c, verify(bad, hash, sig.clone()), 0, vec![]).await;
    }

    // unsupported curve
    let call = RawEcall::EcdsaVerify {
        curve: 0x22,
        pubkey,
        msg_hash: hash.to_vec(),
        signature: sig,
    };
    check(c, call, 0, vec![]).await;
}

const BIP340: u32 = 0;

fn host_schnorr_sign(privkey: &[u8; 32], msg: &[u8], aux: &[u8; 32]) -> Vec<u8> {
    let key = k256::schnorr::SigningKey::from_bytes(privkey).unwrap();
    key.sign_raw(msg, aux).unwrap().to_bytes().to_vec()
}

fn host_xonly(privkey: &[u8; 32]) -> Vec<u8> {
    let key = k256::schnorr::SigningKey::from_bytes(privkey).unwrap();
    key.verifying_key().to_bytes().to_vec()
}

fn host_schnorr_verify(xonly: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let key = k256::schnorr::VerifyingKey::from_bytes(xonly).unwrap();
    let sig = k256::schnorr::Signature::try_from(sig).unwrap();
    key.verify_raw(msg, &sig).is_ok()
}

/// Whether some point of the curve has x-coordinate `x`.
fn has_point_with_x(x: &[u8; 32]) -> bool {
    k256::schnorr::VerifyingKey::from_bytes(x).is_ok()
}

fn schnorr_sign_call(privkey: [u8; 32], msg: Vec<u8>, entropy: Option<[u8; 32]>) -> RawEcall {
    RawEcall::SchnorrSign {
        curve: SECP256K1,
        mode: BIP340,
        hash_id: SHA256_ID,
        privkey: privkey.to_vec(),
        msg,
        entropy,
    }
}

fn schnorr_verify_call(pubkey: Vec<u8>, msg: Vec<u8>, signature: Vec<u8>) -> RawEcall {
    RawEcall::SchnorrVerify {
        curve: SECP256K1,
        mode: BIP340,
        hash_id: SHA256_ID,
        pubkey,
        msg,
        signature,
    }
}

#[tokio::test]
async fn test_schnorr_sign() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let aux = [0x5au8; 32];
    let msg = |len: usize| (0..len).map(|i| i as u8).collect::<Vec<u8>>();

    // keys whose public key has an even and an odd y-coordinate
    let keys: Vec<[u8; 32]> = (1..20u64).map(privkey).collect();
    let parity = |k: &[u8; 32]| {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let pk = k256::SecretKey::from_slice(k).unwrap().public_key();
        pk.to_encoded_point(true).as_bytes()[0]
    };
    let even = *keys.iter().find(|k| parity(k) == 0x02).unwrap();
    let odd = *keys.iter().find(|k| parity(k) == 0x03).unwrap();

    for key in [even, odd] {
        for len in [0, 32, 128, 129, 512] {
            let expected = host_schnorr_sign(&key, &msg(len), &aux);
            check(c, schnorr_sign_call(key, msg(len), Some(aux)), 64, expected).await;
        }
    }

    // without auxiliary randomness, signatures are valid and randomized
    let first = ecall(c, schnorr_sign_call(odd, msg(32), None)).await;
    let second = ecall(c, schnorr_sign_call(odd, msg(32), None)).await;
    assert_eq!((first.status, second.status), (64, 64));
    assert_ne!(first.output, second.output);
    assert!(host_schnorr_verify(&host_xonly(&odd), &msg(32), &first.output));
    assert!(host_schnorr_verify(&host_xonly(&odd), &msg(32), &second.output));

    // a message longer than the cap
    check(c, schnorr_sign_call(odd, msg(513), Some(aux)), 0, vec![]).await;
    // invalid private keys
    for key in [privkey(0), SECP256K1_N, [0xff; 32]] {
        check(c, schnorr_sign_call(key, msg(32), Some(aux)), 0, vec![]).await;
    }
    // unsupported curve, mode and hash
    for (curve, mode, hash_id) in [(0x22, BIP340, SHA256_ID), (SECP256K1, 1, SHA256_ID), (SECP256K1, BIP340, 5)] {
        let call = RawEcall::SchnorrSign {
            curve,
            mode,
            hash_id,
            privkey: odd.to_vec(),
            msg: msg(32),
            entropy: Some(aux),
        };
        check(c, call, 0, vec![]).await;
    }
}

#[tokio::test]
async fn test_schnorr_verify() {
    let mut setup = setup().await;
    let c = &mut setup.client;
    let key = privkey(0x4321);
    let xonly = host_xonly(&key);
    let msg = b"a message".to_vec();
    let long_msg = vec![0x77u8; 512];
    let sig = host_schnorr_sign(&key, &msg, &[1; 32]);
    let long_sig = host_schnorr_sign(&key, &long_msg, &[1; 32]);

    check(c, schnorr_verify_call(xonly.clone(), msg.clone(), sig.clone()), 1, vec![]).await;
    check(c, schnorr_verify_call(xonly.clone(), long_msg.clone(), long_sig), 1, vec![]).await;
    // wrong message or key
    check(c, schnorr_verify_call(xonly.clone(), b"another".to_vec(), sig.clone()), 0, vec![]).await;
    check(c, schnorr_verify_call(host_xonly(&privkey(5)), msg.clone(), sig.clone()), 0, vec![]).await;
    // a message longer than the cap
    let mut too_long = long_msg.clone();
    too_long.push(0);
    check(c, schnorr_verify_call(xonly.clone(), too_long, sig.clone()), 0, vec![]).await;

    // r and s out of range, and wrong lengths
    let p = hex_literal::hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    let mut bad = Vec::new();
    for (start, value) in [(0, p), (0, [0u8; 32]), (32, SECP256K1_N), (32, [0u8; 32])] {
        let mut s = sig.clone();
        s[start..start + 32].copy_from_slice(&value);
        bad.push(s);
    }
    bad.push(sig[..63].to_vec());
    let mut sig65 = sig.clone();
    sig65.push(0);
    bad.push(sig65);
    for s in bad {
        check(c, schnorr_verify_call(xonly.clone(), msg.clone(), s), 0, vec![]).await;
    }

    // public keys that are not the x-coordinate of a point of the curve
    let x_not_on_curve: [u8; 32] = (1..100u64)
        .map(|x| -> [u8; 32] { be(x, 32).try_into().unwrap() })
        .find(|x| !has_point_with_x(x))
        .unwrap();
    for x in [x_not_on_curve.to_vec(), p.to_vec(), vec![0xff; 32]] {
        check(c, schnorr_verify_call(x, msg.clone(), sig.clone()), 0, vec![]).await;
    }

    // unsupported curve, mode and hash
    for (curve, mode, hash_id) in [(0x22, BIP340, SHA256_ID), (SECP256K1, 1, SHA256_ID), (SECP256K1, BIP340, 5)] {
        let call = RawEcall::SchnorrVerify {
            curve,
            mode,
            hash_id,
            pubkey: xonly.clone(),
            msg: msg.clone(),
            signature: sig.clone(),
        };
        check(c, call, 0, vec![]).await;
    }
}
