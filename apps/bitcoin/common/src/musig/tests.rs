use alloc::vec;
use alloc::vec::Vec;
use hex_literal::hex;

use sdk::bignum::BigNumMod;
use sdk::curve::{EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey};

use super::*;

// =============================================================================
// KeyAgg vectors (BIP-327 key_agg_vectors.json)
// =============================================================================

// The three reference pubkeys.
const X1: PlainPk = hex!("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
const X2: PlainPk = hex!("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
const X3: PlainPk = hex!("023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66");

fn assert_aggregate_xonly(pubkeys: &[PlainPk], expected_xonly: [u8; 32]) {
    let ctx = key_agg(pubkeys).expect("key_agg succeeds");
    assert_eq!(ctx.q.x, expected_xonly, "aggregate x-only mismatch");
}

#[test]
fn key_agg_vectors_bip327() {
    // valid_test_cases[0]: [X1, X2, X3]
    assert_aggregate_xonly(
        &[X1, X2, X3],
        hex!("90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"),
    );
    // valid_test_cases[1]: [X3, X2, X1]
    assert_aggregate_xonly(
        &[X3, X2, X1],
        hex!("6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"),
    );
    // valid_test_cases[2]: [X1, X1, X1]
    assert_aggregate_xonly(
        &[X1, X1, X1],
        hex!("B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"),
    );
    // valid_test_cases[3]: [X1, X1, X2, X2]
    assert_aggregate_xonly(
        &[X1, X1, X2, X2],
        hex!("69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"),
    );
}

// =============================================================================
// SecNonce semantics: nonce_gen recomputes deterministically from `rand`
// =============================================================================

#[test]
fn nonce_gen_is_deterministic_in_rand() {
    let pk: PlainPk = X1;
    let aggpk: XOnlyPk = hex!("90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C");
    let rand_bytes = hex!("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");

    let (_sn1, pub1) = nonce_gen(&rand_bytes, &pk, &aggpk).unwrap();
    let (_sn2, pub2) = nonce_gen(&rand_bytes, &pk, &aggpk).unwrap();
    assert_eq!(pub1, pub2, "nonce_gen must be deterministic in `rand`");

    let rand2 = hex!("F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0");
    let (_sn3, pub3) = nonce_gen(&rand2, &pk, &aggpk).unwrap();
    assert_ne!(pub1, pub3, "nonce_gen must differ when `rand` differs");
}

// =============================================================================
// Round-trip: 2-of-2 keypath signing → BIP-340 verify
// =============================================================================
//
// Generates two random keypairs, runs the full musig2 protocol (no tweaks),
// aggregates the partial signatures into a final (R, s) Schnorr sig, and
// verifies it against the BIP-340 schnorr verifier (`schnorr_verify`).

fn priv_to_compressed_pk(sk: &[u8; 32]) -> PlainPk {
    let privkey = EcfpPrivateKey::<Secp256k1, 32>::new(*sk);
    privkey.to_public_key().to_compressed()
}

#[test]
fn round_trip_two_party_keypath_no_tweaks() {
    let sk1 = hex!("0101010101010101010101010101010101010101010101010101010101010101");
    let sk2 = hex!("0202020202020202020202020202020202020202020202020202020202020202");
    let msg = hex!("F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF22C39");

    let pk1 = priv_to_compressed_pk(&sk1);
    let pk2 = priv_to_compressed_pk(&sk2);

    // Sort participants per KeySort.
    let mut sorted: Vec<PlainPk> = vec![pk1, pk2];
    sorted.sort();

    let ctx = key_agg(&sorted).unwrap();
    let aggpk_xonly: XOnlyPk = ctx.q.x;
    // BIP-340 verification needs an even-y aggregate. The bare aggregate may
    // be odd-y; for this no-tweaks test, just inject an x-only tweak of 0 to
    // normalize parity.
    let tweaks: Vec<[u8; 32]> = vec![[0u8; 32]];
    let is_xonly: Vec<bool> = vec![true];

    // Round 1: each signer generates a (secnonce, pubnonce).
    let rand1 = hex!("1111111111111111111111111111111111111111111111111111111111111111");
    let rand2 = hex!("2222222222222222222222222222222222222222222222222222222222222222");
    let (sn1, pn1) = nonce_gen(&rand1, &pk1, &aggpk_xonly).unwrap();
    let (sn2, pn2) = nonce_gen(&rand2, &pk2, &aggpk_xonly).unwrap();

    // Aggregate nonces.
    let aggnonce = nonce_agg(&[pn1, pn2]).unwrap();

    // Round 2: each signer produces a partial sig.
    let sctx = SessionContext {
        aggnonce: &aggnonce,
        pubkeys: &sorted,
        tweaks: &tweaks,
        is_xonly: &is_xonly,
        msg: &msg,
    };
    let psig1 = sign(sn1, &sk1, &sctx).unwrap();
    let psig2 = sign(sn2, &sk2, &sctx).unwrap();

    // Aggregate partial sigs into a final BIP-340 (R.x || s) signature.
    let sig = partial_sig_agg(&sctx, &[psig1, psig2]).unwrap();

    // The signature verifies under the (post-all-tweaks) aggregate xonly key
    // with prefix 0x02, since BIP-340 always interprets the verifier key as
    // even-y.
    let tweaked_q_x: [u8; 32] = sig[..32].try_into().unwrap(); // R.x; not the verifier key
    // Recompute the verifier key (tweaked Q.x) from key_agg + apply_tweak.
    let verifier_xonly = {
        let mut keyagg = key_agg(&sorted).unwrap();
        super::apply_tweak(&mut keyagg, &[0u8; 32], true).unwrap();
        keyagg.q.x
    };
    let pk_for_verify = EcfpPublicKey::<Secp256k1, 32>::from_compressed(&{
        let mut p = [0u8; 33];
        p[0] = 0x02;
        p[1..].copy_from_slice(&verifier_xonly);
        p
    })
    .unwrap();

    pk_for_verify
        .schnorr_verify(&msg, &sig)
        .expect("aggregated musig2 schnorr signature must verify under the tweaked aggregate key");

    // Silence unused-warning on the BigNumMod / N imports if any.
    let _ = (tweaked_q_x, BigNumMod::<32, N>::from_u32(0));
}

// =============================================================================
// BIP-32 unhardened CKDpub with tweak exposure
// =============================================================================

use bitcoin::bip32::{ChainCode, ChildNumber, Xpub};
use bitcoin::secp256k1;

/// BIP-32 test vector 1: parent m/0h derives to child m/0h/1 at index 1.
/// Both parent and child are taken verbatim from the BIP-32 specification.
#[test]
fn ckdpub_with_tweak_bip32_tv1_m0h_to_m0h1() {
    let parent_pubkey: [u8; 33] =
        hex!("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");
    let parent_chain_code: [u8; 32] =
        hex!("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");

    let parent = Xpub {
        network: bitcoin::NetworkKind::Main,
        depth: 1,
        parent_fingerprint: Default::default(),
        child_number: ChildNumber::Hardened { index: 0 },
        public_key: secp256k1::PublicKey::from_slice(&parent_pubkey).unwrap(),
        chain_code: ChainCode::from(parent_chain_code),
    };

    let (child, tweak) = ckdpub_with_tweak(&parent, ChildNumber::Normal { index: 1 }).unwrap();

    // Expected m/0h/1 pubkey and chain_code from BIP-32 test vector 1.
    assert_eq!(
        child.public_key.serialize(),
        hex!("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")
    );
    assert_eq!(
        child.chain_code.as_bytes(),
        &hex!("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")
    );

    // The tweak is non-zero (a passing CKDpub never produces a zero tweak).
    assert_ne!(tweak, [0u8; 32]);

    // Hardened child must be rejected.
    let err = ckdpub_with_tweak(&parent, ChildNumber::Hardened { index: 0 }).unwrap_err();
    assert_eq!(err, MusigError::DerivationFailed);
}

// =============================================================================
// BIP-388 aggregate xpub
// =============================================================================

/// Sanity-check: the aggregate xpub's pubkey x-coordinate matches a
/// direct `key_agg` of the (sorted) participant pubkeys, and the chaincode
/// is exactly the BIP-328 constant.
#[test]
fn aggregate_xpub_matches_key_agg() {
    fn xpub_from(pubkey: [u8; 33]) -> Xpub {
        Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            public_key: secp256k1::PublicKey::from_slice(&pubkey).unwrap(),
            chain_code: ChainCode::from([1u8; 32]),
        }
    }

    let xpubs = vec![xpub_from(X1), xpub_from(X2), xpub_from(X3)];
    let agg = aggregate_xpub(&xpubs).unwrap();

    // Same as [X1, X2, X3] sorted is the input to key_agg in the helper.
    let mut sorted = vec![X1, X2, X3];
    sorted.sort();
    let expected = key_agg(&sorted).unwrap();
    assert_eq!(&agg.public_key.serialize()[1..], &expected.q.x);

    // BIP-388 / BIP-328 chaincode.
    assert_eq!(agg.chain_code.as_bytes(), &BIP_328_CHAINCODE);
    // The synthetic prefix is always 0x02 ("even-y").
    assert_eq!(agg.public_key.serialize()[0], 0x02);
}

/// End-to-end: aggregate three xpubs, then derive an unhardened child of the
/// aggregate. The two BIP-32 tweaks returned alongside the child Xpubs are the
/// scalars the musig signing handler will feed into [`apply_tweak`].
#[test]
fn aggregate_xpub_then_two_ckdpub_steps() {
    fn xpub_from(pubkey: [u8; 33]) -> Xpub {
        Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Normal { index: 0 },
            public_key: secp256k1::PublicKey::from_slice(&pubkey).unwrap(),
            chain_code: ChainCode::from([2u8; 32]),
        }
    }

    let agg = aggregate_xpub(&[xpub_from(X1), xpub_from(X2)]).unwrap();
    let (child1, t1) = ckdpub_with_tweak(&agg, ChildNumber::Normal { index: 0 }).unwrap();
    let (child2, t2) = ckdpub_with_tweak(&child1, ChildNumber::Normal { index: 7 }).unwrap();

    // The two-step derivation must equal a single derive_pub call over the
    // same path (sanity check that the helper matches rust-bitcoin's BIP-32).
    let secp = secp256k1::Secp256k1::new();
    let path = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 7 },
    ];
    let expected = agg.derive_pub(&secp, &path).unwrap();
    assert_eq!(child2.public_key, expected.public_key);
    assert_eq!(child2.chain_code, expected.chain_code);

    // Tweaks are non-zero (the HMAC output is overwhelmingly never zero).
    assert_ne!(t1, [0u8; 32]);
    assert_ne!(t2, [0u8; 32]);
    // ... and they differ from each other (different index/parent).
    assert_ne!(t1, t2);
}
