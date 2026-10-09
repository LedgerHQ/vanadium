//! The official BIP-352 test vectors, for sending and receiving.

use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{OutPoint, Script, Txid, Witness};
use sdk::curve::{EcfpPrivateKey, Secp256k1, Secp256k1Point, Secp256k1Scalar};
use serde_json::Value;
use vnd_bitcoin_common::silent_payments::{
    create_outputs, ecdh_share, input_hash, input_private_key, labeled_spend_key, scan,
    shared_secret, spending_key, Labels, SilentPaymentCode,
};

const VECTORS: &str = include_str!("data/bip352/send_and_receive_test_vectors.json");

/// The x-coordinate of the BIP-341 NUMS point H, used as the internal key of taproot outputs
/// that can only be spent through their scripts.
const NUMS_H: [u8; 32] =
    hex_literal::hex!("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

fn bytes(v: &Value) -> Vec<u8> {
    Vec::<u8>::from_hex(v.as_str().unwrap()).unwrap()
}

fn scalar(v: &Value) -> Secp256k1Scalar {
    Secp256k1Scalar::from_be_bytes(&bytes(v).try_into().unwrap()).unwrap()
}

fn hex_point(p: &Secp256k1Point) -> String {
    p.to_compressed().unwrap().to_lower_hex_string()
}

/// An input of a vector: its outpoint, and its contribution to BIP-352 if it is eligible.
struct Input {
    outpoint: OutPoint,
    /// The public key, and whether the input is taproot, for an eligible input.
    eligible: Option<(Secp256k1Point, bool)>,
    private_key: Option<Secp256k1Scalar>,
}

/// A port of `get_pubkey_from_input` of the BIP-352 reference implementation: the public key
/// that an input contributes to BIP-352, if it is eligible, found from the spent output's script
/// and from what the input reveals.
fn input_public_key(
    prevout: &Script,
    script_sig: &[u8],
    witness: &Witness,
) -> Option<Secp256k1Point> {
    let compressed = |b: &[u8]| -> Option<Secp256k1Point> {
        Secp256k1Point::from_compressed(b.try_into().ok()?).ok()
    };
    if prevout.is_p2pkh() {
        // the compressed key whose hash the output commits to, even in a malleated scriptSig
        let hash = &prevout.as_bytes()[3..23];
        for end in (33..=script_sig.len()).rev() {
            let candidate = &script_sig[end - 33..end];
            if hash160::Hash::hash(candidate).as_byte_array() == hash {
                if let Some(p) = compressed(candidate) {
                    return Some(p);
                }
            }
        }
    }
    if prevout.is_p2sh() && script_sig.len() > 1 && Script::from_bytes(&script_sig[1..]).is_p2wpkh()
    {
        if let Some(p) = witness.last().and_then(compressed) {
            return Some(p);
        }
    }
    if prevout.is_p2wpkh() {
        if let Some(p) = witness.last().and_then(compressed) {
            return Some(p);
        }
    }
    if prevout.is_p2tr() && !witness.is_empty() {
        let mut stack: Vec<&[u8]> = witness.iter().collect();
        if stack.len() > 1 && stack.last().unwrap().first() == Some(&0x50) {
            stack.pop(); // the annex
        }
        if stack.len() > 1 && stack.last().unwrap().get(1..33) == Some(&NUMS_H[..]) {
            // a script-path spend whose internal key is H is not eligible
            return None;
        }
        return Secp256k1Point::lift_x(&prevout.as_bytes()[2..].try_into().unwrap()).ok();
    }
    None
}

fn inputs(vin: &Value) -> Vec<Input> {
    vin.as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let prevout = bytes(&input["prevout"]["scriptPubKey"]["hex"]);
            let witness_bytes = bytes(&input["txinwitness"]);
            let witness = if witness_bytes.is_empty() {
                Witness::new()
            } else {
                bitcoin::consensus::deserialize(&witness_bytes).unwrap()
            };
            let prevout = Script::from_bytes(&prevout);
            Input {
                outpoint: OutPoint {
                    txid: Txid::from_str(input["txid"].as_str().unwrap()).unwrap(),
                    vout: input["vout"].as_u64().unwrap() as u32,
                },
                eligible: input_public_key(prevout, &bytes(&input["scriptSig"]), &witness)
                    .map(|p| (p, prevout.is_p2tr())),
                private_key: input.get("private_key").map(scalar),
            }
        })
        .collect()
}

fn sum(points: impl Iterator<Item = Secp256k1Point>) -> Secp256k1Point {
    points.fold(Secp256k1Point::default(), |acc, p| &acc + &p)
}

fn check_sending(case: &str, test: &Value) {
    let (given, expected) = (&test["given"], &test["expected"]);
    let inputs = inputs(&given["vin"]);
    let outpoints: Vec<OutPoint> = inputs.iter().map(|i| i.outpoint).collect();

    let eligible: Vec<&Input> = inputs.iter().filter(|i| i.eligible.is_some()).collect();
    let pub_keys: Vec<String> = eligible
        .iter()
        .map(|i| hex_point(&i.eligible.unwrap().0))
        .collect();
    let expected_pub_keys: Vec<String> = expected["input_pub_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(pub_keys, expected_pub_keys, "{case}: input public keys");

    let expected_sets: Vec<HashSet<String>> = expected["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|set| {
            set.as_array()
                .unwrap()
                .iter()
                .map(|o| o.as_str().unwrap().into())
                .collect()
        })
        .collect();
    if eligible.is_empty() {
        assert!(expected_sets[0].is_empty(), "{case}: no eligible inputs");
        return;
    }

    let a = eligible.iter().fold(Secp256k1Scalar::zero(), |acc, i| {
        &acc + &input_private_key(i.private_key.as_ref().unwrap(), i.eligible.unwrap().1)
    });
    if let Some(sum) = expected.get("input_private_key_sum") {
        assert_eq!(a, scalar(sum), "{case}: input private key sum");
    }

    let mut recipients = Vec::new();
    for (index, entry) in given["recipients"].as_array().unwrap().iter().enumerate() {
        let (hrp, code) =
            SilentPaymentCode::from_address(entry["address"].as_str().unwrap()).unwrap();
        assert_eq!(hrp, "sp");
        assert_eq!(
            hex_point(code.scan()),
            entry["scan_pub_key"].as_str().unwrap()
        );
        assert_eq!(
            hex_point(code.spend()),
            entry["spend_pub_key"].as_str().unwrap()
        );
        if let Some(secret) = expected["shared_secrets"][index].as_str() {
            let ih = input_hash(&outpoints, &(&Secp256k1::get_generator() * &a)).unwrap();
            let computed = shared_secret(&ih, &ecdh_share(&a, code.scan())).unwrap();
            assert_eq!(
                hex_point(&computed),
                secret,
                "{case}: shared secret {index}"
            );
        }
        let count = entry.get("count").and_then(Value::as_u64).unwrap_or(1);
        recipients.extend(std::iter::repeat(code).take(count as usize));
    }

    // a failure (inputs summing to zero, too many recipients) creates no outputs
    let outputs: HashSet<String> = create_outputs(&a, &outpoints, &recipients)
        .map(|outputs| outputs.iter().map(|o| o.to_lower_hex_string()).collect())
        .unwrap_or_default();
    assert!(
        expected_sets.contains(&outputs),
        "{case}: outputs {outputs:?}"
    );
}

/// Returns the number of outputs found.
fn check_receiving(case: &str, test: &Value) -> usize {
    let (given, expected) = (&test["given"], &test["expected"]);
    let inputs = inputs(&given["vin"]);
    let outpoints: Vec<OutPoint> = inputs.iter().map(|i| i.outpoint).collect();
    let b_scan = scalar(&given["key_material"]["scan_priv_key"]);
    let b_spend = scalar(&given["key_material"]["spend_priv_key"]);
    let g = Secp256k1::get_generator();
    let (scan_key, spend_key) = (&g * &b_scan, &g * &b_spend);
    let label_ms: Vec<u32> = given["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_u64().unwrap() as u32)
        .collect();

    // the addresses: unlabeled, then one per label
    let mut addresses = vec![SilentPaymentCode::new(scan_key, spend_key).unwrap()];
    for &m in &label_ms {
        let spend = labeled_spend_key(&spend_key, &b_scan, m).unwrap();
        addresses.push(SilentPaymentCode::new(scan_key, spend).unwrap());
    }
    let addresses: Vec<String> = addresses
        .iter()
        .map(|c| c.to_address("sp").unwrap())
        .collect();
    let expected_addresses: Vec<String> = expected["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().into())
        .collect();
    assert_eq!(addresses, expected_addresses, "{case}: addresses");

    let eligible: Vec<Secp256k1Point> = inputs
        .iter()
        .filter_map(|i| i.eligible.map(|e| e.0))
        .collect();
    let a_sum = sum(eligible.iter().copied());
    if eligible.is_empty() || a_sum.is_zero() {
        assert!(
            expected["outputs"].as_array().unwrap().is_empty(),
            "{case}: no outputs"
        );
        return 0;
    }
    if let Some(expected_sum) = expected["input_pub_key_sum"].as_str() {
        assert_eq!(
            hex_point(&a_sum),
            expected_sum,
            "{case}: input public key sum"
        );
    }
    let ih = input_hash(&outpoints, &a_sum).unwrap();
    assert_eq!(
        hex_point(&(&a_sum * &ih)),
        expected["tweak"].as_str().unwrap(),
        "{case}: tweak"
    );
    assert_eq!(
        hex_point(&shared_secret(&ih, &(&a_sum * &b_scan)).unwrap()),
        expected["shared_secret"].as_str().unwrap(),
        "{case}: shared secret"
    );

    let outputs: Vec<[u8; 32]> = given["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| bytes(o).try_into().unwrap())
        .collect();
    let mut labels = Labels::new();
    for &m in &label_ms {
        labels.insert(&b_scan, m).unwrap();
    }
    let found = scan(&b_scan, &spend_key, &a_sum, &outpoints, &outputs, &labels).unwrap();

    // each found output can be spent: a BIP-340 signature with its key, and the reference's
    // message and auxiliary randomness, matches the reference's signature
    let msg = sha256::Hash::hash(b"message").to_byte_array();
    let aux = sha256::Hash::hash(b"random auxiliary data").to_byte_array();
    let found: HashSet<(String, String, String)> = found
        .iter()
        .map(|f| {
            let d = spending_key(&b_spend, &f.tweak).unwrap();
            let sig = EcfpPrivateKey::new(*d.as_be_bytes())
                .schnorr_sign(&msg, Some(&aux))
                .unwrap();
            (
                f.output_key.to_lower_hex_string(),
                f.tweak.as_be_bytes().to_lower_hex_string(),
                sig.to_lower_hex_string(),
            )
        })
        .collect();

    match (expected.get("outputs"), expected.get("n_outputs")) {
        (Some(outputs), _) => {
            let expected: HashSet<(String, String, String)> = outputs
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    let field = |k: &str| o[k].as_str().unwrap().to_string();
                    (
                        field("pub_key"),
                        field("priv_key_tweak"),
                        field("signature"),
                    )
                })
                .collect();
            assert_eq!(found, expected, "{case}: found outputs");
        }
        (None, Some(n)) => assert_eq!(
            found.len() as u64,
            n.as_u64().unwrap(),
            "{case}: number of outputs"
        ),
        (None, None) => panic!("{case}: no expected outputs"),
    }
    found.len()
}

#[test]
fn bip352_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let (mut sending, mut receiving, mut found) = (0, 0, 0);
    for case in vectors.as_array().unwrap() {
        let name = case["comment"].as_str().unwrap();
        for test in case["sending"].as_array().unwrap() {
            check_sending(name, test);
            sending += 1;
        }
        for test in case["receiving"].as_array().unwrap() {
            found += check_receiving(name, test);
            receiving += 1;
        }
    }
    // every test of the file was checked
    assert_eq!((sending, receiving), (28, 29));
    assert!(found > 2323, "the K_max vectors find {found} outputs");
}
