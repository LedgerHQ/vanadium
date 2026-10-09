//! The official BIP-374 test vectors for DLEQ proofs.

use bitcoin::hex::FromHex;
use sdk::curve::{Secp256k1Point, Secp256k1Scalar};
use vnd_bitcoin_common::silent_payments::{generate_proof, verify_proof};

const GENERATE: &str = include_str!("data/bip374/test_vectors_generate_proof.csv");
const VERIFY: &str = include_str!("data/bip374/test_vectors_verify_proof.csv");

/// The rows of a CSV file, as maps from the column names.
fn rows(csv: &str) -> Vec<std::collections::HashMap<&str, &str>> {
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next().unwrap().split(',').collect();
    lines
        .filter(|l| !l.is_empty())
        .map(|l| header.iter().copied().zip(l.split(',')).collect())
        .collect()
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    <[u8; N]>::from_hex(hex).unwrap()
}

fn point(hex: &str) -> Secp256k1Point {
    if hex == "INFINITY" {
        return Secp256k1Point::default();
    }
    Secp256k1Point::from_compressed(&bytes(hex)).unwrap()
}

fn message(hex: &str) -> Option<[u8; 32]> {
    (!hex.is_empty()).then(|| bytes(hex))
}

#[test]
fn generate_proof_vectors() {
    for row in rows(GENERATE) {
        let g = point(row["point_G"]);
        let b = point(row["point_B"]);
        let m = message(row["message"]);
        // a scalar that is not smaller than n cannot be built at all
        let proof = Secp256k1Scalar::from_be_bytes(&bytes(row["scalar_a"]))
            .and_then(|a| generate_proof(&a, &b, &bytes(row["auxrand_r"]), &g, m.as_ref()).ok());
        match row["result_proof"] {
            "INVALID" => assert!(proof.is_none(), "row {}", row["index"]),
            expected => assert_eq!(proof, Some(bytes(expected)), "row {}", row["index"]),
        }
    }
}

#[test]
fn verify_proof_vectors() {
    for row in rows(VERIFY) {
        let valid = verify_proof(
            &point(row["point_A"]),
            &point(row["point_B"]),
            &point(row["point_C"]),
            &bytes(row["proof"]),
            &point(row["point_G"]),
            message(row["message"]).as_ref(),
        );
        assert_eq!(
            valid,
            row["result_success"] == "TRUE",
            "row {}",
            row["index"]
        );
    }
}
