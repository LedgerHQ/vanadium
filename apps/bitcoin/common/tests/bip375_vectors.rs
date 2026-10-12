//! The official BIP-375 test vectors.
//!
//! The vectors' maps are not sorted, as the parser requires, so they are sorted first. Then every
//! vector must parse, except for the invalid ones about the PSBT's structure, which the
//! parser rejects. The rest of the validation is a port of BIP-375's reference validator
//! (`validate_psbt.py`), on top of the parser and of the silent payment cryptography; it stays in
//! the test because it decides which inputs are eligible, and which keys they contribute, as
//! loosely as the reference does. The signer will decide it from the accounts of the inputs.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::{OutPoint, Script, ScriptBuf, Txid};
use hashes::Hash;
use sdk::curve::{Secp256k1, Secp256k1Point};
use serde_json::Value;
use vnd_bitcoin_common::fastpsbt::{Input, Psbt};
use vnd_bitcoin_common::silent_payments::{
    input_hash, output_key, recipients, shared_secret, verify_proof,
};

const VECTORS: &str = include_str!("data/bip375/bip375_test_vectors.json");

const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;

/// The x-coordinate of the BIP-341 NUMS point H.
const NUMS_H: [u8; 32] =
    hex_literal::hex!("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

/// The checks of the reference validator, in the order it runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Structure,
    EcdhCoverage,
    InputEligibility,
    OutputScripts,
}

const ALL_CHECKS: [Check; 4] = [
    Check::Structure,
    Check::EcdhCoverage,
    Check::InputEligibility,
    Check::OutputScripts,
];

impl Check {
    fn from_name(name: &str) -> Self {
        match name {
            "psbt_structure" => Check::Structure,
            "ecdh_coverage" => Check::EcdhCoverage,
            "input_eligibility" => Check::InputEligibility,
            "output_scripts" => Check::OutputScripts,
            _ => panic!("unknown check {name}"),
        }
    }

    /// The check that the description of an invalid vector says fails.
    fn from_description(description: &str) -> Self {
        let (name, _) = description.split_once(':').unwrap();
        match name {
            "psbt structure" => Check::Structure,
            "ecdh coverage" => Check::EcdhCoverage,
            "input eligibility" => Check::InputEligibility,
            "output scripts" => Check::OutputScripts,
            _ => panic!("unknown check in {description}"),
        }
    }

    fn run(self, psbt: &Psbt) -> Result<(), String> {
        match self {
            // the parser already ran it
            Check::Structure => Ok(()),
            Check::EcdhCoverage => ecdh_coverage(psbt),
            Check::InputEligibility => input_eligibility(psbt),
            Check::OutputScripts => output_scripts(psbt),
        }
    }
}

fn point(bytes: &[u8; 33]) -> Result<Secp256k1Point, String> {
    Secp256k1Point::from_compressed(bytes).map_err(|e| format!("invalid point: {e}"))
}

fn add(sum: Option<Secp256k1Point>, p: Secp256k1Point) -> Option<Secp256k1Point> {
    Some(match sum {
        Some(sum) => &sum + &p,
        None => p,
    })
}

/// The script of the output that an input spends.
fn prevout_script(input: &Input) -> ScriptBuf {
    if let Some(txout) = input.get_witness_utxo().unwrap() {
        return txout.script_pubkey.clone();
    }
    let tx = input.get_non_witness_utxo().unwrap().expect("a prevout");
    tx.output[input.output_index.unwrap() as usize]
        .script_pubkey
        .clone()
}

/// Whether an input is eligible: its prevout is P2PKH, P2WPKH, P2SH-P2WPKH, or P2TR without
/// the internal key H.
fn is_eligible(input: &Input) -> bool {
    let spk = prevout_script(input);
    if spk.is_p2pkh() || spk.is_p2wpkh() {
        true
    } else if spk.is_p2tr() {
        let internal_key = input
            .iter_keys(PSBT_IN_TAP_INTERNAL_KEY)
            .find(|(key_data, _)| key_data.is_empty())
            .map(|(_, value)| value);
        internal_key != Some(&NUMS_H[..])
    } else if spk.is_p2sh() {
        Script::from_bytes(input.redeem_script.expect("a redeem script")).is_p2wpkh()
    } else {
        false
    }
}

/// The public key of an eligible input: the key of its first BIP-32 derivation, or else its
/// taproot output key.
fn input_public_key(input: &Input) -> Option<Secp256k1Point> {
    if !is_eligible(input) {
        return None;
    }
    if let Some((key, _)) = input.bip32_derivations().next() {
        if let Ok(key) = key.try_into() {
            return Secp256k1Point::from_compressed(key).ok();
        }
    }
    let spk = prevout_script(input);
    if spk.is_p2tr() {
        return Secp256k1Point::lift_x(spk.as_bytes()[2..34].try_into().unwrap()).ok();
    }
    None
}

/// The ECDH share for `scan_key`, and the sum `A` of the public keys it covers: the global share
/// with all the eligible inputs, or else the sum of the shares of the eligible inputs.
fn ecdh_share_and_key_sum(
    psbt: &Psbt,
    scan_key: &[u8; 33],
) -> Result<Option<(Secp256k1Point, Secp256k1Point)>, String> {
    if let Some(share) = psbt.get_sp_ecdh_share(scan_key) {
        let key_sum = psbt
            .inputs
            .iter()
            .filter_map(input_public_key)
            .fold(None, add);
        if let Some(key_sum) = key_sum {
            return Ok(Some((point(share)?, key_sum)));
        }
    }
    let (mut share_sum, mut key_sum) = (None, None);
    for input in &psbt.inputs {
        let Some(share) = input.get_sp_ecdh_share(scan_key) else {
            continue;
        };
        if !is_eligible(input) {
            continue;
        }
        share_sum = add(share_sum, point(share)?);
        if let Some(key) = input_public_key(input) {
            key_sum = add(key_sum, key);
        }
    }
    Ok(share_sum.zip(key_sum))
}

fn check_proof(
    a: &Secp256k1Point,
    scan_key: &[u8; 33],
    share: &[u8; 33],
    proof: &[u8; 64],
) -> Result<(), String> {
    let g = Secp256k1::get_generator();
    if verify_proof(a, &point(scan_key)?, &point(share)?, proof, &g, None) {
        Ok(())
    } else {
        Err("invalid DLEQ proof".into())
    }
}

/// Every scan key with a computed output script has ECDH shares for all the eligible inputs, and
/// their DLEQ proofs verify.
fn ecdh_coverage(psbt: &Psbt) -> Result<(), String> {
    let mut scan_keys: Vec<[u8; 33]> = psbt
        .outputs
        .iter()
        .filter_map(|o| o.sp_v0_info.map(|info| info[..33].try_into().unwrap()))
        .collect();
    scan_keys.sort();
    scan_keys.dedup();

    for scan_key in &scan_keys {
        let global_share = psbt.get_sp_ecdh_share(scan_key);
        let any_input_share = psbt
            .inputs
            .iter()
            .any(|i| i.get_sp_ecdh_share(scan_key).is_some());
        let has_computed_output = psbt.outputs.iter().any(|o| {
            o.script.is_some() && o.sp_v0_info.is_some_and(|info| info[..33] == scan_key[..])
        });
        if has_computed_output && global_share.is_none() && !any_input_share {
            return Err("computed output without ECDH shares".into());
        }

        if let Some(share) = global_share {
            let proof = psbt
                .get_sp_dleq_proof(scan_key)
                .ok_or("global ECDH share without DLEQ proof")?;
            let (_, key_sum) = ecdh_share_and_key_sum(psbt, scan_key)?
                .ok_or("global ECDH share without eligible inputs")?;
            check_proof(&key_sum, scan_key, share, proof)?;
        } else if has_computed_output {
            for (i, input) in psbt.inputs.iter().enumerate() {
                if !is_eligible(input) {
                    continue;
                }
                let share = input
                    .get_sp_ecdh_share(scan_key)
                    .ok_or(format!("input {i} without ECDH share"))?;
                let proof = input
                    .get_sp_dleq_proof(scan_key)
                    .ok_or(format!("input {i} without DLEQ proof"))?;
                let key = input_public_key(input).ok_or(format!("input {i} without public key"))?;
                check_proof(&key, scan_key, share, proof)?;
            }
        }
    }
    Ok(())
}

/// With silent payment outputs, no input spends a segwit output of version 2 or more, and
/// every sighash type is SIGHASH_ALL.
fn input_eligibility(psbt: &Psbt) -> Result<(), String> {
    if psbt.outputs.iter().all(|o| o.sp_v0_info.is_none()) {
        return Ok(());
    }
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(txout) = input.get_witness_utxo().unwrap() {
            let spk = txout.script_pubkey.as_bytes();
            let segwit_v2_or_more = (4..=42).contains(&spk.len())
                && (0x52..=0x60).contains(&spk[0])
                && spk[1] as usize == spk.len() - 2;
            if segwit_v2_or_more {
                return Err(format!("input {i} spends segwit version 2 or more"));
            }
        }
    }
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.sighash_type.is_some_and(|t| t != 1) {
            return Err(format!("input {i} is not SIGHASH_ALL"));
        }
    }
    Ok(())
}

/// Every computed script of a silent payment output is the one that BIP-352 derives, with the
/// `k` of [`recipients`].
fn output_scripts(psbt: &Psbt) -> Result<(), String> {
    let outpoints: Vec<OutPoint> = psbt
        .inputs
        .iter()
        .map(|i| OutPoint {
            txid: Txid::from_byte_array(*i.previous_txid.unwrap()),
            vout: i.output_index.unwrap(),
        })
        .collect();

    for recipient in recipients(psbt).map_err(|e| format!("{e:?}"))? {
        let output = &psbt.outputs[recipient.output_index];
        let scan_key = recipient.code.scan().to_compressed().unwrap();
        match ecdh_share_and_key_sum(psbt, &scan_key)? {
            Some((share, key_sum)) => {
                let input_hash = input_hash(&outpoints, &key_sum).map_err(|e| format!("{e:?}"))?;
                let secret = shared_secret(&input_hash, &share).map_err(|e| format!("{e:?}"))?;
                let key = output_key(&secret, recipient.code.spend(), recipient.k)
                    .map_err(|e| format!("{e:?}"))?;
                let script = [&[0x51, 0x20][..], key.x()].concat();
                if output.script.is_some_and(|s| s != script) {
                    return Err(format!(
                        "output {} is not the derived script",
                        recipient.output_index
                    ));
                }
            }
            None if output.script.is_some() => {
                return Err(format!(
                    "output {} has a script but no ECDH share",
                    recipient.output_index
                ));
            }
            None => {}
        }
    }
    Ok(())
}

fn read_compact_size(raw: &[u8], pos: &mut usize) -> usize {
    let (len, value) = match raw[*pos] {
        n @ 0..=0xfc => (1, n as u64),
        0xfd => (
            3,
            u16::from_le_bytes(raw[*pos + 1..*pos + 3].try_into().unwrap()) as u64,
        ),
        0xfe => (
            5,
            u32::from_le_bytes(raw[*pos + 1..*pos + 5].try_into().unwrap()) as u64,
        ),
        0xff => (
            9,
            u64::from_le_bytes(raw[*pos + 1..*pos + 9].try_into().unwrap()),
        ),
    };
    *pos += len;
    value as usize
}

/// Reads a map, returning its key-value pairs with their serialization.
fn read_map<'a>(raw: &'a [u8], pos: &mut usize) -> Vec<(&'a [u8], &'a [u8])> {
    let mut pairs = Vec::new();
    loop {
        let start = *pos;
        let key_len = read_compact_size(raw, pos);
        if key_len == 0 {
            return pairs;
        }
        let key = &raw[*pos..*pos + key_len];
        *pos += key_len;
        let value_len = read_compact_size(raw, pos);
        *pos += value_len;
        pairs.push((key, &raw[start..*pos]));
    }
}

/// The PSBTv2 `raw` with the pairs of each map sorted by key.
fn sort_maps(raw: &[u8]) -> Vec<u8> {
    let mut pos = 5;
    let global = read_map(raw, &mut pos);
    let count = |key_type: u8| {
        let (_, pair) = global.iter().find(|(key, _)| key == &[key_type]).unwrap();
        read_compact_size(pair, &mut 3)
    };
    let n_maps = count(0x04) + count(0x05);
    let mut maps = vec![global];
    for _ in 0..n_maps {
        maps.push(read_map(raw, &mut pos));
    }
    assert_eq!(pos, raw.len());

    let mut res = raw[..5].to_vec();
    for mut map in maps {
        map.sort();
        for (_, pair) in map {
            res.extend_from_slice(pair);
        }
        res.push(0);
    }
    res
}

/// Parses a vector and runs its checks, returning the first that fails.
fn validate(vector: &Value) -> Result<(), (Check, String)> {
    let raw = STANDARD.decode(vector["psbt"].as_str().unwrap()).unwrap();
    let raw = sort_maps(&raw);
    let psbt = Psbt::parse(&raw).map_err(|e| (Check::Structure, format!("{e:?}")))?;
    let checks: Vec<Check> = match vector.get("checks") {
        Some(checks) => checks
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Check::from_name(c.as_str().unwrap()))
            .collect(),
        None => ALL_CHECKS.to_vec(),
    };
    for check in checks {
        check.run(&psbt).map_err(|e| (check, e))?;
    }
    Ok(())
}

#[test]
fn bip375_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();

    let valid = vectors["valid"].as_array().unwrap();
    for vector in valid {
        let description = vector["description"].as_str().unwrap();
        if let Err((check, e)) = validate(vector) {
            panic!("{description}: {check:?} failed: {e}");
        }
    }

    let invalid = vectors["invalid"].as_array().unwrap();
    for vector in invalid {
        let description = vector["description"].as_str().unwrap();
        match validate(vector) {
            Ok(()) => panic!("{description}: accepted"),
            Err((check, _)) => assert_eq!(
                check,
                Check::from_description(description),
                "{description}: the wrong check failed"
            ),
        }
    }

    assert_eq!((valid.len(), invalid.len()), (20, 23));
}
