use alloc::{borrow::Cow, vec::Vec};

use common::message::{RequestGetExtendedPubkey, ResponseGetExtendedPubkey};
use sdk::{
    curve::{Curve, EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey},
    hash::{Hasher, Ripemd160, Sha256},
};

const BIP32_TESTNET_PUBKEY_VERSION: u32 = 0x043587CFu32;

fn get_pubkey_fingerprint(pubkey: &EcfpPublicKey<Secp256k1, 32>) -> u32 {
    let pk_bytes = pubkey.as_ref().to_bytes();
    let mut sha256hasher = Sha256::new();
    sha256hasher.update(&[pk_bytes[64] % 2 + 0x02]);
    sha256hasher.update(&pk_bytes[1..33]);
    let mut sha256 = [0u8; 32];
    sha256hasher.digest(&mut sha256);

    let hash = Ripemd160::hash(&sha256);

    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

pub fn handle_get_extended_pubkey<'a, 'b>(
    req: &'a RequestGetExtendedPubkey,
) -> Result<ResponseGetExtendedPubkey<'b>, &'static str> {
    if req.bip32_path.len() > 256 {
        return Err("Derivation path is too long");
    }

    if req.display {
        todo!("Display is not yet implemented")
    }

    let hd_node = sdk::curve::Secp256k1::derive_hd_node(&req.bip32_path)?;
    let privkey: EcfpPrivateKey<Secp256k1, 32> = EcfpPrivateKey::new(*hd_node.privkey);
    let pubkey = privkey.to_public_key();
    let pubkey_bytes = pubkey.as_ref().to_bytes();

    let depth = req.bip32_path.len() as u8;

    let parent_fpr: u32 = if req.bip32_path.is_empty() {
        0
    } else {
        let hd_node =
            sdk::curve::Secp256k1::derive_hd_node(&req.bip32_path[..req.bip32_path.len() - 1])?;
        let parent_privkey: EcfpPrivateKey<Secp256k1, 32> = EcfpPrivateKey::new(*hd_node.privkey);
        let parent_pubkey = parent_privkey.to_public_key();
        get_pubkey_fingerprint(&parent_pubkey)
    };

    let child_number: u32 = if req.bip32_path.is_empty() {
        0
    } else {
        req.bip32_path[req.bip32_path.len() - 1]
    };

    let mut xpub = Vec::with_capacity(78);
    xpub.extend_from_slice(&BIP32_TESTNET_PUBKEY_VERSION.to_be_bytes());
    xpub.push(depth);
    xpub.extend_from_slice(&parent_fpr.to_be_bytes());
    xpub.extend_from_slice(&child_number.to_be_bytes());
    xpub.extend_from_slice(&hd_node.chaincode);
    xpub.push(pubkey_bytes[64] % 2 + 0x02);
    xpub.extend_from_slice(&pubkey_bytes[1..33]);

    Ok(ResponseGetExtendedPubkey {
        pubkey: Cow::Owned(xpub),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bs58;

    use std::num::ParseIntError;

    // TODO: this should be implemented and tested elsewhere
    /// Parse a Bitcoin-style derivation path (e.g., "m/48'/1'/4'/1'/0/7") into a list of
    /// child indices as `u32`. Hardened indices are marked by an apostrophe (`'`).
    pub fn parse_derivation_path(path: &str) -> Result<Vec<u32>, String> {
        // Split by '/' to get each component. e.g. "m/48'/1'/4'/1'/0/7" -> ["m", "48'", "1'", "4'", "1'", "0", "7"]
        let mut components = path.split('/').collect::<Vec<&str>>();

        // The first component should be "m". Remove it if present.
        if let Some(first) = components.first() {
            if *first == "m" {
                components.remove(0);
            }
        }

        let mut indices = Vec::new();
        for comp in components {
            // Check if this component is hardened
            let hardened = comp.ends_with('\'');

            // Remove the apostrophe if hardened
            let raw_index = if hardened {
                &comp[..comp.len() - 1]
            } else {
                comp
            };

            // Parse the numeric portion
            let index: u32 = raw_index.parse::<u32>().map_err(|e: ParseIntError| {
                format!("Invalid derivation index '{}': {}", comp, e)
            })?;

            // If hardened, add the 0x80000000 mask
            let child_number = if hardened {
                0x80000000_u32
                    .checked_add(index)
                    .ok_or_else(|| format!("Invalid hardened index '{}': overflowed", comp))?
            } else {
                index
            };

            indices.push(child_number);
        }

        Ok(indices)
    }

    #[test]
    fn test_handle_get_extended_pubkey() {
        let testcases = vec![
            ("m/44'/1'/0'", "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"),
            ("m/44'/1'/10'", "tpubDCwYjpDhUdPGp21gSpVay2QPJVh6WNySWMXPhbcu1DsxH31dF7mY18oibbu5RxCLBc1Szerjscuc3D5HyvfYqfRvc9mesewnFqGmPjney4d"),
            ("m/44'/1'/2'/1/42", "tpubDGF9YgHKv6qh777rcqVhpmDrbNzgophJM9ec7nHiSfrbss7fVBXoqhmZfohmJSvhNakDHAspPHjVVNL657tLbmTXvSeGev2vj5kzjMaeupT"),
            ("m/48'/1'/4'/1'/0/7", "tpubDK8WPFx4WJo1R9mEL7Wq325wBiXvkAe8ipgb9Q1QBDTDUD2YeCfutWtzY88NPokZqJyRPKHLGwTNLT7jBG59aC6VH8q47LDGQitPB6tX2d7"),
            ("m/49'/1'/1'/1/3", "tpubDGnetmJDCL18TyaaoyRAYbkSE9wbHktSdTS4mfsR6inC8c2r6TjdBt3wkqEQhHYPtXpa46xpxDaCXU2PRNUGVvDzAHPG6hHRavYbwAGfnFr"),
            ("m/84'/1'/2'/0/10", "tpubDG9YpSUwScWJBBSrhnAT47NcT4NZGLcY18cpkaiWHnkUCi19EtCh8Heeox268NaFF6o56nVeSXuTyK6jpzTvV1h68Kr3edA8AZp27MiLUNt"),
            ("m/86'/1'/4'/1/12", "tpubDHTZ815MvTaRmo6Qg1rnU6TEU4ZkWyA56jA1UgpmMcBGomnSsyo34EZLoctzZY9MTJ6j7bhccceUeXZZLxZj5vgkVMYfcZ7DNPsyRdFpS3f"),
        ];

        for (path, expected_xpub) in testcases {
            // decode the derivation path into a Vec<u32>

            let req = RequestGetExtendedPubkey {
                bip32_path: parse_derivation_path(path).unwrap(),
                display: false,
            };

            let response = handle_get_extended_pubkey(&req).unwrap();

            assert_eq!(
                response.pubkey,
                bs58::decode(expected_xpub)
                    .with_check(None)
                    .into_vec()
                    .unwrap()
            );
        }
    }
}