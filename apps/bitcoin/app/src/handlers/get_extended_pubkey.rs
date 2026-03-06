use alloc::{format, vec::Vec};

use common::{errors::Error, identity, message::Response};
use sdk::{
    curve::{Curve, EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey},
    hash::{Hasher, Ripemd160, Sha256},
};

use crate::{constants::BIP32_TESTNET_PUBKEY_VERSION, identity::compute_identity_signature};

// TODO: refactor using vlib_bitcoin
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

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_identity_key(app: &mut sdk::App, value: &str, index: Option<u32>) -> bool {
    use alloc::vec;
    use sdk::ux::{Icon, TagValue};

    let (intro_text, intro_subtext): (alloc::string::String, alloc::string::String) = match index {
        None => {
            if sdk::ux::has_page_api() {
                ("Export root\nidentity key".into(), "".into())
            } else {
                ("Export root".into(), "identity key".into())
            }
        }
        Some(i) => {
            if sdk::ux::has_page_api() {
                (format!("Export identity\nkey #{}", i), "".into())
            } else {
                ("Export".into(), format!("identity key #{}", i))
            }
        }
    };

    let tag = match index {
        None => "Identity key",
        Some(_) => "Compressed pubkey",
    };

    let pairs = vec![TagValue {
        tag: tag.into(),
        value: value.into(),
    }];

    let approved = app
        .review_pairs(
            &intro_text,
            &intro_subtext,
            &pairs,
            "Verify identity key",
            "Confirm",
            false,
        )
        .await;
    app.show_info(
        if approved {
            Icon::Success
        } else {
            Icon::Failure
        },
        if approved {
            "Identity key verified"
        } else {
            "Identity key rejected"
        },
    );
    approved
}

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_xpub(app: &mut sdk::App, xpub: &str, path: &[u32]) -> bool {
    use alloc::{string::ToString, vec};
    use sdk::ux::{Icon, TagValue};

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Verify Bitcoin\nextended public key", "")
    } else {
        ("Verify Bitcoin", "extended public key")
    };

    let path_display =
        bitcoin::bip32::DerivationPath::from(path.iter().map(|&x| x.into()).collect::<Vec<_>>());

    let pairs = vec![
        TagValue {
            tag: "Path".into(),
            value: path_display.to_string(),
        },
        TagValue {
            tag: "Public key".into(),
            value: xpub.into(),
        },
    ];

    let approved = app
        .review_pairs(
            intro_text,
            intro_subtext,
            &pairs,
            "Verify public key",
            "Confirm",
            false,
        )
        .await;
    app.show_info(
        if approved {
            Icon::Success
        } else {
            Icon::Failure
        },
        if approved {
            "Public key verified"
        } else {
            "Public key rejected"
        },
    );
    approved
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_identity_key(_app: &mut sdk::App, _value: &str, _index: Option<u32>) -> bool {
    true
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_xpub(_app: &mut sdk::App, _xpub: &str, _path: &[u32]) -> bool {
    true
}

pub async fn handle_get_extended_pubkey(
    app: &mut sdk::App,
    bip32_path: &common::message::Bip32Path,
    display: bool,
    identity_index: Option<u32>,
) -> Result<Response, Error> {
    if bip32_path.0.len() > 256 {
        return Err(Error::DerivationPathTooLong);
    }

    let hd_node = sdk::curve::Secp256k1::derive_hd_node(&bip32_path.0)
        .map_err(|_| Error::KeyDerivationFailed)?;
    let privkey: EcfpPrivateKey<Secp256k1, 32> = EcfpPrivateKey::new(*hd_node.privkey);
    let pubkey = privkey.to_public_key();
    let pubkey_bytes = pubkey.as_ref().to_bytes();

    let compressed_pubkey_hex = {
        let mut compressed = alloc::vec![pubkey_bytes[64] % 2 + 0x02];
        compressed.extend_from_slice(&pubkey_bytes[1..33]);
        compressed
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<alloc::string::String>()
    };

    let depth = bip32_path.0.len() as u8;

    let parent_fpr: u32 = if bip32_path.0.is_empty() {
        0
    } else {
        let hd_node =
            sdk::curve::Secp256k1::derive_hd_node(&bip32_path.0[..bip32_path.0.len() - 1])
                .map_err(|_| Error::KeyDerivationFailed)?;
        let parent_privkey: EcfpPrivateKey<Secp256k1, 32> = EcfpPrivateKey::new(*hd_node.privkey);
        let parent_pubkey = parent_privkey.to_public_key();
        get_pubkey_fingerprint(&parent_pubkey)
    };

    let child_number: u32 = if bip32_path.0.is_empty() {
        0
    } else {
        bip32_path.0[bip32_path.0.len() - 1]
    };

    let mut xpub = Vec::with_capacity(78);
    xpub.extend_from_slice(&BIP32_TESTNET_PUBKEY_VERSION.to_be_bytes());
    xpub.push(depth);
    xpub.extend_from_slice(&parent_fpr.to_be_bytes());
    xpub.extend_from_slice(&child_number.to_be_bytes());
    xpub.extend_from_slice(&hd_node.chaincode);
    xpub.push(pubkey_bytes[64] % 2 + 0x02);
    xpub.extend_from_slice(&pubkey_bytes[1..33]);

    if display {
        let xpub_base58 = bitcoin::base58::encode_check(&xpub);
        let value = match identity::is_identity_path(&bip32_path.0) {
            Some(None) => &xpub_base58,
            Some(Some(_)) => &compressed_pubkey_hex,
            None => &xpub_base58,
        };
        let approved = match identity::is_identity_path(&bip32_path.0) {
            Some(index) => display_identity_key(app, value, index).await,
            None => display_xpub(app, &xpub_base58, &bip32_path.0).await,
        };
        if !approved {
            return Err(Error::UserRejected);
        }
    }

    let identity_sig = match identity_index {
        Some(i) => Some(compute_identity_signature(
            identity::MSG_TYPE_XPUB,
            &xpub,
            i,
        )?),
        None => None,
    };

    Ok(Response::ExtendedPubkey { xpub, identity_sig })
}

#[cfg(test)]
mod tests {
    use super::*;

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

            let response = sdk::executor::block_on(handle_get_extended_pubkey(
                &mut sdk::App::singleton(),
                &common::message::Bip32Path(parse_derivation_path(path).unwrap()),
                false,
                None,
            ))
            .unwrap();

            assert_eq!(
                response,
                Response::ExtendedPubkey {
                    xpub: bitcoin::base58::decode_check(expected_xpub).unwrap(),
                    identity_sig: None,
                }
            );
        }
    }
}
