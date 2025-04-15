use alloc::vec::Vec;

use common::{
    bip388::{DescriptorTemplate, SegwitVersion},
    message::{PartialSignature, Response},
    psbt::PsbtAccountCoordinates,
    taproot::{GetTapLeafHash, GetTapTreeHash},
};

use bitcoin::{
    bip32::ChildNumber,
    hashes::Hash,
    key::{Keypair, TapTweak},
    psbt::Psbt,
    sighash::SighashCache,
    TapLeafHash, TapNodeHash, TapSighashType, Transaction, TxOut,
};
use common::psbt::{PsbtAccount, PsbtAccountGlobal, PsbtAccountInput};
use sdk::curve::{Curve, EcfpPrivateKey, ToPublicKey};

fn sign_input_ecdsa(
    psbt: &Psbt,
    input_index: usize,
    sighash_cache: &mut SighashCache<Transaction>,
    path: &[ChildNumber],
) -> Result<PartialSignature, &'static str> {
    let (sighash, sighash_type) = psbt
        .sighash_ecdsa(input_index, sighash_cache)
        .map_err(|_| "Error computing sighash")?;

    let path: Vec<u32> = path.iter().map(|&x| x.into()).collect();
    let hd_node = sdk::curve::Secp256k1::derive_hd_node(&path)?;
    let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> = EcfpPrivateKey::new(*hd_node.privkey);
    let pubkey = privkey.to_public_key();
    let pubkey_uncompressed = pubkey.as_ref().to_bytes();
    let mut pubkey_compressed = Vec::with_capacity(33);
    pubkey_compressed.push(2 + pubkey_uncompressed[64] % 2);
    pubkey_compressed.extend_from_slice(&pubkey_uncompressed[1..33]);

    let mut signature = privkey.ecdsa_sign_hash(sighash.as_ref())?;
    signature.push(sighash_type.to_u32() as u8);

    Ok(PartialSignature {
        input_index: input_index as u32,
        signature,
        pubkey: pubkey_compressed,
        leaf_hash: None,
    })
}

fn sign_input_schnorr(
    psbt: &Psbt,
    input_index: usize,
    sighash_cache: &mut SighashCache<Transaction>,
    path: &[ChildNumber],
    taptree_hash: Option<[u8; 32]>,
    leaf_hash: Option<TapLeafHash>,
) -> Result<PartialSignature, &'static str> {
    let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now

    let prevouts = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().ok_or("Missing witness utxo"))
        .collect::<Result<Vec<TxOut>, &'static str>>()?;

    let sighash = if let Some(leaf_hash) = leaf_hash {
        sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                sighash_type,
            )
            .map_err(|_| "Error computing sighash")?
    } else {
        sighash_cache
            .taproot_key_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                sighash_type,
            )
            .map_err(|_| "Error computing sighash")?
    };

    let path: Vec<u32> = path.iter().map(|&x| x.into()).collect();
    let hd_node = sdk::curve::Secp256k1::derive_hd_node(&path)?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair: Keypair =
        Keypair::from_seckey_slice(&secp, hd_node.privkey.as_ref()).map_err(|_| "Invalid key")?;

    let signing_privkey = if !leaf_hash.is_none() {
        // script path signing, no further tweak
        EcfpPrivateKey::new(keypair.secret_bytes())
    } else {
        // key path signing, apply tap_tweak
        let tweaked_keypair = keypair.tap_tweak(
            &secp,
            taptree_hash.map(|t| TapNodeHash::from_slice(&t).unwrap()),
        );

        EcfpPrivateKey::new(tweaked_keypair.to_inner().secret_bytes())
    };

    let mut signature = signing_privkey.schnorr_sign(sighash.as_ref())?;

    if sighash_type != TapSighashType::Default {
        signature.push(sighash_type as u8)
    }

    Ok(PartialSignature {
        input_index: input_index as u32,
        signature,
        pubkey: signing_privkey.to_public_key().as_ref().to_bytes()[1..33].to_vec(),
        leaf_hash: leaf_hash.map(|x| x.to_byte_array().to_vec()),
    })
}

pub fn handle_sign_psbt(_app: &mut sdk::App, psbt: &[u8]) -> Result<Response, &'static str> {
    let psbt = Psbt::deserialize(psbt).map_err(|_| "Failed to parse PSBT")?;

    let accounts = psbt.get_accounts()?;

    let mut warn_unverified_inputs: bool = false;

    /***** input checks *****/

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let Some((account_id, coords)) = input.get_account_coordinates()? else {
            return Err("External inputs are not supported");
        };

        if account_id as usize >= accounts.len() {
            return Err("Invalid account ID");
        }

        let PsbtAccount::WalletPolicy(wallet_policy) = &accounts[account_id as usize];

        let segwit_version = wallet_policy.get_segwit_version()?;

        if segwit_version == SegwitVersion::Legacy && input.witness_utxo.is_some() {
            return Err("Witness UTXO is not allowed for Legacy transaction");
        }

        if segwit_version == SegwitVersion::Legacy || segwit_version == SegwitVersion::SegwitV0 {
            // check that non-witness UTXO
            match &input.non_witness_utxo {
                Some(tx) => {
                    let prevout_id_computed = tx.compute_txid();
                    if psbt.unsigned_tx.input[input_index].previous_output.txid
                        != prevout_id_computed
                    {
                        return Err("Non-witness UTXO does not match the previous output");
                    }
                }
                None => {
                    if segwit_version == SegwitVersion::Legacy {
                        // for legacy transactions, non-witness UTXO is not required
                        return Err("Non-witness UTXO is required for SegWit version");
                    } else {
                        // for Segwitv0 transactions, non-witness UTXO is not mandatory,
                        // but we show a warning if missing
                        warn_unverified_inputs = true;
                    }
                }
            }
        }

        if segwit_version.is_segwit() && input.witness_utxo.is_none() {
            return Err("Witness UTXO is required for SegWit version");
        }

        // TODO: other checks:
        // - validate redeemScript (if provided)
        // - validate witnssScript (if provided)
    }

    /***** output checks *****/
    // TODO

    /***** user validation UI *****/

    // TODO:
    // - show necessary warnings
    // - show transaction details

    /***** Sign transaction *****/
    // TODO

    let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());

    let master_fingerprint = sdk::curve::Secp256k1::get_master_fingerprint();

    let mut partial_signatures = Vec::with_capacity(psbt.inputs.len());

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let Some((account_id, coords)) = input.get_account_coordinates()? else {
            return Err("External inputs are not supported");
        };
        if account_id as usize >= accounts.len() {
            return Err("Invalid account ID");
        }

        let PsbtAccountCoordinates::WalletPolicy(coords) = coords;

        let PsbtAccount::WalletPolicy(wallet_policy) = &accounts[account_id as usize];
        for (kp, tapleaf_desc) in wallet_policy.descriptor_template.placeholders() {
            let key_info = wallet_policy.key_information[kp.key_index as usize].clone();
            let Some(key_origin) = key_info
                .origin_info
                .as_ref()
                .filter(|x| x.fingerprint == master_fingerprint)
            else {
                continue;
            };

            // TODO: in principle, there could be collisions on the fingerprint; we shouldn't sign in that case

            let mut path = Vec::with_capacity(key_origin.derivation_path.len() + 2);
            path.extend_from_slice(&key_origin.derivation_path);
            if !coords.is_change {
                path.push(kp.num1.into());
            } else {
                path.push(kp.num2.into());
            }
            path.push(coords.address_index.into());

            if input.witness_utxo.is_some() {
                // sign all segwit types (including wrapped)
                match wallet_policy.get_segwit_version() {
                    Ok(SegwitVersion::SegwitV0) => {
                        // sign as segwit v0
                        let partial_signature =
                            sign_input_ecdsa(&psbt, input_index, &mut sighash_cache, &path)?;
                        partial_signatures.push(partial_signature);
                    }
                    Ok(SegwitVersion::Taproot) => {
                        // TODO currently only handling key path spends (with or without a taptree)
                        let taptree_hash = match &wallet_policy.descriptor_template {
                            DescriptorTemplate::Tr(_, tree) => tree
                                .as_ref()
                                .map(|t| {
                                    t.get_taptree_hash(
                                        &wallet_policy.key_information,
                                        coords.is_change,
                                        coords.address_index,
                                    )
                                })
                                .transpose(),
                            _ => return Err("Unexpected state: should be a Taproot wallet policy"),
                        }?;

                        let leaf_hash = tapleaf_desc
                            .map(|desc| {
                                desc.get_tapleaf_hash(
                                    &wallet_policy.key_information,
                                    coords.is_change,
                                    coords.address_index,
                                )
                            })
                            .transpose()?;

                        let partial_signature = sign_input_schnorr(
                            &psbt,
                            input_index,
                            &mut sighash_cache,
                            &path,
                            taptree_hash,
                            leaf_hash,
                        )?;
                        partial_signatures.push(partial_signature);
                    }
                    _ => return Err("Unexpected state: should be SegwitV0 or Taproot"),
                }
            } else {
                // sign as legacy p2pkh or p2sh
                partial_signatures.push(sign_input_ecdsa(
                    &psbt,
                    input_index,
                    &mut sighash_cache,
                    &path,
                )?);
            }
        }
    }

    Ok(Response::PsbtSigned(partial_signatures))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        base64::{engine::general_purpose::STANDARD, Engine as _},
        secp256k1::{
            self,
            schnorr::{self, Signature},
        },
        PublicKey, XOnlyPublicKey,
    };
    use common::{
        bip388::{KeyPlaceholder, WalletPolicy},
        psbt::fill_psbt_with_bip388_coordinates,
    };
    use hex_literal::hex;
    use sdk::curve::EcfpPublicKey;

    fn prepare_psbt(psbt: &mut Psbt, wallet_policy: &WalletPolicy) {
        let placeholders: Vec<KeyPlaceholder> = wallet_policy
            .descriptor_template
            .placeholders()
            .map(|(k, _)| k.clone())
            .collect();

        assert!(placeholders.len() == 1);
        let key_placeholder = placeholders[0];

        fill_psbt_with_bip388_coordinates(psbt, wallet_policy, None, None, &key_placeholder, 0)
            .unwrap();
    }

    #[test]
    fn test_handle_sign_psbt_pkh() {
        let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "pkh(@0/**)", 
            vec![
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".try_into().unwrap()
            ]
        ).unwrap();
        prepare_psbt(&mut psbt, &wallet_policy);

        let response = handle_sign_psbt(&mut sdk::App::singleton(), &psbt.serialize()).unwrap();

        assert_eq!(response, Response::PsbtSigned(vec![
            PartialSignature {
                input_index: 0,
                signature: hex!("3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401").to_vec(),
                pubkey: hex!("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718").to_vec(),
                leaf_hash: None
            }
        ]));
    }

    #[test]
    fn test_handle_sign_psbt_wpkh() {
        let psbt_b64 = "cHNidP8BAHQCAAAAAXoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////AqC7DQAAAAAAGXapFDRKD0jKFQ7CuQOBdmC5tosTpnAmiKx0OCMAAAAAABYAFOs4+puBKPgfJule2wxf+uqDaQ/kAAAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxGESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXKGWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAAAAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAAAACICAinsR3JxMe0liKIMRu2pq7fapvSf1Quv5wucWqaWHE7MGPWswv1UAACAAQAAgAAAAIABAAAACgAAAAA=";
        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "wpkh(@0/**)", 
            vec![
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()
            ]
        ).unwrap();
        prepare_psbt(&mut psbt, &wallet_policy);

        let response = handle_sign_psbt(&mut sdk::App::singleton(), &psbt.serialize()).unwrap();

        assert_eq!(response, Response::PsbtSigned(vec![
            PartialSignature {
                input_index: 0,
                signature: hex!("3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01").to_vec(),
                pubkey: hex!("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068").to_vec(),
                leaf_hash: None
            }
        ]));
    }

    #[test]
    fn test_handle_sign_psbt_tr() {
        let psbt_b64 = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";
        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "tr(@0/**)", 
            vec![
                "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U".try_into().unwrap()
            ]
        ).unwrap();
        prepare_psbt(&mut psbt, &wallet_policy);

        let response = handle_sign_psbt(&mut sdk::App::singleton(), &psbt.serialize()).unwrap();

        let Response::PsbtSigned(partial_signatures) = response else {
            panic!("Expected PsbtSigned response");
        };

        let expected_pubkey0 = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .unwrap()
            .script_pubkey
            .as_bytes()[2..]
            .to_vec();

        assert_eq!(partial_signatures.len(), 1);
        assert_eq!(partial_signatures[0].input_index, 0);
        assert_eq!(partial_signatures[0].pubkey, expected_pubkey0);

        let sighash = hex!("75C96FB06A12DB4CD011D8C95A5995DB758A4F2837A22F30F0F579619A4466F3");
        let pubkey = XOnlyPublicKey::from_slice(&expected_pubkey0).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        secp.verify_schnorr(
            &Signature::from_slice(&partial_signatures[0].signature).unwrap(),
            &bitcoin::secp256k1::Message::from_digest(sighash),
            &pubkey,
        )
        .expect("Signature verification failed");
    }
}
