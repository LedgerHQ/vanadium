//! Single-signature accounts: one signature per supported script type.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::{psbt::Psbt, secp256k1::schnorr::Signature, XOnlyPublicKey};
use common::{
    bip388::WalletPolicy,
    message::{PartialSignature, Response},
    por::{ProofOfRegistration, Registerable},
    psbt::prepare_psbt,
};
use hex_literal::hex;

use super::super::handle_sign_psbt;
use super::super::test_utils::serialize_as_psbtv2;

#[test]
fn test_handle_sign_psbt_pkh() {
    let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
    let mut psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "pkh(@0/**)",
        vec![
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "My legacy account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();

    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
        None,
    ))
    .unwrap();

    assert_eq!(response, Response::PsbtSigned {
        signatures: vec![
            PartialSignature {
                input_index: 0,
                signature: hex!("3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401").to_vec(),
                pubkey: hex!("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718").to_vec(),
                leaf_hash: None
            }
        ],
        musig_pubnonces: Vec::new(),
        musig_partial_sigs: Vec::new(),
    });
}

#[test]
fn test_handle_sign_psbt_wpkh() {
    let psbt_b64 = "cHNidP8BAHQCAAAAAXoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////AqC7DQAAAAAAGXapFDRKD0jKFQ7CuQOBdmC5tosTpnAmiKx0OCMAAAAAABYAFOs4+puBKPgfJule2wxf+uqDaQ/kAAAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxGESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXKGWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAAAAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAAAACICAinsR3JxMe0liKIMRu2pq7fapvSf1Quv5wucWqaWHE7MGPWswv1UAACAAQAAgAAAAIABAAAACgAAAAA=";
    let mut psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "wpkh(@0/**)",
        vec![
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()
        ]
    ).unwrap();
    let account_name = "My segwit account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
        None,
    ))
    .unwrap();

    assert_eq!(response, Response::PsbtSigned {
        signatures: vec![
            PartialSignature {
                input_index: 0,
                signature: hex!("3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01").to_vec(),
                pubkey: hex!("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068").to_vec(),
                leaf_hash: None
            }
        ],
        musig_pubnonces: Vec::new(),
        musig_partial_sigs: Vec::new(),
    });
}

#[test]
fn test_handle_sign_psbt_tr() {
    let psbt_b64 = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";
    let mut psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "tr(@0/**)",
        vec![
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "My taproot account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
        None,
    ))
    .unwrap();

    let Response::PsbtSigned {
        signatures: partial_signatures,
        ..
    } = response
    else {
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

#[test]
fn test_handle_sign_psbt_with_resident_pubkey() {
    let psbt_b64 = "cHNidP8BAKYCAAAAAs6MJQ9uBSUCmJpgUB9wGYZGqTMGYmOnXuyrkUGhcHyCAQAAAAD9////heZDgiEqZove1y7DCgxH7C8ERyDQkoVefghpmYDeKlwAAAAAAP3///8C5ygAAAAAAAAiUSAGDJP2Niux4bvyYwYNNDt/ff0v3KIN49hbSJrnZb0MQoSQAQAAAAAAFgAUKcCaIuEMi5OceEB5MbFv3Bxi7/AAAAAAAAEBKxFJAQAAAAAAIlEg1Klrfzt/O4NPudEUKKEhj69xxtM3OGnhY4Z3E9fqjHshFsZ2FyAcWD9j8ONZl/Sek1uj3W1JVPmlhZBzRiPIKiG1GQCthdlVMAAAgAEAAIAAAACAAAAAAAAAAAABFyDGdhcgHFg/Y/DjWZf0npNbo91tSVT5pYWQc0YjyCohtQABASsicQAAAAAAACJRIMRxNS3nHwMfn/AcfJ4/Bk3YkBzFZ0mz2NL1Atr1s4MIIRbJq1223YydIq4HkOWtLr6DBB9LrP8lN/ulMpG93sru0xkArYXZVTAAAIABAACAAAAAgAAAAAACAAAAARcgyatdtt2MnSKuB5DlrS6+gwQfS6z/JTf7pTKRvd7K7tMAAQUgOEeAjyIcpdjjuYWnkpRzrpDt2GVALyLidlPWZSDzRRchBzhHgI8iHKXY47mFp5KUc66Q7dhlQC8i4nZT1mUg80UXGQCthdlVMAAAgAEAAIAAAACAAAAAAAMAAAAAAA==";

    let mut psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "tr(@0/**)",
        vec![
            "[ad85d955/44'/1'/0']tpubDD7URPdwnhN6XNWRkMLhaGvhp1xaZNTAqgn8qULdENfMrUbCUcV4Kd4FQzVSHkKx9nmU7sNjBMPa96b9g3KTSJTAvTsTcT5mYDz97fUppvd".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "Resident taproot account";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
        None,
    ))
    .unwrap();

    let Response::PsbtSigned {
        signatures: partial_signatures,
        ..
    } = response
    else {
        panic!("Expected PsbtSigned response");
    };

    assert_eq!(partial_signatures.len(), 2);
}
