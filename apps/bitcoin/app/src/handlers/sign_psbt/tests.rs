use super::handle_sign_psbt;
use crate::handlers::musig_signing;
use bitcoin::hashes::Hash;
use common::{
    errors::Error,
    message::{PartialSignature, Response},
    por::{ProofOfRegistration, Registerable},
    script::ToScript,
};
use sdk::curve::{Curve, EcfpPrivateKey, EcfpPublicKey, ToPublicKey};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::{psbt::Psbt, secp256k1::schnorr::Signature, XOnlyPublicKey};
use common::{bip388::WalletPolicy, psbt::prepare_psbt};
use hex_literal::hex;

use super::test_utils::serialize_as_psbtv2;

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

    let account_name = "My legacy account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();

    prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
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
    let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "wpkh(@0/**)",
        vec![
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()
        ]
    ).unwrap();
    let account_name = "My segwit account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
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
    let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "tr(@0/**)",
        vec![
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "My taproot account #0";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
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

    let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

    let wallet_policy = WalletPolicy::new(
        "tr(@0/**)",
        vec![
            "[ad85d955/44'/1'/0']tpubDD7URPdwnhN6XNWRkMLhaGvhp1xaZNTAqgn8qULdENfMrUbCUcV4Kd4FQzVSHkKx9nmU7sNjBMPa96b9g3KTSJTAvTsTcT5mYDz97fUppvd".try_into().unwrap()
        ]
    ).unwrap();

    let account_name = "Resident taproot account";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
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

#[test]
fn test_handle_sign_psbt_identity_key_failures() {
    // Case 1: wrong PoR, valid output signature ==> rejected with InvalidProofOfRegistration.
    let psbt_b64 = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAJqgrDKRos0I/UumLXE7d5tvVkt7zHndvnarnKUN1Ge9HJhmQuQMoaf/vKtO65UgQ455M/uN77Q1CWn7Wb9AfsQABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";
    let psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();
    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ));
    assert_eq!(result, Err(Error::InvalidProofOfRegistration));

    // Case 2: valid PoR, but the Schnorr signature over the output script is invalid ==> rejected with InvalidIdentitySignature.
    let psbt_b64 = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvuFIxVHknuLpQ/zP3rTZie8gIyZjCHfUXcOEGSDcFFboAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAEREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";
    let psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();
    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ));
    assert_eq!(result, Err(Error::InvalidIdentitySignature));
}

#[test]
fn test_handle_sign_psbt_identity_key_success() {
    let psbt_b64 = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvuFIxVHknuLpQ/zP3rTZie8gIyZjCHfUXcOEGSDcFFboAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAR5l6X7yUsuUpkyekIKx81HNmEE3mnqVB7/5A1UpjtZuvx0c2N93OOf6HvpNKpvounBUpNoOYTRJvVhKqqrl/KgABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";
    let psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();
    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ));

    assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
}

/// A PSBT for `tr(musig(@0,@1)/**)` whose participant xpubs the device
/// doesn't control. The musig branch should fire (no longer silently
/// skipped) and produce no output — empty `signatures`, `musig_pubnonces`
/// and `musig_partial_sigs`.
///
/// The cosigner xpubs match the C reference app's
/// `tests/test_musig2.py::test_musig2_hotsigner_keypath`; the witness UTXO
/// scriptPubKey at `(is_change=false, address_index=3)` is taken verbatim
/// from the same test.
#[test]
fn test_handle_sign_psbt_musig_no_local_participant() {
    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
    use bitcoin::{
        absolute, secp256k1::XOnlyPublicKey, transaction, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            // P2WPKH to a dummy address — must be an addressable script.
            script_pubkey: ScriptBuf::from_bytes(
                hex!("0014" "00112233445566778899aabbccddeeff00112233").to_vec(),
            ),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    // The previous output: a P2TR locked to the musig aggregate at
    // (is_change=false, address_index=3). The scriptPubKey is the value
    // independently re-derived in `common::script::tests::tr_musig_keypath_to_script`.
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: ScriptBuf::from_bytes(
            hex!("5120c1fdfebed063aa148340c45132e6718d8de81466ae2b90929e3d9328364cd6ed").to_vec(),
        ),
    });
    // BIP-373 tap_bip32_derivation: keyed by the BIP-32-tweaked aggregate
    // x-only key; fingerprint is the synthetic BIP-388 aggregate xpub's
    // BIP-32 fingerprint.
    let agg_xonly = XOnlyPublicKey::from_slice(&hex!(
        "9066461650209f8bbc59b05af5d1615c50f5f79c188d7be742fd932252f68f0c"
    ))
    .unwrap();
    let agg_fpr = Fingerprint::from(hex!("5b8fbc93"));
    let path = DerivationPath::from(vec![
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 3 },
    ]);
    psbt.inputs[0]
        .tap_key_origins
        .insert(agg_xonly, (vec![], (agg_fpr, path)));

    let wallet_policy = WalletPolicy::new(
        "tr(musig(@0,@1)/**)",
        vec![
            "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
                .try_into()
                .unwrap(),
            "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"
                .try_into()
                .unwrap(),
        ],
    )
    .unwrap();

    let account_name = "Musig for my ears";
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    let response = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ))
    .unwrap();

    match response {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
        } => {
            assert!(
                signatures.is_empty(),
                "no plain placeholders ⇒ no signatures"
            );
            assert!(
                musig_pubnonces.is_empty(),
                "no local participants ⇒ no pubnonces"
            );
            assert!(
                musig_partial_sigs.is_empty(),
                "no local participants ⇒ no partial sigs"
            );
        }
        _ => panic!("Expected PsbtSigned response"),
    }
}

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    absolute, transaction, Amount, OutPoint, Sequence, TapSighashType, Transaction, TxIn, Txid,
};
use common::bip388::{KeyInformation, KeyOrigin};
use common::musig as musig_lib;
use std::str::FromStr;

/// Hot cosigner xprv (BIP-32 master) used by these tests. Same key as the
/// C reference's `test_musig2.py::test_musig2_hotsigner_keypath`.
const COSIGNER_XPRV: &str = "tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz";

/// BIP-32 path the device-controlled cosigner xpub claims to live at.
/// Any non-hardened-only path will do; the device just needs to be able to
/// re-derive it locally from its master seed.
const DEVICE_PATH: [u32; 4] = [0x80000030, 0x80000001, 0x80000000, 0x80000002];

/// Builds the device's xpub at [`DEVICE_PATH`] by re-deriving from the
/// host-side SDK's master.
fn device_xpub() -> Xpub {
    let node = sdk::curve::Secp256k1::derive_hd_node(&DEVICE_PATH).unwrap();
    let compressed = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*node.privkey)
        .to_public_key()
        .to_compressed();
    Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: 4,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Hardened { index: 2 },
        public_key: bitcoin::secp256k1::PublicKey::from_slice(&compressed).unwrap(),
        chain_code: ChainCode::from(node.chaincode),
    }
}

fn cosigner_xprv() -> Xpriv {
    Xpriv::from_str(COSIGNER_XPRV).unwrap()
}

fn cosigner_xpub(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Xpub {
    Xpub::from_priv(secp, &cosigner_xprv())
}

/// Builds the 2-of-2 keypath wallet policy `tr(musig(@0,@1)/**)` where
/// `@0` is device-controlled (with origin info) and `@1` is the bare hot
/// cosigner xpub. The exact origin path doesn't matter as long as the
/// device can re-derive it locally.
fn make_2of2_keypath_policy() -> WalletPolicy {
    let secp = Secp256k1::new();
    let standard_fpr = sdk::curve::Secp256k1::get_master_fingerprint();
    let key_info_0 = KeyInformation {
        pubkey: device_xpub(),
        origin_info: Some(KeyOrigin {
            fingerprint: standard_fpr,
            derivation_path: DEVICE_PATH.iter().map(|&n| ChildNumber::from(n)).collect(),
        }),
    };
    let key_info_1 = KeyInformation {
        pubkey: cosigner_xpub(&secp),
        origin_info: None,
    };
    WalletPolicy::new("tr(musig(@0,@1)/**)", vec![key_info_0, key_info_1]).unwrap()
}

/// Constructs a one-input/one-output PSBT for the given wallet policy at
/// `(is_change=false, address_index)`. The output is a dummy P2WPKH. The
/// witness UTXO scriptPubKey is derived via the wallet policy itself so
/// `analyze_transaction` accepts the PSBT.
fn build_musig_keypath_psbt(wallet_policy: &WalletPolicy, address_index: u32) -> Psbt {
    let secp = Secp256k1::new();
    let expected_script = wallet_policy.to_script(false, address_index).unwrap();

    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x42; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(
                hex!("0014" "00112233445566778899aabbccddeeff00112233").to_vec(),
            ),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        value: Amount::from_sat(60_000),
        script_pubkey: expected_script,
    });

    // Inject the BIP-373 tap_bip32_derivation entry for the BIP-32-tweaked
    // aggregate, keyed by its xonly key and tagged with the aggregate
    // xpub's BIP-32 fingerprint.
    let participant_xpubs: Vec<Xpub> = wallet_policy
        .key_information()
        .iter()
        .map(|ki| ki.pubkey)
        .collect();
    let agg_xpub = musig_lib::aggregate_xpub(&participant_xpubs).unwrap();
    let path = vec![
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal {
            index: address_index,
        },
    ];
    let agg_child = agg_xpub
        .derive_pub(&secp, &path.iter().copied().collect::<DerivationPath>())
        .unwrap();
    let agg_xonly: [u8; 32] = agg_child.public_key.x_only_public_key().0.serialize();
    psbt.inputs[0].tap_key_origins.insert(
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&agg_xonly).unwrap(),
        (vec![], (agg_xpub.fingerprint(), DerivationPath::from(path))),
    );

    psbt
}

/// Inserts a BIP-373 `PSBT_IN_MUSIG2_PUB_NONCE` entry into `psbt.inputs[0].unknown`.
/// Key layout (per BIP-373): `0x1B || participant_pk(33) || agg_pk(33)`
/// — leaf_hash is omitted for keypath spends.
fn insert_pubnonce(
    psbt: &mut Psbt,
    participant_pk: &[u8; 33],
    agg_pk: &[u8; 33],
    pubnonce: &[u8; 66],
) {
    let mut keydata = Vec::with_capacity(66);
    keydata.extend_from_slice(participant_pk);
    keydata.extend_from_slice(agg_pk);
    psbt.inputs[0].unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0x1B,
            key: keydata,
        },
        pubnonce.to_vec(),
    );
}

/// Off-device emulation of the hot cosigner. Per BIP-388, MuSig2 signing
/// uses the cosigner's *master* xpub (the one listed in `keys_info`); the
/// `(change, address_index)` derivation is applied via session tweaks,
/// not by deriving children.
fn cosigner_master_round1(
    agg_xonly_tweaked: &[u8; 32],
    rand_root: &[u8; 32],
) -> ([u8; 33], musig_lib::SecNonce, musig_lib::PubNonce, [u8; 32]) {
    let secp = Secp256k1::new();
    let xpriv = cosigner_xprv();
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let participant_pk: [u8; 33] = xpub.public_key.serialize();
    let sk: [u8; 32] = xpriv.private_key.secret_bytes();
    let (secnonce, pubnonce) =
        musig_lib::nonce_gen(rand_root, &participant_pk, agg_xonly_tweaked).unwrap();
    (participant_pk, secnonce, pubnonce, sk)
}

/// Full 2-of-2 keypath MuSig2 round trip through `handle_sign_psbt`,
/// finishing with an aggregated 64-byte Schnorr signature that verifies
/// under the BIP-341-tweaked aggregate.
#[test]
fn test_handle_sign_psbt_musig_2of2_keypath_round_trip() {
    musig_signing::reset_storage_for_tests();

    let address_index: u32 = 7;
    let wallet_policy = make_2of2_keypath_policy();
    let account_name = "Musig 2-of-2 keypath";

    let mut psbt = build_musig_keypath_psbt(&wallet_policy, address_index);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    // ---- Round 1 ----
    let r1 = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ))
    .unwrap();
    let device_pubnonce = match r1 {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
        } => {
            assert!(signatures.is_empty());
            assert!(musig_partial_sigs.is_empty());
            assert_eq!(musig_pubnonces.len(), 1, "expected one device pubnonce");
            musig_pubnonces.into_iter().next().unwrap()
        }
        _ => panic!("Expected PsbtSigned"),
    };
    let agg_pk: [u8; 33] = device_pubnonce.aggregate_pubkey;
    // The BIP-340 verifier key is the agg key with even-y prefix (BIP-341).
    let agg_xonly: [u8; 32] = agg_pk[1..].try_into().unwrap();

    // ---- Off-device: compute cosigner's pubnonce ----
    let (cosigner_pk, _cosigner_secnonce, cosigner_pubnonce, cosigner_sk) =
        cosigner_master_round1(&agg_xonly, &[0xAB; 32]);

    // ---- Inject both pubnonces and run Round 2 ----
    insert_pubnonce(
        &mut psbt,
        &device_pubnonce.participant_pk,
        &agg_pk,
        &device_pubnonce.pubnonce,
    );
    insert_pubnonce(&mut psbt, &cosigner_pk, &agg_pk, &cosigner_pubnonce.0);

    let r2 = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ))
    .unwrap();
    let device_psig = match r2 {
        Response::PsbtSigned {
            signatures,
            musig_pubnonces,
            musig_partial_sigs,
        } => {
            assert!(signatures.is_empty());
            assert!(musig_pubnonces.is_empty());
            assert_eq!(musig_partial_sigs.len(), 1);
            musig_partial_sigs.into_iter().next().unwrap()
        }
        _ => panic!("Expected PsbtSigned"),
    };

    // ---- Off-device: cosigner's partial signature ----
    // Reproduce the per-input info to get tweaks/keys/order; the cosigner
    // and device run the exact same protocol, so they share the SessionContext.
    let placeholder = wallet_policy
        .descriptor_template()
        .placeholders()
        .next()
        .unwrap()
        .0
        .clone();
    let info = musig_signing::compute_per_input_info(
        wallet_policy.key_information(),
        &placeholder,
        false,
        address_index,
        musig_signing::SpendPath::Keypath { taptree_hash: None },
    )
    .unwrap();
    let aggnonce = musig_lib::nonce_agg(&[
        musig_lib::PubNonce(device_pubnonce.pubnonce),
        cosigner_pubnonce,
    ])
    .unwrap();
    // Sighash — both sides compute it the same way.
    let prevouts = vec![psbt.inputs[0].witness_utxo.clone().unwrap()];
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    let sighash: [u8; 32] = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .unwrap()
        .to_byte_array();

    let tweaks_slice = &info.tweaks[..info.n_tweaks];
    let is_xonly_slice = &info.is_xonly[..info.n_tweaks];
    let sctx = musig_lib::SessionContext {
        aggnonce: &aggnonce,
        pubkeys: &info.keys,
        tweaks: tweaks_slice,
        is_xonly: is_xonly_slice,
        msg: &sighash,
    };
    // The cosigner must hand `nonce_gen` a fresh secnonce, since `sign`
    // consumes it; re-derive deterministically from the same rand_root.
    let (_, cosigner_secnonce_recomputed, _, _) = cosigner_master_round1(&agg_xonly, &[0xAB; 32]);
    let cosigner_psig = musig_lib::sign(cosigner_secnonce_recomputed, &cosigner_sk, &sctx).unwrap();

    // ---- Aggregate the two partial signatures and verify ----
    let final_sig =
        musig_lib::partial_sig_agg(&sctx, &[device_psig.signature, cosigner_psig]).unwrap();
    // The BIP-340 verifier key has prefix 0x02 (even-y) and the x of the
    // taptweaked aggregate.
    let mut verifier_pk = [0u8; 33];
    verifier_pk[0] = 0x02;
    verifier_pk[1..].copy_from_slice(&agg_pk[1..]);
    let pk_for_verify =
        EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(&verifier_pk).unwrap();
    pk_for_verify
        .schnorr_verify(&sighash, &final_sig)
        .expect("aggregated MuSig2 Schnorr signature must verify under the taptweaked aggregate");
}

/// Round 2 without a prior round 1 → the device has no session in
/// persistent storage and must error cleanly.
#[test]
fn test_handle_sign_psbt_musig_round2_without_round1_errors() {
    musig_signing::reset_storage_for_tests();

    let address_index: u32 = 11;
    let wallet_policy = make_2of2_keypath_policy();
    let account_name = "Musig negative test #1";

    let mut psbt = build_musig_keypath_psbt(&wallet_policy, address_index);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    // Compute what the agg_pk would be so we can inject pubnonces under
    // the right BIP-373 key — the device will *try* to enter round 2.
    let placeholder = wallet_policy
        .descriptor_template()
        .placeholders()
        .next()
        .unwrap()
        .0
        .clone();
    let info = musig_signing::compute_per_input_info(
        wallet_policy.key_information(),
        &placeholder,
        false,
        address_index,
        musig_signing::SpendPath::Keypath { taptree_hash: None },
    )
    .unwrap();
    let agg_pk = info.agg_key_tweaked;
    let agg_xonly: [u8; 32] = agg_pk[1..].try_into().unwrap();

    // Both pubnonces must be present so the handler ENTERS round 2; it
    // then fails because there's no persisted session. We use *master*
    // participant pks (BIP-388 musig signs with master keys).
    let device_master_pk = {
        let n = sdk::curve::Secp256k1::derive_hd_node(&DEVICE_PATH).unwrap();
        EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*n.privkey)
            .to_public_key()
            .to_compressed()
    };
    let (_sn_dev, pn_dev) =
        musig_lib::nonce_gen(&[0xDEu8; 32], &device_master_pk, &agg_xonly).unwrap();
    let (cosigner_pk, _, cosigner_pubnonce, _) = cosigner_master_round1(&agg_xonly, &[0xCDu8; 32]);
    insert_pubnonce(&mut psbt, &device_master_pk, &agg_pk, &pn_dev.0);
    insert_pubnonce(&mut psbt, &cosigner_pk, &agg_pk, &cosigner_pubnonce.0);

    // No prior round 1 ⇒ no session in storage ⇒ MissingMusigSession.
    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ));
    assert_eq!(result, Err(Error::MissingMusigSession));
}

/// Round 2 with the device's own pubnonce in the PSBT but the cosigner's
/// missing → the device should error with `MissingMusigPubnonce`.
#[test]
fn test_handle_sign_psbt_musig_round2_missing_cosigner_pubnonce_errors() {
    musig_signing::reset_storage_for_tests();

    let address_index: u32 = 13;
    let wallet_policy = make_2of2_keypath_policy();
    let account_name = "Musig negative test #2";

    let mut psbt = build_musig_keypath_psbt(&wallet_policy, address_index);
    let por =
        ProofOfRegistration::new(&wallet_policy.registration_id(account_name)).dangerous_as_bytes();
    prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

    // ---- Round 1 (real) ----
    let r1 = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ))
    .unwrap();
    let device_pubnonce = match r1 {
        Response::PsbtSigned {
            musig_pubnonces, ..
        } => musig_pubnonces.into_iter().next().unwrap(),
        _ => panic!(),
    };
    let agg_pk = device_pubnonce.aggregate_pubkey;

    // Inject ONLY the device's pubnonce → the device should detect the
    // cosigner's missing and fail.
    insert_pubnonce(
        &mut psbt,
        &device_pubnonce.participant_pk,
        &agg_pk,
        &device_pubnonce.pubnonce,
    );

    let result = sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(&psbt),
    ));
    assert_eq!(result, Err(Error::MissingMusigPubnonce));
}
