#![cfg(feature = "speculos-tests")]

use base64::{self, Engine};
use bitcoin::Psbt;
use common::{
    message::{Account, KeyTree},
    psbt::{prepare_psbt, SigningPolicy, ENGINE_ID_PROGRAM},
};
use sdk::test_utils::{setup_test, TestSetup};

use vnd_bitcoin_client::{insert_signing_policies, BitcoinClient};

pub async fn setup() -> TestSetup<BitcoinClient> {
    let vanadium_binary = std::env::var("VANADIUM_BINARY")
        .unwrap_or_else(|_| "../../../vm/target/flex/release/app-vanadium".to_string());
    let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
        "../app/target/riscv32imac-unknown-none-elf/release/vnd-bitcoin".to_string()
    });
    setup_test(&vanadium_binary, &vapp_binary, |transport| {
        BitcoinClient::new(transport)
    })
    .await
}

// parse the keys_info arg in the format "key_info1, key_info2, ..."
pub fn parse_keys_info(
    keys_info: &str,
) -> Result<Vec<common::bip388::KeyInformation>, &'static str> {
    let keys_info = keys_info
        .split(',')
        .map(|ki| ki.trim()) // tolerate extra spaces
        .map(|ki| common::bip388::KeyInformation::try_from(ki))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "failed to parse key information")?;

    Ok(keys_info)
}

pub fn parse_wallet_policy(
    descriptor_template: &str,
    keys_info: &[&str],
) -> Result<common::bip388::WalletPolicy, &'static str> {
    let keys = keys_info
        .iter()
        .map(|ki| common::bip388::KeyInformation::try_from(*ki))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Failed to parse key info")?;
    common::bip388::WalletPolicy::new(descriptor_template, keys)
        .map_err(|_| "Failed to build wallet policy")
}

fn serialize_as_psbtv2(psbt: &Psbt) -> Vec<u8> {
    common::psbt::psbt_v0_to_v2(&psbt.serialize()).expect("Failed to convert PSBTv0 to PSBTv2")
}

#[tokio::test]
async fn test_get_fingerprint() {
    let mut setup = setup().await;

    let fpr = setup
        .client
        .get_master_fingerprint(KeyTree::Standard)
        .await
        .unwrap();
    assert_eq!(fpr, 0xf5acc2fd);
}

#[tokio::test]
async fn test_e2e_sign_transaction() {
    // this test registers a taproot wallet account and uses it to sign a PSBT
    let mut setup = setup().await;
    let client = &mut setup.client;

    let psbt_b64 = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";
    let mut psbt = Psbt::deserialize(
        &base64::engine::general_purpose::STANDARD
            .decode(&psbt_b64)
            .unwrap(),
    )
    .unwrap();

    let descriptor_template = "tr(@0/**)";
    let keys_info = vec![
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
    ];
    let wallet_policy = parse_wallet_policy(descriptor_template, &keys_info).unwrap();

    let account_name = "My taproot account #0";
    let (_, por) = client
        .register_account(
            account_name,
            &Account::WalletPolicy(wallet_policy.clone()),
            Vec::new(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
    println!("Registered account, got POR: {:?}", por);

    prepare_psbt(
        &mut psbt,
        &[(&wallet_policy, &account_name, &por.dangerous_as_bytes())],
    )
    .unwrap();

    let result = client.sign_psbt(&serialize_as_psbtv2(&psbt)).await.unwrap();

    // we don't check the actual signatures here, just that we got something back
    // more detailed tests are in the unit tests of the handlers
    assert!(result.signatures.len() == 1);
}

#[tokio::test]
async fn test_e2e_policy_bound_account() {
    const POLICY_SOURCE: &[u8] =
        b"if context.fee * 10 > context.inputs_total { fail(); } approve();";
    // 100,000 sat input, 90,000 sat output: fee is exactly 10%.
    const ACCEPTED_PSBT: &str = "cHNidP8BAFICAAAAAUJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAAAAAD9////AZBfAQAAAAAAFgAUABEiM0RVZneImaq7zN3u/wARIjMAAAAAAAEBH6CGAQAAAAAAFgAUZCGSqhOGRG5T7JrfZjrFIkQGd0YiBgN+E+ybnEy9PF8m0A14dKIwiEvsmggVBrrQSF9B+J7Obxj1rML9VAAAgAEAAIAAAACAAAAAAAAAAAAAAA==";
    // 100,000 sat input, 89,999 sat output: fee is 10% plus one satoshi.
    const REJECTED_PSBT: &str = "cHNidP8BAFICAAAAAUJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAAAAAD9////AY9fAQAAAAAAFgAUABEiM0RVZneImaq7zN3u/wARIjMAAAAAAAEBH6CGAQAAAAAAFgAUZCGSqhOGRG5T7JrfZjrFIkQGd0YiBgN+E+ybnEy9PF8m0A14dKIwiEvsmggVBrrQSF9B+J7Obxj1rML9VAAAgAEAAIAAAACAAAAAAAAAAAAAAA==";

    let mut setup = setup().await;
    let client = &mut setup.client;

    let signing_policy = SigningPolicy::new(ENGINE_ID_PROGRAM, 0, POLICY_SOURCE.to_vec());
    let policy_hash = hex::encode(signing_policy.hash());
    let key_info = format!(
        "[f5acc2fd/84'/1'/0'/{}]tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
        policy_hash
    );
    let wallet_policy = parse_wallet_policy("wpkh(@0/**)", &[key_info.as_str()]).unwrap();
    let account_name = "Policy-bound account";

    let (_, por) = client
        .register_account(
            account_name,
            &Account::WalletPolicy(wallet_policy.clone()),
            vec![signing_policy.clone()],
            None,
            None,
            false,
        )
        .await
        .unwrap();

    let mut psbt = Psbt::deserialize(
        &base64::engine::general_purpose::STANDARD
            .decode(ACCEPTED_PSBT)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(psbt.inputs[0].bip32_derivation.len(), 1);
    let expected_pubkey = psbt.inputs[0]
        .bip32_derivation
        .keys()
        .next()
        .unwrap()
        .serialize()
        .to_vec();
    prepare_psbt(
        &mut psbt,
        &[(&wallet_policy, account_name, &por.dangerous_as_bytes())],
    )
    .unwrap();
    let psbt = insert_signing_policies(
        &serialize_as_psbtv2(&psbt),
        std::slice::from_ref(&signing_policy),
    )
    .unwrap();

    let result = client.sign_psbt(&psbt).await.unwrap();
    assert_eq!(result.signatures.len(), 1, "a 10% fee must be accepted");
    assert_eq!(result.signatures[0].input_index, 0);
    assert_eq!(result.signatures[0].pubkey, expected_pubkey);
    assert!(!result.signatures[0].signature.is_empty());

    let mut psbt = Psbt::deserialize(
        &base64::engine::general_purpose::STANDARD
            .decode(REJECTED_PSBT)
            .unwrap(),
    )
    .unwrap();
    prepare_psbt(
        &mut psbt,
        &[(&wallet_policy, account_name, &por.dangerous_as_bytes())],
    )
    .unwrap();
    let psbt = insert_signing_policies(
        &serialize_as_psbtv2(&psbt),
        std::slice::from_ref(&signing_policy),
    )
    .unwrap();

    let result = client.sign_psbt(&psbt).await.unwrap();
    assert!(
        result.signatures.is_empty(),
        "a fee above 10% must be denied"
    );
}
