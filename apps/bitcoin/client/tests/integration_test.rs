#![cfg(feature = "speculos-tests")]

use base64::{self, Engine};
use bitcoin::Psbt;
use common::{message::Account, psbt::prepare_psbt};
use sdk::test_utils::{setup_test, TestSetup};

use vnd_bitcoin_client::BitcoinClient;

pub async fn setup() -> TestSetup<BitcoinClient> {
    let vanadium_binary = std::env::var("VANADIUM_BINARY")
        .unwrap_or_else(|_| "../../../vm/target/flex/release/app-vanadium".to_string());
    let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
        "../app/target/riscv32imc-unknown-none-elf/release/vnd-bitcoin".to_string()
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
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys_info)
}

pub fn parse_wallet_policy(
    descriptor_template: &str,
    keys_info: &[&str],
) -> Result<common::message::WalletPolicy, &'static str> {
    let wallet_policy_msg = common::message::WalletPolicy {
        template: descriptor_template.to_string(),
        keys_info: keys_info
            .iter()
            .map(|ki| {
                let ki = common::bip388::KeyInformation::try_from(*ki).unwrap();
                common::message::PubkeyInfo {
                    pubkey: ki.pubkey.encode().to_vec(),
                    origin: ki
                        .origin_info
                        .as_ref()
                        .map(|origin_info| common::message::KeyOrigin {
                            fingerprint: origin_info.fingerprint,
                            path: common::message::Bip32Path(
                                origin_info
                                    .derivation_path
                                    .iter()
                                    .map(|step| u32::from(*step))
                                    .collect(),
                            ),
                        }),
                }
            })
            .collect(),
    };
    Ok(wallet_policy_msg)
}

fn serialize_as_psbtv2(psbt: &Psbt) -> Vec<u8> {
    common::psbt::psbt_v0_to_v2(&psbt.serialize()).expect("Failed to convert PSBTv0 to PSBTv2")
}

#[tokio::test]
async fn test_get_fingerprint() {
    let mut setup = setup().await;

    let fpr = setup.client.get_master_fingerprint().await.unwrap();
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

    // TODO: simplify this once the client is modified to accept types from common:bip388 instead of common:message
    let descriptor_template = "tr(@0/**)";
    let keys_info = vec![
        "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
    ];
    let wallet_policy = common::bip388::WalletPolicy::new(
        descriptor_template,
        parse_keys_info(&keys_info.join(",")).unwrap(),
    )
    .unwrap();
    let wallet_policy_msg = parse_wallet_policy(descriptor_template, &keys_info).unwrap();

    let account_name = "My taproot account #0";
    let (_, por) = client
        .register_account(account_name, &Account::WalletPolicy(wallet_policy_msg))
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
    assert!(result.len() == 1);
}
