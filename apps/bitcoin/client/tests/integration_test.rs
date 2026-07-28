#![cfg(feature = "speculos-tests")]

use base64::{self, Engine};
use bitcoin::Psbt;
use common::{
    message::{Account, KeyTree},
    psbt::{prepare_psbt, SigningPolicy, ENGINE_ID_PROGRAM},
    script::ToScript,
};
use sdk::test_utils::{setup_test, TestSetup};

use vnd_bitcoin_client::{insert_signing_policies, signing_policy_key_path, BitcoinClient};

/// Format a raw BIP-32 path (top bit marks hardened) as a descriptor string.
fn format_path(path: &[u32]) -> String {
    const HARDENED: u32 = 0x8000_0000;
    path.iter()
        .map(|&s| {
            if s & HARDENED != 0 {
                format!("{}'", s & !HARDENED)
            } else {
                format!("{}", s)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

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
    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
    use bitcoin::hashes::Hash as _;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use std::str::FromStr;

    const POLICY_SOURCE: &[u8] =
        b"if context.fee * 10 > context.inputs_total { fail(); } approve();";

    let mut setup = setup().await;
    let client = &mut setup.client;

    let signing_policy = SigningPolicy::new(ENGINE_ID_PROGRAM, 0, POLICY_SOURCE.to_vec());

    // The signing-policy binding lives entirely in a standard BIP-32 origin path
    // derived from the program hash: m/1347175257'/1'/0'/p1/p2/p3/p4. Fetch the
    // device's real xpub at that path and build an ordinary wallet policy.
    let coin_type: u32 = 1; // testnet
    let account: u32 = 0;
    let path = signing_policy_key_path(coin_type, account, &signing_policy.hash());
    let path_str = format_path(&path);
    let (xpub_bytes, _) = client
        .get_extended_pubkey(KeyTree::Standard, &path_str, false, None)
        .await
        .unwrap();
    let account_xpub = Xpub::decode(&xpub_bytes).unwrap();
    let fpr = client
        .get_master_fingerprint(KeyTree::Standard)
        .await
        .unwrap();

    let key_info = format!("[{:08x}/{}]{}", fpr, path_str, account_xpub);
    let wallet_policy = parse_wallet_policy("tr(@0/**)", &[key_info.as_str()]).unwrap();
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
    let por = por.dangerous_as_bytes();

    // Receiving key at .../0/0 and the input's P2TR scriptPubKey.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let child = account_xpub
        .derive_pub(&secp, &DerivationPath::from_str("m/0/0").unwrap())
        .unwrap();
    let internal_key = child.public_key.x_only_public_key().0;
    let input_spk = wallet_policy.to_script(false, 0).unwrap();
    // For a key-path spend the device signs with the tap-tweaked output key,
    // which is exactly the 32-byte key pushed by the P2TR scriptPubKey
    // (`OP_1 <32-byte output key>`).
    let expected_pubkey = input_spk.as_bytes()[2..].to_vec();
    let full_path = DerivationPath::from_str(&format!("m/{}/0/0", path_str)).unwrap();

    // A 100_000-sat input; the fee is (100_000 - output_value). The policy caps
    // the fee at 10% of inputs, so a 90_000 output (10% fee) is accepted and an
    // 89_999 output (>10% fee) is denied.
    let build_signed = |output_value: u64| {
        let mut external_spk = vec![0x00u8, 0x14];
        external_spk.extend_from_slice(&[0x11u8; 20]);
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x42; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::from_bytes(external_spk),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: input_spk.clone(),
        });
        psbt.inputs[0].tap_key_origins.insert(
            internal_key,
            (
                vec![],
                (Fingerprint::from(fpr.to_be_bytes()), full_path.clone()),
            ),
        );
        prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();
        insert_signing_policies(
            &serialize_as_psbtv2(&psbt),
            std::slice::from_ref(&signing_policy),
        )
        .unwrap()
    };

    // Accepted: 90_000 output ⇒ 10_000 fee = exactly 10%.
    let result = client.sign_psbt(&build_signed(90_000)).await.unwrap();
    assert_eq!(result.signatures.len(), 1, "a 10% fee must be accepted");
    assert_eq!(result.signatures[0].input_index, 0);
    assert_eq!(result.signatures[0].pubkey, expected_pubkey);
    assert!(!result.signatures[0].signature.is_empty());

    // Rejected: 89_999 output ⇒ 10_001 fee > 10%.
    let result = client.sign_psbt(&build_signed(89_999)).await.unwrap();
    assert!(
        result.signatures.is_empty(),
        "a fee above 10% must be denied"
    );
}
