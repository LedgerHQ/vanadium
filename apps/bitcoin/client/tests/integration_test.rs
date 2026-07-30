#![cfg(feature = "speculos-tests")]

use base64::{self, Engine};
use bitcoin::Psbt;
use common::{
    message::{Account, KeyTree},
    psbt::prepare_psbt,
};
use sdk::test_utils::{setup_test, TestSetup};

use vnd_bitcoin_client::BitcoinClient;

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
            vec![],
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

/// A minimal `.vpol` image whose program immediately exits with `decision`.
///
/// Hand-assembled rather than built with the policy SDK, so this test does not
/// depend on a RISC-V toolchain being present.
fn exit_image(decision: u32) -> Vec<u8> {
    const EXIT: u32 = 0x0001;
    let addi = |rd: u32, imm: u32| (imm & 0xFFF) << 20 | rd << 7 | 0x13;
    let code: Vec<u8> = [addi(5, EXIT), addi(10, decision), 0x0000_0073]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();

    let mut img = Vec::new();
    img.extend_from_slice(b"VPOL");
    img.push(0); // abi_version
    img.push(0); // flags
    img.push(0); // label_len
    img.push(0); // reserved
    img.extend_from_slice(&0u32.to_le_bytes()); // entrypoint
    img.extend_from_slice(&(code.len() as u32).to_le_bytes()); // code_len
    img.extend_from_slice(&256u32.to_le_bytes()); // data_len
    img.extend_from_slice(&64u32.to_le_bytes()); // state_len
    img.extend_from_slice(&0u32.to_le_bytes()); // data_init_len
    img.extend_from_slice(&1024u32.to_le_bytes()); // stack_len
    img.extend_from_slice(&10_000u32.to_le_bytes()); // step_budget_base
    img.extend_from_slice(&1_000u32.to_le_bytes()); // step_budget_per_input
    img.extend_from_slice(&code);
    img
}

#[tokio::test]
async fn test_e2e_policy_bound_account() {
    // Registers an account whose key is bound to a signing policy, then signs with
    // it twice: once with a policy that approves and once with one that refuses.
    use vnd_bitcoin_client::{
        insert_signing_policies, signing_policy_key_path, SigningPolicy, ENGINE_ID_RISCV,
    };

    let mut setup = setup().await;
    let client = &mut setup.client;

    let fpr = client
        .get_master_fingerprint(KeyTree::Standard)
        .await
        .unwrap();

    // One run per policy: an approving one, then a refusing one.
    for (decision, expected_signatures) in [(2u32, 1usize), (0u32, 0usize)] {
        let policy = SigningPolicy::new(ENGINE_ID_RISCV, 0, exit_image(decision));
        let hash = policy.hash();

        // The key must be derived at the path the program's hash determines.
        let path = signing_policy_key_path(1, 0, &hash);
        let path_str = format_path(&path);
        let xpub = client
            .get_extended_pubkey(KeyTree::Standard, &path_str, false, None)
            .await
            .unwrap()
            .0;
        let xpub = bitcoin::bip32::Xpub::decode(&xpub).unwrap();

        let key_info = format!("[{:08x}/{}]{}", fpr, &path_str[2..], xpub);
        let wallet_policy = parse_wallet_policy("wpkh(@0/**)", &[&key_info]).unwrap();

        let account_name = "Policy account";
        let (_, por) = client
            .register_account(
                account_name,
                &Account::WalletPolicy(wallet_policy.clone()),
                vec![policy.clone()],
                None,
                None,
                false,
            )
            .await
            .unwrap();

        let mut psbt = build_wpkh_psbt(&wallet_policy);
        prepare_psbt(
            &mut psbt,
            &[(&wallet_policy, &account_name, &por.dangerous_as_bytes())],
        )
        .unwrap();

        let raw = insert_signing_policies(&serialize_as_psbtv2(&psbt), &[policy]).unwrap();
        let result = client.sign_psbt(&raw).await.unwrap();

        assert_eq!(
            result.signatures.len(),
            expected_signatures,
            "decision {decision} must yield {expected_signatures} signature(s)"
        );
    }
}

/// Renders a derivation path in descriptor form.
fn format_path(path: &[u32]) -> String {
    let mut out = String::from("m");
    for &step in path {
        out.push('/');
        if step & 0x8000_0000 != 0 {
            out.push_str(&format!("{}\'", step & 0x7FFF_FFFF));
        } else {
            out.push_str(&step.to_string());
        }
    }
    out
}

/// One segwit-v0 input from `wallet_policy` at (change=0, index=0), one external
/// output, with the non-witness UTXO attached so the amount is verified.
fn build_wpkh_psbt(wallet_policy: &common::bip388::WalletPolicy) -> Psbt {
    use bitcoin::bip32::{ChildNumber, DerivationPath};
    use bitcoin::{absolute, transaction, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut};
    use common::script::ToScript as _;

    let spk = wallet_policy.to_script(false, 0).unwrap();
    let prev_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        }],
    };
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_tx.compute_txid(),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(
                hex::decode("001400112233445566778899aabbccddeeff00112233").unwrap(),
            ),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(prev_tx.output[0].clone());
    psbt.inputs[0].non_witness_utxo = Some(prev_tx);

    // prepare_psbt locates the account's inputs through their BIP-32 derivations.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let key_info = &wallet_policy.key_information()[0];
    let origin = key_info.origin_info.as_ref().unwrap();
    let child_steps = [
        ChildNumber::Normal { index: 0 },
        ChildNumber::Normal { index: 0 },
    ];
    let child = key_info
        .pubkey
        .derive_pub(
            &secp,
            &child_steps.iter().copied().collect::<DerivationPath>(),
        )
        .unwrap();
    let mut full_path: Vec<ChildNumber> = origin.derivation_path.iter().copied().collect();
    full_path.extend_from_slice(&child_steps);
    psbt.inputs[0].bip32_derivation.insert(
        child.public_key,
        (
            origin.fingerprint.to_be_bytes().into(),
            full_path.into_iter().collect(),
        ),
    );
    psbt
}
