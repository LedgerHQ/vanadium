#![cfg(feature = "speculos-tests")]

use base64::{self, Engine};
use common::{
    message::KeyTree,
    psbt::{prepare_psbt, PsbtV2},
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
    let mut psbt = PsbtV2::from_v0(
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
        .register_account(account_name, &wallet_policy, None, None, false)
        .await
        .unwrap();
    println!("Registered account, got POR: {:?}", por);

    prepare_psbt(
        &mut psbt,
        &[(&wallet_policy, &account_name, &por.dangerous_as_bytes())],
    )
    .unwrap();

    let result = client.sign_psbt(&psbt.serialize()).await.unwrap();

    // we don't check the actual signatures here, just that we got something back
    // more detailed tests are in the unit tests of the handlers
    assert!(result.signatures.len() == 1);
}

#[tokio::test]
async fn test_e2e_send_to_silent_payment_address() {
    // this test registers a segwit account, and pays from it to a silent payment address
    use bitcoin::{
        bip32::{ChildNumber, Xpub},
        hashes::Hash,
        secp256k1::{ecdsa::Signature, Message, Secp256k1},
        sighash::SighashCache,
        Amount, EcdsaSighashType, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
    };
    use common::{
        fastpsbt::{PSBT_OUT_SCRIPT, PSBT_OUT_SP_V0_INFO},
        script::ToScript,
        silent_payments::{self as sp, Secp256k1 as Curve, Secp256k1Point, SilentPaymentCode},
    };

    let mut setup = setup().await;
    let client = &mut setup.client;

    let xpub = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
    let wallet_policy =
        parse_wallet_policy("wpkh(@0/**)", &[&format!("[f5acc2fd/84'/1'/0']{xpub}")]).unwrap();
    let account_name = "My segwit account #0";
    let (_, por) = client
        .register_account(account_name, &wallet_policy, None, None, false)
        .await
        .unwrap();

    // the first address of the BIP-352 test vectors
    let (_, code) = SilentPaymentCode::from_address("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").unwrap();

    let secp = Secp256k1::new();
    let key = xpub
        .parse::<Xpub>()
        .unwrap()
        .derive_pub(&secp, &[ChildNumber::from(0), ChildNumber::from(2)])
        .unwrap()
        .public_key;
    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: wallet_policy.to_script(false, 2).unwrap(),
    };
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            ..Default::default()
        }],
        // the script of the output to the code is a placeholder, removed below
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut psbt_v0 = bitcoin::psbt::Psbt::from_unsigned_tx(tx.clone()).unwrap();
    psbt_v0.inputs[0].witness_utxo = Some(prevout.clone());
    psbt_v0.inputs[0].bip32_derivation.insert(
        key,
        (
            "f5acc2fd".parse().unwrap(),
            "m/84'/1'/0'/0/2".parse().unwrap(),
        ),
    );
    let mut psbt = PsbtV2::from_v0(&psbt_v0.serialize()).unwrap();
    psbt.outputs[0].remove(PSBT_OUT_SCRIPT, &[]);
    psbt.outputs[0].insert(PSBT_OUT_SP_V0_INFO, &[], code.to_bytes().to_vec());
    prepare_psbt(
        &mut psbt,
        &[(&wallet_policy, &account_name, &por.dangerous_as_bytes())],
    )
    .unwrap();

    let result = client.sign_psbt(&psbt.serialize()).await.unwrap();
    assert_eq!(result.signatures.len(), 1);
    assert_eq!(result.sp_shares.len(), 1);
    assert_eq!(result.sp_output_scripts.len(), 1);
    result.merge_into(&mut psbt).unwrap();
    assert_eq!(
        psbt.global
            .get(common::fastpsbt::PSBT_GLOBAL_TX_MODIFIABLE, &[]),
        Some(&[0][..])
    );

    // the share is proven for the input's key, and gives the script of the output
    let share = &result.sp_shares[0];
    assert_eq!(share.scan_key[..], code.to_bytes()[..33]);
    let a = Secp256k1Point::from_compressed(&key.serialize()).unwrap();
    let c = Secp256k1Point::from_compressed(&share.share).unwrap();
    let g = Curve::get_generator();
    assert!(sp::verify_proof(
        &a,
        code.scan(),
        &c,
        &share.dleq_proof,
        &g,
        None
    ));
    let input_hash = sp::input_hash(&[tx.input[0].previous_output], &a).unwrap();
    let secret = sp::shared_secret(&input_hash, &c).unwrap();
    let output_key = sp::output_key(&secret, code.spend(), 0).unwrap();
    let script = psbt.outputs[0].script().unwrap();
    assert_eq!(
        script.as_bytes(),
        [&[0x51, 0x20][..], output_key.x()].concat()
    );

    // the signature is valid for the transaction with that script
    tx.output[0].script_pubkey = script;
    let sighash = SighashCache::new(&tx)
        .p2wpkh_signature_hash(
            0,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    let signature = &result.signatures[0].signature;
    let (_, der) = signature.split_last().unwrap();
    secp.verify_ecdsa(
        &Message::from_digest(sighash.to_byte_array()),
        &Signature::from_der(der).unwrap(),
        &key,
    )
    .unwrap();
}

#[tokio::test]
async fn test_e2e_silent_payment_account() {
    // this test exports the scan key of a silent payment account, registers the account, and gets
    // its addresses
    use bitcoin::{
        bip32::{DerivationPath, Xpriv},
        secp256k1::Secp256k1,
        NetworkKind,
    };
    use common::{
        account::{Account, SilentPaymentCoordinates},
        errors::Error,
        silent_payments::{Secp256k1 as Curve, Secp256k1Scalar},
    };
    use vnd_bitcoin_client::BitcoinClientError;

    let mut setup = setup().await;
    let client = &mut setup.client;

    let account = client.export_silent_payment_scan_key(3).await.unwrap();

    // the keys of the account, from the default seed of Speculos
    let seed = hex::decode("b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564").unwrap();
    let key = |path: &str| {
        let master = Xpriv::new_master(NetworkKind::Test, &seed).unwrap();
        let path: DerivationPath = path.parse().unwrap();
        let key = master.derive_priv(&Secp256k1::new(), &path).unwrap();
        Secp256k1Scalar::from_be_bytes(&key.private_key.secret_bytes()).unwrap()
    };
    assert_eq!(account.account_index(), 3);
    assert_eq!(account.scan_key(), &key("m/352'/1'/3'/1'/0"));
    assert_eq!(
        account.spend_key(),
        &(&Curve::get_generator() * &key("m/352'/1'/3'/0'/0"))
    );

    let name = "Silent payments #3";
    let (_, por) = client
        .register_account(name, &account, None, None, false)
        .await
        .unwrap();

    for label in [None, Some(1)] {
        let coords = SilentPaymentCoordinates::Code { label };
        let (address, identity_sig) = client
            .get_address(&account, name, &coords, Some(&por), false, None)
            .await
            .unwrap();
        assert!(address.starts_with("tsp1"));
        assert_eq!(address, account.get_address(&coords).unwrap());
        assert_eq!(identity_sig, None);
    }

    let change = SilentPaymentCoordinates::Code { label: Some(0) };
    assert!(matches!(
        client
            .get_address(&account, name, &change, Some(&por), false, None)
            .await,
        Err(BitcoinClientError::AppError(
            Error::SilentPaymentChangeLabel
        ))
    ));
}

#[tokio::test]
async fn test_e2e_spend_from_silent_payment_account() {
    // this test registers a silent payment account, finds a payment to it by scanning, and spends
    // it with the change to the account's change label
    use bitcoin::{
        hashes::Hash,
        secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey},
        sighash::{Prevouts, SighashCache},
        Amount, OutPoint, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
    };
    use common::{
        account::{Account, Destination, SilentPaymentCoordinates},
        fastpsbt::{PSBT_IN_SP_TWEAK, PSBT_OUT_SCRIPT, PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL},
        silent_payments::{
            self as sp, Secp256k1 as Curve, Secp256k1Point, Secp256k1Scalar, SilentPaymentCode,
        },
    };

    let mut setup = setup().await;
    let client = &mut setup.client;

    let account = client.export_silent_payment_scan_key(2).await.unwrap();
    let name = "Silent payments #2";
    let (_, por) = client
        .register_account(name, &account, None, None, false)
        .await
        .unwrap();
    let code = |label| -> SilentPaymentCode {
        let coords = SilentPaymentCoordinates::Code { label };
        let Destination::SilentPaymentCode(code) = account.destination(&coords).unwrap() else {
            panic!("not a code");
        };
        code
    };
    let p2tr = |x: &[u8; 32]| ScriptBuf::from_bytes([&[0x51, 0x20][..], x].concat());
    // the sum of the keys of a transaction's only input, a taproot one
    let input_key = |x: &[u8; 32]| {
        Secp256k1Point::from_compressed(&[&[0x02][..], x].concat().try_into().unwrap()).unwrap()
    };

    // a sender pays to the account's address, and scanning finds the tweak of the payment
    let sender_key = Secp256k1Scalar::from_be_bytes(&[0x42; 32]).unwrap();
    let sender_outpoint = OutPoint {
        txid: Txid::from_byte_array([7; 32]),
        vout: 1,
    };
    let payment = sp::create_outputs(&sender_key, &[sender_outpoint], &[code(None)]).unwrap()[0];
    let found = sp::scan(
        account.scan_key(),
        account.spend_key(),
        &(&Curve::get_generator() * &sender_key),
        &[sender_outpoint],
        &[payment],
        &sp::Labels::new(),
    )
    .unwrap();
    let tweak = *found[0].tweak.as_be_bytes();
    let received = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: p2tr(&payment),
    };

    // the account spends it: a payment to a script, and the change to the change label
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([9; 32]),
        vout: 0,
    };
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            ..Default::default()
        }],
        // the script of the change is a placeholder, removed below
        output: vec![
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20])),
            },
            TxOut {
                value: Amount::from_sat(39_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        ],
    };
    let mut psbt_v0 = bitcoin::psbt::Psbt::from_unsigned_tx(tx.clone()).unwrap();
    psbt_v0.inputs[0].witness_utxo = Some(received.clone());
    let mut psbt = PsbtV2::from_v0(&psbt_v0.serialize()).unwrap();
    psbt.inputs[0].insert(PSBT_IN_SP_TWEAK, &[], tweak.to_vec());
    psbt.outputs[1].remove(PSBT_OUT_SCRIPT, &[]);
    psbt.outputs[1].insert(PSBT_OUT_SP_V0_INFO, &[], code(Some(0)).to_bytes().to_vec());
    psbt.outputs[1].insert(PSBT_OUT_SP_V0_LABEL, &[], 0u32.to_le_bytes().to_vec());
    prepare_psbt(&mut psbt, &[(&account, name, &por.dangerous_as_bytes())]).unwrap();

    let result = client.sign_psbt(&psbt.serialize()).await.unwrap();
    assert_eq!(result.signatures.len(), 1);
    assert_eq!(result.sp_shares.len(), 1);
    assert_eq!(result.sp_output_scripts.len(), 1);
    result.merge_into(&mut psbt).unwrap();

    // the signature spends the received output
    let change_script = ScriptBuf::from_bytes(result.sp_output_scripts[0].script.clone());
    tx.output[1].script_pubkey = change_script.clone();
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[received]), TapSighashType::Default)
        .unwrap();
    let signature = &result.signatures[0];
    assert_eq!(signature.pubkey, payment);
    Secp256k1::new()
        .verify_schnorr(
            &Signature::from_slice(&signature.signature).unwrap(),
            &Message::from_digest(sighash.to_byte_array()),
            &XOnlyPublicKey::from_slice(&payment).unwrap(),
        )
        .unwrap();

    // scanning with the account's scan key finds the change
    let change: [u8; 32] = change_script.as_bytes()[2..].try_into().unwrap();
    let mut labels = sp::Labels::new();
    labels.insert(account.scan_key(), 0).unwrap();
    let found = sp::scan(
        account.scan_key(),
        account.spend_key(),
        &input_key(&payment),
        &[outpoint],
        &[change],
        &labels,
    )
    .unwrap();
    assert_eq!(found.len(), 1);
}
