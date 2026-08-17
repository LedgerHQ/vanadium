//! End-to-end test of signing a transaction whose external output is authenticated by a
//! DNS-anchored identity key (see `docs/dns-identity.md`).
//!
//! This is the only test of the **success** path. Everything else covers rejections, because a chain
//! that validates cannot be synthesised: validation goes to the real IANA root trust anchors, so a
//! real published record is required.
//!
//! It is therefore driven by environment variables and skips when they are unset, so it never breaks
//! CI. See `docs/dns-identity.md` for the full runbook; in short:
//!
//! ```text
//! # 1. read the device's identity public key, and publish it
//! vnd_bitcoin_cli --hid
//! ₿ get-identity-key --index 0
//! ₿ make-dns-identity-record you@example.com --pubkey <33-byte hex>
//! #    ... publish the printed TXT record in your DNSSEC-signed zone ...
//!
//! # 2. capture the proof
//! ₿ fetch-dns-identity you@example.com --out /tmp/you.chain
//!
//! # 3. run this test against a device or Speculos
//! export VND_DNS_IDENTITY_NAME=you@example.com
//! export VND_DNS_IDENTITY_CHAIN=/tmp/you.chain
//! cargo test --features speculos-tests --test dns_identity_e2e -- --nocapture
//! ```
//!
//! The captured chain does not go stale for this test. The device has no clock and checks the
//! signature validity window against the time the client sends, so the test pins that time to the
//! middle of the captured window. Only a run against the true current time needs a fresh capture,
//! and not because of your zone: the chain also carries the root's and the TLD's signatures, which
//! are re-issued every few days whatever validity the leaf zone is configured with.

#![cfg(feature = "speculos-tests")]

use base64::{self, Engine};
use bitcoin::{Address, Psbt};
use common::{
    message::{Account, AccountCoordinates, WalletPolicyCoordinates},
    psbt::{prepare_psbt, PsbtOutputAuthWrite},
};
use sdk::test_utils::{setup_test, TestSetup};
use std::str::FromStr;

use vnd_bitcoin_client::dns_identity::{
    add_identity_proof_to_psbt, validate_identity_proof, DnsIdentityProof,
};
use vnd_bitcoin_client::BitcoinClient;

async fn setup() -> TestSetup<BitcoinClient> {
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

fn serialize_as_psbtv2(psbt: &Psbt) -> Vec<u8> {
    common::psbt::psbt_v0_to_v2(&psbt.serialize()).expect("Failed to convert PSBTv0 to PSBTv2")
}

/// The published proof under test, or `None` if the environment does not provide one.
fn published_proof() -> Option<DnsIdentityProof> {
    let (Ok(name), Ok(path)) = (
        std::env::var("VND_DNS_IDENTITY_NAME"),
        std::env::var("VND_DNS_IDENTITY_CHAIN"),
    ) else {
        eprintln!(
            "skipping: set VND_DNS_IDENTITY_NAME and VND_DNS_IDENTITY_CHAIN to run this test \
             (see the module docs for the runbook)"
        );
        return None;
    };

    let chain = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {}", path, e));
    // No time check here: the point is that a captured chain stays usable after its window has
    // passed. The device still enforces the window, against the time we pin below.
    let proof = validate_identity_proof(&name, chain, 0, None)
        .unwrap_or_else(|e| panic!("the captured chain for {} does not validate: {}", name, e));

    println!(
        "₿{} publishes {} (chain {} bytes, valid {}..{})",
        proof.hrn,
        hex::encode(proof.pubkey),
        proof.chain.len(),
        proof.valid_from,
        proof.expires
    );
    Some(proof)
}

/// A time inside the captured chain's own validity window, which is what the device is told "now"
/// is. Pinning it here is what keeps the test reproducible after the chain has expired in reality.
fn pinned_time(proof: &DnsIdentityProof) -> u64 {
    proof.valid_from + (proof.expires - proof.valid_from) / 2
}

/// The wallet policy used to produce a signable input, and to derive an address the device can
/// attest to. Same one as the plain signing integration test.
const DESCRIPTOR_TEMPLATE: &str = "tr(@0/**)";
const KEY_INFO: &str = "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U";
const PSBT_B64: &str = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";

/// Builds the transaction under test: one input spending a registered account, and one external
/// output which the device can authenticate.
///
/// The attested address belongs to the same account, which is what lets a single device play both
/// payer and payee: `get_address` hands back an address together with a signature over its script,
/// and because that output carries no `ACCOUNT` coordinates the device treats it as external and
/// looks for exactly that attestation.
async fn build_attested_psbt(
    client: &mut BitcoinClient,
    proof: &DnsIdentityProof,
) -> Vec<u8> {
    let wallet_policy = common::bip388::WalletPolicy::new(
        DESCRIPTOR_TEMPLATE,
        vec![common::bip388::KeyInformation::try_from(KEY_INFO).unwrap()],
    )
    .unwrap();
    let account = Account::WalletPolicy(wallet_policy.clone());
    let account_name = "My taproot account #0";

    let (_, por) = client
        .register_account(account_name, &account, None, None, false)
        .await
        .expect("failed to register the account");

    // An address of this account, plus an identity signature over its scriptPubKey.
    let coords = AccountCoordinates::WalletPolicy(WalletPolicyCoordinates {
        is_change: false,
        address_index: 7,
    });
    let (address, identity_sig) = client
        .get_address(&account, account_name, &coords, Some(&por), false, Some(0))
        .await
        .expect("failed to get an attested address");
    let identity_sig = identity_sig.expect("device returned no identity signature");

    let signing_pubkey: [u8; 33] = identity_sig
        .identity_pubkey
        .as_slice()
        .try_into()
        .expect("identity pubkey must be 33 bytes");
    assert_eq!(
        signing_pubkey, proof.pubkey,
        "the device's identity key at index 0 is {}, but ₿{} publishes {}. \
         Publish the device's key, or point the test at the matching name.",
        hex::encode(signing_pubkey),
        proof.hrn,
        hex::encode(proof.pubkey),
    );

    let mut psbt = Psbt::deserialize(
        &base64::engine::general_purpose::STANDARD
            .decode(PSBT_B64)
            .unwrap(),
    )
    .unwrap();
    prepare_psbt(
        &mut psbt,
        &[(&wallet_policy, &account_name, &por.dangerous_as_bytes())],
    )
    .unwrap();

    // Redirect the external output to the attested address. It is the output the wallet policy does
    // not derive, so `prepare_psbt` left it without coordinates.
    let external = psbt
        .outputs
        .iter()
        .position(|o| o.bip32_derivation.is_empty() && o.tap_key_origins.is_empty())
        .expect("the test PSBT should have exactly one external output");
    let script = Address::from_str(&address)
        .expect("device returned an unparseable address")
        .assume_checked()
        .script_pubkey();
    psbt.unsigned_tx.output[external].script_pubkey = script;

    let sig: [u8; 64] = identity_sig
        .signature
        .as_slice()
        .try_into()
        .expect("identity signature must be 64 bytes");
    psbt.outputs[external]
        .add_auth_proof(&common::psbt::OutputAuthProof::IdentitySignature {
            pubkey: signing_pubkey,
            sig,
        })
        .unwrap();

    add_identity_proof_to_psbt(&mut psbt, proof).unwrap();

    serialize_as_psbtv2(&psbt)
}

/// The success path: the device validates the chain, accepts the attestation, and signs.
///
/// If it displays the output as anything other than `₿<name>`, that is a UI bug this test cannot
/// see; watch the screen when running against a device built without `autoapprove`.
#[tokio::test]
async fn test_e2e_sign_with_dns_authenticated_output() {
    let Some(proof) = published_proof() else {
        return;
    };
    let mut setup = setup().await;
    let psbt = build_attested_psbt(&mut setup.client, &proof).await;

    let result = setup
        .client
        .sign_psbt(&psbt, Some(pinned_time(&proof)))
        .await
        .expect("signing a DNS-authenticated transaction failed");

    assert_eq!(result.signatures.len(), 1);
}

/// The device must not be willing to sign the same transaction once the proof is tampered with.
#[tokio::test]
async fn test_e2e_rejects_tampered_chain() {
    let Some(mut proof) = published_proof() else {
        return;
    };
    let mut setup = setup().await;

    // Corrupt a byte near the end of the chain, which lands in a signature or a record rather than
    // in the framing, so the failure is a validation failure and not a parse error.
    let last = proof.chain.len() - 8;
    proof.chain[last] ^= 0x01;

    let psbt = build_attested_psbt(&mut setup.client, &proof).await;
    let result = setup.client.sign_psbt(&psbt, Some(pinned_time(&proof))).await;

    assert!(
        result.is_err(),
        "the device signed a transaction whose DNSSEC proof had been tampered with"
    );
}

/// A proof outside its validity window must be refused, which is what stops a host replaying a
/// long-expired binding for a key that has since been rotated away.
#[tokio::test]
async fn test_e2e_rejects_expired_proof() {
    let Some(proof) = published_proof() else {
        return;
    };
    let mut setup = setup().await;
    let psbt = build_attested_psbt(&mut setup.client, &proof).await;

    // An hour past expiry is still inside BIP-353's skew allowance; a day past it is not.
    let result = setup
        .client
        .sign_psbt(&psbt, Some(proof.expires + 86_400))
        .await;

    assert!(
        result.is_err(),
        "the device accepted a DNSSEC proof a day past its expiry"
    );
}
