//! End-to-end checks of the DNS-anchored identity key stack against live DNS.
//!
//! These are `#[ignore]`d: they need network access, they depend on records in a third party's zone,
//! and they verify signatures against the real IANA root trust anchors, so they cannot be made
//! hermetic. Run them explicitly:
//!
//! ```text
//! cargo test --test dns_identity_live -- --ignored --nocapture
//! ```
//!
//! They exist because nothing else exercises the whole path — query, RFC 9102 parse, DNSSEC
//! validation to the root, CNAME resolution, and BIP-353's record selection rules — against records
//! that were not produced by this code.

use std::net::SocketAddr;

use common::dns_identity::{hrn_to_dns_name, parse_idkey_param, select_bitcoin_uri};
use common::errors::Error;
use dnssec_prover::rr::RR;
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;
use vnd_bitcoin_client::dns_identity::build_txt_proof_sequentially as build_txt_proof;

fn resolver() -> SocketAddr {
    "1.1.1.1:53".parse().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A BIP-353 record published by the author of that BIP. It carries payment instructions rather than
/// an `idkey`, so it is the right shape to test everything *except* the final parameter lookup.
///
/// The same label also holds a TXT record that does not begin with `bitcoin:`, which BIP-353 requires
/// clients to ignore, so this doubles as a real-world test of that rule.
const KNOWN_BIP353_NAME: &str = "matt@mattcorallo.com";

#[test]
#[ignore = "requires network access and a third-party DNS zone"]
fn live_proof_validates_to_the_root() {
    let dns_name = hrn_to_dns_name(KNOWN_BIP353_NAME).expect("valid name");
    assert_eq!(
        dns_name.as_str(),
        "matt.user._bitcoin-payment.mattcorallo.com."
    );

    let (chain, ttl) = build_txt_proof(resolver(), &dns_name).expect("failed to build proof");
    println!("chain: {} bytes, ttl {}s", chain.len(), ttl);

    let rrs = parse_rr_stream(&chain).expect("failed to parse the chain");
    let verified = verify_rr_stream(&rrs).expect("chain does not validate to the root");
    println!(
        "valid from {} to {} (now {})",
        verified.valid_from, verified.expires, now()
    );
    assert!(verified.valid_from <= now());
    assert!(verified.expires >= now());

    // BIP-353's selection rules: exactly one record beginning with `bitcoin:`, others ignored.
    let txts: Vec<_> = verified
        .resolve_name(&dns_name)
        .into_iter()
        .filter_map(|rr| match rr {
            RR::Txt(txt) => Some(txt),
            _ => None,
        })
        .collect();
    assert!(
        txts.len() >= 2,
        "expected this label to also hold a non-bitcoin: record, found {}",
        txts.len()
    );

    let uri = select_bitcoin_uri(txts.into_iter()).expect("failed to select the bitcoin: record");
    let uri_str = String::from_utf8(uri.clone()).expect("record is valid UTF-8");
    println!("uri: {}", uri_str);
    assert!(uri_str.starts_with("bitcoin:"));

    // This record publishes payment instructions, not an identity key, so the lookup must fail
    // cleanly rather than accepting something else as a key.
    assert_eq!(
        parse_idkey_param(&uri),
        Err(Error::DnsIdentityRecordInvalid)
    );
}

/// The chain a real zone produces must fit within what the device is willing to validate. If this
/// fails for typical zones, MAX_DNSSEC_CHAIN_LEN is set too low to be useful.
#[test]
#[ignore = "requires network access and a third-party DNS zone"]
fn live_proof_fits_the_device_bound() {
    let dns_name = hrn_to_dns_name(KNOWN_BIP353_NAME).expect("valid name");
    let (chain, _) = build_txt_proof(resolver(), &dns_name).expect("failed to build proof");
    assert!(
        chain.len() <= common::dns_identity::MAX_DNSSEC_CHAIN_LEN,
        "chain is {} bytes, over the {} byte bound",
        chain.len(),
        common::dns_identity::MAX_DNSSEC_CHAIN_LEN
    );
}
