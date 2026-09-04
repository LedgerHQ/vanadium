//! Offline tests of DNSSEC proof validation against a real, captured authentication chain.
//!
//! `verify_rr_stream` validates to the real IANA root trust anchors, so a chain that actually
//! verifies cannot be synthesised — a positive test needs a chain captured from a live zone. The
//! fixture here was captured with the client's `fetch-dns-identity` command from
//! `matt.user._bitcoin-payment.mattcorallo.com`, a BIP-353 record published by the author of that
//! BIP. Its contents are public payment instructions (an address and a BOLT12 offer).
//!
//! It publishes payment instructions rather than an `idkey`, which makes it a precise instrument:
//! `verify_dnssec_identity_key` can only reach the record-parsing step, and therefore only report
//! `DnsIdentityRecordInvalid`, if every preceding step succeeded — parsing the chain, verifying
//! every signature up to the root, checking the validity window, and applying BIP-353's record
//! selection rules. Each of those failing instead produces a distinct error, which is what lets
//! these tests tell them apart.
//!
//! Times are pinned inside the captured RRSIG window so the tests never depend on the clock.

use vnd_bitcoin_common::dns_identity::verify_dnssec_identity_key;
use vnd_bitcoin_common::errors::Error;

const CHAIN: &[u8] = include_bytes!("fixtures/mattcorallo-bip353-txt.chain");

const NAME: &str = "matt@mattcorallo.com";

/// The signature validity window of the captured chain, as reported at capture time.
const VALID_FROM: u64 = 1786420800;
const EXPIRES: u64 = 1786761472;
/// A time comfortably inside that window.
const INSIDE: u64 = 1786500000;

/// Any key: the record publishes no `idkey`, so the comparison is never reached.
const SOME_PUBKEY: [u8; 33] = [0x02; 33];

#[test]
fn real_chain_validates_and_reaches_the_record() {
    // Reaching DnsIdentityRecordInvalid means the whole DNSSEC path succeeded.
    assert_eq!(
        verify_dnssec_identity_key(NAME, CHAIN, &SOME_PUBKEY, INSIDE),
        Err(Error::DnsIdentityRecordInvalid)
    );
}

#[test]
fn real_chain_is_rejected_before_its_inception() {
    assert_eq!(
        verify_dnssec_identity_key(NAME, CHAIN, &SOME_PUBKEY, VALID_FROM - 1),
        Err(Error::DnssecProofExpired)
    );
}

#[test]
fn real_chain_is_rejected_after_expiry_plus_grace() {
    // BIP-353 allows an hour of clock skew, so the proof is still accepted just after expiry...
    assert_eq!(
        verify_dnssec_identity_key(NAME, CHAIN, &SOME_PUBKEY, EXPIRES + 60),
        Err(Error::DnsIdentityRecordInvalid)
    );
    // ...but not beyond the grace period.
    assert_eq!(
        verify_dnssec_identity_key(NAME, CHAIN, &SOME_PUBKEY, EXPIRES + 3601),
        Err(Error::DnssecProofExpired)
    );
}

#[test]
fn real_chain_is_rejected_when_the_name_does_not_match() {
    // A chain that proves records for one name must not authenticate another. The records simply do
    // not resolve at the derived label, so no TXT record is found.
    assert_eq!(
        verify_dnssec_identity_key("matt@example.com", CHAIN, &SOME_PUBKEY, INSIDE),
        Err(Error::DnsIdentityRecordInvalid)
    );
    assert_eq!(
        verify_dnssec_identity_key("alice@mattcorallo.com", CHAIN, &SOME_PUBKEY, INSIDE),
        Err(Error::DnsIdentityRecordInvalid)
    );
}

#[test]
fn real_chain_is_rejected_when_corrupted() {
    // Flip a byte in each third of the chain: whichever record or signature it lands in, validation
    // must fail rather than yield unauthenticated data.
    for pos in [CHAIN.len() / 6, CHAIN.len() / 2, CHAIN.len() - 8] {
        let mut corrupted = CHAIN.to_vec();
        corrupted[pos] ^= 0x01;
        let result = verify_dnssec_identity_key(NAME, &corrupted, &SOME_PUBKEY, INSIDE);
        assert!(
            matches!(
                result,
                Err(Error::DnssecValidationFailed) | Err(Error::DnsIdentityRecordInvalid)
            ),
            "flipping byte {} gave {:?}, which is not a rejection",
            pos,
            result
        );
    }
}

#[test]
fn real_chain_is_rejected_when_truncated() {
    for len in [0, 1, CHAIN.len() / 2, CHAIN.len() - 1] {
        assert_eq!(
            verify_dnssec_identity_key(NAME, &CHAIN[..len], &SOME_PUBKEY, INSIDE),
            Err(Error::DnssecValidationFailed),
            "a {} byte prefix of the chain was not rejected",
            len
        );
    }
}
