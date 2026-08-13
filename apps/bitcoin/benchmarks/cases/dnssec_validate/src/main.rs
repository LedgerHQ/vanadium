// This benchmark measures the cost of validating an RFC 9102 DNSSEC authentication chain, which is
// what backs a DNS-anchored identity key (see docs/dns-identity.md).
//
// This is the one expensive step on the signing path that cannot be deferred to a background task:
// the name it yields is what the review screens display, so nothing can be shown to the user until
// it completes. The number that matters is therefore latency, not throughput.
//
// The chain below is a real one, captured from a live zone; see the fixture's own documentation.
// Validating it exercises the whole path: RSA and ECDSA signature verification at every zone cut up
// to the root, DS digests, and canonical RRset ordering.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use common::dns_identity::verify_dnssec_identity_key;
use common::errors::Error;

sdk::bootstrap!();

// Shared with the offline validation tests in `common`, rather than duplicated, so that the
// benchmark and the tests can never drift onto different data.
const CHAIN: &[u8] = include_bytes!("../../../../common/tests/fixtures/mattcorallo-bip353-txt.chain");

const NAME: &str = "matt@mattcorallo.com";

/// A time inside the captured signature validity window.
const NOW: u64 = 1786500000;

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let pubkey = [0x02u8; 33];

    for _rep in 0..n_reps {
        let res = verify_dnssec_identity_key(NAME, CHAIN, &pubkey, NOW);
        // This record publishes payment instructions rather than an idkey, so the expected outcome
        // is a failure at the very last step. Asserting it is what guarantees the benchmark measured
        // a full validation, rather than an early bail that would flatter the result.
        if res != Err(Error::DnsIdentityRecordInvalid) {
            panic!("chain did not validate as expected");
        }
        core::hint::black_box(&res);
    }

    sdk::exit(0);
}
