//! DNS-anchored identity keys: verifying that a human-readable name publishes an identity key.
//!
//! This is a variant of BIP-353 in which the DNS TXT record encodes a public key instead of a
//! payment destination. See `docs/dns-identity.md` for the specification.

use alloc::string::String;
use alloc::vec::Vec;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use dnssec_prover::rr::{Name, Txt, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;

use crate::errors::Error;

/// The bech32m human-readable part of an encoded identity key.
pub const IDKEY_HRP: &str = "idkey";

/// The BIP-21 query parameter carrying an identity key.
pub const IDKEY_PARAM: &[u8] = b"idkey";

/// The version byte prefixed to the public key inside the bech32m payload.
pub const IDKEY_VERSION: u8 = 0x00;

/// The fixed labels between the local part of a name and its domain, as in BIP-353.
pub const BIP353_LABELS: &str = "user._bitcoin-payment";

/// The scheme every payment-instruction TXT record must start with, per BIP-353.
const BITCOIN_URI_SCHEME: &[u8] = b"bitcoin:";

/// Maximum size of an RFC 9102 authentication chain we are willing to validate, per key.
///
/// A chain to the root is normally 1-4 KiB. The bound exists so that a host cannot make the device
/// spend unbounded time and heap on signature verification before the user sees anything.
pub const MAX_DNSSEC_CHAIN_LEN: usize = 8192;

/// Maximum number of DNSSEC-authenticated identity keys we are willing to validate per transaction.
pub const MAX_DNSSEC_IDENTITY_KEYS: usize = 4;

/// BIP-353 grants an hour of clock skew on RRSIG expiration.
const EXPIRY_GRACE_SECS: u64 = 3600;

/// Converts a human-readable name into the DNS name its records live at.
///
/// `alice@example.com` becomes `alice.user._bitcoin-payment.example.com.`, as in BIP-353.
///
/// The name must be ASCII: a publisher whose name contains non-ASCII characters is required to
/// publish the punycode form. Rendering `xn--...` on screen is unfriendly, but it is immune to the
/// homograph attacks that a device with a small screen and a limited font cannot otherwise defend
/// against.
pub fn hrn_to_dns_name(hrn: &str) -> Result<Name, Error> {
    if !hrn.is_ascii() {
        return Err(Error::InvalidHumanReadableName);
    }
    // The name is transported with a one-byte length prefix.
    if hrn.is_empty() || hrn.len() > 255 {
        return Err(Error::InvalidHumanReadableName);
    }

    let mut parts = hrn.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::InvalidHumanReadableName);
    };
    if local.is_empty() || domain.is_empty() {
        return Err(Error::InvalidHumanReadableName);
    }
    // A local part containing a dot would silently shift the meaning of the assembled name, and a
    // domain must not be already rooted or we would build a name with an empty label.
    if local.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::InvalidHumanReadableName);
    }

    let mut name = String::with_capacity(local.len() + BIP353_LABELS.len() + domain.len() + 3);
    name.push_str(local);
    name.push('.');
    name.push_str(BIP353_LABELS);
    name.push('.');
    name.push_str(domain);
    name.push('.');

    // `Name` enforces the DNS limits on total length and on individual labels.
    name.try_into().map_err(|_| Error::InvalidHumanReadableName)
}

/// Reconstructs the single `bitcoin:` URI published at a label, following BIP-353.
///
/// The character-strings of a record's RDATA are concatenated in order without separators. Records
/// which do not begin with `bitcoin:`, ignoring case, are ignored; if more than one does, the label
/// is invalid.
pub fn select_bitcoin_uri<'a, I: Iterator<Item = &'a Txt>>(txts: I) -> Result<Vec<u8>, Error> {
    let mut found: Option<Vec<u8>> = None;
    for txt in txts {
        let data: Vec<u8> = txt.data.iter().collect();
        if data.len() < BITCOIN_URI_SCHEME.len() {
            continue;
        }
        if !data[..BITCOIN_URI_SCHEME.len()].eq_ignore_ascii_case(BITCOIN_URI_SCHEME) {
            continue;
        }
        if found.is_some() {
            return Err(Error::DnsIdentityRecordInvalid);
        }
        found = Some(data);
    }
    found.ok_or(Error::DnsIdentityRecordInvalid)
}

/// Extracts the identity key from the `idkey` parameter of a `bitcoin:` URI.
///
/// Exactly one `idkey` parameter must be present; other parameters, which may carry an address or a
/// silent payment code for wallets that do not implement this specification, are ignored.
pub fn parse_idkey_param(uri: &[u8]) -> Result<[u8; 33], Error> {
    let query = match uri.iter().position(|b| *b == b'?') {
        Some(pos) => &uri[pos + 1..],
        // No query part at all: the record carries no identity key.
        None => return Err(Error::DnsIdentityRecordInvalid),
    };

    let mut value = None;
    for param in query.split(|b| *b == b'&') {
        let Some(eq) = param.iter().position(|b| *b == b'=') else {
            continue;
        };
        // BIP-21 parameter names are case-sensitive.
        if &param[..eq] != IDKEY_PARAM {
            continue;
        }
        if value.is_some() {
            return Err(Error::DnsIdentityRecordInvalid);
        }
        value = Some(&param[eq + 1..]);
    }

    let value = value.ok_or(Error::DnsIdentityRecordInvalid)?;
    decode_idkey(value)
}

/// Decodes the bech32m encoding of an identity key.
pub fn decode_idkey(encoded: &[u8]) -> Result<[u8; 33], Error> {
    let encoded = core::str::from_utf8(encoded).map_err(|_| Error::DnsIdentityRecordInvalid)?;

    let hrp = Hrp::parse(IDKEY_HRP).expect("IDKEY_HRP is a valid bech32 hrp");
    let checked = CheckedHrpstring::new::<Bech32m>(encoded)
        .map_err(|_| Error::DnsIdentityRecordInvalid)?;
    if checked.hrp() != hrp {
        return Err(Error::DnsIdentityRecordInvalid);
    }

    let payload: Vec<u8> = checked.byte_iter().collect();
    if payload.len() != 1 + 33 || payload[0] != IDKEY_VERSION {
        return Err(Error::DnsIdentityRecordInvalid);
    }

    let mut pubkey = [0u8; 33];
    pubkey.copy_from_slice(&payload[1..]);
    // Reject anything that is not a plausible compressed point before it reaches the caller; the
    // full on-curve check happens when the key is used to verify a signature.
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return Err(Error::DnsIdentityRecordInvalid);
    }
    Ok(pubkey)
}

/// Encodes an identity key as it appears in the `idkey` parameter of a DNS record.
pub fn encode_idkey(pubkey: &[u8; 33]) -> String {
    let hrp = Hrp::parse(IDKEY_HRP).expect("IDKEY_HRP is a valid bech32 hrp");
    let mut payload = Vec::with_capacity(34);
    payload.push(IDKEY_VERSION);
    payload.extend_from_slice(pubkey);
    bech32::encode::<Bech32m>(hrp, &payload).expect("the payload has a fixed, valid length")
}

/// Verifies that `hrn` publishes `pubkey`, according to `chain`.
///
/// `chain` is an RFC 9102 `AuthenticationChain`, validated to a built-in trust anchor for the root
/// zone. `now` is the current UNIX time, used to enforce the validity period of every signature in
/// the chain.
///
/// A device with no trusted clock necessarily takes `now` from its untrusted host; it must display
/// the date it used so that a user can notice a host presenting a long-expired proof.
pub fn verify_dnssec_identity_key(
    hrn: &str,
    chain: &[u8],
    pubkey: &[u8; 33],
    now: u64,
) -> Result<(), Error> {
    if chain.len() > MAX_DNSSEC_CHAIN_LEN {
        return Err(Error::DnssecValidationFailed);
    }
    let expected_name = hrn_to_dns_name(hrn)?;

    let rrs = parse_rr_stream(chain).map_err(|_| Error::DnssecValidationFailed)?;
    let verified = verify_rr_stream(&rrs).map_err(|_| Error::DnssecValidationFailed)?;

    // The records are only meaningful inside the validity period of the signatures that cover them.
    if now < verified.valid_from || now.saturating_sub(EXPIRY_GRACE_SECS) > verified.expires {
        return Err(Error::DnssecProofExpired);
    }

    // `resolve_name` follows any CNAME or DNAME indirection, each link of which was itself verified.
    let resolved = verified.resolve_name(&expected_name);
    let uri = select_bitcoin_uri(resolved.into_iter().filter_map(|rr| match rr {
        RR::Txt(txt) => Some(txt),
        _ => None,
    }))?;

    if &parse_idkey_param(&uri)? != pubkey {
        return Err(Error::DnsIdentityKeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn txt(data: &[u8]) -> Txt {
        Txt {
            name: "alice.user._bitcoin-payment.example.com.".try_into().unwrap(),
            data: data.try_into().unwrap(),
        }
    }

    // The secp256k1 generator point. Not a usable identity key, but it makes the encoding
    // reproducible, and it is the key used in the example in docs/dns-identity.md.
    const G: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const G_ENCODED: &str = "idkey1qqp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqz57u8d";

    #[test]
    fn test_hrn_to_dns_name() {
        assert_eq!(
            hrn_to_dns_name("alice@example.com").unwrap().as_str(),
            "alice.user._bitcoin-payment.example.com."
        );
        assert_eq!(
            hrn_to_dns_name("bob@sub.example.co.uk").unwrap().as_str(),
            "bob.user._bitcoin-payment.sub.example.co.uk."
        );
    }

    #[test]
    fn test_hrn_to_dns_name_rejects_malformed() {
        for bad in [
            "",                      // empty
            "alice",                 // no domain
            "alice@",                // empty domain
            "@example.com",          // empty local part
            "a@b@example.com",       // two separators
            "alice.smith@ex.com",    // dot in the local part shifts the label structure
            "alice@.example.com",    // leading dot would produce an empty label
            "alice@example.com.",    // already rooted
            "alice@exämple.com",     // non-ASCII must be published as punycode
            "₿alice@example.com",    // the display prefix is not part of the name
        ] {
            assert_eq!(
                hrn_to_dns_name(bad),
                Err(Error::InvalidHumanReadableName),
                "should have rejected {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_hrn_to_dns_name_rejects_overlong() {
        let long_local = "a".repeat(250);
        let hrn = alloc::format!("{}@example.com", long_local);
        assert_eq!(hrn_to_dns_name(&hrn), Err(Error::InvalidHumanReadableName));
    }

    #[test]
    fn test_idkey_roundtrip() {
        assert_eq!(encode_idkey(&G), G_ENCODED);
        assert_eq!(decode_idkey(G_ENCODED.as_bytes()).unwrap(), G);
    }

    #[test]
    fn test_decode_idkey_rejects_malformed() {
        // Wrong human-readable part.
        let wrong_hrp = G_ENCODED.replacen("idkey", "sp", 1);
        assert_eq!(
            decode_idkey(wrong_hrp.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );

        // Corrupted checksum.
        let mut corrupted = G_ENCODED.to_string();
        corrupted.pop();
        corrupted.push('q');
        assert_eq!(
            decode_idkey(corrupted.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );

        // Bech32 rather than bech32m.
        let hrp = Hrp::parse(IDKEY_HRP).unwrap();
        let mut payload = alloc::vec![IDKEY_VERSION];
        payload.extend_from_slice(&G);
        let bech32 = bech32::encode::<bech32::Bech32>(hrp, &payload).unwrap();
        assert_eq!(
            decode_idkey(bech32.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );

        // Unknown version byte.
        let mut payload = alloc::vec![0x01];
        payload.extend_from_slice(&G);
        let bad_version = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        assert_eq!(
            decode_idkey(bad_version.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );

        // Right length, but not a compressed point.
        let mut payload = alloc::vec![IDKEY_VERSION, 0x04];
        payload.extend_from_slice(&G[1..]);
        let not_a_point = bech32::encode::<Bech32m>(hrp, &payload).unwrap();
        assert_eq!(
            decode_idkey(not_a_point.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );

        // Truncated payload.
        let bad_len = bech32::encode::<Bech32m>(hrp, &[IDKEY_VERSION, 0x02, 0x03]).unwrap();
        assert_eq!(
            decode_idkey(bad_len.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );
    }

    #[test]
    fn test_parse_idkey_param() {
        let uri = alloc::format!("bitcoin:?idkey={}", G_ENCODED);
        assert_eq!(parse_idkey_param(uri.as_bytes()).unwrap(), G);

        // Alongside other parameters, in either order, and with an address present.
        let uri = alloc::format!("bitcoin:bc1qexample?sp=sp1qsomething&idkey={}", G_ENCODED);
        assert_eq!(parse_idkey_param(uri.as_bytes()).unwrap(), G);
        let uri = alloc::format!("bitcoin:?idkey={}&label=Alice", G_ENCODED);
        assert_eq!(parse_idkey_param(uri.as_bytes()).unwrap(), G);
    }

    #[test]
    fn test_parse_idkey_param_rejects_malformed() {
        // No query part.
        assert_eq!(
            parse_idkey_param(b"bitcoin:bc1qexample"),
            Err(Error::DnsIdentityRecordInvalid)
        );
        // No idkey parameter.
        assert_eq!(
            parse_idkey_param(b"bitcoin:?sp=sp1qsomething"),
            Err(Error::DnsIdentityRecordInvalid)
        );
        // Two idkey parameters, even if identical.
        let uri = alloc::format!("bitcoin:?idkey={}&idkey={}", G_ENCODED, G_ENCODED);
        assert_eq!(
            parse_idkey_param(uri.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );
        // A parameter whose name merely ends in "idkey" must not match.
        let uri = alloc::format!("bitcoin:?myidkey={}", G_ENCODED);
        assert_eq!(
            parse_idkey_param(uri.as_bytes()),
            Err(Error::DnsIdentityRecordInvalid)
        );
    }

    #[test]
    fn test_select_bitcoin_uri() {
        let records = [txt(b"bitcoin:?idkey=abc")];
        assert_eq!(select_bitcoin_uri(records.iter()).unwrap(), b"bitcoin:?idkey=abc");

        // Records that do not start with the scheme are ignored, and the comparison is
        // case-insensitive.
        let records = [
            txt(b"v=spf1 -all"),
            txt(b"BITCOIN:?idkey=abc"),
            txt(b"some other record"),
        ];
        assert_eq!(select_bitcoin_uri(records.iter()).unwrap(), b"BITCOIN:?idkey=abc");
    }

    #[test]
    fn test_select_bitcoin_uri_concatenates_character_strings() {
        // A TXT record longer than 255 bytes is split into several character-strings, which must be
        // concatenated without separators.
        let long = alloc::format!("bitcoin:?idkey={}&label={}", G_ENCODED, "x".repeat(300));
        let record = txt(long.as_bytes());
        assert_eq!(select_bitcoin_uri([record].iter()).unwrap(), long.as_bytes());
    }

    #[test]
    fn test_select_bitcoin_uri_rejects_ambiguous() {
        // Two payment-instruction records at the same label make it invalid.
        let records = [txt(b"bitcoin:?idkey=abc"), txt(b"bitcoin:?idkey=def")];
        assert_eq!(
            select_bitcoin_uri(records.iter()),
            Err(Error::DnsIdentityRecordInvalid)
        );

        // No payment-instruction record at all.
        let records = [txt(b"v=spf1 -all")];
        assert_eq!(
            select_bitcoin_uri(records.iter()),
            Err(Error::DnsIdentityRecordInvalid)
        );
    }

    #[test]
    fn test_verify_rejects_oversized_chain() {
        let chain = alloc::vec![0u8; MAX_DNSSEC_CHAIN_LEN + 1];
        assert_eq!(
            verify_dnssec_identity_key("alice@example.com", &chain, &G, 0),
            Err(Error::DnssecValidationFailed)
        );
    }

    #[test]
    fn test_verify_rejects_garbage_chain() {
        assert_eq!(
            verify_dnssec_identity_key("alice@example.com", &[0xff; 64], &G, 0),
            Err(Error::DnssecValidationFailed)
        );
    }

    #[test]
    fn test_verify_checks_the_name_before_the_chain() {
        // A malformed name is rejected without any signature verification being attempted.
        assert_eq!(
            verify_dnssec_identity_key("not-a-name", &[], &G, 0),
            Err(Error::InvalidHumanReadableName)
        );
    }
}
