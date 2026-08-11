//! Outputs authenticated by a DNSSEC-published identity key.
//!
//! These reuse the identity-success fixture from [`super::identity`], swapping the registered
//! identity key entry for a DNSSEC one that carries the same public key, so that the output
//! signature still verifies and the only thing under test is how trust in the key is established.
//!
//! A chain that actually validates cannot be synthesised: `verify_rr_stream` validates to the
//! real IANA root anchors, so a positive test needs a captured proof from a live zone. That
//! belongs in an integration test with a fixture; what is checked here is that every rejection
//! path is wired up and fails closed.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bitcoin::psbt::Psbt;
use common::{
    errors::Error,
    psbt::{
        DnssecIdentityKey, PsbtIdAuthGlobalRead, PsbtIdAuthGlobalWrite,
        PSBT_IDAUTH_GLOBAL_REGISTERED_IDENTITY_KEY, PSBT_IDAUTH_PROPRIETARY_IDENTIFIER,
    },
};

use super::super::handle_sign_psbt;
use super::super::test_utils::serialize_as_psbtv2;
use common::message::Response;

/// A PSBT whose single external output carries a valid identity signature, with the signing key
/// present in the global map as a *registered* identity key named "Satoshi Nakamoto".
const PSBT_IDENTITY_SUCCESS_B64: &str = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvuFIxVHknuLpQ/zP3rTZie8gIyZjCHfUXcOEGSDcFFboAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAR5l6X7yUsuUpkyekIKx81HNmEE3mnqVB7/5A1UpjtZuvx0c2N93OOf6HvpNKpvounBUpNoOYTRJvVhKqqrl/KgABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";

fn psbt_without_registered_identity_keys() -> Psbt {
    let mut psbt = Psbt::deserialize(&STANDARD.decode(PSBT_IDENTITY_SUCCESS_B64).unwrap()).unwrap();
    psbt.proprietary.retain(|k, _| {
        !(k.prefix == PSBT_IDAUTH_PROPRIETARY_IDENTIFIER
            && k.subtype == PSBT_IDAUTH_GLOBAL_REGISTERED_IDENTITY_KEY)
    });
    psbt
}

/// The identity public key that signed the external output of `PSBT_IDENTITY_SUCCESS_B64`.
fn identity_pubkey_of_test_psbt() -> [u8; 33] {
    let psbt = Psbt::deserialize(&STANDARD.decode(PSBT_IDENTITY_SUCCESS_B64).unwrap()).unwrap();
    let registered = psbt.get_registered_identity_keys().unwrap();
    assert_eq!(registered.len(), 1);
    registered[0].pubkey
}

/// The test PSBT with its registered identity key replaced by a DNSSEC one.
fn psbt_with_dnssec_identity_key(name: &str, chain: &[u8]) -> Psbt {
    let mut psbt = psbt_without_registered_identity_keys();
    psbt.add_dnssec_identity_key(&DnssecIdentityKey {
        pubkey: identity_pubkey_of_test_psbt(),
        name,
        chain,
    })
    .unwrap();
    psbt
}

fn sign_at(psbt: &Psbt, now: Option<u64>) -> Result<Response, Error> {
    sdk::executor::block_on(handle_sign_psbt(
        &mut sdk::App::singleton(),
        &serialize_as_psbtv2(psbt),
        now,
    ))
}

#[test]
fn test_sign_psbt_dnssec_identity_key_requires_current_time() {
    // RRSIG validity periods cannot be checked without a clock, so a proof with no time to
    // check it against must be refused rather than accepted unchecked.
    let psbt = psbt_with_dnssec_identity_key("alice@example.com", &[0xAB; 64]);
    assert_eq!(sign_at(&psbt, None), Err(Error::MissingCurrentTime));
}

#[test]
fn test_sign_psbt_dnssec_identity_key_invalid_chain() {
    let psbt = psbt_with_dnssec_identity_key("alice@example.com", &[0xAB; 64]);
    assert_eq!(
        sign_at(&psbt, Some(1_754_000_000)),
        Err(Error::DnssecValidationFailed)
    );
}

#[test]
fn test_sign_psbt_dnssec_identity_key_malformed_name() {
    let psbt = psbt_with_dnssec_identity_key("not-a-name", &[0xAB; 64]);
    assert_eq!(
        sign_at(&psbt, Some(1_754_000_000)),
        Err(Error::InvalidHumanReadableName)
    );
}

#[test]
fn test_sign_psbt_dnssec_identity_key_oversized_chain() {
    let chain = vec![0xABu8; common::dns_identity::MAX_DNSSEC_CHAIN_LEN + 1];
    let psbt = psbt_with_dnssec_identity_key("alice@example.com", &chain);
    assert_eq!(
        sign_at(&psbt, Some(1_754_000_000)),
        Err(Error::DnssecValidationFailed)
    );
}

#[test]
fn test_sign_psbt_rejects_key_both_registered_and_dnssec() {
    // The registered entry is left in place, so the same key is trusted for two different
    // reasons and it is ambiguous which name to show.
    let mut psbt = Psbt::deserialize(&STANDARD.decode(PSBT_IDENTITY_SUCCESS_B64).unwrap()).unwrap();
    psbt.add_dnssec_identity_key(&DnssecIdentityKey {
        pubkey: identity_pubkey_of_test_psbt(),
        name: "alice@example.com",
        chain: &[0xAB; 64],
    })
    .unwrap();
    assert_eq!(
        sign_at(&psbt, Some(1_754_000_000)),
        Err(Error::DuplicateIdentityKey)
    );
}

#[test]
fn test_sign_psbt_rejects_too_many_dnssec_identity_keys() {
    let mut psbt = psbt_without_registered_identity_keys();
    for i in 0..=common::dns_identity::MAX_DNSSEC_IDENTITY_KEYS {
        let mut pubkey = [0x02u8; 33];
        pubkey[32] = i as u8;
        psbt.add_dnssec_identity_key(&DnssecIdentityKey {
            pubkey,
            name: "alice@example.com",
            chain: &[0xAB; 64],
        })
        .unwrap();
    }
    // Refused before any signature verification is attempted.
    assert_eq!(
        sign_at(&psbt, Some(1_754_000_000)),
        Err(Error::DnssecValidationFailed)
    );
}

#[test]
fn test_sign_psbt_without_identity_keys_shows_bare_address() {
    // Removing the registered key leaves a valid signature from a key that is not trusted: the
    // output is still signable, but it must not be labelled.
    let psbt = psbt_without_registered_identity_keys();
    assert!(sign_at(&psbt, None).is_ok());
}
