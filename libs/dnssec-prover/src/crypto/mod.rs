//! Implementations of cryptographic verification
//!
//! This is the Vanadium fork of `dnssec-prover`. Upstream implements RSA and the secp256r1 /
//! secp384r1 group law over its own pure-Rust bignum backend (`crypto/bigint.rs`), because there
//! is no Rust crypto library it is willing to depend on. On a Vanadium V-App there is a better
//! option: the modular-arithmetic ECALLs run natively on the secure element while the V-App code
//! is interpreted, so every multiplication moved behind an ECALL is both far faster and absent
//! from the app binary.
//!
//! So this fork drops `bigint.rs` entirely and rebuilds the three verification entry points
//! `validation.rs` needs on top of the app SDK:
//!
//!  * [`rsa::validate_rsa`] is a thin DNSKEY-decoding wrapper over `sdk::rsa`, which performs the
//!    whole `s^e mod n` in one `bn_powm` ECALL.
//!  * [`secp256r1::validate_ecdsa`] and [`secp384r1::validate_ecdsa`] keep upstream's Jacobian
//!    formulas and double-and-add ladder in [`ec`], but every field operation is a `bn_*` ECALL
//!    via `sdk::bignum::BigNumMod`.
//!
//! The ECALL ABI has no P-256/P-384 curve, only `CurveKind::Secp256k1`, so the ladder itself
//! cannot (yet) be delegated. Adding those curves would collapse each ECDSA verification to a
//! single ECALL; the field-level acceleration here needs no ABI change.
//!
//! Hashing already went through `bitcoin_hashes`, which this repo patches to its own ECALL-backed
//! fork, so [`hash`] is untouched from upstream.

pub mod hash;
mod ec;
pub mod rsa;
pub mod secp256r1;
pub mod secp384r1;
