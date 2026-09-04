//! Implementations of cryptographic verification
//!
//! This is the Vanadium fork of `dnssec-prover`. Upstream implements RSA and the secp256r1 /
//! secp384r1 group law over its own pure-Rust bignum backend (`crypto/bigint.rs`), because there
//! is no Rust crypto library it is willing to depend on. On a Vanadium V-App there is a better
//! option: the crypto ECALLs run natively on the secure element while the V-App code is
//! interpreted, so work moved behind one is both far faster and absent from the app binary.
//!
//! So this fork drops `bigint.rs` and `ec.rs` entirely, and each of the three verification entry
//! points `validation.rs` needs is now **a single ECALL**:
//!
//!  * [`rsa::validate_rsa`] is DNSKEY decoding around `sdk::rsa`, whose `s^e mod n` is one
//!    `bn_powm`.
//!  * [`secp256r1::validate_ecdsa`] and [`secp384r1::validate_ecdsa`] are RFC 6605 decoding
//!    around `sdk::curve`, whose verification is one `ecdsa_verify`. See [`ecdsa`].
//!
//! Hashing already went through `bitcoin_hashes`, which this repo patches to its own ECALL-backed
//! fork, so [`hash`] is untouched from upstream.
//!
//! For scale: validating one real chain (two RSA-2048 and four ECDSA P-256 signatures) issued
//! 56,315 ECALLs when the elliptic-curve arithmetic was still interpreted Rust over `bn_*`. It
//! now issues roughly thirty.

pub mod hash;
mod ecdsa;
pub mod rsa;
pub mod secp256r1;
pub mod secp384r1;
