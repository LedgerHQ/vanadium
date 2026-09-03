//! Implementations of cryptographic verification
//!
//! Sadly, the choices for cryptographic verification in Rust are somewhat limited. For us (RSA and
//! secp256r1/secp384r1) there's really only `ring` and `RustCrypto`.
//!
//! While `ring` is great, it struggles with platform support and has a fairly involved dependency
//! tree due to its reliance on C backends.
//!
//! `RustCrypto`, on the other hand, tries to stick to Rust, which is great, but in doing so takes
//! on more (unnecessary) dependencies and has a particularly unusable MSRV policy. Thus, its
//! somewhat difficult to take on as a dependency.
//!
//! Instead, we go our own way here, and luckily actually implementing the required algorithms
//! isn't all that difficult, at least if we're okay with performance being marginally sub-par.
//! Because we don't ever do any signing, we don't need to worry about constant-time-ness, further
//! reducing complexity.
//!
//! While we could similarly go our own way on hashing, too, rust-bitcoin's `bitcoin_hashes` crate
//! does what we need without any unnecessary dependencies and with a very conservative MSRV
//! policy. Thus we go ahead and use that for our hashing needs.

pub mod bigint;
mod ec;
pub mod hash;
pub mod rsa;
pub mod secp256r1;
pub mod secp384r1;
