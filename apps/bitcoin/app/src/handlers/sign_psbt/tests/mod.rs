//! End-to-end tests that drive whole PSBTs through [`super::handle_sign_psbt`].
//!
//! The individual modules of `sign_psbt` carry their own unit tests; these cover the
//! flow as a whole. Fixtures shared with those unit tests live in
//! [`super::test_utils`].

mod basic;
mod dnssec_identity;
mod identity;
mod musig;
