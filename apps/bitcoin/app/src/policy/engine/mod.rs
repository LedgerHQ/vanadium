//! Implementations of the [`super::PolicyEngine`] trait.
//!
//! Each submodule provides one engine; keep them self-contained so the
//! dispatcher in `policy::mod` can register or drop them independently.

pub mod program;
