#![no_std]

// We make this module empty if not target_vanadium_ledger, otherwise rust-analyzer complains
// as it cannot compile RISC-V assembly on non-RISC-V targets.

#[cfg(feature = "target_vanadium_ledger")]
mod ecalls_impl;

#[cfg(feature = "target_vanadium_ledger")]
pub use ecalls_impl::*;
