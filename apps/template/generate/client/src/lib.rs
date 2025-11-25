#![cfg_attr(not(feature = "client"), no_std)]

extern crate alloc;

mod common;
pub use common::Command;

#[cfg(feature = "client")]
mod client;

#[cfg(feature = "client")]
pub use client::*;
