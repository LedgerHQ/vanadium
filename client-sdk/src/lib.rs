// Re-export from the app SDK
pub use app_sdk::hash;

pub mod elf;
pub mod memory;

#[cfg(feature = "transport")]
mod apdu;
#[cfg(feature = "transport")]
pub mod comm;
#[cfg(feature = "transport")]
pub mod linewriter;
#[cfg(feature = "transport")]
pub mod transport;
#[cfg(feature = "transport")]
pub mod transport_native_hid;
#[cfg(feature = "transport")]
pub mod vanadium_client;

#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use common::manifest;

// re-export if using the cargo_toml feature
#[cfg(feature = "cargo_toml")]
pub use cargo_toml;
