//! The network that the app works on.
//!
//! The app only supports the test networks for now. Every value that depends on the network is
//! defined here, so that supporting another network starts here.

use bitcoin::params::Params;

/// The parameters of the addresses of scripts (testnet4, whose addresses are those of every
/// test network).
pub const ADDRESS_PARAMS: Params = Params::TESTNET4;

/// The human-readable part of silent payment addresses (BIP-352).
pub const SP_HRP: &str = "tsp";

/// The human-readable part of the BIP-392 keys of silent payment accounts.
pub const SPSCAN_HRP: &str = "tspscan";

/// The coin type of the BIP-44 style derivation paths, such as `m/352'/coin_type'/…` (SLIP-44).
pub const COIN_TYPE: u32 = 1;

/// The version bytes of a serialized extended public key (BIP-32).
pub const BIP32_PUBKEY_VERSION: u32 = 0x043587CF;

/// The ticker of the amounts shown to the user.
pub const COIN_TICKER: &str = "TEST";
