pub const COIN_TICKER: &'static str = "TEST";

pub const BIP32_TESTNET_PUBKEY_VERSION: u32 = 0x043587CFu32;

// For amount (in sats) not smaller than THRESHOLD_WARN_HIGH_FEES_AMOUNT, we show a warning
// if the percentage (in whole percents) of fees over total input amount is greater than or
// equal to THRESHOLD_WARN_HIGH_FEES_PERCENT. (E.g. 10 means 10%).
pub const THRESHOLD_WARN_HIGH_FEES_PERCENT: u64 = 10; // 10%
pub const THRESHOLD_WARN_HIGH_FEES_AMOUNT: u64 = 100_000;

/// Compressed public key of the standard NUMS unspendable point from BIP-341
pub const NUMS_COMPRESSED_PUBKEY: [u8; 33] =
    hex_literal::hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");
