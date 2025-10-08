pub const COIN_TICKER: &'static str = "TEST";

// For amount (in sats) not smaller than THRESHOLD_WARN_HIGH_FEES_AMOUNT, we show a warning
// if the percentage (in whole percents) of fees over total input amount is greater than or
// equal to THRESHOLD_WARN_HIGH_FEES_PERCENT. (E.g. 10 means 10%).
pub const THRESHOLD_WARN_HIGH_FEES_PERCENT: u64 = 10; // 10%
pub const THRESHOLD_WARN_HIGH_FEES_AMOUNT: u64 = 100_000;
