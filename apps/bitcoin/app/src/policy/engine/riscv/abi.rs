//! Ecall numbers for the policy ABI, version 0.
//!
//! The calling convention is Vanadium's own: number in `t0`, arguments in
//! `a0`..`a7`, return value in `a0`.

// Control
pub const EXIT: u32 = 0x0001;
pub const PANIC: u32 = 0x0002;
pub const LOG: u32 = 0x0003;

// Transaction shape
pub const TX_VERSION: u32 = 0x0010;
pub const LOCKTIME: u32 = 0x0011;
pub const INPUT_COUNT: u32 = 0x0012;
pub const OUTPUT_COUNT: u32 = 0x0013;
pub const FEE: u32 = 0x0014;
pub const TOTALS: u32 = 0x0015;

// The signing key
pub const SELF_PUBKEY: u32 = 0x0016;
pub const SELF_POLICY_HASH: u32 = 0x0017;

// Inputs
pub const INPUT_AMOUNT: u32 = 0x0018;
pub const INPUT_PREVOUT: u32 = 0x0019;
pub const INPUT_SEQUENCE: u32 = 0x001A;
pub const INPUT_SCRIPT_PUBKEY: u32 = 0x001B;
pub const INPUT_FLAGS: u32 = 0x001C;
pub const INPUT_ACCOUNT: u32 = 0x001D;
pub const INPUT_TAPTREE_HASH: u32 = 0x001E;
pub const ATTEMPT_INPUT: u32 = 0x001F;

// Outputs
pub const OUTPUT_AMOUNT: u32 = 0x0020;
pub const OUTPUT_SCRIPT_PUBKEY: u32 = 0x0021;
pub const OUTPUT_FLAGS: u32 = 0x0022;
pub const OUTPUT_ACCOUNT: u32 = 0x0023;

// Raw PSBT access
pub const PSBT_LEN: u32 = 0x0040;
pub const PSBT_READ: u32 = 0x0041;

// Accelerated calls
pub const SHA256: u32 = 0x0050;
pub const RIPEMD160: u32 = 0x0054;
pub const TAGGED_HASH: u32 = 0x0056;
pub const TAPLEAF_HASH: u32 = 0x0060;
pub const TAPBRANCH_HASH: u32 = 0x0061;
pub const TAPTWEAK_PUBKEY: u32 = 0x0062;
pub const XONLY_ADD_TWEAK: u32 = 0x0063;
pub const SCHNORR_VERIFY: u32 = 0x0070;

/// Returned by lookups for data that is legitimately absent, as distinct from an
/// error. Chosen so it cannot be confused with a length or a count.
pub const NOT_FOUND: u32 = 0xFFFF_FFFF;

/// Success, for calls that report only whether they worked.
pub const OK: u32 = 0;

/// `a0` on the final call, where there is no current input.
pub const NO_INPUT: u32 = 0xFFFF_FFFF;

/// Largest buffer copied across the sandbox boundary in one go.
pub const MAX_ECALL_BUFFER: usize = 256;
