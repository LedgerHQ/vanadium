//! Parsing and validation of `.vpol` policy program images.
//!
//! The format is specified in `apps/bitcoin/docs/SIGNING_POLICIES.md`. This module
//! is the only place that interprets the header, and it never executes anything:
//! validation happens at account registration, long before a transaction exists.

use vanadium_common::constants::PAGE_SIZE;

use crate::policy::PolicyError;

/// `"VPOL"`.
pub const MAGIC: [u8; 4] = *b"VPOL";

/// Size of the fixed part of the header, before the label.
const FIXED_HEADER_LEN: usize = 40;

/// Maximum length of the self-declared label.
pub const MAX_LABEL_LEN: usize = 32;

// Resource limits. Provisional: they need calibrating against a measurement of
// nested-interpretation throughput, which does not exist yet.
pub const MAX_CODE_LEN: u32 = 8192;
pub const MAX_DATA_LEN: u32 = 4096;
pub const MAX_STATE_LEN: u32 = 1024;
pub const MAX_STACK_LEN: u32 = 4096;
/// Total page-rounded memory a sandbox may reserve from the app's heap.
pub const MAX_SANDBOX_MEMORY: u32 = 12 * 1024;
pub const MAX_STEP_BUDGET_BASE: u32 = 1 << 20;
pub const MAX_STEP_BUDGET_PER_INPUT: u32 = 1 << 18;
/// Absolute ceiling on interpreted instructions, regardless of what the header
/// declares.
pub const MAX_TOTAL_STEPS: u64 = 1 << 22;

/// Sandbox segment base addresses. Fixed by the ABI, not carried in the image.
pub const CODE_START: u32 = 0x0001_0000;
pub const DATA_START: u32 = 0x0002_0000;
/// Matches the V-App convention (`vanadium_common::constants::DEFAULT_STACK_START`).
pub const STACK_START: u32 = 0xF000_0000;

/// Number of pages needed to hold `len` bytes.
pub fn n_pages(len: u32) -> u32 {
    len.div_ceil(PAGE_SIZE as u32)
}

/// A validated policy program image.
///
/// Holding one is proof that the header passed [`Image::parse`], so the engine can
/// rely on every documented invariant without re-checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image<'a> {
    pub abi_version: u8,
    pub entrypoint: u32,
    pub code_len: u32,
    pub data_len: u32,
    pub state_len: u32,
    pub data_init_len: u32,
    pub stack_len: u32,
    pub step_budget_base: u32,
    pub step_budget_per_input: u32,
    label: &'a [u8],
    code: &'a [u8],
    data_init: &'a [u8],
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

impl<'a> Image<'a> {
    /// Parse and fully validate an image. Performs the checks specified in
    /// "Validation at registration", in order, and executes nothing.
    pub fn parse(raw: &'a [u8]) -> Result<Self, PolicyError> {
        if raw.len() < FIXED_HEADER_LEN {
            return Err(PolicyError::InvalidImage);
        }
        if raw[0..4] != MAGIC {
            return Err(PolicyError::InvalidImage);
        }

        let abi_version = raw[4];
        let flags = raw[5];
        let label_len = raw[6] as usize;
        let reserved = raw[7];

        if flags != 0 || reserved != 0 {
            return Err(PolicyError::InvalidImage);
        }
        if label_len > MAX_LABEL_LEN {
            return Err(PolicyError::InvalidImage);
        }

        let entrypoint = read_u32(raw, 8);
        let code_len = read_u32(raw, 12);
        let data_len = read_u32(raw, 16);
        let state_len = read_u32(raw, 20);
        let data_init_len = read_u32(raw, 24);
        let stack_len = read_u32(raw, 28);
        let step_budget_base = read_u32(raw, 32);
        let step_budget_per_input = read_u32(raw, 36);

        // The label area is zero-padded to a multiple of 4.
        let header_len = FIXED_HEADER_LEN + label_len.next_multiple_of(4);
        if raw.len() < header_len {
            return Err(PolicyError::InvalidImage);
        }
        let label = &raw[FIXED_HEADER_LEN..FIXED_HEADER_LEN + label_len];
        if !label.iter().all(|b| (0x20..=0x7E).contains(b)) {
            return Err(PolicyError::InvalidImage);
        }
        // Padding must actually be zero, so that one logical image has exactly one
        // byte encoding and therefore exactly one hash.
        if raw[FIXED_HEADER_LEN + label_len..header_len]
            .iter()
            .any(|&b| b != 0)
        {
            return Err(PolicyError::InvalidImage);
        }

        if code_len < 2 || code_len > MAX_CODE_LEN {
            return Err(PolicyError::ProgramTooLarge);
        }
        if entrypoint % 2 != 0 || entrypoint >= code_len {
            return Err(PolicyError::InvalidImage);
        }

        if data_len > MAX_DATA_LEN || stack_len > MAX_STACK_LEN || state_len > MAX_STATE_LEN {
            return Err(PolicyError::ProgramTooLarge);
        }
        // Every segment must be non-empty: MemorySegment::new rejects a zero size.
        if data_len < 4 || stack_len < 4 {
            return Err(PolicyError::InvalidImage);
        }
        if state_len > data_len || data_init_len > data_len - state_len {
            return Err(PolicyError::InvalidImage);
        }

        let total_pages = n_pages(code_len) + n_pages(data_len) + n_pages(stack_len);
        if total_pages * (PAGE_SIZE as u32) > MAX_SANDBOX_MEMORY {
            return Err(PolicyError::ProgramTooLarge);
        }

        if step_budget_base > MAX_STEP_BUDGET_BASE
            || step_budget_per_input > MAX_STEP_BUDGET_PER_INPUT
        {
            return Err(PolicyError::ProgramTooLarge);
        }

        let expected_len = header_len
            .checked_add(code_len as usize)
            .and_then(|n| n.checked_add(data_init_len as usize))
            .ok_or(PolicyError::InvalidImage)?;
        if raw.len() != expected_len {
            return Err(PolicyError::InvalidImage);
        }

        let code = &raw[header_len..header_len + code_len as usize];
        let data_init = &raw[header_len + code_len as usize..];

        Ok(Self {
            abi_version,
            entrypoint,
            code_len,
            data_len,
            state_len,
            data_init_len,
            stack_len,
            step_budget_base,
            step_budget_per_input,
            label,
            code,
            data_init,
        })
    }

    pub fn code(&self) -> &'a [u8] {
        self.code
    }

    pub fn data_init(&self) -> &'a [u8] {
        self.data_init
    }

    /// The self-declared label. Committed by the policy hash, but written by
    /// whoever wrote the program: it is a mnemonic, never evidence.
    pub fn label(&self) -> &'a [u8] {
        self.label
    }

    /// Offset of the shared state within the data segment. The state occupies the
    /// last `state_len` bytes.
    pub fn state_offset(&self) -> u32 {
        self.data_len - self.state_len
    }

    /// Total interpreted-instruction budget for one transaction, shared across
    /// every invocation of this policy.
    pub fn total_budget(&self, attempt_count: u32) -> u64 {
        let per_input =
            (self.step_budget_per_input as u64).saturating_mul(attempt_count as u64);
        (self.step_budget_base as u64)
            .saturating_add(per_input)
            .min(MAX_TOTAL_STEPS)
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use alloc::vec::Vec;

    use super::*;

    /// Builds a `.vpol` image around `code`. Used by the engine tests.
    pub struct ImageBuilder {
        pub abi_version: u8,
        pub flags: u8,
        pub reserved: u8,
        pub label: Vec<u8>,
        pub entrypoint: u32,
        pub data_len: u32,
        pub state_len: u32,
        pub stack_len: u32,
        pub step_budget_base: u32,
        pub step_budget_per_input: u32,
        pub code: Vec<u8>,
        pub data_init: Vec<u8>,
        /// If set, overrides the computed `code_len` field (to build bad images).
        pub code_len_override: Option<u32>,
    }

    impl ImageBuilder {
        pub fn new(code: Vec<u8>) -> Self {
            Self {
                abi_version: 0,
                flags: 0,
                reserved: 0,
                label: Vec::new(),
                entrypoint: 0,
                data_len: 256,
                state_len: 64,
                stack_len: 1024,
                step_budget_base: 10_000,
                step_budget_per_input: 1_000,
                code,
                data_init: Vec::new(),
                code_len_override: None,
            }
        }

        pub fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&MAGIC);
            out.push(self.abi_version);
            out.push(self.flags);
            out.push(self.label.len() as u8);
            out.push(self.reserved);
            out.extend_from_slice(&self.entrypoint.to_le_bytes());
            let code_len = self.code_len_override.unwrap_or(self.code.len() as u32);
            out.extend_from_slice(&code_len.to_le_bytes());
            out.extend_from_slice(&self.data_len.to_le_bytes());
            out.extend_from_slice(&self.state_len.to_le_bytes());
            out.extend_from_slice(&(self.data_init.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.stack_len.to_le_bytes());
            out.extend_from_slice(&self.step_budget_base.to_le_bytes());
            out.extend_from_slice(&self.step_budget_per_input.to_le_bytes());
            out.extend_from_slice(&self.label);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(&self.code);
            out.extend_from_slice(&self.data_init);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::ImageBuilder;
    use super::*;
    use alloc::vec;

    fn code() -> alloc::vec::Vec<u8> {
        vec![0x73, 0x00, 0x00, 0x00] // ecall
    }

    #[test]
    fn parses_a_minimal_image() {
        let raw = ImageBuilder::new(code()).build();
        let img = Image::parse(&raw).unwrap();
        assert_eq!(img.abi_version, 0);
        assert_eq!(img.code_len, 4);
        assert_eq!(img.code(), &code()[..]);
        assert_eq!(img.data_init(), b"");
        assert_eq!(img.label(), b"");
        assert_eq!(img.state_offset(), 256 - 64);
    }

    #[test]
    fn label_is_read_and_padded() {
        let mut b = ImageBuilder::new(code());
        b.label = b"vault v1".to_vec(); // 8 bytes, already a multiple of 4
        let raw = b.build();
        assert_eq!(Image::parse(&raw).unwrap().label(), b"vault v1");

        let mut b = ImageBuilder::new(code());
        b.label = b"fee".to_vec(); // 3 bytes -> one byte of zero padding
        let raw = b.build();
        assert_eq!(Image::parse(&raw).unwrap().label(), b"fee");
    }

    #[test]
    fn rejects_bad_magic_and_reserved_fields() {
        let mut raw = ImageBuilder::new(code()).build();
        raw[0] = b'X';
        assert_eq!(Image::parse(&raw), Err(PolicyError::InvalidImage));

        let mut b = ImageBuilder::new(code());
        b.flags = 1;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));

        let mut b = ImageBuilder::new(code());
        b.reserved = 1;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn rejects_non_printable_label_and_nonzero_padding() {
        let mut b = ImageBuilder::new(code());
        b.label = vec![0x01, 0x02, 0x03];
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));

        // A one-byte label leaves three padding bytes; dirtying one must be rejected
        // so that a logical image has exactly one encoding and therefore one hash.
        let mut b = ImageBuilder::new(code());
        b.label = b"x".to_vec();
        let mut raw = b.build();
        raw[41] = 0xFF;
        assert_eq!(Image::parse(&raw), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn rejects_bad_entrypoint() {
        let mut b = ImageBuilder::new(code());
        b.entrypoint = 1; // odd
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));

        let mut b = ImageBuilder::new(code());
        b.entrypoint = 4; // == code_len, out of range
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn rejects_empty_segments() {
        // MemorySegment::new rejects a zero size, so a program with no data at all
        // must be refused rather than failing to load later.
        let mut b = ImageBuilder::new(code());
        b.data_len = 0;
        b.state_len = 0;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));

        let mut b = ImageBuilder::new(code());
        b.stack_len = 0;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn rejects_oversized_declarations() {
        let mut b = ImageBuilder::new(code());
        b.data_len = MAX_DATA_LEN + 4;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::ProgramTooLarge));

        let mut b = ImageBuilder::new(code());
        b.state_len = MAX_STATE_LEN + 4;
        b.data_len = MAX_DATA_LEN;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::ProgramTooLarge));

        let mut b = ImageBuilder::new(code());
        b.stack_len = MAX_STACK_LEN + 4;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::ProgramTooLarge));

        let mut b = ImageBuilder::new(code());
        b.step_budget_base = MAX_STEP_BUDGET_BASE + 1;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::ProgramTooLarge));

        let mut b = ImageBuilder::new(code());
        b.step_budget_per_input = MAX_STEP_BUDGET_PER_INPUT + 1;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::ProgramTooLarge));
    }

    #[test]
    fn rejects_state_larger_than_data() {
        let mut b = ImageBuilder::new(code());
        b.data_len = 64;
        b.state_len = 128;
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn rejects_data_init_overlapping_the_shared_state() {
        let mut b = ImageBuilder::new(code());
        b.data_len = 64;
        b.state_len = 32;
        b.data_init = vec![0xAA; 33]; // 33 > 64 - 32
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn rejects_total_memory_over_the_cap() {
        let mut b = ImageBuilder::new(vec![0u8; MAX_CODE_LEN as usize]);
        b.data_len = MAX_DATA_LEN;
        b.stack_len = MAX_STACK_LEN;
        // 8192 + 4096 + 4096 = 16384 > 12 KiB
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::ProgramTooLarge));
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut raw = ImageBuilder::new(code()).build();
        raw.push(0x00); // one trailing byte too many
        assert_eq!(Image::parse(&raw), Err(PolicyError::InvalidImage));

        let raw = ImageBuilder::new(code()).build();
        assert_eq!(
            Image::parse(&raw[..raw.len() - 1]),
            Err(PolicyError::InvalidImage)
        );
    }

    #[test]
    fn rejects_code_len_beyond_the_image() {
        let mut b = ImageBuilder::new(code());
        b.code_len_override = Some(MAX_CODE_LEN);
        assert_eq!(Image::parse(&b.build()), Err(PolicyError::InvalidImage));
    }

    #[test]
    fn budget_scales_with_attempts_and_is_capped() {
        let mut b = ImageBuilder::new(code());
        b.step_budget_base = 1000;
        b.step_budget_per_input = 100;
        let raw = b.build();
        let img = Image::parse(&raw).unwrap();
        assert_eq!(img.total_budget(0), 1000);
        assert_eq!(img.total_budget(3), 1300);

        let mut b = ImageBuilder::new(code());
        b.step_budget_base = MAX_STEP_BUDGET_BASE;
        b.step_budget_per_input = MAX_STEP_BUDGET_PER_INPUT;
        let raw = b.build();
        let img = Image::parse(&raw).unwrap();
        assert_eq!(img.total_budget(u32::MAX), MAX_TOTAL_STEPS);
    }
}
