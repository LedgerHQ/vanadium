/// The size of each memory page of the V-app. The starting address of the page must be a multiple
/// of this value.
pub const PAGE_SIZE: usize = 256;

pub const PAGE_MASK: u32 = !(PAGE_SIZE as u32 - 1);

/// Calculates the start address of the page containing the given address.
#[inline(always)]
pub fn page_start(address: u32) -> u32 {
    address & !((PAGE_SIZE as u32) - 1)
}

pub const MIN_STACK_SIZE: usize = 1 << 14; // 16 KiB
pub const DEFAULT_STACK_SIZE: usize = 1 << 16; // 64 KiB
pub const MAX_STACK_SIZE: usize = 1 << 27; // 128 MiB

/// Memory address where the stack begins by default.
/// Note that the stack grows downwards, so this is the smallest
/// acceptable address on the stack.
pub const DEFAULT_STACK_START: u32 = 0xf0000000;

// Storage slots for persistent data
pub const STORAGE_SLOT_SIZE: usize = 32; // 32 bytes per slot
pub const MAX_STORAGE_SLOTS: u32 = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_stack_constants() {
        // sanity checks on the constants
        assert!(MIN_STACK_SIZE < DEFAULT_STACK_SIZE);
        assert!(DEFAULT_STACK_SIZE < MAX_STACK_SIZE);
        assert!(
            (DEFAULT_STACK_START as u64) + (DEFAULT_STACK_SIZE as u64) <= 0x1_0000_0000,
            "Stack extends beyond 32-bit address space"
        );
    }
}
