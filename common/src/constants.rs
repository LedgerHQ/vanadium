/// The size of each memory page of the V-app. The starting address of the page must be a multiple
/// of this value.
pub const PAGE_SIZE: usize = 256;

pub const PAGE_MASK: u32 = !(PAGE_SIZE as u32 - 1);

/// Calculates the start address of the page containing the given address.
#[inline(always)]
pub fn page_start(address: u32) -> u32 {
    address & !((PAGE_SIZE as u32) - 1)
}
