//! Memory backends for the policy sandbox.
//!
//! The data and stack segments use `vanadium_common::vm::VecMemory`. The code
//! segment uses [`SliceMemory`], which serves pages straight out of the image
//! bytes instead of copying up to 8 KiB into the app's 64 KiB heap.

use vanadium_common::{
    constants::PAGE_SIZE,
    vm::{MemoryError, Page, PagedMemory, VecMemory},
};

/// A read-only `PagedMemory` view over a byte slice, with a one-page scratch
/// buffer so that repeated accesses within a page do not re-copy.
///
/// `PagedMemory::get_page` must hand out `DerefMut`, so a caller could in
/// principle write into the scratch page. Nothing does: `Cpu` resolves writes
/// against the stack and data segments only, and rejects any address that falls
/// in the code segment. Writes that did land here would be silently dropped on
/// the next page miss, which is why this type is used exclusively for code.
#[derive(Debug)]
pub struct SliceMemory<'a> {
    data: &'a [u8],
    cached: Option<u32>,
    scratch: Page,
}

impl<'a> SliceMemory<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            cached: None,
            scratch: Page {
                data: [0; PAGE_SIZE],
            },
        }
    }
}

impl<'a> PagedMemory for SliceMemory<'a> {
    type PageRef<'b>
        = &'b mut Page
    where
        Self: 'b;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, MemoryError> {
        if self.cached != Some(page_index) {
            let start = (page_index as usize)
                .checked_mul(PAGE_SIZE)
                .ok_or(MemoryError::Overflow)?;
            if start >= self.data.len() {
                return Err(MemoryError::PageNotFound);
            }
            let end = core::cmp::min(start + PAGE_SIZE, self.data.len());
            // A trailing partial page is zero-filled. The enclosing MemorySegment
            // is sized to the exact code length, so those bytes are unreachable.
            self.scratch.data = [0; PAGE_SIZE];
            self.scratch.data[..end - start].copy_from_slice(&self.data[start..end]);
            self.cached = Some(page_index);
        }
        Ok(&mut self.scratch)
    }
}

/// The sandbox's memory backing.
///
/// `Cpu<'a, M>` types all three of its segments over one `M`, so the read-only code
/// backing and the read-write data/stack backings have to be the same Rust type.
/// Both variants' `PageRef` is `&mut Page`, so the dispatch costs one branch per
/// page access and nothing else.
#[derive(Debug)]
pub enum PolicyMemory<'a> {
    /// Read-only, served from the image.
    Code(SliceMemory<'a>),
    /// Read-write, zero-initialized.
    Rw(VecMemory),
}

impl<'a> PolicyMemory<'a> {
    pub fn code(data: &'a [u8]) -> Self {
        PolicyMemory::Code(SliceMemory::new(data))
    }

    /// A zero-filled read-write backing of `n_pages` pages. The zeroes are what the
    /// shared state's first invocation observes.
    pub fn rw(n_pages: usize) -> Self {
        PolicyMemory::Rw(VecMemory::new(n_pages))
    }
}

impl<'a> PagedMemory for PolicyMemory<'a> {
    type PageRef<'b>
        = &'b mut Page
    where
        Self: 'b;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, MemoryError> {
        match self {
            PolicyMemory::Code(m) => m.get_page(page_index),
            PolicyMemory::Rw(m) => m.get_page(page_index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn serves_pages_from_the_slice() {
        let mut data = vec![0u8; PAGE_SIZE * 2 + 5];
        data[0] = 0xAA;
        data[PAGE_SIZE] = 0xBB;
        data[PAGE_SIZE * 2] = 0xCC;

        let mut mem = SliceMemory::new(&data);
        assert_eq!(mem.get_page(0).unwrap().data[0], 0xAA);
        assert_eq!(mem.get_page(1).unwrap().data[0], 0xBB);
        assert_eq!(mem.get_page(2).unwrap().data[0], 0xCC);
    }

    #[test]
    fn zero_fills_a_trailing_partial_page() {
        let data = vec![0xFFu8; PAGE_SIZE + 3];
        let mut mem = SliceMemory::new(&data);
        let page = mem.get_page(1).unwrap();
        assert_eq!(&page.data[..3], &[0xFF, 0xFF, 0xFF]);
        assert!(page.data[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_pages_past_the_end() {
        let data = vec![0u8; 4];
        let mut mem = SliceMemory::new(&data);
        assert!(mem.get_page(0).is_ok());
        assert!(mem.get_page(1).is_err());
    }

    #[test]
    fn stale_writes_do_not_leak_across_page_misses() {
        // Not a supported operation, but pin the behaviour: the scratch page is
        // reloaded from the slice, so a discarded write cannot corrupt the image.
        let data = vec![0x11u8; PAGE_SIZE * 2];
        let mut mem = SliceMemory::new(&data);
        mem.get_page(0).unwrap().data[0] = 0x99;
        assert_eq!(mem.get_page(1).unwrap().data[0], 0x11);
        assert_eq!(mem.get_page(0).unwrap().data[0], 0x11);
    }
}
