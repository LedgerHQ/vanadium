use common::constants::page_start;
use common::constants::PAGE_SIZE;
use common::vm::MemoryError;
use std::cmp::min;

use common::accumulator::{AccumulatorError, HashOutput, MerkleAccumulator, VectorAccumulator};

use crate::hash::Sha256;

// Serializes a page in the format expected for the content of the leaf in the MerkleAccumulator, as follows:
// - Clear-text pages are serialized as a 0 byte, followed by 12 0 bytes, followed by PAGE_SIZE bytes (page plaintext).
// - Encrypted pages are serialized as a 1 byte, followed by 12 bytes for the nonce, followed by PAGE_SIZE bytes (page ciphertext).
fn get_serialized_page(data: &[u8], nonce: Option<&[u8; 12]>) -> Vec<u8> {
    let mut serialized_page = Vec::<u8>::with_capacity(1 + 12 + PAGE_SIZE);
    if let Some(nonce) = nonce {
        serialized_page.push(1); // is_encrypted
        serialized_page.extend_from_slice(nonce);
    } else {
        serialized_page.extend_from_slice(&[0; 13]); // 1 byte for is_encrypted, 12 bytes for nonce
    }
    serialized_page.extend_from_slice(data);
    serialized_page
}

#[derive(Debug)]
pub enum MemorySegmentError {
    PageNotFound,
    InvalidPageSize,
    MemoryError(MemoryError),
    AccumulatorError(AccumulatorError),
}

impl From<MemoryError> for MemorySegmentError {
    fn from(e: MemoryError) -> Self {
        MemorySegmentError::MemoryError(e)
    }
}

impl From<AccumulatorError> for MemorySegmentError {
    fn from(e: AccumulatorError) -> Self {
        MemorySegmentError::AccumulatorError(e)
    }
}

impl std::fmt::Display for MemorySegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MemorySegmentError::PageNotFound => write!(f, "Page not found"),
            MemorySegmentError::InvalidPageSize => write!(f, "Invalid page size"),
            MemorySegmentError::MemoryError(e) => write!(f, "Memory error: {}", e),
            MemorySegmentError::AccumulatorError(e) => write!(f, "Accumulator error: {}", e),
        }
    }
}

impl std::error::Error for MemorySegmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemorySegmentError::MemoryError(e) => Some(e),
            MemorySegmentError::AccumulatorError(e) => Some(e),
            _ => None,
        }
    }
}

// Represents a memory segment stored by the client, using a MerkleAccumulator to provide proofs of integrity.
pub struct MemorySegment {
    content: MerkleAccumulator<Sha256, Vec<u8>, 32>,
}

impl MemorySegment {
    pub fn new(start: u32, data: &[u8]) -> Self {
        let end = start + data.len() as u32;

        let mut pages: Vec<Vec<u8>> = Vec::new();

        // current position, in terms of address; `start` needs to be subtracted for the position in `data`
        let mut current_addr = start;
        loop {
            if current_addr >= end {
                break;
            }
            let mut page_content: Vec<u8> = Vec::with_capacity(PAGE_SIZE);
            let page_start_addr = page_start(current_addr as u32);
            let page_end_addr = page_start_addr + PAGE_SIZE as u32;
            let content_end_addr = min(page_end_addr, end);

            // 0-pad with current_addr - page_start_addr bytes (always 0, except for the first page if unaligned to PAGE_SIZE)
            page_content.extend_from_slice(&vec![0; (current_addr - page_start_addr) as usize]);

            // copy content_end_addr - current_addr bytes from data
            page_content.extend_from_slice(
                &data[(current_addr - start) as usize..(content_end_addr - start) as usize],
            );

            // 0-pad with page_end_addr - content_end_addr bytes bytes (always 0, except possibly for last page)
            page_content.extend_from_slice(&vec![0; (page_end_addr - content_end_addr) as usize]);

            current_addr = page_end_addr;

            let serialized_page = get_serialized_page(&page_content, None);

            pages.push(serialized_page);
        }

        // ensure that the number of pages is a power of two, which is required for the MerkleAccumulator
        // we pad with empty pages, which are valid pages with all-zero content.
        let target_len = pages
            .len()
            .checked_next_power_of_two()
            .expect("Too many pages");
        while pages.len() < target_len {
            pages.push(get_serialized_page(&[0; PAGE_SIZE], None));
        }

        Self {
            content: MerkleAccumulator::<Sha256, Vec<u8>, 32>::new(pages),
        }
    }

    pub fn get_page(
        &self,
        page_index: u32,
    ) -> Result<(Vec<u8>, Vec<HashOutput<32>>), MemorySegmentError> {
        let content = self
            .content
            .get(page_index as usize)
            .ok_or(MemorySegmentError::PageNotFound)?
            .clone();

        let proof = self.content.prove(page_index as usize)?;

        Ok((content, proof))
    }

    pub fn store_page(
        &mut self,
        page_index: u32,
        content: &[u8],
    ) -> Result<(Vec<HashOutput<32>>, HashOutput<32>), MemorySegmentError> {
        if content.len() != 1 + 12 + PAGE_SIZE {
            return Err(MemorySegmentError::InvalidPageSize);
        }
        let proof = self.content.update(page_index as usize, content.to_vec())?;
        Ok(proof)
    }

    pub fn get_content_root(&self) -> &HashOutput<32> {
        self.content.root()
    }
}
