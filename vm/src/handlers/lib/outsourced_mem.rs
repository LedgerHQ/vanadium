use core::cell::RefCell;

use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use common::accumulator::{
    HashOutput, Hasher, InclusionProofVerifier, MerkleAccumulator, ResettableHasher,
    StreamingVectorAccumulator, UpdateProofVerifier,
};
use common::vm::{Page, PagedMemory};
use ledger_device_sdk::io;

use common::client_commands::{
    CommitPageMessage, CommitPageProofContinuedMessage, CommitPageProofContinuedResponse,
    CommitPageProofResponse, GetPageMessage, GetPageProofContinuedMessage,
    GetPageProofContinuedResponse, GetPageResponse, Message, SectionKind,
};
use common::constants::PAGE_SIZE;

use crate::aes::AesCtr;
use crate::hash::Sha256Hasher;

use crate::handlers::lib::evict::PageEvictionStrategy;
use crate::io::{interrupt, SerializeToComm};

#[derive(Clone, Debug)]
struct CachedPage {
    idx: u32,                  // Page index
    page: Page,                // Page data
    page_hash: HashOutput<32>, // Hash of the page data when loaded (before any changes)
    valid: bool,               // Indicates if the slot contains a valid page
    modified: bool,            // Indicates if the page has been modified since it was loaded
}

impl Default for CachedPage {
    fn default() -> Self {
        Self {
            idx: 0,
            page: Page {
                data: [0; PAGE_SIZE],
            },
            page_hash: [0; 32].into(),
            valid: false,
            modified: false,
        }
    }
}

pub struct OutsourcedMemory<'c, const N: usize> {
    comm: Rc<RefCell<&'c mut io::Comm<N>>>,
    cached_pages: Vec<CachedPage>,
    n_pages: u32,
    merkle_root: HashOutput<32>,
    aes_ctr: Rc<RefCell<AesCtr>>,
    hasher: Sha256Hasher,
    is_readonly: bool,
    section_kind: SectionKind,
    eviction_strategy: Box<dyn PageEvictionStrategy + 'c>,
    last_accessed_page: Option<(u32, usize)>,
    #[cfg(feature = "metrics")]
    pub n_page_loads: usize,
    #[cfg(feature = "metrics")]
    pub n_page_commits: usize,
}

impl<'c, const N: usize> core::fmt::Debug for OutsourcedMemory<'c, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutsourcedMemory")
            .field("comm", &"...")
            .field("cached_pages", &self.cached_pages)
            .field("is_readonly", &self.is_readonly)
            .field("section_kind", &self.section_kind)
            .finish()
    }
}

/// Computes the hash of a page as a MerkleAccumulator element.
/// Note that this assumes that a 0 byte is prepended to the hash of the serialized content of the page.
/// Therefore, it would be incorrect if an accumulator different than the MerkleAccumulator is used.
fn get_page_hash(
    hasher: &mut Sha256Hasher,
    data: &[u8],
    nonce: Option<&[u8; 12]>,
) -> HashOutput<32> {
    hasher.reset();
    hasher.update(&[0x0u8]); // leaves in the Merkle tree have the 0x00 prefix
    match nonce {
        Some(nonce) => {
            hasher.update(&[0x1u8]);
            hasher.update(nonce)
        }
        None => hasher.update(&[0x0u8; 13]),
    };
    hasher.update(data);
    hasher.finalize_inplace().into()
}

impl<'c, const N: usize> OutsourcedMemory<'c, N> {
    pub fn new(
        comm: Rc<RefCell<&'c mut io::Comm<N>>>,
        max_pages_in_cache: usize,
        is_readonly: bool,
        section_kind: SectionKind,
        n_pages: u32,
        merkle_root: HashOutput<32>,
        aes_ctr: Rc<RefCell<AesCtr>>,
        eviction_strategy: Box<dyn PageEvictionStrategy + 'c>,
    ) -> Self {
        Self {
            comm,
            cached_pages: vec![CachedPage::default(); max_pages_in_cache],
            n_pages,
            merkle_root,
            aes_ctr,
            is_readonly,
            section_kind,
            eviction_strategy,
            hasher: Sha256Hasher::new(),
            last_accessed_page: None,
            #[cfg(feature = "metrics")]
            n_page_loads: 0,
            #[cfg(feature = "metrics")]
            n_page_commits: 0,
        }
    }

    // Return the number of bytes used by a each additional cached page
    pub const fn size_per_page() -> usize {
        core::mem::size_of::<CachedPage>()
    }

    #[inline]
    /// Computes the number of pages to use for a given number of pages, after taking padding into account.
    pub fn n_pages_adjusted(n_pages: usize) -> usize {
        n_pages
            .checked_next_power_of_two()
            .expect("Number of pages exceeds the maximum allowed")
    }

    fn commit_page_at(&mut self, index: usize) -> Result<(), common::vm::MemoryError> {
        #[cfg(feature = "trace_pages")]
        crate::trace!(
            "page_commit",
            "light_green",
            "section: {:?}, page_index: {}",
            self.section_kind,
            index
        );

        let cached_page = &self.cached_pages[index];
        assert!(cached_page.valid, "Trying to commit an invalid page");

        let page_hash_old = &cached_page.page_hash;

        #[cfg(feature = "metrics")]
        {
            self.n_page_commits += 1;
        }

        let mut aes_ctr = self.aes_ctr.borrow_mut();

        let (nonce, payload) = aes_ctr
            .encrypt(&cached_page.page.data)
            .map_err(|_| common::vm::MemoryError::GenericError("AES encryption failed"))?;
        let new_page_hash = get_page_hash(&mut self.hasher, &payload, Some(&nonce));

        assert!(payload.len() == PAGE_SIZE);

        let payload_array: &[u8; PAGE_SIZE] = payload
            .as_slice()
            .try_into()
            .expect("The payload is the correct size");

        let mut comm = self.comm.borrow_mut();
        let mut resp = comm.begin_response();
        CommitPageMessage::new(
            self.section_kind,
            cached_page.idx,
            true,
            nonce,
            payload_array,
        )
        .serialize_to_comm(&mut resp);

        let command =
            interrupt(resp).map_err(|e| common::vm::MemoryError::GenericError(e.as_str()))?;

        // Decode the proof
        let proof_data = command.get_data();

        let proof_response = CommitPageProofResponse::deserialize(&proof_data)
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid proof data"))?;

        let n = proof_response.n; // Total number of elements in the proof
        if n == 0 {
            return Err(common::vm::MemoryError::GenericError(
                "Proof must contain at least one element",
            ));
        }
        if proof_response.t as usize != proof_response.proof.len() {
            return Err(common::vm::MemoryError::GenericError(
                "Proof fragment size does not match the expected number of elements",
            ));
        }

        let new_root = HashOutput::<32>::as_hash_output(proof_response.new_root).clone();

        // Verify the Merkle update proof using streaming verification
        let mut verifier = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::begin_update_proof(
            &self.merkle_root,
            &new_root,
            page_hash_old,
            &new_page_hash,
            cached_page.idx as usize,
            Self::n_pages_adjusted(self.n_pages as usize),
        );

        for el in proof_response.proof.iter() {
            verifier.feed(&mut self.hasher, HashOutput::<32>::as_hash_output(el));
        }
        let mut n_processed_elements = proof_response.t as usize;

        // If we need more elements, request them
        while n_processed_elements < n as usize {
            let mut resp = comm.begin_response();
            CommitPageProofContinuedMessage::new().serialize_to_comm(&mut resp);

            let command =
                interrupt(resp).map_err(|e| common::vm::MemoryError::GenericError(e.as_str()))?;

            let continued_response = CommitPageProofContinuedResponse::deserialize(
                &command.get_data(),
            )
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid continued proof data"))?;

            if continued_response.t as usize != continued_response.proof.len() {
                return Err(common::vm::MemoryError::GenericError(
                    "Continued proof size does not match the expected number of elements",
                ));
            }
            for el in continued_response.proof.iter() {
                verifier.feed(&mut self.hasher, HashOutput::<32>::as_hash_output(el));
            }
            n_processed_elements += continued_response.t as usize;
        }

        if !verifier.verified() {
            return Err(common::vm::MemoryError::GenericError(
                "Merkle update verification failed",
            ));
        }

        // Update the root to the new root
        self.merkle_root = new_root;

        Ok(())
    }

    fn load_page(
        &mut self,
        page_index: u32,
    ) -> Result<(Page, HashOutput<32>), common::vm::MemoryError> {
        #[cfg(feature = "metrics")]
        {
            self.n_page_loads += 1;
        }

        #[cfg(feature = "trace_pages")]
        crate::trace!(
            "page_load",
            "light_green",
            "section: {:?}, page_index: {}",
            self.section_kind,
            page_index
        );

        let mut comm = self.comm.borrow_mut();
        let mut resp = comm.begin_response();
        GetPageMessage::new(self.section_kind, page_index).serialize_to_comm(&mut resp);

        let command =
            interrupt(resp).map_err(|e| common::vm::MemoryError::GenericError(e.as_str()))?;

        let page_response = GetPageResponse::deserialize(command.get_data())
            .map_err(|_| common::vm::MemoryError::GenericError("Invalid page data"))?;

        let page_hash = if page_response.is_encrypted {
            get_page_hash(
                &mut self.hasher,
                page_response.page_data,
                Some(&page_response.nonce),
            )
        } else {
            get_page_hash(&mut self.hasher, page_response.page_data, None)
        };

        let n = page_response.n; // Total number of elements in the proof
        if page_response.t as usize != page_response.proof.len() {
            return Err(common::vm::MemoryError::GenericError(
                "Proof fragment size does not match the expected number of elements",
            ));
        }

        // Verify the Merkle inclusion proof using streaming verification
        let mut verifier = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::begin_inclusion_proof(
            &self.merkle_root,
            &page_hash,
            page_index as usize,
            (self.n_pages as usize)
                .checked_next_power_of_two()
                .expect("Too many pages"),
        );

        for el in page_response.proof.iter() {
            verifier.feed(&mut self.hasher, HashOutput::<32>::as_hash_output(el));
        }

        let nonce = page_response.nonce.clone();
        let is_page_encrypted = page_response.is_encrypted;

        let mut n_processed_elements = page_response.t as usize;
        let data = *page_response.page_data;

        // If we need more elements, request them
        while n_processed_elements < n as usize {
            let mut resp = comm.begin_response();
            GetPageProofContinuedMessage::new().serialize_to_comm(&mut resp);

            let command =
                interrupt(resp).map_err(|e| common::vm::MemoryError::GenericError(e.as_str()))?;

            let continued_response =
                GetPageProofContinuedResponse::deserialize(&command.get_data()).map_err(|_| {
                    common::vm::MemoryError::GenericError("Invalid continued proof data")
                })?;

            if continued_response.t as usize != continued_response.proof.len() {
                return Err(common::vm::MemoryError::GenericError(
                    "Continued proof size does not match the expected number of elements",
                ));
            }

            for el in continued_response.proof.iter() {
                verifier.feed(&mut self.hasher, HashOutput::<32>::as_hash_output(el));
            }
            n_processed_elements += continued_response.t as usize;
        }

        if !verifier.verified() {
            return Err(common::vm::MemoryError::GenericError(
                "Merkle inclusion verification failed",
            ));
        }

        if is_page_encrypted {
            // Decrypt the page data
            let aes_ctr = self.aes_ctr.borrow();
            let decrypted_data = aes_ctr
                .decrypt(&nonce, &data)
                .map_err(|_| common::vm::MemoryError::GenericError("AES decryption failed"))?;

            // validate decrypted size matches expected page size
            if decrypted_data.len() != PAGE_SIZE {
                return Err(common::vm::MemoryError::GenericError(
                    "Decrypted page size mismatch",
                ));
            }

            // safe conversion since we just validated the length
            let page_data: [u8; PAGE_SIZE] = decrypted_data.try_into().unwrap();

            Ok((Page { data: page_data }, page_hash))
        } else {
            Ok((Page { data }, page_hash))
        }
    }
}

pub struct CachedPageRef<'a> {
    cached_page: &'a mut CachedPage,
}

impl<'a> core::ops::Deref for CachedPageRef<'a> {
    type Target = Page;

    fn deref(&self) -> &Self::Target {
        &self.cached_page.page
    }
}

impl<'a> core::ops::DerefMut for CachedPageRef<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.cached_page.modified = true;
        &mut self.cached_page.page
    }
}

impl<'c, const N: usize> OutsourcedMemory<'c, N> {
    #[inline]
    /// Returns a mutable reference to the page in the cache, updating the last accessed page.
    fn get_cached_page_ref(&mut self, page_index: u32, slot: usize) -> CachedPageRef<'_> {
        self.last_accessed_page = Some((page_index, slot));
        CachedPageRef {
            cached_page: &mut self.cached_pages[slot],
        }
    }
}

impl<'c, const N: usize> PagedMemory for OutsourcedMemory<'c, N> {
    type PageRef<'a>
        = CachedPageRef<'a>
    where
        Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, common::vm::MemoryError> {
        // Check if this is the same page as the last accessed one; if so, return immediately.
        // For the purpose of cache strategies, we do not want to count consecutive accesses
        // as separate ones. Therefore, here we return without informing the eviction strategy.
        if let Some((last_page_index, last_slot)) = self.last_accessed_page {
            if page_index == last_page_index {
                return Ok(self.get_cached_page_ref(page_index, last_slot));
            }
        }

        // Search for the page in cache
        for i in 0..self.cached_pages.len() {
            if self.cached_pages[i].valid && self.cached_pages[i].idx == page_index {
                self.eviction_strategy.on_access(i, page_index);

                return Ok(self.get_cached_page_ref(page_index, i));
            }
        }

        // Page not found in cache
        // Find a free slot
        let mut slot: Option<usize> = None;
        for i in 0..self.cached_pages.len() {
            if !self.cached_pages[i].valid {
                slot = Some(i);
                break;
            }
        }

        // If no free slot, evict a page
        if slot.is_none() {
            let evict_index = self.eviction_strategy.choose_victim();

            // Commit the page if this memory is not readonly and the page was modified
            if !self.is_readonly && self.cached_pages[evict_index].modified {
                self.commit_page_at(evict_index)?;
            }

            // Invalidate the evicted page
            let evicted_page_index = self.cached_pages[evict_index].idx;
            self.cached_pages[evict_index].valid = false;
            self.eviction_strategy
                .on_invalidate(evict_index, evicted_page_index);
            slot = Some(evict_index);

            #[cfg(feature = "trace_pages")]
            crate::trace!(
                "page_evict",
                "light_green",
                "section: {:?}, page_index: {}, slot: {}",
                self.section_kind,
                evicted_page_index,
                evict_index
            );
        }

        let slot = slot.unwrap();

        // Load the page into the slot
        let (page_data, page_hash) = self.load_page(page_index)?;
        self.cached_pages[slot] = CachedPage {
            idx: page_index,
            page: page_data,
            page_hash,
            valid: true,
            modified: false,
        };
        self.eviction_strategy.on_load(slot, page_index);

        Ok(self.get_cached_page_ref(page_index, slot))
    }
}
