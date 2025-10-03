//! This module provides traits and implementations for page eviction strategies,
//! to be used in the `OutsourcedMemory` structure.

use alloc::{collections::VecDeque, vec, vec::Vec};

pub trait PageEvictionStrategy {
    /// Called when a page is accessed in a given slot.
    fn on_access(&mut self, slot_index: usize, page_index: u32);

    /// Called when a new page is loaded into a slot.
    fn on_load(&mut self, slot_index: usize, page_index: u32);

    /// Choose a victim slot to evict.
    fn choose_victim(&mut self) -> usize;

    /// Called when a slot is invalidated.
    fn on_invalidate(&mut self, slot_index: usize, page_index: u32);
}

/// A simple LRU (Least Recently Used) eviction strategy.
pub struct LruEvictionStrategy {
    usage_counters: Vec<u32>,
    global_counter: u32,
}

impl LruEvictionStrategy {
    pub fn new(num_slots: usize) -> Self {
        Self {
            usage_counters: vec![0; num_slots],
            global_counter: 0,
        }
    }
}

impl PageEvictionStrategy for LruEvictionStrategy {
    fn on_access(&mut self, slot_index: usize, _page_index: u32) {
        self.global_counter = self.global_counter.wrapping_add(1);
        self.usage_counters[slot_index] = self.global_counter;
    }

    fn on_load(&mut self, slot_index: usize, _page_index: u32) {
        self.global_counter = self.global_counter.wrapping_add(1);
        self.usage_counters[slot_index] = self.global_counter;
    }

    fn choose_victim(&mut self) -> usize {
        let mut oldest_usage = u32::MAX;
        let mut evict_index = 0;
        for i in 0..self.usage_counters.len() {
            if self.usage_counters[i] < oldest_usage {
                oldest_usage = self.usage_counters[i];
                evict_index = i;
            }
        }
        evict_index
    }

    fn on_invalidate(&mut self, slot_index: usize, _page_index: u32) {
        // For LRU, we can just reset the counter.
        self.usage_counters[slot_index] = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageState {
    Free,
    A1(u32), // In A1 queue, with a timestamp for FIFO
    Am(u32), // In Am queue, with a timestamp for LRU
}

/// 2Q: A Low Overhead High Performance Buffer Management Replacement Algorithm
/// https://www.vldb.org/conf/1994/P439.PDF
/// This implementation keeps the A1 and Am queues implied by using the `PageState` enum.
/// While this implies linear scanning, this should be acceptable for the small size of
/// the cache that we expect.
#[derive(Debug)]
pub struct TwoQEvictionStrategy {
    states: Vec<PageState>,
    global_counter: u32,
    a1_max_size: usize,
    a1_size: usize,
    a1out: VecDeque<u32>,
    a1out_max_size: usize,
}

impl TwoQEvictionStrategy {
    pub fn new(num_slots: usize, a1_max_size: usize, a1out_max_size: usize) -> Self {
        if a1_max_size >= num_slots {
            panic!("A1 max size must be smaller than total slots");
        }
        Self {
            states: vec![PageState::Free; num_slots],
            global_counter: 0,
            a1_max_size,
            a1_size: 0,
            a1out: VecDeque::with_capacity(a1out_max_size),
            a1out_max_size,
        }
    }

    // estimates how much space this struct uses for each additional page slot
    pub const fn size_per_page() -> usize {
        core::mem::size_of::<PageState>() + core::mem::size_of::<u32>()
    }
}

impl PageEvictionStrategy for TwoQEvictionStrategy {
    fn on_access(&mut self, slot_index: usize, _page_index: u32) {
        self.global_counter = self.global_counter.wrapping_add(1);
        match self.states[slot_index] {
            PageState::A1(_) => {
                // do nothing: counter is not updated in A1, as it's FIFO
            }
            PageState::Am(_) => {
                // Re-accessed in Am, update LRU counter
                self.states[slot_index] = PageState::Am(self.global_counter);
            }
            PageState::Free => {
                // Should not happen on access, but handle defensively
            }
        }
    }

    fn on_load(&mut self, slot_index: usize, page_index: u32) {
        self.global_counter = self.global_counter.wrapping_add(1);
        // If the page is in A1out, move it to Am
        if let Some(pos) = self.a1out.iter().position(|&x| x == page_index) {
            self.a1out.remove(pos);
            self.states[slot_index] = PageState::Am(self.global_counter);
        } else {
            // Otherwise, add it to A1
            self.states[slot_index] = PageState::A1(self.global_counter);
            self.a1_size += 1;
        }
    }

    fn choose_victim(&mut self) -> usize {
        if self.a1_size >= self.a1_max_size {
            // Evict from A1 (FIFO)
            let mut oldest_time = u32::MAX;
            let mut victim_index = 0;
            for (i, state) in self.states.iter().enumerate() {
                if let PageState::A1(time) = *state {
                    if time < oldest_time {
                        oldest_time = time;
                        victim_index = i;
                    }
                }
            }

            victim_index
        } else {
            // Evict from Am (LRU)
            let mut oldest_time = u32::MAX;
            let mut victim_index = 0;
            let mut found_in_am = false;
            for (i, state) in self.states.iter().enumerate() {
                if let PageState::Am(time) = *state {
                    if time < oldest_time {
                        oldest_time = time;
                        victim_index = i;
                        found_in_am = true;
                    }
                }
            }

            if !found_in_am {
                // Fallback to A1 if Am is empty
                return self.choose_victim_from_a1_fallback();
            }

            victim_index
        }
    }

    fn on_invalidate(&mut self, slot_index: usize, page_index: u32) {
        if let PageState::A1(_) = self.states[slot_index] {
            self.a1_size -= 1;
            // Add to A1out
            if self.a1out.len() == self.a1out_max_size {
                self.a1out.pop_front();
            }
            self.a1out.push_back(page_index);
        }
        self.states[slot_index] = PageState::Free;
    }
}

impl TwoQEvictionStrategy {
    fn choose_victim_from_a1_fallback(&self) -> usize {
        let mut oldest_time = u32::MAX;
        let mut victim_index = 0;
        let mut found = false;
        for (i, state) in self.states.iter().enumerate() {
            if let PageState::A1(time) = *state {
                if time < oldest_time {
                    oldest_time = time;
                    victim_index = i;
                    found = true;
                }
            }
        }

        if !found {
            unreachable!("This never happens, as there is always a page to evict in A1 or Am")
        }

        victim_index
    }
}
