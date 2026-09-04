//! An insertion sort, used in place of the slice sorts from `core`.
//!
//! `[T]::sort_unstable_by` is `ipnsort`, and `[T]::sort_by` is `driftsort`. Both are excellent
//! and both are large: a single instantiation drags in pattern detection, a median-of-medians
//! pivot search, a heapsort fallback and a family of branchless small-sort networks. Measured on
//! the Bitcoin V-App, the two `sort_unstable*` call sites on the validation path accounted for
//! roughly 15 KB of `.text` between them -- more than all of this crate's RSA and elliptic-curve
//! code once that moved onto the ECALLs.
//!
//! Nothing here is sorted at a size where an O(n^2) sort is worth noticing. An RRset is a handful
//! of records, and the one other sorted list is bounded by [`crate::MAX_PROOF_STEPS`], which is
//! 20. Against that, a DNSSEC chain also performs several RSA and ECDSA verifications, so the
//! sorts are not measurable either way.
//!
//! This sort is *stable*, where the calls it replaces were not. That is a safe direction to move
//! in: the order `sort_unstable_by` produces among elements that compare equal is explicitly
//! unspecified, so no correct caller could have depended on it.

use core::cmp::Ordering;

/// Sorts `slice` by `compare`, stably, in place.
pub(crate) fn insertion_sort_by<T, F: FnMut(&T, &T) -> Ordering>(slice: &mut [T], mut compare: F) {
    for i in 1..slice.len() {
        let mut j = i;
        // Walk the element at `i` down past everything greater than it. Stopping at the first
        // element that is not greater -- rather than not less -- is what makes this stable.
        while j > 0 && compare(&slice[j - 1], &slice[j]) == Ordering::Greater {
            slice.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Sorts `slice` in its natural order, stably, in place.
pub(crate) fn insertion_sort<T: Ord>(slice: &mut [T]) {
    insertion_sort_by(slice, |a, b| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A deterministic LCG, so a failure is always reproducible.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    #[test]
    fn sorts_the_degenerate_lengths() {
        let mut empty: [u32; 0] = [];
        insertion_sort(&mut empty);

        let mut one = [7u32];
        insertion_sort(&mut one);
        assert_eq!(one, [7]);

        let mut two = [2u32, 1];
        insertion_sort(&mut two);
        assert_eq!(two, [1, 2]);
    }

    #[test]
    fn sorts_already_sorted_and_reversed_input() {
        let mut sorted: Vec<u32> = (0..32).collect();
        insertion_sort(&mut sorted);
        assert_eq!(sorted, (0..32).collect::<Vec<_>>());

        let mut reversed: Vec<u32> = (0..32).rev().collect();
        insertion_sort(&mut reversed);
        assert_eq!(reversed, (0..32).collect::<Vec<_>>());
    }

    #[test]
    fn agrees_with_the_core_sort_on_random_input() {
        // The point of the whole module: produce exactly what the call it replaces produced.
        let mut rng = Lcg(0x5eed);
        for len in 0..40usize {
            for _ in 0..20 {
                // A small key range, so there are plenty of equal elements to disagree over.
                let v: Vec<u32> = (0..len).map(|_| (rng.next() % 8) as u32).collect();
                let mut mine = v.clone();
                let mut theirs = v.clone();
                insertion_sort(&mut mine);
                theirs.sort_unstable();
                assert_eq!(mine, theirs, "disagreed on {:?}", v);
            }
        }
    }

    #[test]
    fn is_stable() {
        // Sort pairs on the key alone; equal keys must keep their input order. Nothing in this
        // crate depends on stability, but it is the property that makes replacing an unstable
        // sort safe, so it should not be lost silently.
        let mut rng = Lcg(0xc0ffee);
        for len in 0..40usize {
            let v: Vec<(u32, usize)> =
                (0..len).map(|i| ((rng.next() % 5) as u32, i)).collect();
            let mut sorted = v.clone();
            insertion_sort_by(&mut sorted, |a, b| a.0.cmp(&b.0));

            for w in sorted.windows(2) {
                assert!(w[0].0 <= w[1].0, "not sorted: {:?}", sorted);
                if w[0].0 == w[1].0 {
                    assert!(w[0].1 < w[1].1, "not stable: {:?}", sorted);
                }
            }
            assert_eq!(sorted.len(), v.len());
        }
    }

    #[test]
    fn leaves_the_multiset_alone() {
        let mut rng = Lcg(1);
        for len in 0..40usize {
            let v: Vec<u32> = (0..len).map(|_| (rng.next() % 8) as u32).collect();
            let mut sorted = v.clone();
            insertion_sort(&mut sorted);
            let mut counts = [0i32; 8];
            for x in &v {
                counts[*x as usize] += 1;
            }
            for x in &sorted {
                counts[*x as usize] -= 1;
            }
            assert_eq!(counts, [0; 8], "elements were lost or duplicated: {:?}", v);
        }
    }
}
