//! Reverse parser: turn cleartext descriptions back into descriptor templates.
//!
//! This module is compiled only when the `cleartext-decode` feature (or
//! `cfg(test)`) is active — see the conditional `mod decode;` in the parent.
//! Everything here is decode-only; the encoder lives in the parent module.
//!
//! The high-level entry point is [`from_cleartext_impl`], which the
//! [`super::ClearText::from_cleartext`] trait method delegates to.

use alloc::{
    boxed::Box,
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use super::super::time::{parse_relative_time_to_seconds, parse_utc_date_to_timestamp};
use super::super::{DescriptorTemplate, KeyExpression, KeyExpressionType, TapTree};
use super::{
    CleartextPart, CleartextSpec, CleartextValue, DescriptorClass, TapleafClass, TapleafPattern,
    TopLevelPattern, SEQUENCE_LOCKTIME_TYPE_FLAG, TAPLEAF_SPECS, TOP_LEVEL_SPECS,
};

/// Error type for `from_cleartext`.
#[derive(Debug)]
pub enum CleartextDecodeError {
    /// The input descriptions slice was empty.
    EmptyInput,
    /// The cleartext string could not be matched to any known pattern.
    UnrecognizedPattern,
    /// A descriptor template string embedded in the cleartext could not be parsed.
    InvalidDescriptor(String),
    /// A key placeholder was expected to be a plain key but was not.
    ExpectedPlainKey,
    /// Internal inconsistency in spec/pattern matching (should not happen).
    InternalError(&'static str),
}

// `DescriptorClass::from_cleartext_pattern`, `TapleafClass::from_cleartext_pattern`,
// `top_level_variants`, and `tapleaf_to_descriptors` are generated from
// `specs/cleartext.toml` by `build.rs` (see `emit_decode` there).
include!(concat!(env!("OUT_DIR"), "/cleartext_decode_generated.rs"));

fn parse_key_index(s: &str) -> Option<KeyExpression> {
    let rest = s.strip_prefix('@')?;
    if let Ok(idx) = rest.parse::<u32>() {
        // "@N" canonical format
        Some(KeyExpression::plain(idx, 0, 1))
    } else if let Some((idx_str, deriv)) = rest.split_once('/') {
        // "@N/<M;K>/*" explicit derivation format
        let key_index = idx_str.parse().ok()?;
        let deriv = deriv.strip_prefix('<')?.strip_suffix(">/*")?;
        let (m, k) = deriv.split_once(';')?;
        let num1 = m.parse().ok()?;
        let num2 = k.parse().ok()?;
        Some(KeyExpression::plain(key_index, num1, num2))
    } else {
        None
    }
}

fn parse_key_indices(s: &str) -> Option<Vec<KeyExpression>> {
    // Formats: "@A", "@A and @B", "@A, @B and @C", "@A, @B, @C and @D", ...
    if let Some((init, last)) = s.rsplit_once(" and ") {
        let last_kp = parse_key_index(last.trim())?;
        let mut kps: Vec<KeyExpression> = Vec::new();
        for part in init.split(", ") {
            kps.push(parse_key_index(part.trim())?);
        }
        kps.push(last_kp);
        Some(kps)
    } else {
        // Single key: "@A"
        Some(vec![parse_key_index(s.trim())?])
    }
}

fn parse_relative_time(s: &str) -> Option<u32> {
    let secs = parse_relative_time_to_seconds(s)?;
    if secs % 512 != 0 {
        return None;
    }
    Some(secs / 512 | SEQUENCE_LOCKTIME_TYPE_FLAG)
}

struct CleartextValueCursor {
    values: alloc::vec::IntoIter<CleartextValue>,
}

impl CleartextValueCursor {
    fn new(values: Vec<CleartextValue>) -> Self {
        Self {
            values: values.into_iter(),
        }
    }

    fn threshold(&mut self) -> Option<u32> {
        match self.values.next()? {
            CleartextValue::Threshold(value) => Some(value),
            _ => None,
        }
    }

    fn key_index(&mut self) -> Option<KeyExpression> {
        match self.values.next()? {
            CleartextValue::KeyIndex(value) => Some(value),
            _ => None,
        }
    }

    fn key_indices(&mut self) -> Option<Vec<KeyExpression>> {
        match self.values.next()? {
            CleartextValue::KeyIndices(value) => Some(value),
            _ => None,
        }
    }

    fn blocks(&mut self) -> Option<u32> {
        match self.values.next()? {
            CleartextValue::Blocks(value) => Some(value),
            _ => None,
        }
    }

    fn relative_time(&mut self) -> Option<u32> {
        match self.values.next()? {
            CleartextValue::RelativeTime(value) => Some(value),
            _ => None,
        }
    }

    fn block_height(&mut self) -> Option<u32> {
        match self.values.next()? {
            CleartextValue::BlockHeight(value) => Some(value),
            _ => None,
        }
    }

    fn timestamp(&mut self) -> Option<u32> {
        match self.values.next()? {
            CleartextValue::Timestamp(value) => Some(value),
            _ => None,
        }
    }

    fn finish(mut self) -> Option<()> {
        if self.values.next().is_none() {
            Some(())
        } else {
            None
        }
    }
}

fn parse_cleartext_value(part: CleartextPart, input: &str) -> Option<CleartextValue> {
    match part {
        CleartextPart::Literal(_) => None,
        CleartextPart::Threshold => input.parse().ok().map(CleartextValue::Threshold),
        CleartextPart::KeyIndex => parse_key_index(input).map(CleartextValue::KeyIndex),
        CleartextPart::KeyIndices => parse_key_indices(input).map(CleartextValue::KeyIndices),
        CleartextPart::Blocks => input.parse().ok().map(CleartextValue::Blocks),
        CleartextPart::RelativeTime => parse_relative_time(input).map(CleartextValue::RelativeTime),
        CleartextPart::BlockHeight => input.parse().ok().map(CleartextValue::BlockHeight),
        CleartextPart::Timestamp => {
            parse_utc_date_to_timestamp(input).map(CleartextValue::Timestamp)
        }
    }
}

fn parse_with_specs<K: Copy>(
    specs: &[CleartextSpec<K>],
    input: &str,
) -> Vec<(K, Vec<CleartextValue>)> {
    let mut matches = Vec::new();
    for spec in specs {
        for values in parse_with_spec(spec, input) {
            matches.push((spec.kind, values));
        }
    }
    matches
}

fn parse_with_spec<K>(spec: &CleartextSpec<K>, input: &str) -> Vec<Vec<CleartextValue>> {
    debug_assert!(
        spec.parts.windows(2).all(|window| {
            matches!(window[0], CleartextPart::Literal(_))
                || matches!(window[1], CleartextPart::Literal(_))
        }),
        "cleartext specs require literal separators between dynamic fields"
    );
    let mut matches = Vec::new();
    parse_spec_parts(spec.parts, 0, input, Vec::new(), &mut matches);
    matches
}

fn parse_spec_parts(
    parts: &[CleartextPart],
    part_index: usize,
    input: &str,
    values: Vec<CleartextValue>,
    matches: &mut Vec<Vec<CleartextValue>>,
) {
    if part_index == parts.len() {
        if input.is_empty() {
            matches.push(values);
        }
        return;
    }

    match parts[part_index] {
        CleartextPart::Literal(literal) => {
            if let Some(rest) = input.strip_prefix(literal) {
                parse_spec_parts(parts, part_index + 1, rest, values, matches);
            }
        }
        field => match parts.get(part_index + 1) {
            Some(CleartextPart::Literal(next_literal)) => {
                let mut search_start = 0;
                while let Some(offset) = input[search_start..].find(next_literal) {
                    let split = search_start + offset;
                    if let Some(value) = parse_cleartext_value(field, &input[..split]) {
                        let mut next_values = values.clone();
                        next_values.push(value);
                        parse_spec_parts(
                            parts,
                            part_index + 1,
                            &input[split..],
                            next_values,
                            matches,
                        );
                    }
                    search_start = split + next_literal.len();
                }
            }
            Some(_) => {
                debug_assert!(
                    false,
                    "cleartext specs require literal separators between dynamic fields"
                );
            }
            None => {
                if let Some(value) = parse_cleartext_value(field, input) {
                    let mut next_values = values;
                    next_values.push(value);
                    parse_spec_parts(parts, part_index + 1, "", next_values, matches);
                }
            }
        },
    }
}

fn push_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.iter().any(|existing| existing == &item) {
        items.push(item);
    }
}

/// Lazy iterator that generates permutations of `[0, 1, ..., n-1]` in lexicographic order
/// without storing them all in memory.
struct PermutationIter {
    current: Vec<usize>,
    first: bool,
    done: bool,
}

impl PermutationIter {
    fn new(n: usize) -> Self {
        Self {
            current: (0..n).collect(),
            first: true,
            done: n == 0,
        }
    }
}

impl Iterator for PermutationIter {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.first {
            self.first = false;
            return Some(self.current.clone());
        }
        let n = self.current.len();
        // Find largest i such that current[i] < current[i + 1]
        let Some(i) = (0..n - 1).rfind(|&k| self.current[k] < self.current[k + 1]) else {
            self.done = true;
            return None;
        };
        // Find largest j such that current[i] < current[j]
        let j = (0..n)
            .rfind(|&j| self.current[i] < self.current[j])
            .unwrap();
        self.current.swap(i, j);
        self.current[i + 1..].reverse();
        Some(self.current.clone())
    }
}

/// Rewrite all placeholders in `dt` to carry canonical `<2i;2i+1>/*` derivation
/// pairs, assigned in source order *per distinct key expression*. Used by the
/// generated `top_level_variants` to canonicalize templates produced from the
/// cleartext (which only encodes the canonical form).
fn canonicalize_derivations(dt: &mut DescriptorTemplate) {
    let mut next_per_key: alloc::collections::BTreeMap<KeyExpressionType, u32> =
        alloc::collections::BTreeMap::new();
    for kp in dt.placeholders_mut() {
        let n = next_per_key.entry(kp.key_type.clone()).or_insert(0);
        kp.num1 = *n;
        kp.num2 = *n + 1;
        *n += 2;
    }
}

/// Given a base descriptor template (with canonical derivation pairs (0,1), (2,3), ...
/// assigned to placeholder occurrences in source order, per key expression), return the
/// list of all variants obtained by permuting the assignment of those canonical pairs
/// across the occurrences of each key expression.
fn expand_derivation_orderings(base: DescriptorTemplate) -> Vec<DescriptorTemplate> {
    use alloc::collections::BTreeMap;

    // Collect the source-order positions of placeholders, grouped by key expression.
    let mut groups: BTreeMap<KeyExpressionType, Vec<usize>> = BTreeMap::new();
    for (i, (kp, _)) in base.placeholders().enumerate() {
        groups.entry(kp.key_type.clone()).or_default().push(i);
    }

    let positions_per_group: Vec<Vec<usize>> = groups.into_values().collect();
    let group_sizes: Vec<usize> = positions_per_group.iter().map(|p| p.len()).collect();

    let mut results = Vec::new();
    let mut chosen: Vec<Vec<usize>> = Vec::with_capacity(group_sizes.len());
    expand_derivation_orderings_rec(
        &positions_per_group,
        &group_sizes,
        &mut chosen,
        &base,
        &mut results,
    );
    results
}

fn expand_derivation_orderings_rec(
    positions_per_group: &[Vec<usize>],
    group_sizes: &[usize],
    chosen: &mut Vec<Vec<usize>>,
    base: &DescriptorTemplate,
    results: &mut Vec<DescriptorTemplate>,
) {
    if chosen.len() == group_sizes.len() {
        // Build mapping: source-position -> (num1, num2)
        let mut mapping: alloc::collections::BTreeMap<usize, (u32, u32)> =
            alloc::collections::BTreeMap::new();
        for (g, perm) in chosen.iter().enumerate() {
            let positions = &positions_per_group[g];
            for (slot, &src_pos) in positions.iter().enumerate() {
                let p = perm[slot];
                mapping.insert(src_pos, (2 * p as u32, 2 * p as u32 + 1));
            }
        }
        let mut new_dt = base.clone();
        let mut idx = 0;
        for kp in new_dt.placeholders_mut() {
            let (n1, n2) = mapping[&idx];
            kp.num1 = n1;
            kp.num2 = n2;
            idx += 1;
        }
        results.push(new_dt);
        return;
    }
    let g = chosen.len();
    for perm in PermutationIter::new(group_sizes[g]) {
        chosen.push(perm);
        expand_derivation_orderings_rec(positions_per_group, group_sizes, chosen, base, results);
        chosen.pop();
    }
}

fn parse_leaf_candidates(s: &str) -> Result<Vec<TapleafClass>, CleartextDecodeError> {
    let mut leaves = Vec::new();
    for (kind, values) in parse_with_specs(TAPLEAF_SPECS, s) {
        push_unique(
            &mut leaves,
            TapleafClass::from_cleartext_pattern(kind, values).ok_or(
                CleartextDecodeError::InternalError("spec/from_cleartext_pattern mismatch"),
            )?,
        );
    }
    if leaves.is_empty() {
        leaves.push(TapleafClass::Other(s.to_string()));
    }
    Ok(leaves)
}

fn collect_tapleaf_combinations(
    per_leaf_candidates: &[Vec<TapleafClass>],
    current: &mut Vec<TapleafClass>,
    combinations: &mut Vec<Vec<TapleafClass>>,
) {
    if current.len() == per_leaf_candidates.len() {
        combinations.push(current.clone());
        return;
    }

    for leaf in &per_leaf_candidates[current.len()] {
        current.push(leaf.clone());
        collect_tapleaf_combinations(per_leaf_candidates, current, combinations);
        current.pop();
    }
}

fn parse_top_level_candidates(
    descriptions: &[&str],
) -> Result<Vec<DescriptorClass>, CleartextDecodeError> {
    match descriptions {
        [] => Err(CleartextDecodeError::EmptyInput),
        [single] => {
            let mut classes = Vec::new();
            for (kind, values) in parse_with_specs(TOP_LEVEL_SPECS, single) {
                push_unique(
                    &mut classes,
                    DescriptorClass::from_cleartext_pattern(kind, values).ok_or(
                        CleartextDecodeError::InternalError("spec/from_cleartext_pattern mismatch"),
                    )?,
                );
            }
            if classes.is_empty() {
                classes.push(DescriptorClass::Other);
            }
            Ok(classes)
        }
        [first, rest @ ..] => {
            let mut classes = Vec::new();
            let mut per_leaf_candidates = Vec::new();
            for &leaf in rest {
                per_leaf_candidates.push(parse_leaf_candidates(leaf)?);
            }

            let mut leaf_combinations = Vec::new();
            collect_tapleaf_combinations(
                &per_leaf_candidates,
                &mut Vec::new(),
                &mut leaf_combinations,
            );

            for (kind, values) in parse_with_specs(TOP_LEVEL_SPECS, first) {
                let base_class = DescriptorClass::from_cleartext_pattern(kind, values).ok_or(
                    CleartextDecodeError::InternalError("spec/from_cleartext_pattern mismatch"),
                )?;
                match base_class {
                    DescriptorClass::Taproot { internal_key, .. } => {
                        for leaves in &leaf_combinations {
                            push_unique(
                                &mut classes,
                                DescriptorClass::Taproot {
                                    internal_key: internal_key.clone(),
                                    leaves: leaves.clone(),
                                },
                            );
                        }
                    }
                    DescriptorClass::TaprootMusig {
                        threshold, keys, ..
                    } => {
                        for leaves in &leaf_combinations {
                            push_unique(
                                &mut classes,
                                DescriptorClass::TaprootMusig {
                                    threshold,
                                    keys: keys.clone(),
                                    leaves: leaves.clone(),
                                },
                            );
                        }
                    }
                    _ => continue,
                }
            }

            if classes.is_empty() {
                Err(CleartextDecodeError::UnrecognizedPattern)
            } else {
                Ok(classes)
            }
        }
    }
}

/// Enumerate all distinct unordered binary tree topologies for `n` leaves
/// and return a lazy iterator over every combination of leaf variant assignments.
///
/// A binary tree with `n` leaves has `T(n)` distinct unordered shapes where
/// `T(n) = (2n - 3)!! = 1 * 3 * 5 * ... * (2n - 3)` for `n > 1`, and `T(1) = 1`.
///
/// `leaf_variants[i]` is the set of `DescriptorTemplate` alternatives for leaf `i`.
fn enumerate_taptrees(
    leaf_variants: Vec<Vec<DescriptorTemplate>>,
) -> Box<dyn Iterator<Item = TapTree>> {
    assert!(!leaf_variants.is_empty());
    if leaf_variants.len() == 1 {
        let variants = leaf_variants.into_iter().next().unwrap();
        return Box::new(variants.into_iter().map(|d| TapTree::Script(Box::new(d))));
    }
    let indices: Vec<usize> = (0..leaf_variants.len()).collect();
    enumerate_taptrees_indices(indices, Rc::new(leaf_variants))
}

/// Recursively enumerate unordered binary trees over the given subset of leaf indices,
/// returning a lazy iterator.
///
/// To avoid counting mirror-image trees twice (since swapping the two children
/// of any internal node produces an identical Merkle root), we fix the smallest
/// leaf index in the left subtree.
fn enumerate_taptrees_indices(
    indices: Vec<usize>,
    leaf_variants: Rc<Vec<Vec<DescriptorTemplate>>>,
) -> Box<dyn Iterator<Item = TapTree>> {
    if indices.len() == 1 {
        let variants = leaf_variants[indices[0]].clone();
        return Box::new(variants.into_iter().map(|d| TapTree::Script(Box::new(d))));
    }
    // Pin the smallest index in the left subtree to canonicalise.
    // Partition the remaining indices between left and right.
    let first = indices[0];
    let rest: Vec<usize> = indices[1..].to_vec();
    let n_rest = rest.len();
    // left_extra_mask: bitmask over `rest` — bits set → go to left subtree
    // left_extra_mask = 0 means left subtree = {first}, right subtree = rest (all)
    // left_extra_mask = (1 << n_rest) - 1 is invalid (right subtree empty)
    Box::new(
        (0..(1u64 << n_rest))
            .filter(move |&mask| n_rest > mask.count_ones() as usize)
            .flat_map(
                move |left_extra_mask| -> Box<dyn Iterator<Item = TapTree>> {
                    let mut left_indices = vec![first];
                    let mut right_indices = Vec::new();
                    for (bit, &idx) in rest.iter().enumerate() {
                        if left_extra_mask & (1u64 << bit) != 0 {
                            left_indices.push(idx);
                        } else {
                            right_indices.push(idx);
                        }
                    }
                    // Collect right subtree (iterated multiple times in the Cartesian product).
                    let right_trees: Rc<Vec<TapTree>> = Rc::new(
                        enumerate_taptrees_indices(right_indices, Rc::clone(&leaf_variants))
                            .collect(),
                    );
                    let left_trees =
                        enumerate_taptrees_indices(left_indices, Rc::clone(&leaf_variants));
                    Box::new(left_trees.flat_map(move |lt| {
                        let right = Rc::clone(&right_trees);
                        (0..right.len()).map(move |i| {
                            TapTree::Branch(Box::new(lt.clone()), Box::new(right[i].clone()))
                        })
                    }))
                },
            ),
    )
}

/// Top-level entry point: parse `descriptions` and yield every descriptor
/// template that would round-trip to the same cleartext form. Called from
/// [`super::ClearText::from_cleartext`].
pub(super) fn from_cleartext_impl(
    descriptions: &[&str],
) -> Result<Box<dyn Iterator<Item = DescriptorTemplate>>, CleartextDecodeError> {
    let classes = parse_top_level_candidates(descriptions)?;
    // `top_level_variants` only fails for `DescriptorClass::Other`; surface that
    // upfront so the chain below can call it lazily, one class at a time.
    if classes.iter().any(|c| matches!(c, DescriptorClass::Other)) {
        return Err(CleartextDecodeError::UnrecognizedPattern);
    }
    Ok(Box::new(
        classes
            .into_iter()
            .flat_map(|class| top_level_variants(class).ok().into_iter().flatten())
            .flat_map(expand_derivation_orderings),
    ))
}
