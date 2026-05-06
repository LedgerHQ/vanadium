//! Bidirectional conversion between BIP388 descriptor templates and human-readable
//! "cleartext" descriptions suitable for display on constrained UIs (e.g. hardware signers).
//!
//! # Architecture
//!
//! 1. **Classification** — [`DescriptorTemplate::classify`] / [`classify_as_tapleaf`] map the
//!    full descriptor AST onto a small set of recognized spending-policy shapes
//!    ([`DescriptorClass`] / [`TapleafClass`]). Anything unrecognized becomes `Other`.
//!
//! 2. **Spec-driven formatting** — Each recognized shape has a [`CleartextSpec`]: an array of
//!    [`CleartextPart`] tokens (literal strings interleaved with typed dynamic fields such as
//!    key indices, thresholds, and lock values). Both the encoder ([`to_cleartext`]) and the
//!    decoder ([`from_cleartext`]) are driven by the *same* specs (in the [`specs`] sub-module),
//!    so the two directions stay structurally consistent by construction.
//!
//! 3. **Confusion score** — A single cleartext string can correspond to multiple distinct
//!    descriptor templates (e.g. `wpkh` vs `sh(wpkh)`). [`ClearText::confusion_score`]
//!    quantifies this ambiguity; descriptions are only shown when the score is below
//!    [`MAX_CONFUSION_SCORE`].
//!
//! 4. **Reverse parsing** (feature-gated: `cleartext-decode`) — [`ClearText::from_cleartext`]
//!    parses a cleartext description back into *all* structurally distinct descriptor template
//!    candidates, including enumeration of taproot tree topologies.
//!
//! 5. **Canonical display order** — Taproot leaves are sorted via [`TapleafClass::display_cmp`]
//!    so the cleartext output is deterministic regardless of the original tree shape. The number
//!    of structurally distinct trees is taken into account in the confusion score.

use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use super::time::{format_seconds, format_utc_date};
use super::{DescriptorTemplate, KeyExpressionType, KeyPlaceholder};

#[cfg(any(test, feature = "cleartext-decode"))]
use super::time::{parse_relative_time_to_seconds, parse_utc_date_to_timestamp};
#[cfg(any(test, feature = "cleartext-decode"))]
use super::TapTree;
#[cfg(any(test, feature = "cleartext-decode"))]
use alloc::{boxed::Box, rc::Rc};

// Maximum confusion score for which cleartext descriptions are shown instead of the raw descriptor template.
pub const MAX_CONFUSION_SCORE: u64 = 3600;

const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Error type for `from_cleartext`.
#[cfg(any(test, feature = "cleartext-decode"))]
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

// `DescriptorClass`, `TapleafClass`, `TopLevelPattern`, `TapleafPattern`,
// the `TOP_LEVEL_SPECS` / `TAPLEAF_SPECS` cleartext templates, and all the
// pattern-matching code (`classify`, `classify_as_tapleaf`, `cleartext_pattern`,
// `order`, `outer_score`, `per_leaf_score`, `from_cleartext_pattern`,
// `tapleaf_to_descriptors`, `top_level_variants`) are generated from
// `cleartext.spec.toml` by `build.rs`.
include!(concat!(env!("OUT_DIR"), "/cleartext_generated.rs"));

// Represents a part of a clear-text representation of a descriptor template or tapleaf. A sequence of cleartext parts
// fully defines the structure of the cleartext representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CleartextPart {
    Literal(&'static str),
    Threshold,
    KeyIndex,
    KeyIndices,
    Blocks,
    RelativeTime,
    BlockHeight,
    Timestamp,
}

pub(super) struct CleartextSpec<K> {
    pub(super) kind: K,
    pub(super) parts: &'static [CleartextPart],
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CleartextValue {
    Threshold(u32),
    KeyIndex(KeyPlaceholder),
    KeyIndices(Vec<KeyPlaceholder>),
    Blocks(u32),
    RelativeTime(u32),
    BlockHeight(u32),
    Timestamp(u32),
}

/// Compares two key placeholders for canonical display ordering:
/// - plain key vs plain key: ordered by key index
/// - plain key vs musig: plain key comes first
/// - musig vs musig: ordered by number of keys, then left-to-right by key index
fn cmp_key(a: &KeyPlaceholder, b: &KeyPlaceholder) -> core::cmp::Ordering {
    use super::KeyExpressionType;
    match (&a.key_type, &b.key_type) {
        (KeyExpressionType::PlainKey(i1), KeyExpressionType::PlainKey(i2)) => i1.cmp(i2),
        (KeyExpressionType::PlainKey(_), KeyExpressionType::Musig(_)) => core::cmp::Ordering::Less,
        (KeyExpressionType::Musig(_), KeyExpressionType::PlainKey(_)) => {
            core::cmp::Ordering::Greater
        }
        (KeyExpressionType::Musig(i1), KeyExpressionType::Musig(i2)) => {
            i1.len().cmp(&i2.len()).then_with(|| i1.cmp(i2))
        }
    }
}

impl TapleafClass {
    /// Full canonical display order. Categories come from `order()` (generated);
    /// within a category, ties are broken by:
    /// - `SingleSig`: key_index
    /// - `BothMustSign`: key_index1, then key_index2
    /// - `SortedMultisig` / `Multisig`: number of keys, then threshold
    /// - `*SingleSig` lock variants: key_index, then lock value
    /// - `*MultiSig` lock variants: number of keys, then threshold, then lock value
    /// - `Other`: lexicographic by descriptor string
    #[rustfmt::skip]
    fn display_cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        use TapleafClass as TC;
        let cat = self.order().cmp(&other.order());
        if cat != Ordering::Equal {
            return cat;
        }
        match (self, other) {
            (
                TC::SingleSig { key: k1 },
                TC::SingleSig { key: k2 },
            ) => cmp_key(k1, k2),
            (
                TC::BothMustSign { key1: a1, key2: b1 },
                TC::BothMustSign { key1: a2, key2: b2 },
            ) => cmp_key(a1, a2).then(cmp_key(b1, b2)),
            (
                TC::SortedMultisig { threshold: t1, keys: k1 },
                TC::SortedMultisig { threshold: t2, keys: k2 },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)),
            (
                TC::Multisig { threshold: t1, keys: k1 },
                TC::Multisig { threshold: t2, keys: k2 },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)),
            (
                TC::RelativeHeightlockSingleSig { key: k1, blocks: b1 },
                TC::RelativeHeightlockSingleSig { key: k2, blocks: b2 },
            ) => cmp_key(k1, k2).then(b1.cmp(b2)),
            (
                TC::RelativeHeightlockBothMustSign { key1: a1, key2: b1, blocks: bl1 },
                TC::RelativeHeightlockBothMustSign { key1: a2, key2: b2, blocks: bl2 },
            ) => cmp_key(a1, a2).then(cmp_key(b1, b2)).then(bl1.cmp(bl2)),
            (
                TC::RelativeHeightlockMultiSig { threshold: t1, keys: k1, blocks: b1 },
                TC::RelativeHeightlockMultiSig { threshold: t2, keys: k2, blocks: b2 },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(b1.cmp(b2)),
            (
                TC::RelativeTimelockSingleSig { key: k1, relative_time: t1 },
                TC::RelativeTimelockSingleSig { key: k2, relative_time: t2 },
            ) => cmp_key(k1, k2).then(t1.cmp(t2)),
            (
                TC::RelativeTimelockBothMustSign { key1: a1, key2: b1, relative_time: t1 },
                TC::RelativeTimelockBothMustSign { key1: a2, key2: b2, relative_time: t2 },
            ) => cmp_key(a1, a2).then(cmp_key(b1, b2)).then(t1.cmp(t2)),
            (
                TC::RelativeTimelockMultiSig { threshold: t1, keys: k1, relative_time: tm1 },
                TC::RelativeTimelockMultiSig { threshold: t2, keys: k2, relative_time: tm2 },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(tm1.cmp(tm2)),
            (
                TC::AbsoluteHeightlockSingleSig { key: k1, block_height: h1 },
                TC::AbsoluteHeightlockSingleSig { key: k2, block_height: h2 },
            ) => cmp_key(k1, k2).then(h1.cmp(h2)),
            (
                TC::AbsoluteHeightlockBothMustSign { key1: a1, key2: b1, block_height: h1 },
                TC::AbsoluteHeightlockBothMustSign { key1: a2, key2: b2, block_height: h2 },
            ) => cmp_key(a1, a2).then(cmp_key(b1, b2)).then(h1.cmp(h2)),
            (
                TC::AbsoluteHeightlockMultiSig { threshold: t1, keys: k1, block_height: h1 },
                TC::AbsoluteHeightlockMultiSig { threshold: t2, keys: k2, block_height: h2 },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(h1.cmp(h2)),
            (
                TC::AbsoluteTimelockSingleSig { key: k1, timestamp: ts1 },
                TC::AbsoluteTimelockSingleSig { key: k2, timestamp: ts2 },
            ) => cmp_key(k1, k2).then(ts1.cmp(ts2)),
            (
                TC::AbsoluteTimelockBothMustSign { key1: a1, key2: b1, timestamp: ts1 },
                TC::AbsoluteTimelockBothMustSign { key1: a2, key2: b2, timestamp: ts2 },
            ) => cmp_key(a1, a2).then(cmp_key(b1, b2)).then(ts1.cmp(ts2)),
            (
                TC::AbsoluteTimelockMultiSig { threshold: t1, keys: k1, timestamp: ts1 },
                TC::AbsoluteTimelockMultiSig { threshold: t2, keys: k2, timestamp: ts2 },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(ts1.cmp(ts2)),
            (TC::Other(s1), TC::Other(s2)) => s1.cmp(s2),
            // Same order() value implies same variant; this arm is unreachable.
            _ => Ordering::Equal,
        }
    }
}

fn format_key(kp: &KeyPlaceholder, canonical: bool) -> String {
    if canonical {
        match &kp.key_type {
            super::KeyExpressionType::PlainKey(key_index) => format!("@{}", key_index),
            super::KeyExpressionType::Musig(key_indices) => {
                let inner: Vec<String> =
                    key_indices.iter().map(|idx| format!("@{}", idx)).collect();
                format!("musig({})", inner.join(","))
            }
        }
    } else {
        // Always use explicit derivation form for non-canonical display
        match &kp.key_type {
            super::KeyExpressionType::PlainKey(key_index) => {
                format!("@{}/<{};{}>/*", key_index, kp.num1, kp.num2)
            }
            super::KeyExpressionType::Musig(key_indices) => {
                let inner: Vec<String> =
                    key_indices.iter().map(|idx| format!("@{}", idx)).collect();
                format!("musig({})/<{};{}>/*", inner.join(","), kp.num1, kp.num2)
            }
        }
    }
}

fn format_key_indices(keys: &[KeyPlaceholder], canonical: bool) -> String {
    match keys {
        [] => String::new(),
        [single] => format_key(single, canonical),
        [init @ .., last] => {
            let parts: Vec<String> = init.iter().map(|k| format_key(k, canonical)).collect();
            format!("{} and {}", parts.join(", "), format_key(last, canonical))
        }
    }
}

fn format_relative_time(time: u32) -> String {
    format_seconds((time & !SEQUENCE_LOCKTIME_TYPE_FLAG) * 512)
}

/// Classify every leaf of a tap-tree and collect the results in tree-traversal
/// order. Used by the generated `classify` for `tr(...)` patterns.
fn tree_to_leaves(t: &super::TapTree) -> Vec<TapleafClass> {
    t.tapleaves().map(|l| l.classify_as_tapleaf()).collect()
}

fn cleartext_spec<K: Copy + Eq>(
    specs: &'static [CleartextSpec<K>],
    kind: K,
) -> &'static CleartextSpec<K> {
    specs
        .iter()
        .find(|spec| spec.kind == kind)
        .expect("missing cleartext spec")
}

/// Render a single dynamic cleartext part. `Literal` parts are inlined by
/// `format_with_spec` directly; passing one here returns `None`. Any other
/// (part, value) pairing represents a codegen-side bug since the two are
/// produced in lockstep.
fn format_cleartext_value(
    part: CleartextPart,
    value: &CleartextValue,
    canonical: bool,
) -> Option<String> {
    Some(match (part, value) {
        (CleartextPart::Literal(_), _) => return None,
        (CleartextPart::Threshold, CleartextValue::Threshold(t)) => t.to_string(),
        (CleartextPart::KeyIndex, CleartextValue::KeyIndex(k)) => format_key(k, canonical),
        (CleartextPart::KeyIndices, CleartextValue::KeyIndices(ks)) => {
            format_key_indices(ks, canonical)
        }
        (CleartextPart::Blocks, CleartextValue::Blocks(b)) => b.to_string(),
        (CleartextPart::RelativeTime, CleartextValue::RelativeTime(t)) => format_relative_time(*t),
        (CleartextPart::BlockHeight, CleartextValue::BlockHeight(h)) => h.to_string(),
        (CleartextPart::Timestamp, CleartextValue::Timestamp(t)) => format_utc_date(*t),
        _ => unreachable!("cleartext part/value mismatch (codegen invariant violated)"),
    })
}

fn format_with_spec<K>(
    spec: &CleartextSpec<K>,
    values: &[CleartextValue],
    canonical: bool,
) -> String {
    let mut result = String::new();
    let mut values = values.iter();
    for part in spec.parts {
        match *part {
            CleartextPart::Literal(literal) => result.push_str(literal),
            field => {
                let value = values.next().expect("missing cleartext value");
                result.push_str(
                    &format_cleartext_value(field, value, canonical)
                        .expect("invalid cleartext value"),
                );
            }
        }
    }
    debug_assert!(values.next().is_none(), "unused cleartext values");
    result
}

impl DescriptorClass {
    fn to_cleartext_string(&self, canonical: bool) -> Option<String> {
        let (kind, values) = self.cleartext_pattern()?;
        Some(format_with_spec(
            cleartext_spec(TOP_LEVEL_SPECS, kind),
            &values,
            canonical,
        ))
    }
}

impl TapleafClass {
    fn to_cleartext_string(&self, canonical: bool) -> Option<String> {
        let (kind, values) = self.cleartext_pattern()?;
        Some(format_with_spec(
            cleartext_spec(TAPLEAF_SPECS, kind),
            &values,
            canonical,
        ))
    }
}

pub trait ClearText {
    /// Returns an upper bound on the number of different descriptor templates
    /// that would be mapped to the same cleartext description. u64::MAX is returned
    /// if the confusion score is greater than or equal to u64::MAX.
    fn confusion_score(&self) -> u64;
    /// Returns the cleartext description of the descriptor, For taproot descriptors,
    /// the vector contains first the description of the spending policy of the internal key,
    /// and all the other elements are the cleartext descriptions of the taproot leaves.
    /// Any spending condition that doesn't have a cleartext description is shown as the
    /// unchanged descriptor template, with a confusion score of 1.
    fn to_cleartext(&self) -> (Vec<String>, bool);

    /// Given cleartext descriptions (as produced by `to_cleartext`), returns a
    /// lazy iterator over all structurally distinct instances that would produce
    /// the same cleartext output. The number of yielded instances equals
    /// `confusion_score()`.
    #[cfg(any(test, feature = "cleartext-decode"))]
    fn from_cleartext(
        descriptions: &[&str],
    ) -> Result<Box<dyn Iterator<Item = Self>>, CleartextDecodeError>
    where
        Self: Sized;
}

impl DescriptorTemplate {
    // Verify that, for each distinct key expression in placeholders, its k occurrences carry derivations
    // (in some order) equal to <0;1>/*, <2;3>/*, ..., <2k-2;2k-1>/*. That is, after sorting the (num1, num2)
    // pairs for each key, they must be exactly (0,1), (2,3), .... This guarantees that no information on
    // the derivations is lost when omitting this part in the cleartext representation, up to the
    // permutation of pair assignments to occurrences (which is accounted for in the confusion score).
    fn are_key_derivations_canonical(&self) -> bool {
        let mut pairs_per_key: alloc::collections::BTreeMap<
            super::KeyExpressionType,
            Vec<(u32, u32)>,
        > = alloc::collections::BTreeMap::new();

        for (kp, _) in self.placeholders() {
            pairs_per_key
                .entry(kp.key_type.clone())
                .or_default()
                .push((kp.num1, kp.num2));
        }

        for pairs in pairs_per_key.values_mut() {
            pairs.sort();
            for (i, &(n1, n2)) in pairs.iter().enumerate() {
                let expected = (2 * i as u32, 2 * i as u32 + 1);
                if (n1, n2) != expected {
                    return false;
                }
            }
        }

        true
    }

    // For each distinct key expression that appears k times in the placeholders, returns the product of
    // k! across all keys. This is the number of distinct ways the canonical derivation pairs
    // (0,1), (2,3), ... can be permuted across the k occurrences.
    fn key_derivation_orderings_count(&self) -> u64 {
        let mut counts: alloc::collections::BTreeMap<super::KeyExpressionType, u32> =
            alloc::collections::BTreeMap::new();
        for (kp, _) in self.placeholders() {
            *counts.entry(kp.key_type.clone()).or_insert(0) += 1;
        }
        let mut product = 1u64;
        for &k in counts.values() {
            let mut f = 1u64;
            for i in 1..=k as u64 {
                f = f.saturating_mul(i);
            }
            product = product.saturating_mul(f);
        }
        product
    }
}

impl ClearText for DescriptorTemplate {
    fn confusion_score(&self) -> u64 {
        let class = self.classify();
        let base = match &class {
            DescriptorClass::Taproot { leaves, .. }
            | DescriptorClass::TaprootMusig { leaves, .. } => {
                // The confusion score of a taproot descriptor is the product of the
                // outer score and the per-leaf scores, multiplied by the number T(n)
                // of distinct unordered tap-tree shapes.
                let mut score = class.outer_score();
                let n_leaves = leaves.len();
                for leaf in leaves {
                    score = score.saturating_mul(leaf.per_leaf_score());
                }
                // T(n) = (2n - 3)!! = 1 * 3 * 5 * ... * (2n - 3) for n > 1, and T(1) = 1.
                if n_leaves > 1 {
                    for i in (1..=(2 * n_leaves - 3)).step_by(2) {
                        score = score.saturating_mul(i as u64);
                    }
                }
                score
            }
            _ => class.outer_score(),
        };
        // For each key expression that appears k times in the descriptor template,
        // multiply by k! to account for the possible re-orderings of the canonical
        // derivation pairs across its occurrences (root-level only).
        base.saturating_mul(self.key_derivation_orderings_count())
    }

    fn to_cleartext(&self) -> (Vec<String>, bool) {
        if !self.are_key_derivations_canonical() {
            return (vec![self.to_string()], false);
        }
        match self.classify() {
            class @ DescriptorClass::LegacySingleSig { .. }
            | class @ DescriptorClass::SegwitSingleSig { .. }
            | class @ DescriptorClass::SegwitMultisig { .. } => (
                vec![class.to_cleartext_string(true).expect("missing cleartext")],
                true,
            ),
            class @ DescriptorClass::Taproot { .. }
            | class @ DescriptorClass::TaprootMusig { .. } => {
                let primary_path = class.to_cleartext_string(true).expect("missing cleartext");
                let mut leaves = match class {
                    DescriptorClass::Taproot { leaves, .. } => leaves,
                    DescriptorClass::TaprootMusig { leaves, .. } => leaves,
                    _ => unreachable!(),
                };
                leaves.sort_by(|a, b| a.display_cmp(b));
                let mut descriptions = vec![primary_path];
                let mut all_leaves_have_cleartext = true;
                for leaf in leaves {
                    if let Some(description) = leaf.to_cleartext_string(true) {
                        descriptions.push(description);
                    } else {
                        let TapleafClass::Other(raw) = leaf else {
                            unreachable!();
                        };
                        descriptions.push(raw);
                        all_leaves_have_cleartext = false;
                    }
                }
                (descriptions, all_leaves_have_cleartext)
            }
            DescriptorClass::Other => (vec![self.to_string()], false),
        }
    }

    #[cfg(any(test, feature = "cleartext-decode"))]
    fn from_cleartext(
        descriptions: &[&str],
    ) -> Result<Box<dyn Iterator<Item = Self>>, CleartextDecodeError> {
        let mut variants = Vec::new();
        for class in parse_top_level_candidates(descriptions)? {
            for variant in top_level_variants(class)? {
                for permuted in expand_derivation_orderings(variant) {
                    push_unique(&mut variants, permuted);
                }
            }
        }
        Ok(Box::new(variants.into_iter()))
    }
}

// ---------------------------------------------------------------------------
// from_cleartext helpers (feature-gated)
// ---------------------------------------------------------------------------
#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_key_index(s: &str) -> Option<KeyPlaceholder> {
    let rest = s.strip_prefix('@')?;
    if let Ok(idx) = rest.parse::<u32>() {
        // "@N" canonical format
        Some(KeyPlaceholder::plain(idx, 0, 1))
    } else if let Some((idx_str, deriv)) = rest.split_once('/') {
        // "@N/<M;K>/*" explicit derivation format
        let key_index = idx_str.parse().ok()?;
        let deriv = deriv.strip_prefix('<')?.strip_suffix(">/*")?;
        let (m, k) = deriv.split_once(';')?;
        let num1 = m.parse().ok()?;
        let num2 = k.parse().ok()?;
        Some(KeyPlaceholder::plain(key_index, num1, num2))
    } else {
        None
    }
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_key_indices(s: &str) -> Option<Vec<KeyPlaceholder>> {
    // Formats: "@A", "@A and @B", "@A, @B and @C", "@A, @B, @C and @D", ...
    if let Some((init, last)) = s.rsplit_once(" and ") {
        let last_kp = parse_key_index(last.trim())?;
        let mut kps: Vec<KeyPlaceholder> = Vec::new();
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

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_relative_time(s: &str) -> Option<u32> {
    let secs = parse_relative_time_to_seconds(s)?;
    Some(secs / 512 | SEQUENCE_LOCKTIME_TYPE_FLAG)
}

#[cfg(any(test, feature = "cleartext-decode"))]
struct CleartextValueCursor {
    values: alloc::vec::IntoIter<CleartextValue>,
}

#[cfg(any(test, feature = "cleartext-decode"))]
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

    fn key_index(&mut self) -> Option<KeyPlaceholder> {
        match self.values.next()? {
            CleartextValue::KeyIndex(value) => Some(value),
            _ => None,
        }
    }

    fn key_indices(&mut self) -> Option<Vec<KeyPlaceholder>> {
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

// `DescriptorClass::from_cleartext_pattern` and
// `TapleafClass::from_cleartext_pattern` are generated; see the include! at
// the top of this module.

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
fn push_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.iter().any(|existing| existing == &item) {
        items.push(item);
    }
}

/// Lazy iterator that generates permutations of `[0, 1, ..., n-1]` in lexicographic order
/// without storing them all in memory.
#[cfg(any(test, feature = "cleartext-decode"))]
struct PermutationIter {
    current: Vec<usize>,
    first: bool,
    done: bool,
}

#[cfg(any(test, feature = "cleartext-decode"))]
impl PermutationIter {
    fn new(n: usize) -> Self {
        Self {
            current: (0..n).collect(),
            first: true,
            done: n == 0,
        }
    }
}

#[cfg(any(test, feature = "cleartext-decode"))]
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
#[cfg(any(test, feature = "cleartext-decode"))]
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
#[cfg(any(test, feature = "cleartext-decode"))]
fn expand_derivation_orderings(base: DescriptorTemplate) -> Vec<DescriptorTemplate> {
    use alloc::collections::BTreeMap;

    // Collect the source-order positions of placeholders, grouped by key expression.
    let mut groups: BTreeMap<super::KeyExpressionType, Vec<usize>> = BTreeMap::new();
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

#[cfg(any(test, feature = "cleartext-decode"))]
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

// ---------------------------------------------------------------------------
// Tree enumeration
// `tapleaf_to_descriptors` is generated from the spec; see the include! at the
// top of this module.
// ---------------------------------------------------------------------------

/// Enumerate all distinct unordered binary tree topologies for `n` leaves
/// and return a lazy iterator over every combination of leaf variant assignments.
///
/// A binary tree with `n` leaves has `T(n)` distinct unordered shapes where
/// `T(n) = (2n - 3)!! = 1 * 3 * 5 * ... * (2n - 3)` for `n > 1`, and `T(1) = 1`.
///
/// `leaf_variants[i]` is the set of `DescriptorTemplate` alternatives for leaf `i`.
#[cfg(any(test, feature = "cleartext-decode"))]
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
#[cfg(any(test, feature = "cleartext-decode"))]
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

// `top_level_variants` is generated from the spec; see the include! at the top
// of this module.

#[cfg(test)]
mod tests {
    use super::{ClearText, DescriptorTemplate};
    use alloc::{string::ToString, vec::Vec};
    use core::str::FromStr;

    fn dt(s: &str) -> DescriptorTemplate {
        DescriptorTemplate::from_str(s)
            .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e))
    }

    fn strs(ss: &[&str]) -> Vec<alloc::string::String> {
        ss.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_confusion_score() {
        // (descriptor_template, expected_confusion_score)
        let cases: &[(&str, u64)] = &[
            // Legacy single-sig
            ("pkh(@0/**)", 1),
            // Segwit single-sig
            ("wpkh(@0/**)", 2),
            ("sh(wpkh(@0/**))", 2), // wrapped
            // Segwit multi-sig (wsh + sortedmulti / multi)
            ("wsh(sortedmulti(2,@0/**,@1/**))", 4),
            ("wsh(sortedmulti(2,@0/**,@1/**,@2/**))", 4),
            ("wsh(sortedmulti(3,@0/**,@1/**,@2/**))", 4),
            ("wsh(multi(2,@0/**,@1/**))", 4),
            ("sh(wsh(multi(2,@0/**,@1/**)))", 4), // wrapped
            ("sh(wsh(sortedmulti(2,@0/**,@1/**)))", 4), // wrapped
            ("sh(wsh(multi(2,@0/**,@1/**,@2/**)))", 4), // wrapped
            ("sh(wsh(sortedmulti(3,@0/**,@1/**,@2/**)))", 4), // wrapped
            // Taproot with 1 SingleSig leaf (score 1)
            ("tr(@0/**,pk(@1/**))", 1),
            // Taproot with 2 leaves: both SingleSig (score 1 each), T(2)=1 → 1×1×1=1
            ("tr(@0/**,{pk(@1/**),pk(@2/**)})", 1),
            // Taproot with 2 leaves: SortedMultisig (score 1) + SingleSig (score 1), T(2)=1 → 1×1×1=1
            ("tr(@0/**,{sortedmulti_a(2,@1/**,@2/**),pk(@3/**)})", 1),
            // Taproot with 3 leaves: 3×SingleSig (1×1×1=1), T(3)=3 → 1×3=3
            ("tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})", 3),
            // Taproot with 2 leaves: RelativeHeightlockSingleSig (score 1) + SingleSig (score 1), T(2)=1 → 1
            (
                "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(52560))})",
                1,
            ),
            // Taproot with 2 leaves: RelativeTimelockSingleSig (score 1) + SingleSig (score 1), T(2)=1 → 1
            (
                "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(4194305))})",
                1,
            ),
            // Taproot with 2 leaves: RelativeTimelockMultiSig (score 2, threshold==keys) + SingleSig (score 1), T(2)=1 → 2
            (
                "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),older(4194484))})",
                2,
            ),
            // Taproot with musig internal key: key-path only (score 1)
            ("tr(musig(@0,@1)/**)", 1),
            // Taproot with musig internal key: 3 keys (score 1)
            ("tr(musig(@0,@1,@2)/**)", 1),
            // Taproot with musig internal key + 1 SingleSig leaf (score 1)
            ("tr(musig(@0,@1)/**,pk(@2/**))", 1),
            // Taproot with musig internal key + 2 SingleSig leaves: T(2)=1 → 1
            ("tr(musig(@0,@1)/**,{pk(@2/**),pk(@3/**)})", 1),
            // Taproot with musig internal key + 3 SingleSig leaves: T(3)=3 → 3
            ("tr(musig(@0,@1)/**,{{pk(@2/**),pk(@3/**)},pk(@4/**)})", 3),
            // --------------------------------------------------------------------------------------
            // Taproot with musig() tapleaf (pk(musig(...)) maps to Multisig)
            // --------------------------------------------------------------------------------------
            // pk(musig) leaf: 2-of-2 (threshold==keys, score 2)
            ("tr(@0/**,pk(musig(@1,@2)/**))", 2),
            // pk(musig) leaf: 3-of-3 (threshold==keys, score 2)
            ("tr(@0/**,pk(musig(@1,@2,@3)/**))", 2),
            // pk(musig) + relative heightlock (threshold==keys, score 2)
            ("tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(1008)))", 2),
            // pk(musig) + relative timelock (threshold==keys, score 2)
            ("tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(4194484)))", 2),
            // pk(musig) + absolute heightlock (threshold==keys, score 2)
            ("tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(840000)))", 2),
            // pk(musig) + absolute timelock (threshold==keys, score 2)
            (
                "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(1700000000)))",
                2,
            ),
            // pk(musig) alongside SingleSig: 1*2*T(2)=2
            ("tr(@0/**,{pk(@1/**),pk(musig(@2,@3)/**)})", 2),
            // multi_a with threshold < keys.len() alongside pk(musig): 1*2*T(2)=2
            (
                "tr(@0/**,{multi_a(2,@1/**,@2/**,@3/**),pk(musig(@4,@5)/**)})",
                2,
            ),
            (
                // leaves are unambiguous, but keys @1 and @2 appear twice each, so the result is multiplied by 2! * 2!
                "tr(@0/<0;1>/*,{and_v(v:multi_a(2,@1/<0;1>/*,@2/<0;1>/*,@3/<0;1>/*),older(144)),and_v(v:pk(@1/<2;3>/*),pk(@2/<2;3>/*))})", 
                4
            ),
        ];

        for &(desc_str, expected) in cases {
            assert_eq!(
                dt(desc_str).confusion_score(),
                expected,
                "confusion_score mismatch for {:?}",
                desc_str
            );
        }
    }

    #[test]
    fn test_has_cleartext() {
        // list of descriptor templates that should have a cleartext description
        let cases = &[
            "pkh(@0/**)",
            "wpkh(@0/**)",
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "wsh(sortedmulti(2,@0/**,@1/**,@2/**))",
            "wsh(sortedmulti(3,@0/**,@1/**,@2/**))",
            "wsh(multi(2,@0/**,@1/**))",
            "tr(@0/**)",
            "tr(@0/**,pk(@1/**))",
            "tr(@0/**,{pk(@1/**),pk(@2/**)})",
            "tr(@0/**,{sortedmulti_a(2,@1/**,@2/**),pk(@3/**)})",
            "tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(52560)))",
            "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(1008))})",
            "tr(@0/<0;1>/*,{and_v(v:pk(@1/<0;1>/*),older(4383)),and_v(v:pk(@2/<0;1>/*),pk(@1/<2;3>/*))})",
            "tr(@0/<0;1>/*,{and_v(v:multi_a(2,@1/<0;1>/*,@2/<0;1>/*,@3/<0;1>/*),older(144)),and_v(v:pk(@1/<2;3>/*),pk(@2/<2;3>/*))})",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(4194305)))",
            "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(4194484))})",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),older(4194484))})",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),older(1008)))",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),older(4194484)))",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),after(840000)))",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),after(1700000000)))",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(840000)))",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(840000))})",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(500000000)))",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(1700000000))})",
            // Taproot with musig internal key
            "tr(musig(@0,@1)/**)",
            "tr(musig(@0,@1,@2)/**)",
            "tr(musig(@0,@1)/**,pk(@2/**))",
            "tr(musig(@0,@1)/**,{pk(@2/**),pk(@3/**)})",
            // Taproot with musig tapleaf
            "tr(@0/**,pk(musig(@1,@2)/**))",
            "tr(@0/**,pk(musig(@1,@2,@3)/**))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(1008)))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(4194484)))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(840000)))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(1700000000)))",
            // Key derivation ordering tests (keys appear multiple times with canonical derivations)
            "tr(@0/<0;1>/*,pk(@0/<2;3>/*))",
            "tr(@0/<0;1>/*,{pk(@0/<2;3>/*),pk(@0/<4;5>/*)})",
            "tr(@0/**,{pk(@1/<0;1>/*),pk(@1/<2;3>/*)})",
            "tr(@0/**,{and_v(v:pk(@1/<0;1>/*),older(4383)),pk(@1/<2;3>/*)})",
            "tr(@0/<0;1>/*,{pk(@0/<2;3>/*),and_v(v:pk(@1/<0;1>/*),pk(@1/<2;3>/*))})",
        ];
        for &desc_str in cases {
            assert!(
                dt(desc_str).to_cleartext().1,
                "expected to have cleartext description: {:?}",
                desc_str
            );
        }
    }

    #[test]
    fn test_to_cleartext() {
        // (descriptor_template, expected_descriptions, expected_all_have_cleartext)
        let cases: &[(&str, &[&str], bool)] = &[
            // Legacy single-sig
            ("pkh(@0/**)", &["Legacy single-signature (@0)"], true),
            // Segwit single-sig
            ("wpkh(@0/**)", &["Segwit single-signature (@0)"], true),
            // Multisig: 2-of-2 sortedmulti
            (
                "wsh(sortedmulti(2,@0/**,@1/**))",
                &["2 of @0 and @1 (SegWit)"],
                true,
            ),
            // Multisig: 2-of-3 sortedmulti (format_key_indices with 3 keys)
            (
                "wsh(sortedmulti(2,@0/**,@1/**,@2/**))",
                &["2 of @0, @1 and @2 (SegWit)"],
                true,
            ),
            // Multisig: 3-of-3 sortedmulti
            (
                "wsh(sortedmulti(3,@0/**,@1/**,@2/**))",
                &["3 of @0, @1 and @2 (SegWit)"],
                true,
            ),
            // Multisig: multi (non-sorted)
            (
                "wsh(multi(2,@0/**,@1/**))",
                &["2 of @0 and @1 (SegWit)"],
                true,
            ),
            // Taproot: key-path only (no leaves)
            ("tr(@0/**)", &["Primary path: @0"], true),
            // Taproot: single pk leaf
            (
                "tr(@0/**,pk(@1/**))",
                &["Primary path: @0", "Single-signature (@1)"],
                true,
            ),
            // Taproot: two SingleSig leaves
            (
                "tr(@0/**,{pk(@1/**),pk(@2/**)})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "Single-signature (@2)",
                ],
                true,
            ),
            // Taproot: SortedMultisig leaf + SingleSig leaf (SingleSig sorts first)
            (
                "tr(@0/**,{sortedmulti_a(2,@1/**,@2/**),pk(@3/**)})",
                &[
                    "Primary path: @0",
                    "Single-signature (@3)",
                    "2 of @1 and @2 (sorted)",
                ],
                true,
            ),
            // Taproot: three SingleSig leaves
            (
                "tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "Single-signature (@2)",
                    "Single-signature (@3)",
                ],
                true,
            ),
            // Taproot: relative timelock single-sig leaf
            (
                "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(52560)))",
                &["Primary path: @0", "@1 after 52560 blocks"],
                true,
            ),
            // Taproot: relative timelock single-sig alongside a plain single-sig
            (
                "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(1008))})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "@2 after 1008 blocks",
                ],
                true,
            ),
            // Taproot: relative time-lock single-sig (1 unit = 512s = 8m 32s)
            (
                "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(4194305)))",
                &["Primary path: @0", "@1 after 8m 32s"],
                true,
            ),
            // Taproot: relative time-lock single-sig (180 units = 92160s = 1d 1h 36m)
            (
                "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(4194484))})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "@2 after 1d 1h 36m",
                ],
                true,
            ),
            // Taproot: relative time-lock multisig (180 units = 92160s = 1d 1h 36m)
            (
                "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),older(4194484))})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "2 of @2 and @3 after 1d 1h 36m",
                ],
                true,
            ),
            // Taproot: absolute heightlock single-sig (block height 840000)
            (
                "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(840000)))",
                &["Primary path: @0", "@1 after block height 840000"],
                true,
            ),
            // Taproot: absolute heightlock multisig alongside a plain single-sig
            (
                "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(840000))})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "2 of @2 and @3 after block height 840000",
                ],
                true,
            ),
            // Taproot: absolute timelock single-sig (timestamp 500000000 = 1985-11-05T00:53:20)
            (
                "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(500000000)))",
                &["Primary path: @0", "@1 after date 1985-11-05 00:53:20"],
                true,
            ),
            // Taproot: absolute timelock multisig (timestamp 1700000000 = 2023-11-14 22:13:20)
            (
                "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(1700000000))})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "2 of @2 and @3 after date 2023-11-14 22:13:20",
                ],
                true,
            ),
            // Taproot: relative heightlock both-must-sign
            (
                "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),older(1008)))",
                &["Primary path: @0", "Both @1 and @2 after 1008 blocks"],
                true,
            ),
            // Taproot: relative heightlock both-must-sign alongside a plain single-sig
            (
                "tr(@0/**,{pk(@1/**),and_v(v:and_v(v:pk(@2/<0;1>/*),pk(@3/<0;1>/*)),older(1008))})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "Both @2 and @3 after 1008 blocks",
                ],
                true,
            ),
            // Taproot: relative timelock both-must-sign (180 units = 92160s = 1d 1h 36m)
            (
                "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),older(4194484)))",
                &["Primary path: @0", "Both @1 and @2 after 1d 1h 36m"],
                true,
            ),
            // Taproot: absolute heightlock both-must-sign (block height 840000)
            (
                "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),after(840000)))",
                &["Primary path: @0", "Both @1 and @2 after block height 840000"],
                true,
            ),
            // Taproot: absolute timelock both-must-sign (timestamp 1700000000 = 2023-11-14 22:13:20)
            (
                "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),after(1700000000)))",
                &["Primary path: @0", "Both @1 and @2 after date 2023-11-14 22:13:20"],
                true,
            ),
            // Taproot: first leaf recognized (heightlock single-sig), second leaf unrecognized (complex miniscript)
            (
                "tr(@0/**,{and_v(v:pk(@1/**),older(960)),t:or_c(pk(@2/**),and_v(v:pk(@3/**),or_c(pk(@4/**),v:ripemd160(907cd521fff981ce4063a4dc43c6f3fd28e08995))))})",
                &[
                    "Primary path: @0",
                    "@1 after 960 blocks",
                    "t:or_c(pk(@2/**),and_v(v:pk(@3/**),or_c(pk(@4/**),v:ripemd160(907cd521fff981ce4063a4dc43c6f3fd28e08995))))",
                ],
                false,
            ),
            // Tie-break: two SingleSig leaves given in reverse key_index order → sorted by key_index
            (
                "tr(@0/**,{pk(@2/**),pk(@1/**)})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "Single-signature (@2)",
                ],
                true,
            ),
            // Tie-break: two RelativeHeightlockSingleSig → sorted by key_index, then blocks
            (
                "tr(@0/**,{and_v(v:pk(@2/<0;1>/*),older(2000)),and_v(v:pk(@1/<0;1>/*),older(1000))})",
                &[
                    "Primary path: @0",
                    "@1 after 1000 blocks",
                    "@2 after 2000 blocks",
                ],
                true,
            ),
            // Tie-break: two Multisig leaves → fewer keys first, then smaller threshold
            (
                "tr(@0/**,{multi_a(2,@1/**,@2/**,@3/**),multi_a(2,@4/**,@5/**)})",
                &[
                    "Primary path: @0",
                    "2 of @4 and @5",
                    "2 of @1, @2 and @3",
                ],
                true,
            ),
            // --------------------------------------------------------------------------------------
            // Taproot with musig() internal key
            // --------------------------------------------------------------------------------------
            // Taproot: musig key-path only (2-of-2)
            (
                "tr(musig(@0,@1)/**)",
                &["Primary path: 2 of @0 and @1"],
                true,
            ),
            // Taproot: musig key-path only (3-of-3)
            (
                "tr(musig(@0,@1,@2)/**)",
                &["Primary path: 3 of @0, @1 and @2"],
                true,
            ),
            // Taproot: musig key-path + single leaf
            (
                "tr(musig(@0,@1)/**,pk(@2/**))",
                &[
                    "Primary path: 2 of @0 and @1",
                    "Single-signature (@2)",
                ],
                true,
            ),
            // Taproot: musig key-path + two leaves
            (
                "tr(musig(@0,@1)/**,{pk(@2/**),pk(@3/**)})",
                &[
                    "Primary path: 2 of @0 and @1",
                    "Single-signature (@2)",
                    "Single-signature (@3)",
                ],
                true,
            ),
            // Taproot: musig key-path + relative heightlock leaf
            (
                "tr(musig(@0,@1)/**,and_v(v:pk(@2/<0;1>/*),older(1008)))",
                &[
                    "Primary path: 2 of @0 and @1",
                    "@2 after 1008 blocks",
                ],
                true,
            ),
            // --------------------------------------------------------------------------------------
            // Taproot with musig() tapleaf (pk(musig(...)) maps to Multisig)
            // --------------------------------------------------------------------------------------
            // pk(musig) leaf: 2-of-2
            (
                "tr(@0/**,pk(musig(@1,@2)/**))",
                &["Primary path: @0", "2 of @1 and @2"],
                true,
            ),
            // pk(musig) leaf: 3-of-3
            (
                "tr(@0/**,pk(musig(@1,@2,@3)/**))",
                &["Primary path: @0", "3 of @1, @2 and @3"],
                true,
            ),
            // pk(musig) + relative heightlock
            (
                "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(1008)))",
                &["Primary path: @0", "2 of @1 and @2 after 1008 blocks"],
                true,
            ),
            // pk(musig) + relative timelock (180 units = 92160s = 1d 1h 36m)
            (
                "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(4194484)))",
                &["Primary path: @0", "2 of @1 and @2 after 1d 1h 36m"],
                true,
            ),
            // pk(musig) + absolute heightlock (block 840000)
            (
                "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(840000)))",
                &["Primary path: @0", "2 of @1 and @2 after block height 840000"],
                true,
            ),
            // pk(musig) + absolute timelock (timestamp 1700000000 = 2023-11-14 22:13:20)
            (
                "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(1700000000)))",
                &["Primary path: @0", "2 of @1 and @2 after date 2023-11-14 22:13:20"],
                true,
            ),
            // pk(musig) alongside a plain single-sig
            (
                "tr(@0/**,{pk(@1/**),pk(musig(@2,@3)/**)})",
                &[
                    "Primary path: @0",
                    "Single-signature (@1)",
                    "2 of @2 and @3",
                ],
                true,
            ),
            // --------------------------------------------------------------------------------------
            // Non-canonical key derivations: no cleartext representation; raw to_string() is returned.
            // --------------------------------------------------------------------------------------
            // Legacy single-sig: num1 is not 0 for the first (and only) occurrence
            (
                "pkh(@0/<2;3>/*)",
                &["pkh(@0/<2;3>/*)"],
                false,
            ),
            // Segwit single-sig: num2 is not num1+1
            (
                "wpkh(@0/<0;2>/*)",
                &["wpkh(@0/<0;2>/*)"],
                false,
            ),
            // Taproot, key-path only: internal key has non-canonical derivation
            (
                "tr(@0/<4;5>/*)",
                &["tr(@0/<4;5>/*)"],
                false,
            ),
            // Taproot single leaf: internal key canonical, leaf key non-canonical
            (
                "tr(@0/**,pk(@1/<2;3>/*))",
                &["tr(@0/**,pk(@1/<2;3>/*))"],
                false,
            ),
        ];

        for &(desc_str, expected_txts, expected_has_cleartext) in cases {
            let (txts, has_cleartext) = dt(desc_str).to_cleartext();
            assert_eq!(
                txts,
                strs(expected_txts),
                "cleartext descriptions mismatch for {:?}",
                desc_str
            );
            assert_eq!(
                has_cleartext, expected_has_cleartext,
                "cleartext flag mismatch for {:?}",
                desc_str
            );
        }
    }

    #[test]
    fn test_from_cleartext_roundtrip() {
        // All descriptors from test_to_cleartext and test_confusion_score that
        // have a cleartext representation (has_cleartext == true).
        let cases: &[&str] = &[
            // Legacy single-sig
            "pkh(@0/**)",
            // Segwit single-sig
            "wpkh(@0/**)",
            // Multisig variants
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "wsh(sortedmulti(2,@0/**,@1/**,@2/**))",
            "wsh(sortedmulti(3,@0/**,@1/**,@2/**))",
            "wsh(multi(2,@0/**,@1/**))",
            // Taproot: key-path only
            "tr(@0/**)",
            // Taproot: single leaf
            "tr(@0/**,pk(@1/**))",
            // Taproot: two leaves
            "tr(@0/**,{pk(@1/**),pk(@2/**)})",
            "tr(@0/**,{sortedmulti_a(2,@1/**,@2/**),pk(@3/**)})",
            // Taproot: three leaves
            "tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})",
            // Taproot: relative heightlock
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(52560)))",
            "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(1008))})",
            // Taproot: relative timelock
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(4194305)))",
            "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(4194484))})",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),older(4194484))})",
            // Taproot: absolute heightlock
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(840000)))",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(840000))})",
            // Taproot: absolute timelock
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(500000000)))",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(1700000000))})",
            // Taproot: BothMustSign + locks
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),older(1008)))",
            "tr(@0/**,{pk(@1/**),and_v(v:and_v(v:pk(@2/<0;1>/*),pk(@3/<0;1>/*)),older(1008))})",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),older(4194484)))",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),after(840000)))",
            "tr(@0/**,and_v(v:and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*)),after(1700000000)))",
            // Taproot: BothMustSign (key repeated across leaves with canonical derivations)
            "tr(@0/<0;1>/*,{and_v(v:pk(@1/<0;1>/*),older(4383)),and_v(v:pk(@2/<0;1>/*),pk(@1/<2;3>/*))})",
            "tr(@0/<0;1>/*,{and_v(v:multi_a(2,@1/<0;1>/*,@2/<0;1>/*,@3/<0;1>/*),older(144)),and_v(v:pk(@1/<2;3>/*),pk(@2/<2;3>/*))})",
            // Taproot: musig key-path only
            "tr(musig(@0,@1)/**)",
            "tr(musig(@0,@1,@2)/**)",
            // Taproot: musig key-path with leaves
            "tr(musig(@0,@1)/**,pk(@2/**))",
            "tr(musig(@0,@1)/**,{pk(@2/**),pk(@3/**)})",
            "tr(musig(@0,@1)/**,and_v(v:pk(@2/<0;1>/*),older(1008)))",
            "tr(musig(@0,@1)/**,{pk(@2/**),and_v(v:pk(@3/<0;1>/*),after(840000))})",
            // Taproot: musig tapleaf (pk(musig(...)))
            "tr(@0/**,pk(musig(@1,@2)/**))",
            "tr(@0/**,pk(musig(@1,@2,@3)/**))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(1008)))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),older(4194484)))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(840000)))",
            "tr(@0/**,and_v(v:pk(musig(@1,@2)/**),after(1700000000)))",
            // Key derivation ordering roundtrip tests
            "tr(@0/<0;1>/*,pk(@0/<2;3>/*))",
            "tr(@0/<0;1>/*,{pk(@0/<2;3>/*),pk(@0/<4;5>/*)})",
            "tr(@0/**,{pk(@1/<0;1>/*),pk(@1/<2;3>/*)})",
            "tr(@0/**,{and_v(v:pk(@1/<0;1>/*),older(4383)),pk(@1/<2;3>/*)})",
            // @0 appears twice, @1 appears twice
            "tr(@0/<0;1>/*,{pk(@0/<2;3>/*),and_v(v:pk(@1/<0;1>/*),pk(@1/<2;3>/*))})",
        ];

        for &desc_str in cases {
            let original = dt(desc_str);
            let (cleartext, has_cleartext) = original.to_cleartext();
            assert!(
                has_cleartext,
                "expected to have cleartext description for {:?}",
                desc_str
            );
            let cleartext_refs: Vec<&str> = cleartext.iter().map(|s| s.as_str()).collect();
            let variants: Vec<_> = DescriptorTemplate::from_cleartext(&cleartext_refs)
                .unwrap_or_else(|e| panic!("from_cleartext failed for {:?}: {:?}", desc_str, e))
                .collect();

            // Number of variants must equal confusion_score
            assert_eq!(
                variants.len() as u64,
                original.confusion_score(),
                "variant count != confusion_score for {:?}",
                desc_str
            );

            // Every variant must produce the same cleartext
            for variant in &variants {
                let (variant_ct, variant_clear) = variant.to_cleartext();
                assert_eq!(
                    variant_ct, cleartext,
                    "variant {:?} produces different cleartext for original {:?}",
                    variant, desc_str
                );
                assert_eq!(
                    variant_clear, has_cleartext,
                    "variant {:?} has different cleartext flag for original {:?}",
                    variant, desc_str
                );
            }

            // All variants must be distinct
            for i in 0..variants.len() {
                for j in (i + 1)..variants.len() {
                    assert_ne!(
                        variants[i], variants[j],
                        "duplicate variants at indices {} and {} for {:?}",
                        i, j, desc_str
                    );
                }
            }
        }
    }

    #[test]
    fn test_spec_shape_uniqueness() {
        // For each spec, build a "shape string" by concatenating its parts, replacing
        // literals with their text and every dynamic field with a fixed non-ASCII
        // placeholder. Two specs that map to the same shape string would be
        // indistinguishable by the parser.
        fn shape_string(parts: &[super::CleartextPart]) -> alloc::string::String {
            const PLACEHOLDER: char = '\u{A7}'; // '§'
            let mut s = alloc::string::String::new();
            for part in parts {
                match part {
                    super::CleartextPart::Literal(lit) => s.push_str(lit),
                    _ => s.push(PLACEHOLDER),
                }
            }
            s
        }

        fn check_unique(part_slices: &[&'static [super::CleartextPart]], label: &str) {
            let shapes: Vec<alloc::string::String> = part_slices
                .iter()
                .map(|parts| shape_string(parts))
                .collect();
            for i in 0..shapes.len() {
                for j in (i + 1)..shapes.len() {
                    assert_ne!(
                        shapes[i], shapes[j],
                        "{} entries at indices {} and {} have the same shape: {:?}",
                        label, i, j, shapes[i]
                    );
                }
            }
        }

        check_unique(
            &super::TOP_LEVEL_SPECS
                .iter()
                .map(|s| s.parts)
                .collect::<Vec<_>>(),
            "TOP_LEVEL_SPECS",
        );
        check_unique(
            &super::TAPLEAF_SPECS
                .iter()
                .map(|s| s.parts)
                .collect::<Vec<_>>(),
            "TAPLEAF_SPECS",
        );
    }

    /// Verify that the `musig` spec primitive preserves the full key-expression
    /// derivation paths by propagating them onto each plain key in the resulting
    /// class instance. Both `DescriptorClass::TaprootMusig` (musig as the
    /// taproot internal key) and `TapleafClass::Multisig` (musig as a tapleaf
    /// signer) flatten the shared derivation onto each plain key in `keys`.
    #[test]
    fn test_musig_classify_preserves_derivations() {
        use super::DescriptorClass;

        // musig internal key with non-standard derivation <2;3>: each plain key
        // in `keys` carries (num1=2, num2=3).
        let desc = dt("tr(musig(@0,@1)/<2;3>/*,pk(@2/**))");
        let class = desc.classify();
        match class {
            DescriptorClass::TaprootMusig {
                threshold,
                keys,
                leaves,
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(keys.len(), 2);
                for k in &keys {
                    assert!(k.is_plain());
                    assert_eq!(k.num1, 2);
                    assert_eq!(k.num2, 3);
                }
                assert_eq!(keys[0].plain_key_index(), Some(0));
                assert_eq!(keys[1].plain_key_index(), Some(1));
                assert_eq!(leaves.len(), 1);
            }
            other => panic!("expected TaprootMusig, got {:?}", other),
        }

        // musig in tapleaf with non-standard derivation <4;5>
        let desc2 = dt("tr(@0/**,pk(musig(@1,@2)/<4;5>/*))");
        let class2 = desc2.classify();
        match class2 {
            DescriptorClass::Taproot { leaves, .. } => {
                assert_eq!(leaves.len(), 1);
                match &leaves[0] {
                    super::TapleafClass::Multisig { threshold, keys } => {
                        assert_eq!(*threshold, 2);
                        assert_eq!(keys.len(), 2);
                        for k in keys {
                            assert_eq!(k.num1, 4);
                            assert_eq!(k.num2, 5);
                        }
                    }
                    other => panic!("expected Multisig tapleaf, got {:?}", other),
                }
            }
            other => panic!("expected Taproot, got {:?}", other),
        }

        // Standard derivation musig internal key (sanity check: num1=0, num2=1).
        let desc3 = dt("tr(musig(@0,@1)/**)");
        let class3 = desc3.classify();
        match class3 {
            DescriptorClass::TaprootMusig {
                threshold,
                keys,
                leaves,
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(keys.len(), 2);
                for k in &keys {
                    assert_eq!(k.num1, 0);
                    assert_eq!(k.num2, 1);
                }
                assert!(leaves.is_empty());
            }
            other => panic!("expected TaprootMusig, got {:?}", other),
        }
    }
}
