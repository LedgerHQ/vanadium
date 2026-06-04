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
//!    candidates, including enumeration of taproot tree topologies. The full machinery lives
//!    in the [`decode`] submodule, compiled only when the feature is active.
//!
//! 5. **Canonical display order** — Taproot leaves are sorted via [`TapleafClass::display_cmp`]
//!    so the cleartext output is deterministic regardless of the original tree shape. The number
//!    of structurally distinct trees is taken into account in the confusion score.

use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use super::time::{format_seconds, format_utc_date};
use super::{DescriptorTemplate, KeyExpression, KeyExpressionType};

#[cfg(any(test, feature = "cleartext-decode"))]
mod decode;

#[cfg(any(test, feature = "cleartext-decode"))]
pub use decode::CleartextDecodeError;

#[cfg(any(test, feature = "cleartext-decode"))]
use alloc::boxed::Box;

// Maximum confusion score for which cleartext descriptions are shown instead of the raw descriptor template.
pub const MAX_CONFUSION_SCORE: u64 = 3600;

pub(super) const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Absolute locktimes below this are block heights; at or above, Unix
/// timestamps (BIP-65). Relative locktimes use `SEQUENCE_LOCKTIME_TYPE_FLAG`
/// for the same block-vs-time split instead.
pub(super) const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// A relative locktime encodes a block count or 512-second interval count in
/// its low 16 bits; valid counts are `1..RELATIVE_LOCK_LIMIT`.
pub(super) const RELATIVE_LOCK_LIMIT: u32 = 1 << 16;

/// A spending timelock attached to a tapleaf signer, carrying enough to render
/// all four display forms. `Relative` is the raw `older(...)` sequence value
/// (the type flag distinguishes a block count from a 512-second duration);
/// `Absolute` is the raw `after(...)` value (`< 500_000_000` is a block height,
/// otherwise a Unix timestamp).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Timelock {
    Relative(u32),
    Absolute(u32),
}

/// `older(n)` is recognized as a timelock iff `n` is either a relative block
/// count or a relative 512-second duration (type flag set) — in both cases with
/// a low-16-bit count in `1..RELATIVE_LOCK_LIMIT`. Other values (e.g.
/// `older(0)`) are left unclassified.
pub(super) fn is_valid_relative_locktime(n: u32) -> bool {
    (1..RELATIVE_LOCK_LIMIT).contains(&n)
        || ((SEQUENCE_LOCKTIME_TYPE_FLAG + 1)..(SEQUENCE_LOCKTIME_TYPE_FLAG + RELATIVE_LOCK_LIMIT))
            .contains(&n)
}

/// `after(n)` is recognized as a timelock for any `n >= 1` (a block height when
/// `n < LOCKTIME_THRESHOLD`, otherwise a Unix timestamp).
pub(super) fn is_valid_absolute_locktime(n: u32) -> bool {
    n >= 1
}

// `DescriptorClass`, `TapleafClass`, `TopLevelPattern`, `TapleafPattern`,
// the `TOP_LEVEL_SPECS` / `TAPLEAF_SPECS` cleartext templates, and the
// always-compiled pattern-matching code (`classify`, `classify_as_tapleaf`,
// `cleartext_pattern`, `order`, `outer_score`, `per_leaf_score`) are generated
// from `specs/cleartext.toml` by `build.rs`. The decode-side generated code
// lives in `cleartext_decode_generated.rs` and is included from `decode.rs`.
include!(concat!(env!("OUT_DIR"), "/cleartext_generated.rs"));

// Represents a part of a clear-text representation of a descriptor template or tapleaf. A sequence of cleartext parts
// fully defines the structure of the cleartext representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CleartextPart {
    Literal(&'static str),
    Threshold,
    KeyIndex,
    KeyIndices,
    Timelock,
    Subpolicy,
}

pub(super) struct CleartextSpec<K> {
    pub(super) kind: K,
    pub(super) parts: &'static [CleartextPart],
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CleartextValue {
    Threshold(u32),
    KeyIndex(KeyExpression),
    KeyIndices(Vec<KeyExpression>),
    Timelock(Timelock),
    Subpolicy(alloc::boxed::Box<TapleafClass>),
}

/// Compares two key placeholders for canonical display ordering:
/// - plain key vs plain key: ordered by key index
/// - plain key vs musig: plain key comes first
/// - musig vs musig: ordered by number of keys, then left-to-right by key index
fn cmp_key(a: &KeyExpression, b: &KeyExpression) -> core::cmp::Ordering {
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
    /// - `Timelocked`: signer sub-policy (recursively), then the lock value
    /// - `AndV`: sub1 (recursively), then sub2 (recursively)
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
                TC::Timelocked { sub: s1, timelock: t1 },
                TC::Timelocked { sub: s2, timelock: t2 },
            ) => s1.display_cmp(s2).then(t1.cmp(t2)),
            (TC::AndV { sub1: a1, sub2: a2 }, TC::AndV { sub1: b1, sub2: b2 }) => {
                a1.display_cmp(b1).then_with(|| a2.display_cmp(b2))
            }
            (TC::Other(s1), TC::Other(s2)) => s1.cmp(s2),
            // Same order() value implies same variant; this arm is unreachable.
            _ => Ordering::Equal,
        }
    }
}

fn format_key(kp: &KeyExpression, canonical: bool) -> String {
    if canonical {
        match &kp.key_type {
            KeyExpressionType::PlainKey(key_index) => format!("@{}", key_index),
            KeyExpressionType::Musig(key_indices) => {
                let inner: Vec<String> =
                    key_indices.iter().map(|idx| format!("@{}", idx)).collect();
                format!("musig({})", inner.join(","))
            }
        }
    } else {
        // Always use explicit derivation form for non-canonical display
        match &kp.key_type {
            KeyExpressionType::PlainKey(key_index) => {
                format!("@{}/<{};{}>/*", key_index, kp.num1, kp.num2)
            }
            KeyExpressionType::Musig(key_indices) => {
                let inner: Vec<String> =
                    key_indices.iter().map(|idx| format!("@{}", idx)).collect();
                format!("musig({})/<{};{}>/*", inner.join(","), kp.num1, kp.num2)
            }
        }
    }
}

fn format_key_indices(keys: &[KeyExpression], canonical: bool) -> String {
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

/// Render a timelock as the tail of an "<signer> after ..." description, picking
/// the form from the lock kind and value: relative block count, relative
/// duration, absolute block height, or absolute date.
fn format_timelock(lock: Timelock) -> String {
    match lock {
        Timelock::Relative(n) => {
            if n & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
                format_relative_time(n)
            } else {
                format!("{} blocks", n)
            }
        }
        Timelock::Absolute(n) => {
            if n < LOCKTIME_THRESHOLD {
                format!("block height {}", n)
            } else {
                format!("date {}", format_utc_date(n))
            }
        }
    }
}

/// Classify every leaf of a tap-tree and collect the results in tree-traversal
/// order. Used by the generated `classify` for `tr(...)` patterns.
fn tree_to_leaves(t: &super::TapTree) -> Vec<TapleafClass> {
    t.tapleaves().map(|l| l.classify_as_tapleaf()).collect()
}

fn cleartext_spec<K: Copy + Eq>(
    specs: &'static [CleartextSpec<K>],
    kind: K,
) -> Option<&'static CleartextSpec<K>> {
    specs.iter().find(|spec| spec.kind == kind)
}

/// Render a single dynamic cleartext part. `Literal` parts are inlined by
/// `format_with_spec` directly; passing one here returns `None`. Any other
/// (part, value) pairing represents a codegen-side bug since the two are
/// produced in lockstep; we return `None` and let the caller fall back to a
/// safe default rather than panic on the VM.
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
        (CleartextPart::Timelock, CleartextValue::Timelock(lock)) => format_timelock(*lock),
        (CleartextPart::Subpolicy, CleartextValue::Subpolicy(leaf)) => {
            leaf.to_cleartext_string(canonical)?
        }
        _ => {
            debug_assert!(false, "cleartext part/value mismatch (codegen invariant violated)");
            return None;
        }
    })
}

fn format_with_spec<K>(
    spec: &CleartextSpec<K>,
    values: &[CleartextValue],
    canonical: bool,
) -> Option<String> {
    let mut result = String::new();
    let mut values = values.iter();
    for part in spec.parts {
        match *part {
            CleartextPart::Literal(literal) => result.push_str(literal),
            field => {
                let value = values.next()?;
                result.push_str(&format_cleartext_value(field, value, canonical)?);
            }
        }
    }
    debug_assert!(values.next().is_none(), "unused cleartext values");
    Some(result)
}

impl DescriptorClass {
    fn to_cleartext_string(&self, canonical: bool) -> Option<String> {
        let (kind, values) = self.cleartext_pattern()?;
        format_with_spec(cleartext_spec(TOP_LEVEL_SPECS, kind)?, &values, canonical)
    }
}

impl TapleafClass {
    fn to_cleartext_string(&self, canonical: bool) -> Option<String> {
        let (kind, values) = self.cleartext_pattern()?;
        format_with_spec(cleartext_spec(TAPLEAF_SPECS, kind)?, &values, canonical)
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
        // Helper: a classifier match without a corresponding cleartext spec
        // would indicate the build-time spec is out of sync with `classify()`.
        // We fall back to the raw descriptor instead of panicking on the VM.
        let render = |class: &DescriptorClass| -> Option<String> { class.to_cleartext_string(true) };

        match self.classify() {
            class @ (DescriptorClass::LegacySingleSig { .. }
            | DescriptorClass::SegwitSingleSig { .. }
            | DescriptorClass::SegwitMultisig { .. }) => match render(&class) {
                Some(s) => (vec![s], true),
                None => {
                    debug_assert!(false, "missing cleartext for {:?}", class);
                    (vec![self.to_string()], false)
                }
            },
            class @ (DescriptorClass::Taproot { .. } | DescriptorClass::TaprootMusig { .. }) => {
                let primary_path = match render(&class) {
                    Some(s) => s,
                    None => {
                        debug_assert!(false, "missing cleartext for {:?}", class);
                        return (vec![self.to_string()], false);
                    }
                };
                // Extract leaves; both variants have a `leaves` field.
                let mut leaves = match class {
                    DescriptorClass::Taproot { leaves, .. }
                    | DescriptorClass::TaprootMusig { leaves, .. } => leaves,
                    // The outer match guard makes other variants impossible
                    // here; this arm is dead but defensively returns the raw
                    // descriptor rather than panicking.
                    _ => return (vec![self.to_string()], false),
                };
                leaves.sort_by(|a, b| a.display_cmp(b));
                let mut descriptions = vec![primary_path];
                let mut all_leaves_have_cleartext = true;
                for leaf in leaves {
                    if let Some(description) = leaf.to_cleartext_string(true) {
                        descriptions.push(description);
                    } else {
                        match leaf {
                            TapleafClass::Other(raw) => descriptions.push(raw),
                            // A classified leaf with no cleartext indicates a
                            // spec/classifier mismatch. Push the parent
                            // descriptor as a defensive placeholder rather than
                            // panicking on the VM.
                            other => {
                                debug_assert!(false, "classified leaf has no cleartext: {:?}", other);
                                descriptions.push(self.to_string());
                            }
                        }
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
        decode::from_cleartext_impl(descriptions)
    }
}

#[cfg(test)]
mod tests {
    use super::{ClearText, DescriptorTemplate};
    use alloc::{string::String, vec::Vec};
    use core::str::FromStr;

    fn dt(s: &str) -> DescriptorTemplate {
        DescriptorTemplate::from_str(s)
            .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e))
    }

    /// Return a copy of `dt` with every tap-tree `Branch` rewritten so its two
    /// children are in a deterministic order (by canonical `Display` string).
    /// A BIP341 `TapBranch` sorts its two child hashes, so `{A,B}` and `{B,A}`
    /// denote the same tree; this lets us compare descriptors up to that
    /// (semantically irrelevant) child ordering.
    fn canonicalize_taptree_order(dt: &DescriptorTemplate) -> DescriptorTemplate {
        use crate::TapTree;

        fn canon_tree(t: &TapTree) -> TapTree {
            match t {
                TapTree::Script(d) => TapTree::Script(d.clone()),
                TapTree::Branch(l, r) => {
                    let (cl, cr) = (canon_tree(l), canon_tree(r));
                    if cl.to_string() <= cr.to_string() {
                        TapTree::Branch(alloc::boxed::Box::new(cl), alloc::boxed::Box::new(cr))
                    } else {
                        TapTree::Branch(alloc::boxed::Box::new(cr), alloc::boxed::Box::new(cl))
                    }
                }
            }
        }

        match dt {
            DescriptorTemplate::Tr(key, tree) => {
                DescriptorTemplate::Tr(key.clone(), tree.as_ref().map(canon_tree))
            }
            other => other.clone(),
        }
    }

    /// One entry from `specs/test_vectors.toml`. Every field except
    /// `template` is optional so the same data file can carry partial
    /// vectors (e.g. confusion-score-only) for cases that historically
    /// asserted only one property.
    #[derive(Debug, serde::Deserialize)]
    struct Vector {
        template: String,
        #[serde(default)]
        confusion_score: Option<u64>,
        #[serde(default)]
        cleartext: Option<Vec<String>>,
        #[serde(default)]
        has_cleartext: Option<bool>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct TestVectors {
        vector: Vec<Vector>,
    }

    fn load_vectors() -> Vec<Vector> {
        const RAW: &str = include_str!("specs/test_vectors.toml");
        let parsed: TestVectors =
            toml::from_str(RAW).expect("failed to parse specs/test_vectors.toml");
        parsed.vector
    }

    #[test]
    fn test_vectors_confusion_score() {
        for v in load_vectors() {
            let Some(expected) = v.confusion_score else {
                continue;
            };
            assert_eq!(
                dt(&v.template).confusion_score(),
                expected,
                "confusion_score mismatch for {:?}",
                v.template
            );
        }
    }

    #[test]
    fn test_vectors_to_cleartext() {
        for v in load_vectors() {
            let (Some(expected_ct), Some(expected_hct)) = (&v.cleartext, v.has_cleartext) else {
                continue;
            };
            let (actual_ct, actual_hct) = dt(&v.template).to_cleartext();
            assert_eq!(
                actual_ct, *expected_ct,
                "cleartext mismatch for {:?}",
                v.template
            );
            assert_eq!(
                actual_hct, expected_hct,
                "has_cleartext flag mismatch for {:?}",
                v.template
            );
        }
    }

    /// Covers vectors that pin only the `has_cleartext` flag without an
    /// explicit `cleartext` array (currently none in the data file, but
    /// kept so partial vectors remain useful).
    #[test]
    fn test_vectors_has_cleartext() {
        for v in load_vectors() {
            if v.cleartext.is_some() {
                continue;
            }
            let Some(expected_hct) = v.has_cleartext else {
                continue;
            };
            assert_eq!(
                dt(&v.template).to_cleartext().1,
                expected_hct,
                "has_cleartext flag mismatch for {:?}",
                v.template
            );
        }
    }

    #[test]
    fn test_vectors_from_cleartext_roundtrip() {
        for v in load_vectors() {
            if v.has_cleartext != Some(true) {
                continue;
            }
            let (Some(expected_ct), Some(score)) = (&v.cleartext, v.confusion_score) else {
                continue;
            };

            let cleartext_refs: Vec<&str> = expected_ct.iter().map(|s| s.as_str()).collect();
            let variants: Vec<_> = DescriptorTemplate::from_cleartext(&cleartext_refs)
                .unwrap_or_else(|e| panic!("from_cleartext failed for {:?}: {:?}", v.template, e))
                .collect();

            assert_eq!(
                variants.len() as u64,
                score,
                "variant count != confusion_score for {:?}",
                v.template
            );

            // The decoded candidates must include the template we started from.
            // Parsing normalizes derivations (`/**` == `<0;1>/*`) and
            // `has_cleartext == true` guarantees canonical derivation pairs, so
            // the original matches one of the enumerated variants up to tap-tree
            // branch reordering: BIP341 sorts the two child hashes of a
            // TapBranch, so `{A,B}` and `{B,A}` are the same tree, and the
            // decoder deliberately emits a single canonical representative (the
            // confusion score counts *unordered* trees). We therefore compare
            // after canonicalizing branch child order.
            let original = canonicalize_taptree_order(&dt(&v.template));
            assert!(
                variants
                    .iter()
                    .any(|variant| canonicalize_taptree_order(variant) == original),
                "from_cleartext for {:?} did not yield the original template back \
                 (up to tap-tree branch reordering)",
                v.template
            );

            for variant in &variants {
                let (variant_ct, variant_clear) = variant.to_cleartext();
                assert_eq!(
                    variant_ct, *expected_ct,
                    "variant {:?} produces different cleartext for original {:?}",
                    variant, v.template
                );
                assert!(
                    variant_clear,
                    "variant {:?} has has_cleartext=false for original {:?}",
                    variant, v.template
                );
            }

            for i in 0..variants.len() {
                for j in (i + 1)..variants.len() {
                    assert_ne!(
                        variants[i], variants[j],
                        "duplicate variants at indices {} and {} for {:?}",
                        i, j, v.template
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
