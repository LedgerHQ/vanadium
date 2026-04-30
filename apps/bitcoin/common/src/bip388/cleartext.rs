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

use macros::descriptor_match;

use super::time::{format_seconds, format_utc_date};
use super::{DescriptorTemplate, KeyPlaceholder};

#[cfg(any(test, feature = "cleartext-decode"))]
use super::time::{parse_relative_time_to_seconds, parse_utc_date_to_timestamp};
#[cfg(any(test, feature = "cleartext-decode"))]
use super::TapTree;
#[cfg(any(test, feature = "cleartext-decode"))]
use alloc::{boxed::Box, rc::Rc};
#[cfg(any(test, feature = "cleartext-decode"))]
use core::str::FromStr;

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

// Private intermediate representations for the DescriptorTemplate variants for the root descriptor template that have
// a cleartext representation. Both `confusion_score` and `to_cleartext` match on these types, so their case coverage
// is structurally identical and compiler-enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DescriptorClass {
    LegacySingleSig {
        key: KeyPlaceholder,
    },
    SegwitSingleSig {
        key: KeyPlaceholder,
    },
    SegwitMultisig {
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
    },
    Taproot {
        // taproot descriptor templates where the internal key is a plain key
        internal_key: KeyPlaceholder,
        leaves: Vec<TapleafClass>,
    },
    TaprootMusig {
        // taproot descriptor templates where the internal key is a musig expression
        internal_key: KeyPlaceholder,
        leaves: Vec<TapleafClass>,
    },
    Other,
}

// Private intermediate representations for the DescriptorTemplate variants for tapleaves
// that have a cleartext representation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum TapleafClass {
    // non-miniscript patterns
    SortedMultisig {
        // sortedmulti_a
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
    },
    // miniscript patterns
    SingleSig {
        // pk and pkh
        key: KeyPlaceholder,
    },
    BothMustSign {
        key1: KeyPlaceholder,
        key2: KeyPlaceholder,
    },
    Multisig {
        // multi_a
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
    },
    RelativeHeightlockSingleSig {
        // and_v(v:pk(@x), older(n)), with n >= 1 && n < 65536
        key: KeyPlaceholder,
        blocks: u32,
    },
    RelativeHeightlockBothMustSign {
        // and_v(v:and_v(v:pk(@x1), pk(@x2)), older(n)), with n >= 1 && n < 65536
        key1: KeyPlaceholder,
        key2: KeyPlaceholder,
        blocks: u32,
    },
    RelativeHeightlockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), older(n)), with n >= 1 && n < 65536
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
        blocks: u32,
    },
    RelativeTimelockSingleSig {
        // and_v(v:pk(@x), older(n)) with n >= 4194305 && n < 4259840
        key: KeyPlaceholder,
        time: u32,
    },
    RelativeTimelockBothMustSign {
        // and_v(v:and_v(v:pk(@x1), pk(@x2)), older(n)), with n >= 4194305 && n < 4259840
        key1: KeyPlaceholder,
        key2: KeyPlaceholder,
        time: u32,
    },
    RelativeTimelockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), older(n)) with n >= 4194305 && n < 4259840
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
        time: u32,
    },
    AbsoluteHeightlockSingleSig {
        // and_v(v:pk(@x), after(n)) with n < 500000000
        key: KeyPlaceholder,
        block_height: u32,
    },
    AbsoluteHeightlockBothMustSign {
        // and_v(v:and_v(v:pk(@x1), pk(@x2)), after(n)), with n < 500000000
        key1: KeyPlaceholder,
        key2: KeyPlaceholder,
        block_height: u32,
    },
    AbsoluteHeightlockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), after(n)) with n < 500000000
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
        block_height: u32,
    },
    AbsoluteTimelockSingleSig {
        // and_v(v:pk(@x), after(n)) with n >= 500000000
        key: KeyPlaceholder,
        timestamp: u32,
    },
    AbsoluteTimelockBothMustSign {
        // and_v(v:and_v(v:pk(@x1), pk(@x2)), after(n)), with n >= 500000000
        key1: KeyPlaceholder,
        key2: KeyPlaceholder,
        timestamp: u32,
    },
    AbsoluteTimelockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), after(n)) with n >= 500000000
        threshold: u32,
        keys: Vec<KeyPlaceholder>,
        timestamp: u32,
    },
    Other(String),
}

// Represents a part of a clear-text representation of a descriptor template or tapleaf. A sequence of cleartext parts
// fully defines the structure of the cleartext representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleartextPart {
    Literal(&'static str),
    Threshold,
    KeyIndex,
    KeyIndices,
    Blocks,
    RelativeTime,
    BlockHeight,
    Timestamp,
}

struct CleartextSpec<K> {
    kind: K,
    parts: &'static [CleartextPart],
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TopLevelPattern {
    LegacySingleSig,
    SegwitSingleSig,
    SegwitMultisig,
    Taproot,
    TaprootMusig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TapleafPattern {
    SingleSig,
    SortedMultisig,
    BothMustSign,
    Multisig,
    RelativeHeightlockSingleSig,
    RelativeHeightlockBothMustSign,
    RelativeHeightlockMultiSig,
    RelativeTimelockSingleSig,
    RelativeTimelockBothMustSign,
    RelativeTimelockMultiSig,
    AbsoluteHeightlockSingleSig,
    AbsoluteHeightlockBothMustSign,
    AbsoluteHeightlockMultiSig,
    AbsoluteTimelockSingleSig,
    AbsoluteTimelockBothMustSign,
    AbsoluteTimelockMultiSig,
}

#[rustfmt::skip]
mod specs {
    // This module contains the specifications of the cleartext patterns for the root descriptor template and tapleaves.
    // In order to simplify parsing in the reverse direction (from cleartext to descriptor template), the cleartext
    // patterns must be designed so that they are unambiguous.
    // The current specifications enforce that:
    // - Literal parts can never be confused with non-Literal parts
    // - The list of all literal parts is distinct for distinct patterns, even ignoring the non-literal parts in-between.
    use super::{CleartextPart, CleartextSpec, TapleafPattern, TopLevelPattern};
    use super::CleartextPart::*;

    /// Constructs a `Literal` part, asserting at compile time that the string does not
    /// start or end with an ASCII digit and does not contain `@`. These properties ensure
    /// that the literal cannot be mistaken for a dynamic field rendered by `format_key_index`,
    /// `format_key_indices`, or numeric formatters.
    const fn lit(s: &'static str) -> CleartextPart {
        let bytes = s.as_bytes();
        assert!(!bytes[0].is_ascii_digit(), "literal starts with a digit");
        assert!(!bytes[bytes.len() - 1].is_ascii_digit(), "literal ends with a digit");
        let mut i = 0;
        while i < bytes.len() {
            assert!(bytes[i] != b'@', "literal contains '@'");
            i += 1;
        }
        Literal(s)
    }

    pub(super) const TOP_LEVEL_SPECS: &[CleartextSpec<TopLevelPattern>] = &[
        CleartextSpec {
            kind: TopLevelPattern::LegacySingleSig,
            parts: &[lit("Legacy single-signature ("), KeyIndex, lit(")")],
        },
        CleartextSpec {
            kind: TopLevelPattern::SegwitSingleSig,
            parts: &[lit("Segwit single-signature ("), KeyIndex, lit(")")],
        },
        CleartextSpec {
            kind: TopLevelPattern::SegwitMultisig,
            parts: &[Threshold, lit(" of "), KeyIndices, lit(" (SegWit)")],
        },
        CleartextSpec {
            kind: TopLevelPattern::Taproot,
            parts: &[lit("Primary path: "), KeyIndex],
        },
        CleartextSpec {
            kind: TopLevelPattern::TaprootMusig,
            parts: &[lit("Primary path: "), Threshold, lit(" of "), KeyIndices],
        },
    ];

    pub(super) const TAPLEAF_SPECS: &[CleartextSpec<TapleafPattern>] = &[
        CleartextSpec {
            kind: TapleafPattern::SingleSig,
            parts: &[lit("Single-signature ("), KeyIndex, lit(")")],
        },
        CleartextSpec {
            kind: TapleafPattern::SortedMultisig,
            parts: &[Threshold, lit(" of "), KeyIndices, lit(" (sorted)")],
        },
        CleartextSpec {
            kind: TapleafPattern::BothMustSign,
            parts: &[lit("Both "), KeyIndex, lit(" and "), KeyIndex, lit(" must sign")],
        },
        CleartextSpec {
            kind: TapleafPattern::Multisig,
            parts: &[Threshold, lit(" of "), KeyIndices],
        },
        CleartextSpec {
            kind: TapleafPattern::RelativeHeightlockSingleSig,
            parts: &[KeyIndex, lit(" after "), Blocks, lit(" blocks")],
        },
        CleartextSpec {
            kind: TapleafPattern::RelativeHeightlockBothMustSign,
            parts: &[lit("Both "), KeyIndex, lit(" and "), KeyIndex, lit(" after "), Blocks, lit(" blocks")],
        },
        CleartextSpec {
            kind: TapleafPattern::RelativeHeightlockMultiSig,
            parts: &[Threshold, lit(" of "), KeyIndices, lit(" after "), Blocks, lit(" blocks")],
        },
        CleartextSpec {
            kind: TapleafPattern::RelativeTimelockSingleSig,
            parts: &[KeyIndex, lit(" after "), RelativeTime],
        },
        CleartextSpec {
            kind: TapleafPattern::RelativeTimelockBothMustSign,
            parts: &[lit("Both "), KeyIndex, lit(" and "), KeyIndex, lit(" after "), RelativeTime],
        },
        CleartextSpec {
            kind: TapleafPattern::RelativeTimelockMultiSig,
            parts: &[Threshold, lit(" of "), KeyIndices, lit(" after "), RelativeTime]
        },
        CleartextSpec {
            kind: TapleafPattern::AbsoluteHeightlockSingleSig,
            parts: &[KeyIndex, lit(" after block height "), BlockHeight],
        },
        CleartextSpec {
            kind: TapleafPattern::AbsoluteHeightlockBothMustSign,
            parts: &[lit("Both "), KeyIndex, lit(" and "), KeyIndex, lit(" after block height "), BlockHeight],
        },
        CleartextSpec {
            kind: TapleafPattern::AbsoluteHeightlockMultiSig,
            parts: &[Threshold, lit(" of "), KeyIndices, lit(" after block height "), BlockHeight]
        },
        CleartextSpec {
            kind: TapleafPattern::AbsoluteTimelockSingleSig,
            parts: &[KeyIndex, lit(" after date "), Timestamp],
        },
        CleartextSpec {
            kind: TapleafPattern::AbsoluteTimelockBothMustSign,
            parts: &[lit("Both "), KeyIndex, lit(" and "), KeyIndex, lit(" after date "), Timestamp],
        },
        CleartextSpec {
            kind: TapleafPattern::AbsoluteTimelockMultiSig,
            parts: &[Threshold, lit(" of "), KeyIndices, lit(" after date "), Timestamp]
        },
    ];
}
use specs::{TAPLEAF_SPECS, TOP_LEVEL_SPECS};

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
    /// Returns a numeric key that defines the canonical visualization order for
    /// taptree leaves:
    ///   - simpler conditions come first
    ///   - relative before absolute
    ///   - heightlocks before timelocks
    ///   - `Other` (anything with no cleartext representation) is last
    fn order(&self) -> u32 {
        match self {
            TapleafClass::SingleSig { .. } => 0,
            TapleafClass::BothMustSign { .. } => 1,
            TapleafClass::SortedMultisig { .. } => 2,
            TapleafClass::Multisig { .. } => 3,
            TapleafClass::RelativeHeightlockSingleSig { .. } => 4,
            TapleafClass::RelativeHeightlockBothMustSign { .. } => 5,
            TapleafClass::RelativeHeightlockMultiSig { .. } => 6,
            TapleafClass::RelativeTimelockSingleSig { .. } => 7,
            TapleafClass::RelativeTimelockBothMustSign { .. } => 8,
            TapleafClass::RelativeTimelockMultiSig { .. } => 9,
            TapleafClass::AbsoluteHeightlockSingleSig { .. } => 10,
            TapleafClass::AbsoluteHeightlockBothMustSign { .. } => 11,
            TapleafClass::AbsoluteHeightlockMultiSig { .. } => 12,
            TapleafClass::AbsoluteTimelockSingleSig { .. } => 13,
            TapleafClass::AbsoluteTimelockBothMustSign { .. } => 14,
            TapleafClass::AbsoluteTimelockMultiSig { .. } => 15,
            TapleafClass::Other(_) => 16,
        }
    }

    /// Full canonical display order. Within each category, ties are broken by:
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
                TC::RelativeTimelockSingleSig { key: k1, time: t1 },
                TC::RelativeTimelockSingleSig { key: k2, time: t2 },
            ) => cmp_key(k1, k2).then(t1.cmp(t2)),
            (
                TC::RelativeTimelockBothMustSign { key1: a1, key2: b1, time: t1 },
                TC::RelativeTimelockBothMustSign { key1: a2, key2: b2, time: t2 },
            ) => cmp_key(a1, a2).then(cmp_key(b1, b2)).then(t1.cmp(t2)),
            (
                TC::RelativeTimelockMultiSig { threshold: t1, keys: k1, time: tm1 },
                TC::RelativeTimelockMultiSig { threshold: t2, keys: k2, time: tm2 },
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

impl DescriptorTemplate {
    fn classify(&self) -> DescriptorClass {
        descriptor_match!(self, {
            pkh(key) => {
                DescriptorClass::LegacySingleSig { key: key.clone() }
            },
            // normal or wrapped
            wpkh(key) | sh(wpkh(key)) => {
                DescriptorClass::SegwitSingleSig { key: key.clone() }
            },
            // 4 combinations: multi/sortedmulti; normal/wrapped
            wsh(multi(threshold, keys)) | wsh(sortedmulti(threshold, keys)) | sh(wsh(multi(threshold, keys))) | sh(wsh(sortedmulti(threshold, keys))) => {
                DescriptorClass::SegwitMultisig { threshold, keys: keys.clone() }
            },
            tr(internal_key, tree) => {
                DescriptorClass::Taproot {
                    internal_key: internal_key.clone(),
                    leaves: tree
                        .as_ref()
                        .map(|t| t.tapleaves().map(|l| l.classify_as_tapleaf()).collect())
                        .unwrap_or_default(),
                }
            },
            tr(musig(musig_key), tree) => {
                DescriptorClass::TaprootMusig {
                    internal_key: musig_key.clone(),
                    leaves: tree
                        .as_ref()
                        .map(|t| t.tapleaves().map(|l| l.classify_as_tapleaf()).collect())
                        .unwrap_or_default(),
                }
            },
            _ => { DescriptorClass::Other },
        })
    }

    fn classify_as_tapleaf(&self) -> TapleafClass {
        descriptor_match!(self, {
            sortedmulti_a(threshold, keys) => {
                TapleafClass::SortedMultisig { threshold, keys: keys.clone() }
            },
            pk(key) | pkh(key) => {
                TapleafClass::SingleSig { key: key.clone() }
            },
            multi_a(threshold, keys) => {
                TapleafClass::Multisig { threshold, keys: keys.clone() }
            },
            and_v(v:pk(key), older(blocks)) if blocks >= 1 && blocks < 65536 => {
                TapleafClass::RelativeHeightlockSingleSig { key: key.clone(), blocks }
            },
            and_v(v:and_v(v:pk(key1), pk(key2)), older(blocks)) if blocks >= 1 && blocks < 65536 => {
                TapleafClass::RelativeHeightlockBothMustSign { key1: key1.clone(), key2: key2.clone(), blocks }
            },
            and_v(v:multi_a(threshold, keys), older(blocks)) if blocks >= 1 && blocks < 65536 => {
                TapleafClass::RelativeHeightlockMultiSig { threshold, keys: keys.clone(), blocks }
            },
            and_v(v:pk(key), older(time)) if time >= 4194305 && time < 4259840 => {
                TapleafClass::RelativeTimelockSingleSig { key: key.clone(), time }
            },
            and_v(v:and_v(v:pk(key1), pk(key2)), older(time)) if time >= 4194305 && time < 4259840 => {
                TapleafClass::RelativeTimelockBothMustSign { key1: key1.clone(), key2: key2.clone(), time }
            },
            and_v(v:multi_a(threshold, keys), older(time)) if time >= 4194305 && time < 4259840 => {
                TapleafClass::RelativeTimelockMultiSig { threshold, keys: keys.clone(), time }
            },
            and_v(v:pk(key), after(block_height)) if block_height >= 1 && block_height < 500000000 => {
                TapleafClass::AbsoluteHeightlockSingleSig { key: key.clone(), block_height }
            },
            and_v(v:and_v(v:pk(key1), pk(key2)), after(block_height)) if block_height >= 1 && block_height < 500000000 => {
                TapleafClass::AbsoluteHeightlockBothMustSign { key1: key1.clone(), key2: key2.clone(), block_height }
            },
            and_v(v:multi_a(threshold, keys), after(block_height)) if block_height >= 1 && block_height < 500000000 => {
                TapleafClass::AbsoluteHeightlockMultiSig { threshold, keys: keys.clone(), block_height }
            },
            and_v(v:pk(key), after(timestamp)) if timestamp >= 500000000 => {
                TapleafClass::AbsoluteTimelockSingleSig { key: key.clone(), timestamp }
            },
            and_v(v:and_v(v:pk(key1), pk(key2)), after(timestamp)) if timestamp >= 500000000 => {
                TapleafClass::AbsoluteTimelockBothMustSign { key1: key1.clone(), key2: key2.clone(), timestamp }
            },
            and_v(v:multi_a(threshold, keys), after(timestamp)) if timestamp >= 500000000 => {
                TapleafClass::AbsoluteTimelockMultiSig { threshold, keys: keys.clone(), timestamp }
            },
            pk(musig(musig_key)) | pkh(musig(musig_key)) => {
                let indices = musig_key.musig_key_indices().unwrap();
                let keys: Vec<KeyPlaceholder> = indices
                    .iter()
                    .map(|&idx| KeyPlaceholder::plain(idx, musig_key.num1, musig_key.num2))
                    .collect();
                TapleafClass::Multisig { threshold: keys.len() as u32, keys }
            },
            and_v(v:pk(musig(musig_key)), older(blocks)) if blocks >= 1 && blocks < 65536 => {
                let indices = musig_key.musig_key_indices().unwrap();
                let keys: Vec<KeyPlaceholder> = indices
                    .iter()
                    .map(|&idx| KeyPlaceholder::plain(idx, musig_key.num1, musig_key.num2))
                    .collect();
                TapleafClass::RelativeHeightlockMultiSig { threshold: keys.len() as u32, keys, blocks }
            },
            and_v(v:pk(musig(musig_key)), older(time)) if time >= 4194305 && time < 4259840 => {
                let indices = musig_key.musig_key_indices().unwrap();
                let keys: Vec<KeyPlaceholder> = indices
                    .iter()
                    .map(|&idx| KeyPlaceholder::plain(idx, musig_key.num1, musig_key.num2))
                    .collect();
                TapleafClass::RelativeTimelockMultiSig { threshold: keys.len() as u32, keys, time }
            },
            and_v(v:pk(musig(musig_key)), after(block_height)) if block_height >= 1 && block_height < 500000000 => {
                let indices = musig_key.musig_key_indices().unwrap();
                let keys: Vec<KeyPlaceholder> = indices
                    .iter()
                    .map(|&idx| KeyPlaceholder::plain(idx, musig_key.num1, musig_key.num2))
                    .collect();
                TapleafClass::AbsoluteHeightlockMultiSig { threshold: keys.len() as u32, keys, block_height }
            },
            and_v(v:pk(musig(musig_key)), after(timestamp)) if timestamp >= 500000000 => {
                let indices = musig_key.musig_key_indices().unwrap();
                let keys: Vec<KeyPlaceholder> = indices
                    .iter()
                    .map(|&idx| KeyPlaceholder::plain(idx, musig_key.num1, musig_key.num2))
                    .collect();
                TapleafClass::AbsoluteTimelockMultiSig { threshold: keys.len() as u32, keys, timestamp }
            },
            and_v(v:pk(key1), pk(key2)) => {
                TapleafClass::BothMustSign { key1: key1.clone(), key2: key2.clone() }
            },
            _ => { TapleafClass::Other(self.to_string()) },
        })
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

fn cleartext_spec<K: Copy + Eq>(
    specs: &'static [CleartextSpec<K>],
    kind: K,
) -> &'static CleartextSpec<K> {
    specs
        .iter()
        .find(|spec| spec.kind == kind)
        .expect("missing cleartext spec")
}

fn format_cleartext_value(
    part: CleartextPart,
    value: &CleartextValue,
    canonical: bool,
) -> Option<String> {
    match (part, value) {
        (CleartextPart::Threshold, CleartextValue::Threshold(threshold)) => {
            Some(threshold.to_string())
        }
        (CleartextPart::KeyIndex, CleartextValue::KeyIndex(kp)) => Some(format_key(kp, canonical)),
        (CleartextPart::KeyIndices, CleartextValue::KeyIndices(keys)) => {
            Some(format_key_indices(keys, canonical))
        }
        (CleartextPart::Blocks, CleartextValue::Blocks(blocks)) => Some(blocks.to_string()),
        (CleartextPart::RelativeTime, CleartextValue::RelativeTime(time)) => {
            Some(format_relative_time(*time))
        }
        (CleartextPart::BlockHeight, CleartextValue::BlockHeight(block_height)) => {
            Some(block_height.to_string())
        }
        (CleartextPart::Timestamp, CleartextValue::Timestamp(timestamp)) => {
            Some(format_utc_date(*timestamp))
        }
        (CleartextPart::Literal(_), _) => None,
        _ => None,
    }
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
    fn cleartext_pattern(&self) -> Option<(TopLevelPattern, Vec<CleartextValue>)> {
        match self {
            DescriptorClass::LegacySingleSig { key } => Some((
                TopLevelPattern::LegacySingleSig,
                vec![CleartextValue::KeyIndex(key.clone())],
            )),
            DescriptorClass::SegwitSingleSig { key } => Some((
                TopLevelPattern::SegwitSingleSig,
                vec![CleartextValue::KeyIndex(key.clone())],
            )),
            DescriptorClass::SegwitMultisig { threshold, keys } => Some((
                TopLevelPattern::SegwitMultisig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                ],
            )),
            DescriptorClass::Taproot { internal_key, .. } => Some((
                TopLevelPattern::Taproot,
                vec![CleartextValue::KeyIndex(internal_key.clone())],
            )),
            DescriptorClass::TaprootMusig { internal_key, .. } => {
                let key_indices = internal_key
                    .musig_key_indices()
                    .expect("TaprootMusig internal_key must be musig");
                let keys: Vec<KeyPlaceholder> = key_indices
                    .iter()
                    .map(|&idx| KeyPlaceholder::plain(idx, internal_key.num1, internal_key.num2))
                    .collect();
                Some((
                    TopLevelPattern::TaprootMusig,
                    vec![
                        CleartextValue::Threshold(keys.len() as u32),
                        CleartextValue::KeyIndices(keys),
                    ],
                ))
            }
            DescriptorClass::Other => None,
        }
    }

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
    fn cleartext_pattern(&self) -> Option<(TapleafPattern, Vec<CleartextValue>)> {
        match self {
            TapleafClass::SingleSig { key } => Some((
                TapleafPattern::SingleSig,
                vec![CleartextValue::KeyIndex(key.clone())],
            )),
            TapleafClass::SortedMultisig { threshold, keys } => Some((
                TapleafPattern::SortedMultisig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                ],
            )),
            TapleafClass::BothMustSign { key1, key2 } => Some((
                TapleafPattern::BothMustSign,
                vec![
                    CleartextValue::KeyIndex(key1.clone()),
                    CleartextValue::KeyIndex(key2.clone()),
                ],
            )),
            TapleafClass::Multisig { threshold, keys } => Some((
                TapleafPattern::Multisig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                ],
            )),
            TapleafClass::RelativeHeightlockSingleSig { key, blocks } => Some((
                TapleafPattern::RelativeHeightlockSingleSig,
                vec![
                    CleartextValue::KeyIndex(key.clone()),
                    CleartextValue::Blocks(*blocks),
                ],
            )),
            TapleafClass::RelativeHeightlockBothMustSign { key1, key2, blocks } => Some((
                TapleafPattern::RelativeHeightlockBothMustSign,
                vec![
                    CleartextValue::KeyIndex(key1.clone()),
                    CleartextValue::KeyIndex(key2.clone()),
                    CleartextValue::Blocks(*blocks),
                ],
            )),
            TapleafClass::RelativeHeightlockMultiSig {
                threshold,
                keys,
                blocks,
            } => Some((
                TapleafPattern::RelativeHeightlockMultiSig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                    CleartextValue::Blocks(*blocks),
                ],
            )),
            TapleafClass::RelativeTimelockSingleSig { key, time } => Some((
                TapleafPattern::RelativeTimelockSingleSig,
                vec![
                    CleartextValue::KeyIndex(key.clone()),
                    CleartextValue::RelativeTime(*time),
                ],
            )),
            TapleafClass::RelativeTimelockBothMustSign { key1, key2, time } => Some((
                TapleafPattern::RelativeTimelockBothMustSign,
                vec![
                    CleartextValue::KeyIndex(key1.clone()),
                    CleartextValue::KeyIndex(key2.clone()),
                    CleartextValue::RelativeTime(*time),
                ],
            )),
            TapleafClass::RelativeTimelockMultiSig {
                threshold,
                keys,
                time,
            } => Some((
                TapleafPattern::RelativeTimelockMultiSig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                    CleartextValue::RelativeTime(*time),
                ],
            )),
            TapleafClass::AbsoluteHeightlockSingleSig { key, block_height } => Some((
                TapleafPattern::AbsoluteHeightlockSingleSig,
                vec![
                    CleartextValue::KeyIndex(key.clone()),
                    CleartextValue::BlockHeight(*block_height),
                ],
            )),
            TapleafClass::AbsoluteHeightlockBothMustSign {
                key1,
                key2,
                block_height,
            } => Some((
                TapleafPattern::AbsoluteHeightlockBothMustSign,
                vec![
                    CleartextValue::KeyIndex(key1.clone()),
                    CleartextValue::KeyIndex(key2.clone()),
                    CleartextValue::BlockHeight(*block_height),
                ],
            )),
            TapleafClass::AbsoluteHeightlockMultiSig {
                threshold,
                keys,
                block_height,
            } => Some((
                TapleafPattern::AbsoluteHeightlockMultiSig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                    CleartextValue::BlockHeight(*block_height),
                ],
            )),
            TapleafClass::AbsoluteTimelockSingleSig { key, timestamp } => Some((
                TapleafPattern::AbsoluteTimelockSingleSig,
                vec![
                    CleartextValue::KeyIndex(key.clone()),
                    CleartextValue::Timestamp(*timestamp),
                ],
            )),
            TapleafClass::AbsoluteTimelockBothMustSign {
                key1,
                key2,
                timestamp,
            } => Some((
                TapleafPattern::AbsoluteTimelockBothMustSign,
                vec![
                    CleartextValue::KeyIndex(key1.clone()),
                    CleartextValue::KeyIndex(key2.clone()),
                    CleartextValue::Timestamp(*timestamp),
                ],
            )),
            TapleafClass::AbsoluteTimelockMultiSig {
                threshold,
                keys,
                timestamp,
            } => Some((
                TapleafPattern::AbsoluteTimelockMultiSig,
                vec![
                    CleartextValue::Threshold(*threshold),
                    CleartextValue::KeyIndices(keys.clone()),
                    CleartextValue::Timestamp(*timestamp),
                ],
            )),
            TapleafClass::Other(_) => None,
        }
    }

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
        let base = match self.classify() {
            DescriptorClass::LegacySingleSig { .. } => 1,
            DescriptorClass::SegwitSingleSig { .. } => 2, // wpkh and sh(wpkh)
            DescriptorClass::SegwitMultisig { .. } => 4, // multi or sortedmulti / normal or wrapped
            DescriptorClass::Taproot { leaves, .. }
            | DescriptorClass::TaprootMusig { leaves, .. } => {
                // The confusion score of a taproot descriptor is the product of the confusion scores of the internal key and all the leaves,
                // multiplied by the number T(n) of rearrangements of the tree.
                let mut score = 1u64;
                let n_leaves = leaves.len();
                for leaf in &leaves {
                    let leaf_score = match leaf {
                        TapleafClass::SingleSig { .. } => 1,
                        TapleafClass::SortedMultisig { .. } => 1,
                        TapleafClass::Multisig { threshold, keys } => {
                            if *threshold as usize == keys.len() {
                                2
                            } else {
                                1
                            }
                        }
                        TapleafClass::BothMustSign { .. } => 1,
                        TapleafClass::RelativeHeightlockSingleSig { .. } => 1,
                        TapleafClass::RelativeHeightlockBothMustSign { .. } => 1,
                        TapleafClass::RelativeHeightlockMultiSig {
                            threshold, keys, ..
                        } => {
                            if *threshold as usize == keys.len() {
                                2
                            } else {
                                1
                            }
                        }
                        TapleafClass::RelativeTimelockSingleSig { .. } => 1,
                        TapleafClass::RelativeTimelockBothMustSign { .. } => 1,
                        TapleafClass::RelativeTimelockMultiSig {
                            threshold, keys, ..
                        } => {
                            if *threshold as usize == keys.len() {
                                2
                            } else {
                                1
                            }
                        }
                        TapleafClass::AbsoluteHeightlockSingleSig { .. } => 1,
                        TapleafClass::AbsoluteHeightlockBothMustSign { .. } => 1,
                        TapleafClass::AbsoluteHeightlockMultiSig {
                            threshold, keys, ..
                        } => {
                            if *threshold as usize == keys.len() {
                                2
                            } else {
                                1
                            }
                        }
                        TapleafClass::AbsoluteTimelockSingleSig { .. } => 1,
                        TapleafClass::AbsoluteTimelockBothMustSign { .. } => 1,
                        TapleafClass::AbsoluteTimelockMultiSig {
                            threshold, keys, ..
                        } => {
                            if *threshold as usize == keys.len() {
                                2
                            } else {
                                1
                            }
                        }
                        TapleafClass::Other(_) => 1,
                    };
                    score = score.saturating_mul(leaf_score);
                }

                // Multiply by the number of rearrangements of the tree.
                // T(n) = (2n - 3)!! = 1 * 3 * 5 * ... * (2n - 3) for n > 1, and T(1) = 1.
                if n_leaves > 1 {
                    for i in (1..=(2 * n_leaves - 3)).step_by(2) {
                        score = score.saturating_mul(i as u64);
                    }
                }

                score
            }
            DescriptorClass::Other => 1,
        };
        // For each key expression that appears k times in the descriptor template, multiply by k!
        // to account for the possible re-orderings of the canonical derivation pairs across its
        // occurrences. This is only applied at the root level (not when recurring).
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

#[cfg(any(test, feature = "cleartext-decode"))]
impl DescriptorClass {
    fn from_cleartext_pattern(kind: TopLevelPattern, values: Vec<CleartextValue>) -> Option<Self> {
        let mut values = CleartextValueCursor::new(values);
        let result = match kind {
            TopLevelPattern::LegacySingleSig => DescriptorClass::LegacySingleSig {
                key: values.key_index()?,
            },
            TopLevelPattern::SegwitSingleSig => DescriptorClass::SegwitSingleSig {
                key: values.key_index()?,
            },
            TopLevelPattern::SegwitMultisig => DescriptorClass::SegwitMultisig {
                threshold: values.threshold()?,
                keys: values.key_indices()?,
            },
            TopLevelPattern::Taproot => DescriptorClass::Taproot {
                internal_key: values.key_index()?,
                leaves: Vec::new(),
            },
            TopLevelPattern::TaprootMusig => {
                let threshold = values.threshold()?;
                let keys = values.key_indices()?;
                if threshold as usize != keys.len() {
                    return None;
                }
                let key_indices: Vec<u32> =
                    keys.iter().filter_map(|k| k.plain_key_index()).collect();
                if key_indices.len() != keys.len() {
                    return None;
                }
                let num1 = keys.first().map(|k| k.num1).unwrap_or(0);
                let num2 = keys.first().map(|k| k.num2).unwrap_or(1);
                DescriptorClass::TaprootMusig {
                    internal_key: KeyPlaceholder::musig(key_indices, num1, num2),
                    leaves: Vec::new(),
                }
            }
        };
        values.finish()?;
        Some(result)
    }
}

#[cfg(any(test, feature = "cleartext-decode"))]
impl TapleafClass {
    fn from_cleartext_pattern(kind: TapleafPattern, values: Vec<CleartextValue>) -> Option<Self> {
        let mut values = CleartextValueCursor::new(values);
        let result = match kind {
            TapleafPattern::SingleSig => TapleafClass::SingleSig {
                key: values.key_index()?,
            },
            TapleafPattern::SortedMultisig => TapleafClass::SortedMultisig {
                threshold: values.threshold()?,
                keys: values.key_indices()?,
            },
            TapleafPattern::BothMustSign => TapleafClass::BothMustSign {
                key1: values.key_index()?,
                key2: values.key_index()?,
            },
            TapleafPattern::Multisig => TapleafClass::Multisig {
                threshold: values.threshold()?,
                keys: values.key_indices()?,
            },
            TapleafPattern::RelativeHeightlockSingleSig => {
                TapleafClass::RelativeHeightlockSingleSig {
                    key: values.key_index()?,
                    blocks: values.blocks()?,
                }
            }
            TapleafPattern::RelativeHeightlockBothMustSign => {
                TapleafClass::RelativeHeightlockBothMustSign {
                    key1: values.key_index()?,
                    key2: values.key_index()?,
                    blocks: values.blocks()?,
                }
            }
            TapleafPattern::RelativeHeightlockMultiSig => {
                TapleafClass::RelativeHeightlockMultiSig {
                    threshold: values.threshold()?,
                    keys: values.key_indices()?,
                    blocks: values.blocks()?,
                }
            }
            TapleafPattern::RelativeTimelockSingleSig => TapleafClass::RelativeTimelockSingleSig {
                key: values.key_index()?,
                time: values.relative_time()?,
            },
            TapleafPattern::RelativeTimelockBothMustSign => {
                TapleafClass::RelativeTimelockBothMustSign {
                    key1: values.key_index()?,
                    key2: values.key_index()?,
                    time: values.relative_time()?,
                }
            }
            TapleafPattern::RelativeTimelockMultiSig => TapleafClass::RelativeTimelockMultiSig {
                threshold: values.threshold()?,
                keys: values.key_indices()?,
                time: values.relative_time()?,
            },
            TapleafPattern::AbsoluteHeightlockSingleSig => {
                TapleafClass::AbsoluteHeightlockSingleSig {
                    key: values.key_index()?,
                    block_height: values.block_height()?,
                }
            }
            TapleafPattern::AbsoluteHeightlockBothMustSign => {
                TapleafClass::AbsoluteHeightlockBothMustSign {
                    key1: values.key_index()?,
                    key2: values.key_index()?,
                    block_height: values.block_height()?,
                }
            }
            TapleafPattern::AbsoluteHeightlockMultiSig => {
                TapleafClass::AbsoluteHeightlockMultiSig {
                    threshold: values.threshold()?,
                    keys: values.key_indices()?,
                    block_height: values.block_height()?,
                }
            }
            TapleafPattern::AbsoluteTimelockSingleSig => TapleafClass::AbsoluteTimelockSingleSig {
                key: values.key_index()?,
                timestamp: values.timestamp()?,
            },
            TapleafPattern::AbsoluteTimelockBothMustSign => {
                TapleafClass::AbsoluteTimelockBothMustSign {
                    key1: values.key_index()?,
                    key2: values.key_index()?,
                    timestamp: values.timestamp()?,
                }
            }
            TapleafPattern::AbsoluteTimelockMultiSig => TapleafClass::AbsoluteTimelockMultiSig {
                threshold: values.threshold()?,
                keys: values.key_indices()?,
                timestamp: values.timestamp()?,
            },
        };
        values.finish()?;
        Some(result)
    }
}

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

#[cfg(any(test, feature = "cleartext-decode"))]
fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut current: Vec<usize> = (0..n).collect();
    permute_helper(&mut current, 0, &mut result);
    result
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn permute_helper(arr: &mut Vec<usize>, start: usize, out: &mut Vec<Vec<usize>>) {
    if start == arr.len() {
        out.push(arr.clone());
        return;
    }
    for i in start..arr.len() {
        arr.swap(start, i);
        permute_helper(arr, start + 1, out);
        arr.swap(start, i);
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
    let perms_per_group: Vec<Vec<Vec<usize>>> = positions_per_group
        .iter()
        .map(|positions| permutations(positions.len()))
        .collect();

    let mut results = Vec::new();
    let mut chosen: Vec<&Vec<usize>> = Vec::with_capacity(perms_per_group.len());
    expand_derivation_orderings_rec(
        &positions_per_group,
        &perms_per_group,
        &mut chosen,
        &base,
        &mut results,
    );
    results
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn expand_derivation_orderings_rec<'a>(
    positions_per_group: &[Vec<usize>],
    perms_per_group: &'a [Vec<Vec<usize>>],
    chosen: &mut Vec<&'a Vec<usize>>,
    base: &DescriptorTemplate,
    results: &mut Vec<DescriptorTemplate>,
) {
    if chosen.len() == perms_per_group.len() {
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
    for p in &perms_per_group[g] {
        chosen.push(p);
        expand_derivation_orderings_rec(
            positions_per_group,
            perms_per_group,
            chosen,
            base,
            results,
        );
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
    let err = || CleartextDecodeError::UnrecognizedPattern;
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
                    DescriptorClass::TaprootMusig { internal_key, .. } => {
                        for leaves in &leaf_combinations {
                            push_unique(
                                &mut classes,
                                DescriptorClass::TaprootMusig {
                                    internal_key: internal_key.clone(),
                                    leaves: leaves.clone(),
                                },
                            );
                        }
                    }
                    _ => continue,
                }
            }

            if classes.is_empty() {
                Err(err())
            } else {
                Ok(classes)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Variant generators
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "cleartext-decode"))]
fn tapleaf_to_descriptors(
    leaf: &TapleafClass,
) -> Result<Vec<DescriptorTemplate>, CleartextDecodeError> {
    match leaf {
        TapleafClass::SingleSig { key } => Ok(vec![DescriptorTemplate::Pk(key.clone())]),
        TapleafClass::BothMustSign { key1, key2 } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                key1.clone(),
            )))),
            Box::new(DescriptorTemplate::Pk(key2.clone())),
        )]),
        TapleafClass::SortedMultisig { threshold, keys } => {
            Ok(vec![DescriptorTemplate::Sortedmulti_a(
                *threshold,
                keys.clone(),
            )])
        }
        TapleafClass::Multisig { threshold, keys } => {
            let mut variants = vec![DescriptorTemplate::Multi_a(*threshold, keys.clone())];
            if *threshold as usize == keys.len() {
                variants.push(DescriptorTemplate::Pk(KeyPlaceholder::musig(
                    keys.iter()
                        .map(|k| {
                            k.plain_key_index()
                                .ok_or(CleartextDecodeError::ExpectedPlainKey)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    0,
                    1,
                )));
            }
            Ok(variants)
        }
        TapleafClass::RelativeHeightlockSingleSig { key, blocks } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                    key.clone(),
                )))),
                Box::new(DescriptorTemplate::Older(*blocks)),
            )])
        }
        TapleafClass::RelativeHeightlockBothMustSign { key1, key2, blocks } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::And_v(
                    Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                        key1.clone(),
                    )))),
                    Box::new(DescriptorTemplate::Pk(key2.clone())),
                )))),
                Box::new(DescriptorTemplate::Older(*blocks)),
            )])
        }
        TapleafClass::RelativeHeightlockMultiSig {
            threshold,
            keys,
            blocks,
        } => {
            let mut variants = vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(
                    DescriptorTemplate::Multi_a(*threshold, keys.clone()),
                ))),
                Box::new(DescriptorTemplate::Older(*blocks)),
            )];
            if *threshold as usize == keys.len() {
                variants.push(DescriptorTemplate::And_v(
                    Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                        KeyPlaceholder::musig(
                            keys.iter()
                                .map(|k| {
                                    k.plain_key_index()
                                        .ok_or(CleartextDecodeError::ExpectedPlainKey)
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            0,
                            1,
                        ),
                    )))),
                    Box::new(DescriptorTemplate::Older(*blocks)),
                ));
            }
            Ok(variants)
        }
        TapleafClass::RelativeTimelockSingleSig { key, time } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                    key.clone(),
                )))),
                Box::new(DescriptorTemplate::Older(*time)),
            )])
        }
        TapleafClass::RelativeTimelockBothMustSign { key1, key2, time } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::And_v(
                    Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                        key1.clone(),
                    )))),
                    Box::new(DescriptorTemplate::Pk(key2.clone())),
                )))),
                Box::new(DescriptorTemplate::Older(*time)),
            )])
        }
        TapleafClass::RelativeTimelockMultiSig {
            threshold,
            keys,
            time,
        } => {
            let mut variants = vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(
                    DescriptorTemplate::Multi_a(*threshold, keys.clone()),
                ))),
                Box::new(DescriptorTemplate::Older(*time)),
            )];
            if *threshold as usize == keys.len() {
                variants.push(DescriptorTemplate::And_v(
                    Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                        KeyPlaceholder::musig(
                            keys.iter()
                                .map(|k| {
                                    k.plain_key_index()
                                        .ok_or(CleartextDecodeError::ExpectedPlainKey)
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            0,
                            1,
                        ),
                    )))),
                    Box::new(DescriptorTemplate::Older(*time)),
                ));
            }
            Ok(variants)
        }
        TapleafClass::AbsoluteHeightlockSingleSig { key, block_height } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                    key.clone(),
                )))),
                Box::new(DescriptorTemplate::After(*block_height)),
            )])
        }
        TapleafClass::AbsoluteHeightlockBothMustSign {
            key1,
            key2,
            block_height,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                    key1.clone(),
                )))),
                Box::new(DescriptorTemplate::Pk(key2.clone())),
            )))),
            Box::new(DescriptorTemplate::After(*block_height)),
        )]),
        TapleafClass::AbsoluteHeightlockMultiSig {
            threshold,
            keys,
            block_height,
        } => {
            let mut variants = vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(
                    DescriptorTemplate::Multi_a(*threshold, keys.clone()),
                ))),
                Box::new(DescriptorTemplate::After(*block_height)),
            )];
            if *threshold as usize == keys.len() {
                variants.push(DescriptorTemplate::And_v(
                    Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                        KeyPlaceholder::musig(
                            keys.iter()
                                .map(|k| {
                                    k.plain_key_index()
                                        .ok_or(CleartextDecodeError::ExpectedPlainKey)
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            0,
                            1,
                        ),
                    )))),
                    Box::new(DescriptorTemplate::After(*block_height)),
                ));
            }
            Ok(variants)
        }
        TapleafClass::AbsoluteTimelockSingleSig { key, timestamp } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                    key.clone(),
                )))),
                Box::new(DescriptorTemplate::After(*timestamp)),
            )])
        }
        TapleafClass::AbsoluteTimelockBothMustSign {
            key1,
            key2,
            timestamp,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                    key1.clone(),
                )))),
                Box::new(DescriptorTemplate::Pk(key2.clone())),
            )))),
            Box::new(DescriptorTemplate::After(*timestamp)),
        )]),
        TapleafClass::AbsoluteTimelockMultiSig {
            threshold,
            keys,
            timestamp,
        } => {
            let mut variants = vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(
                    DescriptorTemplate::Multi_a(*threshold, keys.clone()),
                ))),
                Box::new(DescriptorTemplate::After(*timestamp)),
            )];
            if *threshold as usize == keys.len() {
                variants.push(DescriptorTemplate::And_v(
                    Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(
                        KeyPlaceholder::musig(
                            keys.iter()
                                .map(|k| {
                                    k.plain_key_index()
                                        .ok_or(CleartextDecodeError::ExpectedPlainKey)
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                            0,
                            1,
                        ),
                    )))),
                    Box::new(DescriptorTemplate::After(*timestamp)),
                ));
            }
            Ok(variants)
        }
        TapleafClass::Other(s) => {
            let dt = DescriptorTemplate::from_str(s)
                .map_err(|e| CleartextDecodeError::InvalidDescriptor(format!("{:?}", e)))?;
            Ok(vec![dt])
        }
    }
}

// ---------------------------------------------------------------------------
// Tree enumeration
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

/// Generate a lazy iterator over all `DescriptorTemplate` variants for a given `DescriptorClass`.
#[cfg(any(test, feature = "cleartext-decode"))]
fn top_level_variants(
    class: DescriptorClass,
) -> Result<Box<dyn Iterator<Item = DescriptorTemplate>>, CleartextDecodeError> {
    match class {
        DescriptorClass::LegacySingleSig { key } => {
            Ok(Box::new(core::iter::once(DescriptorTemplate::Pkh(key))))
        }
        DescriptorClass::SegwitSingleSig { key } => Ok(Box::new(
            vec![
                DescriptorTemplate::Wpkh(key.clone()),
                DescriptorTemplate::Sh(Box::new(DescriptorTemplate::Wpkh(key))),
            ]
            .into_iter(),
        )),
        DescriptorClass::SegwitMultisig { threshold, keys } => Ok(Box::new(
            vec![
                DescriptorTemplate::Wsh(Box::new(DescriptorTemplate::Multi(
                    threshold,
                    keys.clone(),
                ))),
                DescriptorTemplate::Wsh(Box::new(DescriptorTemplate::Sortedmulti(
                    threshold,
                    keys.clone(),
                ))),
                DescriptorTemplate::Sh(Box::new(DescriptorTemplate::Wsh(Box::new(
                    DescriptorTemplate::Multi(threshold, keys.clone()),
                )))),
                DescriptorTemplate::Sh(Box::new(DescriptorTemplate::Wsh(Box::new(
                    DescriptorTemplate::Sortedmulti(threshold, keys),
                )))),
            ]
            .into_iter(),
        )),
        DescriptorClass::Taproot {
            internal_key,
            leaves,
        } => {
            if leaves.is_empty() {
                return Ok(Box::new(core::iter::once(DescriptorTemplate::Tr(
                    internal_key,
                    None,
                ))));
            }
            let mut per_leaf_variants = Vec::new();
            for leaf in &leaves {
                per_leaf_variants.push(tapleaf_to_descriptors(leaf)?);
            }
            let trees = enumerate_taptrees(per_leaf_variants);
            Ok(Box::new(trees.map(move |t| {
                let mut dt = DescriptorTemplate::Tr(internal_key.clone(), Some(t));
                let mut next_per_key: alloc::collections::BTreeMap<super::KeyExpressionType, u32> =
                    alloc::collections::BTreeMap::new();
                for kp in dt.placeholders_mut() {
                    let next = next_per_key.entry(kp.key_type.clone()).or_insert(0);
                    kp.num1 = *next;
                    kp.num2 = *next + 1;
                    *next += 2;
                }
                dt
            })))
        }
        DescriptorClass::TaprootMusig {
            internal_key,
            leaves,
        } => {
            if leaves.is_empty() {
                return Ok(Box::new(core::iter::once(DescriptorTemplate::Tr(
                    internal_key,
                    None,
                ))));
            }
            let mut per_leaf_variants = Vec::new();
            for leaf in &leaves {
                per_leaf_variants.push(tapleaf_to_descriptors(leaf)?);
            }
            let trees = enumerate_taptrees(per_leaf_variants);
            Ok(Box::new(trees.map(move |t| {
                let mut dt = DescriptorTemplate::Tr(internal_key.clone(), Some(t));
                let mut next_per_key: alloc::collections::BTreeMap<super::KeyExpressionType, u32> =
                    alloc::collections::BTreeMap::new();
                for kp in dt.placeholders_mut() {
                    let next = next_per_key.entry(kp.key_type.clone()).or_insert(0);
                    kp.num1 = *next;
                    kp.num2 = *next + 1;
                    *next += 2;
                }
                dt
            })))
        }
        DescriptorClass::Other => Err(CleartextDecodeError::UnrecognizedPattern),
    }
}

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
            ("tr(@0/**,{pk(@1/**),pkh(@2/**)})", 1),
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
            "tr(@0/**,pkh(@1/**))",
            "tr(@0/**,{pk(@1/**),pkh(@2/**)})",
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
            // Taproot: single pkh leaf
            (
                "tr(@0/**,pkh(@1/**))",
                &["Primary path: @0", "Single-signature (@1)"],
                true,
            ),
            // Taproot: two SingleSig leaves (pk + pkh)
            (
                "tr(@0/**,{pk(@1/**),pkh(@2/**)})",
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
            "tr(@0/**,pkh(@1/**))",
            // Taproot: two leaves
            "tr(@0/**,{pk(@1/**),pkh(@2/**)})",
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

    /// Verify that `descriptor_match!` with musig() preserves the full `KeyExpression`
    /// (including derivation paths), and that `DescriptorClass::TaprootMusig` stores it
    /// as a single `internal_key` of type `Musig`.
    #[test]
    fn test_musig_classify_preserves_derivations() {
        use super::{DescriptorClass, KeyPlaceholder};
        use crate::bip388::KeyExpressionType;

        // musig internal key with non-standard derivation <2;3>
        let desc = dt("tr(musig(@0,@1)/<2;3>/*,pk(@2/**))");
        let class = desc.classify();
        match class {
            DescriptorClass::TaprootMusig {
                internal_key,
                leaves,
            } => {
                // The internal_key must be a single musig KeyExpression
                assert!(internal_key.is_musig());
                assert_eq!(
                    internal_key.key_type,
                    KeyExpressionType::Musig(alloc::vec![0, 1])
                );
                // Derivation paths must be preserved (not hardcoded to 0, 1)
                assert_eq!(internal_key.num1, 2);
                assert_eq!(internal_key.num2, 3);
                // Should have one leaf
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
                        // The individual key placeholders must carry the derivation from the
                        // musig expression
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

        // Standard derivation musig internal key (sanity check: num1=0, num2=1)
        let desc3 = dt("tr(musig(@0,@1)/**)");
        let class3 = desc3.classify();
        match class3 {
            DescriptorClass::TaprootMusig { internal_key, .. } => {
                assert_eq!(internal_key, KeyPlaceholder::musig(alloc::vec![0, 1], 0, 1));
            }
            other => panic!("expected TaprootMusig, got {:?}", other),
        }
    }
}
