use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use macros::descriptor_match;

use super::time::{format_seconds, format_utc_date};
use super::DescriptorTemplate;

#[cfg(any(test, feature = "cleartext-decode"))]
use super::time::{parse_relative_time_to_seconds, parse_utc_date_to_timestamp};
#[cfg(any(test, feature = "cleartext-decode"))]
use super::{KeyPlaceholder, TapTree};
#[cfg(any(test, feature = "cleartext-decode"))]
use alloc::rc::Rc;
#[cfg(any(test, feature = "cleartext-decode"))]
use core::str::FromStr;

// Maximum confusion score for which cleartext descriptions are shown instead of the raw descriptor template.
pub const MAX_CONFUSION_SCORE: u64 = 3600;

const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Error type for `from_cleartext`.
#[derive(Debug)]
pub enum CleartextError {
    /// The cleartext string could not be parsed.
    ParseError(String),
}

// Private intermediate representations used to centralise the single match over
// DescriptorTemplate variants. Both `confusion_score` and `to_cleartext` match
// on these types, so their case coverage is structurally identical and
// compiler-enforced.
enum DescriptorClass {
    LegacySingleSig {
        key_index: u32,
    },
    SegwitSingleSig {
        key_index: u32,
    },
    SegwitMultisig {
        threshold: u32,
        key_indices: Vec<u32>,
    },
    Taproot {
        internal_key_index: u32,
        leaves: Vec<TapleafClass>,
    },
    Other,
}

enum TapleafClass {
    // non-miniscript patterns
    SortedMultisig {
        // sortedmulti_a
        threshold: u32,
        key_indices: Vec<u32>,
    },
    // miniscript patterns
    SingleSig {
        // pk and pkh
        key_index: u32,
    },
    BothMustSign {
        key_index1: u32,
        key_index2: u32,
    },
    Multisig {
        // multi_a
        threshold: u32,
        key_indices: Vec<u32>,
    },
    RelativeHeightlockSingleSig {
        // and_v(v:pk(@x), older(n)), with n >= 1 && n < 65536
        key_index: u32,
        blocks: u32,
    },
    RelativeHeightlockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), older(n)), with n >= 1 && n < 65536
        threshold: u32,
        key_indices: Vec<u32>,
        blocks: u32,
    },
    RelativeTimelockSingleSig {
        // and_v(v:pk(@x), older(n)) with n >= 4194305 && n < 4259840
        key_index: u32,
        time: u32,
    },
    RelativeTimelockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), older(n)) with n >= 4194305 && n < 4259840
        threshold: u32,
        key_indices: Vec<u32>,
        time: u32,
    },
    AbsoluteHeightlockSingleSig {
        // and_v(v:pk(@x), after(n)) with n < 500000000
        key_index: u32,
        block_height: u32,
    },
    AbsoluteHeightlockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), after(n)) with n < 500000000
        threshold: u32,
        key_indices: Vec<u32>,
        block_height: u32,
    },
    AbsoluteTimelockSingleSig {
        // and_v(v:pk(@x), after(n)) with n >= 500000000
        key_index: u32,
        timestamp: u32,
    },
    AbsoluteTimelockMultiSig {
        // and_v(v:multi_a(threshold, key_indices...), after(n)) with n >= 500000000
        threshold: u32,
        key_indices: Vec<u32>,
        timestamp: u32,
    },
    Other(String),
}

impl TapleafClass {
    /// Returns a numeric key that defines the canonical visualization order for
    /// taptree leaves:
    ///   - simpler conditions come first
    ///   - relative before absolute
    ///   - heightlocks before timelocks
    ///   - `Other` is last
    fn order(&self) -> u32 {
        match self {
            TapleafClass::SingleSig { .. } => 0,
            TapleafClass::BothMustSign { .. } => 1,
            TapleafClass::SortedMultisig { .. } => 2,
            TapleafClass::Multisig { .. } => 3,
            TapleafClass::RelativeHeightlockSingleSig { .. } => 4,
            TapleafClass::RelativeHeightlockMultiSig { .. } => 5,
            TapleafClass::RelativeTimelockSingleSig { .. } => 6,
            TapleafClass::RelativeTimelockMultiSig { .. } => 7,
            TapleafClass::AbsoluteHeightlockSingleSig { .. } => 8,
            TapleafClass::AbsoluteHeightlockMultiSig { .. } => 9,
            TapleafClass::AbsoluteTimelockSingleSig { .. } => 10,
            TapleafClass::AbsoluteTimelockMultiSig { .. } => 11,
            TapleafClass::Other(_) => 12,
        }
    }

    /// Full canonical display order. Within each category, ties are broken by:
    /// - `SingleSig`: key_index
    /// - `BothMustSign`: key_index1, then key_index2
    /// - `SortedMultisig` / `Multisig`: number of keys, then threshold
    /// - `*SingleSig` lock variants: key_index, then lock value
    /// - `*MultiSig` lock variants: number of keys, then threshold, then lock value
    /// - `Other`: lexicographic by descriptor string
    fn display_cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        let cat = self.order().cmp(&other.order());
        if cat != Ordering::Equal {
            return cat;
        }
        match (self, other) {
            (
                TapleafClass::SingleSig { key_index: k1 },
                TapleafClass::SingleSig { key_index: k2 },
            ) => k1.cmp(k2),
            (
                TapleafClass::BothMustSign {
                    key_index1: a1,
                    key_index2: b1,
                },
                TapleafClass::BothMustSign {
                    key_index1: a2,
                    key_index2: b2,
                },
            ) => a1.cmp(a2).then(b1.cmp(b2)),
            (
                TapleafClass::SortedMultisig {
                    threshold: t1,
                    key_indices: k1,
                },
                TapleafClass::SortedMultisig {
                    threshold: t2,
                    key_indices: k2,
                },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)),
            (
                TapleafClass::Multisig {
                    threshold: t1,
                    key_indices: k1,
                },
                TapleafClass::Multisig {
                    threshold: t2,
                    key_indices: k2,
                },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)),
            (
                TapleafClass::RelativeHeightlockSingleSig {
                    key_index: k1,
                    blocks: b1,
                },
                TapleafClass::RelativeHeightlockSingleSig {
                    key_index: k2,
                    blocks: b2,
                },
            ) => k1.cmp(k2).then(b1.cmp(b2)),
            (
                TapleafClass::RelativeHeightlockMultiSig {
                    threshold: t1,
                    key_indices: k1,
                    blocks: b1,
                },
                TapleafClass::RelativeHeightlockMultiSig {
                    threshold: t2,
                    key_indices: k2,
                    blocks: b2,
                },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(b1.cmp(b2)),
            (
                TapleafClass::RelativeTimelockSingleSig {
                    key_index: k1,
                    time: t1,
                },
                TapleafClass::RelativeTimelockSingleSig {
                    key_index: k2,
                    time: t2,
                },
            ) => k1.cmp(k2).then(t1.cmp(t2)),
            (
                TapleafClass::RelativeTimelockMultiSig {
                    threshold: t1,
                    key_indices: k1,
                    time: tm1,
                },
                TapleafClass::RelativeTimelockMultiSig {
                    threshold: t2,
                    key_indices: k2,
                    time: tm2,
                },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(tm1.cmp(tm2)),
            (
                TapleafClass::AbsoluteHeightlockSingleSig {
                    key_index: k1,
                    block_height: h1,
                },
                TapleafClass::AbsoluteHeightlockSingleSig {
                    key_index: k2,
                    block_height: h2,
                },
            ) => k1.cmp(k2).then(h1.cmp(h2)),
            (
                TapleafClass::AbsoluteHeightlockMultiSig {
                    threshold: t1,
                    key_indices: k1,
                    block_height: h1,
                },
                TapleafClass::AbsoluteHeightlockMultiSig {
                    threshold: t2,
                    key_indices: k2,
                    block_height: h2,
                },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(h1.cmp(h2)),
            (
                TapleafClass::AbsoluteTimelockSingleSig {
                    key_index: k1,
                    timestamp: ts1,
                },
                TapleafClass::AbsoluteTimelockSingleSig {
                    key_index: k2,
                    timestamp: ts2,
                },
            ) => k1.cmp(k2).then(ts1.cmp(ts2)),
            (
                TapleafClass::AbsoluteTimelockMultiSig {
                    threshold: t1,
                    key_indices: k1,
                    timestamp: ts1,
                },
                TapleafClass::AbsoluteTimelockMultiSig {
                    threshold: t2,
                    key_indices: k2,
                    timestamp: ts2,
                },
            ) => k1.len().cmp(&k2.len()).then(t1.cmp(t2)).then(ts1.cmp(ts2)),
            (TapleafClass::Other(s1), TapleafClass::Other(s2)) => s1.cmp(s2),
            // Same order() value implies same variant; this arm is unreachable.
            _ => Ordering::Equal,
        }
    }
}

impl DescriptorTemplate {
    fn classify(&self) -> DescriptorClass {
        descriptor_match!(self, {
            pkh(key_index) => {
                DescriptorClass::LegacySingleSig { key_index }
            },
            // normal or wrapped
            wpkh(key_index) | sh(wpkh(key_index)) => {
                DescriptorClass::SegwitSingleSig { key_index }
            },
            // 4 combinations: multi/sortedmulti; normal/wrapped
            wsh(multi(threshold, key_indices)) | wsh(sortedmulti(threshold, key_indices)) | sh(wsh(multi(threshold, key_indices))) | sh(wsh(sortedmulti(threshold, key_indices))) => {
                DescriptorClass::SegwitMultisig { threshold, key_indices }
            },
            tr(internal_key, tree) => {
                DescriptorClass::Taproot {
                    internal_key_index: internal_key.key_index,
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
            sortedmulti_a(threshold, key_indices) => {
                TapleafClass::SortedMultisig { threshold, key_indices }
            },
            pk(key_index) | pkh(key_index) => {
                TapleafClass::SingleSig { key_index }
            },
            multi_a(threshold, key_indices) => {
                TapleafClass::Multisig { threshold, key_indices }
            },
            and_v(v:pk(key_index), older(blocks)) if blocks >= 1 && blocks < 65536 => {
                TapleafClass::RelativeHeightlockSingleSig { key_index, blocks }
            },
            and_v(v:multi_a(threshold, key_indices), older(blocks)) if blocks >= 1 && blocks < 65536 => {
                TapleafClass::RelativeHeightlockMultiSig { threshold, key_indices, blocks }
            },
            and_v(v:pk(key_index), older(time)) if time >= 4194305 && time < 4259840 => {
                TapleafClass::RelativeTimelockSingleSig { key_index, time }
            },
            and_v(v:multi_a(threshold, key_indices), older(time)) if time >= 4194305 && time < 4259840 => {
                TapleafClass::RelativeTimelockMultiSig { threshold, key_indices, time }
            },
            and_v(v:pk(key_index), after(block_height)) if block_height >= 1 && block_height < 500000000 => {
                TapleafClass::AbsoluteHeightlockSingleSig { key_index, block_height }
            },
            and_v(v:multi_a(threshold, key_indices), after(block_height)) if block_height >= 1 && block_height < 500000000 => {
                TapleafClass::AbsoluteHeightlockMultiSig { threshold, key_indices, block_height }
            },
            and_v(v:pk(key_index), after(timestamp)) if timestamp >= 500000000 => {
                TapleafClass::AbsoluteTimelockSingleSig { key_index, timestamp }
            },
            and_v(v:multi_a(threshold, key_indices), after(timestamp)) if timestamp >= 500000000 => {
                TapleafClass::AbsoluteTimelockMultiSig { threshold, key_indices, timestamp }
            },
            and_v(v:pk(key_index1), pk(key_index2)) => {
                TapleafClass::BothMustSign { key_index1, key_index2 }
            },
            _ => { TapleafClass::Other(self.to_string()) },
        })
    }
}

fn format_key_indices(key_indices: &[u32]) -> String {
    match key_indices {
        [] => String::new(),
        [single] => format!("@{}", single),
        [init @ .., last] => {
            let parts: Vec<String> = init.iter().map(|i| format!("@{}", i)).collect();
            format!("{} and @{}", parts.join(", "), last)
        }
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
    ) -> Result<Box<dyn Iterator<Item = Self>>, CleartextError>
    where
        Self: Sized;
}

impl ClearText for DescriptorTemplate {
    fn confusion_score(&self) -> u64 {
        match self.classify() {
            DescriptorClass::LegacySingleSig { .. } => 1,
            DescriptorClass::SegwitSingleSig { .. } => 2, // wpkh and sh(wpkh)
            DescriptorClass::SegwitMultisig { .. } => 4,  // multi or sortdmulti / normal or wrapped
            DescriptorClass::Taproot { leaves, .. } => {
                // The confusion score of a taproot descriptor is the product of the confusion scores of the internal key and all the leaves,
                // multiplied by the number T(n) of rearrangements of the tree.
                let mut score = 1u64;
                let n_leaves = leaves.len();
                for leaf in &leaves {
                    let leaf_score = match leaf {
                        TapleafClass::SingleSig { .. } => 2,
                        TapleafClass::SortedMultisig { .. } => 1,
                        TapleafClass::Multisig { .. } => 1,
                        TapleafClass::BothMustSign { .. } => 1,
                        TapleafClass::RelativeHeightlockSingleSig { .. } => 1,
                        TapleafClass::RelativeHeightlockMultiSig { .. } => 1,
                        TapleafClass::RelativeTimelockSingleSig { .. } => 1,
                        TapleafClass::RelativeTimelockMultiSig { .. } => 1,
                        TapleafClass::AbsoluteHeightlockSingleSig { .. } => 1,
                        TapleafClass::AbsoluteHeightlockMultiSig { .. } => 1,
                        TapleafClass::AbsoluteTimelockSingleSig { .. } => 1,
                        TapleafClass::AbsoluteTimelockMultiSig { .. } => 1,
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
        }
    }

    fn to_cleartext(&self) -> (Vec<String>, bool) {
        match self.classify() {
            DescriptorClass::LegacySingleSig { key_index } => (
                vec![format!("Legacy single-signature (@{})", key_index)],
                true,
            ),
            DescriptorClass::SegwitSingleSig { key_index } => (
                vec![format!("Segwit single-signature (@{})", key_index)],
                true,
            ),
            DescriptorClass::SegwitMultisig {
                threshold,
                key_indices,
            } => (
                vec![format!(
                    "{} of {} (SegWit)",
                    threshold,
                    format_key_indices(&key_indices)
                )],
                true,
            ),
            DescriptorClass::Taproot {
                internal_key_index,
                mut leaves,
            } => {
                leaves.sort_by(|a, b| a.display_cmp(b));
                let mut descriptions = vec![format!("Primary path: @{}", internal_key_index)];
                let mut all_leaves_have_cleartext = true;
                for leaf in leaves {
                    let (leaf_descriptions, leaf_has_cleartext) = match leaf {
                        TapleafClass::SingleSig { key_index } => {
                            (vec![format!("Single-signature (@{})", key_index)], true)
                        }
                        TapleafClass::SortedMultisig {
                            threshold,
                            key_indices,
                        } => (
                            vec![format!(
                                "{} of {} (sorted)",
                                threshold,
                                format_key_indices(&key_indices)
                            )],
                            true,
                        ),
                        TapleafClass::BothMustSign {
                            key_index1,
                            key_index2,
                        } => (
                            vec![format!(
                                "Both @{} and @{} must sign",
                                key_index1, key_index2
                            )],
                            true,
                        ),
                        TapleafClass::Multisig {
                            threshold,
                            key_indices,
                        } => (
                            vec![format!(
                                "{} of {}",
                                threshold,
                                format_key_indices(&key_indices)
                            )],
                            true,
                        ),
                        TapleafClass::RelativeHeightlockSingleSig { key_index, blocks } => (
                            vec![format!("@{} after {} blocks", key_index, blocks)],
                            true,
                        ),
                        TapleafClass::RelativeHeightlockMultiSig {
                            threshold,
                            key_indices,
                            blocks,
                        } => (
                            vec![format!(
                                "{} of {} after {} blocks",
                                threshold,
                                format_key_indices(&key_indices),
                                blocks
                            )],
                            true,
                        ),
                        TapleafClass::RelativeTimelockSingleSig { key_index, time } => (
                            vec![format!(
                                "@{} after {}",
                                key_index,
                                format_seconds((time & !SEQUENCE_LOCKTIME_TYPE_FLAG) * 512)
                            )],
                            true,
                        ),
                        TapleafClass::RelativeTimelockMultiSig {
                            threshold,
                            key_indices,
                            time,
                        } => (
                            vec![format!(
                                "{} of {} after {}",
                                threshold,
                                format_key_indices(&key_indices),
                                format_seconds((time & !SEQUENCE_LOCKTIME_TYPE_FLAG) * 512)
                            )],
                            true,
                        ),

                        TapleafClass::AbsoluteHeightlockSingleSig {
                            key_index,
                            block_height,
                        } => (
                            vec![format!(
                                "@{} after block height {}",
                                key_index, block_height
                            )],
                            true,
                        ),
                        TapleafClass::AbsoluteHeightlockMultiSig {
                            threshold,
                            key_indices,
                            block_height,
                        } => (
                            vec![format!(
                                "{} of {} after block height {}",
                                threshold,
                                format_key_indices(&key_indices),
                                block_height
                            )],
                            true,
                        ),
                        TapleafClass::AbsoluteTimelockSingleSig {
                            key_index,
                            timestamp,
                        } => (
                            vec![format!(
                                "@{} after date {}",
                                key_index,
                                format_utc_date(timestamp)
                            )],
                            true,
                        ),
                        TapleafClass::AbsoluteTimelockMultiSig {
                            threshold,
                            key_indices,
                            timestamp,
                        } => (
                            vec![format!(
                                "{} of {} after date {}",
                                threshold,
                                format_key_indices(&key_indices),
                                format_utc_date(timestamp)
                            )],
                            true,
                        ),
                        TapleafClass::Other(s) => (vec![s], false),
                    };
                    descriptions.extend(leaf_descriptions);
                    all_leaves_have_cleartext &= leaf_has_cleartext;
                }
                (descriptions, all_leaves_have_cleartext)
            }
            DescriptorClass::Other => (vec![self.to_string()], false),
        }
    }

    #[cfg(any(test, feature = "cleartext-decode"))]
    fn from_cleartext(
        descriptions: &[&str],
    ) -> Result<Box<dyn Iterator<Item = Self>>, CleartextError> {
        let class = parse_top_level(descriptions)?;
        top_level_variants(class)
    }
}

// ---------------------------------------------------------------------------
// from_cleartext helpers (feature-gated)
// ---------------------------------------------------------------------------
#[cfg(any(test, feature = "cleartext-decode"))]
fn kp(key_index: u32) -> KeyPlaceholder {
    KeyPlaceholder {
        key_index,
        num1: 0,
        num2: 1,
    }
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_key_index(s: &str) -> Option<u32> {
    s.strip_prefix('@')?.parse().ok()
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_key_indices(s: &str) -> Option<Vec<u32>> {
    // Formats: "@A", "@A and @B", "@A, @B and @C", "@A, @B, @C and @D", ...
    if let Some((init, last)) = s.rsplit_once(" and ") {
        let last_idx = parse_key_index(last.trim())?;
        let mut indices: Vec<u32> = Vec::new();
        for part in init.split(", ") {
            indices.push(parse_key_index(part.trim())?);
        }
        indices.push(last_idx);
        Some(indices)
    } else {
        // Single key: "@A"
        Some(vec![parse_key_index(s.trim())?])
    }
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_leaf_description(s: &str) -> Result<TapleafClass, CleartextError> {
    let err = || CleartextError::ParseError(format!("unrecognized leaf: {:?}", s));

    // "Single-signature (@N)"
    if let Some(rest) = s.strip_prefix("Single-signature (") {
        let key_str = rest.strip_suffix(')').ok_or_else(err)?;
        let key_index = parse_key_index(key_str).ok_or_else(err)?;
        return Ok(TapleafClass::SingleSig { key_index });
    }

    // "Both @A and @B must sign"
    if let Some(rest) = s.strip_prefix("Both ") {
        let rest = rest.strip_suffix(" must sign").ok_or_else(err)?;
        let (a, b) = rest.split_once(" and ").ok_or_else(err)?;
        let key_index1 = parse_key_index(a.trim()).ok_or_else(err)?;
        let key_index2 = parse_key_index(b.trim()).ok_or_else(err)?;
        return Ok(TapleafClass::BothMustSign {
            key_index1,
            key_index2,
        });
    }

    // Patterns starting with "@N after ..."
    if s.starts_with('@') {
        if let Some((key_part, after_part)) = s.split_once(" after ") {
            let key_index = parse_key_index(key_part).ok_or_else(err)?;
            return parse_single_sig_lock(key_index, after_part).ok_or_else(err);
        }
    }

    // Patterns starting with "K of ..."
    if let Some(of_pos) = s.find(" of ") {
        let threshold: u32 = s[..of_pos].parse().map_err(|_| err())?;
        let rest = &s[of_pos + 4..];

        // "K of key_list (sorted)"
        if let Some(keys_str) = rest.strip_suffix(" (sorted)") {
            let key_indices = parse_key_indices(keys_str).ok_or_else(err)?;
            return Ok(TapleafClass::SortedMultisig {
                threshold,
                key_indices,
            });
        }

        // "K of key_list after ..."
        if let Some(after_pos) = rest.find(" after ") {
            let keys_str = &rest[..after_pos];
            let after_part = &rest[after_pos + 7..];
            let key_indices = parse_key_indices(keys_str).ok_or_else(err)?;
            return parse_multi_sig_lock(threshold, key_indices, after_part).ok_or_else(err);
        }

        // "K of key_list" (plain multisig)
        let key_indices = parse_key_indices(rest).ok_or_else(err)?;
        return Ok(TapleafClass::Multisig {
            threshold,
            key_indices,
        });
    }

    // Unrecognized → Other (parse as raw descriptor)
    Ok(TapleafClass::Other(s.to_string()))
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_single_sig_lock(key_index: u32, after_part: &str) -> Option<TapleafClass> {
    // "@N after M blocks"
    if let Some(blocks_str) = after_part.strip_suffix(" blocks") {
        let blocks: u32 = blocks_str.parse().ok()?;
        return Some(TapleafClass::RelativeHeightlockSingleSig { key_index, blocks });
    }
    // "@N after block height H"
    if let Some(h_str) = after_part.strip_prefix("block height ") {
        let block_height: u32 = h_str.parse().ok()?;
        return Some(TapleafClass::AbsoluteHeightlockSingleSig {
            key_index,
            block_height,
        });
    }
    // "@N after date D"
    if let Some(d_str) = after_part.strip_prefix("date ") {
        let timestamp = parse_utc_date_to_timestamp(d_str)?;
        return Some(TapleafClass::AbsoluteTimelockSingleSig {
            key_index,
            timestamp,
        });
    }
    // "@N after <duration>" (relative timelock)
    let secs = parse_relative_time_to_seconds(after_part)?;
    let time = secs / 512 | SEQUENCE_LOCKTIME_TYPE_FLAG;
    Some(TapleafClass::RelativeTimelockSingleSig { key_index, time })
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_multi_sig_lock(
    threshold: u32,
    key_indices: Vec<u32>,
    after_part: &str,
) -> Option<TapleafClass> {
    // "... after M blocks"
    if let Some(blocks_str) = after_part.strip_suffix(" blocks") {
        let blocks: u32 = blocks_str.parse().ok()?;
        return Some(TapleafClass::RelativeHeightlockMultiSig {
            threshold,
            key_indices,
            blocks,
        });
    }
    // "... after block height H"
    if let Some(h_str) = after_part.strip_prefix("block height ") {
        let block_height: u32 = h_str.parse().ok()?;
        return Some(TapleafClass::AbsoluteHeightlockMultiSig {
            threshold,
            key_indices,
            block_height,
        });
    }
    // "... after date D"
    if let Some(d_str) = after_part.strip_prefix("date ") {
        let timestamp = parse_utc_date_to_timestamp(d_str)?;
        return Some(TapleafClass::AbsoluteTimelockMultiSig {
            threshold,
            key_indices,
            timestamp,
        });
    }
    // "... after <duration>" (relative timelock)
    let secs = parse_relative_time_to_seconds(after_part)?;
    let time = secs / 512 | SEQUENCE_LOCKTIME_TYPE_FLAG;
    Some(TapleafClass::RelativeTimelockMultiSig {
        threshold,
        key_indices,
        time,
    })
}

#[cfg(any(test, feature = "cleartext-decode"))]
fn parse_top_level(descriptions: &[&str]) -> Result<DescriptorClass, CleartextError> {
    let err = || CleartextError::ParseError("unrecognized cleartext".into());
    match descriptions {
        [] => Err(CleartextError::ParseError("empty descriptions".into())),
        [single] => {
            // "Legacy single-signature (@N)"
            if let Some(rest) = single.strip_prefix("Legacy single-signature (") {
                let key_str = rest.strip_suffix(')').ok_or_else(err)?;
                let key_index = parse_key_index(key_str).ok_or_else(err)?;
                return Ok(DescriptorClass::LegacySingleSig { key_index });
            }
            // "Segwit single-signature (@N)"
            if let Some(rest) = single.strip_prefix("Segwit single-signature (") {
                let key_str = rest.strip_suffix(')').ok_or_else(err)?;
                let key_index = parse_key_index(key_str).ok_or_else(err)?;
                return Ok(DescriptorClass::SegwitSingleSig { key_index });
            }
            // "K of key_list (SegWit)"
            if single.ends_with(" (SegWit)") {
                let core_str = single.strip_suffix(" (SegWit)").unwrap();
                if let Some(of_pos) = core_str.find(" of ") {
                    let threshold: u32 = core_str[..of_pos].parse().map_err(|_| err())?;
                    let key_indices = parse_key_indices(&core_str[of_pos + 4..]).ok_or_else(err)?;
                    return Ok(DescriptorClass::SegwitMultisig {
                        threshold,
                        key_indices,
                    });
                }
            }
            // "Primary path: @N" (taproot with no leaves)
            if let Some(key_str) = single.strip_prefix("Primary path: ") {
                let internal_key_index = parse_key_index(key_str).ok_or_else(err)?;
                return Ok(DescriptorClass::Taproot {
                    internal_key_index,
                    leaves: Vec::new(),
                });
            }
            // Unrecognized single description → Other
            Ok(DescriptorClass::Other)
        }
        [first, rest @ ..] => {
            // "Primary path: @N" + leaf descriptions
            if let Some(key_str) = first.strip_prefix("Primary path: ") {
                let internal_key_index = parse_key_index(key_str).ok_or_else(err)?;
                let mut leaves = Vec::new();
                for &leaf_str in rest {
                    leaves.push(parse_leaf_description(leaf_str)?);
                }
                return Ok(DescriptorClass::Taproot {
                    internal_key_index,
                    leaves,
                });
            }
            Err(err())
        }
    }
}

// ---------------------------------------------------------------------------
// Variant generators
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "cleartext-decode"))]
fn tapleaf_to_descriptors(leaf: &TapleafClass) -> Result<Vec<DescriptorTemplate>, CleartextError> {
    let kps = |indices: &[u32]| -> Vec<KeyPlaceholder> { indices.iter().map(|&i| kp(i)).collect() };
    match leaf {
        TapleafClass::SingleSig { key_index } => {
            let k = kp(*key_index);
            Ok(vec![DescriptorTemplate::Pk(k), DescriptorTemplate::Pkh(k)])
        }
        TapleafClass::BothMustSign {
            key_index1,
            key_index2,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(kp(
                *key_index1,
            ))))),
            Box::new(DescriptorTemplate::Pk(kp(*key_index2))),
        )]),
        TapleafClass::SortedMultisig {
            threshold,
            key_indices,
        } => Ok(vec![DescriptorTemplate::Sortedmulti_a(
            *threshold,
            kps(key_indices),
        )]),
        TapleafClass::Multisig {
            threshold,
            key_indices,
        } => Ok(vec![DescriptorTemplate::Multi_a(
            *threshold,
            kps(key_indices),
        )]),
        TapleafClass::RelativeHeightlockSingleSig { key_index, blocks } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(kp(
                    *key_index,
                ))))),
                Box::new(DescriptorTemplate::Older(*blocks)),
            )])
        }
        TapleafClass::RelativeHeightlockMultiSig {
            threshold,
            key_indices,
            blocks,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(
                DescriptorTemplate::Multi_a(*threshold, kps(key_indices)),
            ))),
            Box::new(DescriptorTemplate::Older(*blocks)),
        )]),
        TapleafClass::RelativeTimelockSingleSig { key_index, time } => {
            Ok(vec![DescriptorTemplate::And_v(
                Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(kp(
                    *key_index,
                ))))),
                Box::new(DescriptorTemplate::Older(*time)),
            )])
        }
        TapleafClass::RelativeTimelockMultiSig {
            threshold,
            key_indices,
            time,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(
                DescriptorTemplate::Multi_a(*threshold, kps(key_indices)),
            ))),
            Box::new(DescriptorTemplate::Older(*time)),
        )]),
        TapleafClass::AbsoluteHeightlockSingleSig {
            key_index,
            block_height,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(kp(
                *key_index,
            ))))),
            Box::new(DescriptorTemplate::After(*block_height)),
        )]),
        TapleafClass::AbsoluteHeightlockMultiSig {
            threshold,
            key_indices,
            block_height,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(
                DescriptorTemplate::Multi_a(*threshold, kps(key_indices)),
            ))),
            Box::new(DescriptorTemplate::After(*block_height)),
        )]),
        TapleafClass::AbsoluteTimelockSingleSig {
            key_index,
            timestamp,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(DescriptorTemplate::Pk(kp(
                *key_index,
            ))))),
            Box::new(DescriptorTemplate::After(*timestamp)),
        )]),
        TapleafClass::AbsoluteTimelockMultiSig {
            threshold,
            key_indices,
            timestamp,
        } => Ok(vec![DescriptorTemplate::And_v(
            Box::new(DescriptorTemplate::V(Box::new(
                DescriptorTemplate::Multi_a(*threshold, kps(key_indices)),
            ))),
            Box::new(DescriptorTemplate::After(*timestamp)),
        )]),
        TapleafClass::Other(s) => {
            let dt = DescriptorTemplate::from_str(s)
                .map_err(|e| CleartextError::ParseError(format!("{:?}", e)))?;
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
) -> Result<Box<dyn Iterator<Item = DescriptorTemplate>>, CleartextError> {
    let kps = |indices: &[u32]| -> Vec<KeyPlaceholder> { indices.iter().map(|&i| kp(i)).collect() };
    match class {
        DescriptorClass::LegacySingleSig { key_index } => Ok(Box::new(core::iter::once(
            DescriptorTemplate::Pkh(kp(key_index)),
        ))),
        DescriptorClass::SegwitSingleSig { key_index } => {
            let k = kp(key_index);
            Ok(Box::new(
                vec![
                    DescriptorTemplate::Wpkh(k),
                    DescriptorTemplate::Sh(Box::new(DescriptorTemplate::Wpkh(k))),
                ]
                .into_iter(),
            ))
        }
        DescriptorClass::SegwitMultisig {
            threshold,
            key_indices,
        } => {
            let keys = kps(&key_indices);
            Ok(Box::new(
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
            ))
        }
        DescriptorClass::Taproot {
            internal_key_index,
            leaves,
        } => {
            let ik = kp(internal_key_index);
            if leaves.is_empty() {
                return Ok(Box::new(core::iter::once(DescriptorTemplate::Tr(ik, None))));
            }
            let mut per_leaf_variants = Vec::new();
            for leaf in &leaves {
                per_leaf_variants.push(tapleaf_to_descriptors(leaf)?);
            }
            let trees = enumerate_taptrees(per_leaf_variants);
            Ok(Box::new(
                trees.map(move |t| DescriptorTemplate::Tr(ik, Some(t))),
            ))
        }
        DescriptorClass::Other => Err(CleartextError::ParseError(
            "cannot enumerate variants for unrecognized descriptor class".into(),
        )),
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
        //
        // Note: tr with 0 or 1 leaves is not tested here because the confusion-score
        // formula contains a `usize` subtraction (`2 * n_leaves - 3`) that overflows
        // for n_leaves < 2 and panics in debug builds.
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
            // Taproot with 2 leaves: both SingleSig (score 2 each), T(2)=1 → 2×2×1=4
            ("tr(@0/**,{pk(@1/**),pkh(@2/**)})", 4),
            // Taproot with 2 leaves: SortedMultisig (score 1) + SingleSig (score 2), T(2)=1 → 1×2×1=2
            ("tr(@0/**,{sortedmulti_a(2,@1/**,@2/**),pk(@3/**)})", 2),
            // Taproot with 3 leaves: 3×SingleSig (2×2×2=8), T(3)=3 → 8×3=24
            ("tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})", 24),
            // Taproot with 2 leaves: RelativeHeightlockSingleSig (score 1) + SingleSig (score 2), T(2)=1 → 2
            (
                "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(52560))})",
                2,
            ),
            // Taproot with 2 leaves: RelativeTimelockSingleSig (score 1) + SingleSig (score 2), T(2)=1 → 2
            (
                "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(4194305))})",
                2,
            ),
            // Taproot with 2 leaves: RelativeTimelockMultiSig (score 1) + SingleSig (score 2), T(2)=1 → 2
            (
                "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),older(4194484))})",
                2,
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
            "tr(@0/<0;1>/*,{and_v(v:pk(@1/<2;3>/*),older(4383)),and_v(v:pk(@2/<0;1>/*),pk(@1/<0;1>/*))})",
            "tr(@0/<0;1>/*,{and_v(v:multi_a(2,@1/<2;3>/*,@2/<0;1>/*,@3/<0;1>/*),older(144)),and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*))})",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),older(4194305)))",
            "tr(@0/**,{pk(@1/**),and_v(v:pk(@2/<0;1>/*),older(4194484))})",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),older(4194484))})",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(840000)))",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(840000))})",
            "tr(@0/**,and_v(v:pk(@1/<0;1>/*),after(500000000)))",
            "tr(@0/**,{pk(@1/**),and_v(v:multi_a(2,@2/<0;1>/*,@3/<0;1>/*),after(1700000000))})",
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
            // Taproot: BothMustSign
            "tr(@0/<0;1>/*,{and_v(v:pk(@1/<2;3>/*),older(4383)),and_v(v:pk(@2/<0;1>/*),pk(@1/<0;1>/*))})",
            "tr(@0/<0;1>/*,{and_v(v:multi_a(2,@1/<2;3>/*,@2/<0;1>/*,@3/<0;1>/*),older(144)),and_v(v:pk(@1/<0;1>/*),pk(@2/<0;1>/*))})",
        ];

        for &desc_str in cases {
            let original = dt(desc_str);
            let (cleartext, has_cleartext) = original.to_cleartext();
            if !has_cleartext {
                continue;
            }
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
}
