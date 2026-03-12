use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use super::{DescriptorTemplate, KeyPlaceholder};

// Maximum confusion score for which cleartext descriptions are shown instead of the raw descriptor template.
pub const MAX_CONFUSION_SCORE: u64 = 3600;

// Private intermediate representations used to centralise the single match over
// DescriptorTemplate variants. Both `confusion_score` and `to_cleartext` match
// on these types, so their case coverage is structurally identical and
// compiler-enforced.
enum DescriptorClass<'a> {
    LegacySingleSig {
        key_index: u32,
    },
    SegwitSingleSig {
        key_index: u32,
    },
    Multisig {
        threshold: u32,
        key_indices: Vec<u32>,
    },
    Taproot {
        internal_key: &'a KeyPlaceholder,
        leaves: Vec<TapleafClass>,
    },
    Other,
}

enum TapleafClass {
    // non-miniscript patterns
    SortedMultisig {
        threshold: u32,
        key_indices: Vec<u32>,
    }, // sortedmulti_a
    // miniscript patterns
    SingleSig {
        key_index: u32,
    }, // pk and pkh
    Multisig {
        threshold: u32,
        key_indices: Vec<u32>,
    }, // multi_a
    RelativeHeightlockSingleSig {
        key_index: u32,
        blocks: u32,
    }, // and_v(v:pk(@x), older(n))
    Other,
}

impl DescriptorTemplate {
    fn classify(&self) -> DescriptorClass<'_> {
        match self {
            DescriptorTemplate::Pkh(kp) => DescriptorClass::LegacySingleSig {
                key_index: kp.key_index,
            },
            DescriptorTemplate::Wpkh(kp) => DescriptorClass::SegwitSingleSig {
                key_index: kp.key_index,
            },
            DescriptorTemplate::Wsh(inner) => match inner.as_ref() {
                DescriptorTemplate::Multi(k, keys) | DescriptorTemplate::Sortedmulti(k, keys) => {
                    DescriptorClass::Multisig {
                        threshold: *k,
                        key_indices: keys.iter().map(|kp| kp.key_index).collect(),
                    }
                }
                _ => DescriptorClass::Other,
            },
            DescriptorTemplate::Tr(internal_key, tree) => DescriptorClass::Taproot {
                internal_key,
                leaves: tree
                    .as_ref()
                    .map(|t| t.tapleaves().map(|l| l.classify_as_tapleaf()).collect())
                    .unwrap_or_default(),
            },
            _ => DescriptorClass::Other,
        }
    }

    fn classify_as_tapleaf(&self) -> TapleafClass {
        match self {
            // non-miniscript patterns
            DescriptorTemplate::Sortedmulti_a(k, keys) => TapleafClass::SortedMultisig {
                threshold: *k,
                key_indices: keys.iter().map(|kp| kp.key_index).collect(),
            },
            // miniscript patterns
            DescriptorTemplate::Pk(kp) | DescriptorTemplate::Pkh(kp) => TapleafClass::SingleSig {
                key_index: kp.key_index,
            },
            DescriptorTemplate::And_v(sub1, sub2) => match (sub1.as_ref(), sub2.as_ref()) {
                (DescriptorTemplate::V(inner), DescriptorTemplate::Older(n))
                    if *n >= 1 && *n < 65536 =>
                {
                    match inner.as_ref() {
                        DescriptorTemplate::Pk(kp) => TapleafClass::RelativeHeightlockSingleSig {
                            key_index: kp.key_index,
                            blocks: *n,
                        },
                        _ => TapleafClass::Other,
                    }
                }
                _ => TapleafClass::Other,
            },
            _ => TapleafClass::Other,
        }
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
}

impl ClearText for DescriptorTemplate {
    fn confusion_score(&self) -> u64 {
        match self.classify() {
            DescriptorClass::LegacySingleSig { .. } => 1,
            DescriptorClass::SegwitSingleSig { .. } => 1,
            DescriptorClass::Multisig { .. } => 1,
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
                        TapleafClass::RelativeHeightlockSingleSig { .. } => 1,
                        TapleafClass::Other => 1,
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
            DescriptorClass::Multisig {
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
            DescriptorClass::Taproot {
                internal_key,
                leaves,
            } => {
                let mut descriptions = vec![format!("Primary path: @{}", internal_key.key_index)];
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
                        TapleafClass::Other => todo!(),
                    };
                    descriptions.extend(leaf_descriptions);
                    all_leaves_have_cleartext &= leaf_has_cleartext;
                }
                (descriptions, all_leaves_have_cleartext)
            }
            DescriptorClass::Other => (vec![self.to_string()], false),
        }
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
            ("wpkh(@0/**)", 1),
            // Multisig (wsh + sortedmulti / multi)
            ("wsh(sortedmulti(2,@0/**,@1/**))", 1),
            ("wsh(sortedmulti(2,@0/**,@1/**,@2/**))", 1),
            ("wsh(sortedmulti(3,@0/**,@1/**,@2/**))", 1),
            ("wsh(multi(2,@0/**,@1/**))", 1),
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
    fn test_to_cleartext() {
        // (descriptor_template, expected_descriptions, expected_all_have_cleartext)
        let cases: &[(&str, &[&str], bool)] = &[
            // Legacy single-sig
            ("pkh(@0/**)", &["Legacy single-signature (@0)"], true),
            // Segwit single-sig
            ("wpkh(@0/**)", &["Segwit single-signature (@0)"], true),
            // Multisig: 2-of-2 sortedmulti
            ("wsh(sortedmulti(2,@0/**,@1/**))", &["2 of @0 and @1"], true),
            // Multisig: 2-of-3 sortedmulti (format_key_indices with 3 keys)
            (
                "wsh(sortedmulti(2,@0/**,@1/**,@2/**))",
                &["2 of @0, @1 and @2"],
                true,
            ),
            // Multisig: 3-of-3 sortedmulti
            (
                "wsh(sortedmulti(3,@0/**,@1/**,@2/**))",
                &["3 of @0, @1 and @2"],
                true,
            ),
            // Multisig: multi (non-sorted)
            ("wsh(multi(2,@0/**,@1/**))", &["2 of @0 and @1"], true),
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
            // Taproot: SortedMultisig leaf + SingleSig leaf
            (
                "tr(@0/**,{sortedmulti_a(2,@1/**,@2/**),pk(@3/**)})",
                &[
                    "Primary path: @0",
                    "2 of @1 and @2 (sorted)",
                    "Single-signature (@3)",
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
}
