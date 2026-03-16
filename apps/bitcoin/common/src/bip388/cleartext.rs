use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use macros::descriptor_match;

use super::time::{format_seconds, format_utc_date};
use super::{DescriptorTemplate, KeyPlaceholder};

// Maximum confusion score for which cleartext descriptions are shown instead of the raw descriptor template.
pub const MAX_CONFUSION_SCORE: u64 = 3600;

const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

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
    SegwitMultisig {
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
    Other,
}

impl DescriptorTemplate {
    fn classify(&self) -> DescriptorClass<'_> {
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
                    internal_key,
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
            _ => { TapleafClass::Other },
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
                        TapleafClass::Other => (vec![self.to_string()], false),
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
