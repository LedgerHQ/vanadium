//! Transaction-review UI: what the review shows ([`review_plan`], a pure function of the
//! [`Review`]), and the screens that show it ([`show_review`]).

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use common::errors::Error;

use sdk::ux::{Icon, TagValue};

use crate::{
    constants::{COIN_TICKER, THRESHOLD_WARN_HIGH_FEES_AMOUNT, THRESHOLD_WARN_HIGH_FEES_PERCENT},
    ux,
};

use super::analyze::{Review, ReviewedAccount};

/// A warning shown, and approved, before the transaction itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Warning {
    /// Some inputs have no non-witness UTXO, so their amounts can't be verified.
    UnverifiedInputs,
    /// The fee is `percent`% of what the inputs spend, at least
    /// [`THRESHOLD_WARN_HIGH_FEES_PERCENT`].
    HighFee { percent: u64 },
}

/// Everything the review of a transaction shows: the warnings, in the order they are shown,
/// then the pairs of the approval screen.
pub(super) struct ReviewPlan {
    pub(super) warnings: Vec<Warning>,
    pub(super) pairs: Vec<TagValue>,
}

/// What the review of `review` shows.
pub(super) fn review_plan(review: &Review) -> Result<ReviewPlan, Error> {
    let mut warnings = Vec::new();
    if review.warn_unverified_inputs {
        warnings.push(Warning::UnverifiedInputs);
    }
    if let Some(percent) = high_fee_percent(review) {
        warnings.push(Warning::HighFee { percent });
    }
    Ok(ReviewPlan {
        warnings,
        pairs: build_display_pairs(review)?,
    })
}

/// The fee as a whole percentage of what the inputs spend, if the user must be warned about it:
/// when the inputs spend at least [`THRESHOLD_WARN_HIGH_FEES_AMOUNT`] and the fee is at least
/// [`THRESHOLD_WARN_HIGH_FEES_PERCENT`] of it.
fn high_fee_percent(review: &Review) -> Option<u64> {
    if review.inputs_total_amount < THRESHOLD_WARN_HIGH_FEES_AMOUNT {
        return None;
    }
    // Both amounts are at most MAX_MONEY, so this doesn't overflow.
    let percent = review.fee() * 100 / review.inputs_total_amount;
    (percent >= THRESHOLD_WARN_HIGH_FEES_PERCENT).then_some(percent)
}

/// Shows `plan`: each warning, then the approval screen. Returns whether the user approved all
/// of them.
pub(super) async fn show_review(app: &mut sdk::App, plan: &ReviewPlan) -> bool {
    for warning in &plan.warnings {
        let approved = match warning {
            Warning::UnverifiedInputs => {
                ux::confirm(
                    app,
                    "Unverified inputs",
                    "Some inputs could not be verified.\nReject if you're not sure.",
                )
                .await
            }
            Warning::HighFee { percent } => {
                ux::confirm(
                    app,
                    "High fees",
                    &format!("Transaction fee fraction is higher than {}%", percent),
                )
                .await
            }
        };
        if !approved {
            return false;
        }
    }

    let button_text = if sdk::ux::has_page_api() {
        "Hold to sign"
    } else {
        "Confirm"
    };
    // "Transaction signed" is only shown once the transaction is.
    ux::review(
        app,
        ux::Review {
            intro: ux::intro("Review transaction", "to send Bitcoin"),
            pairs: &plan.pairs,
            final_text: "Sign transaction",
            button_text,
            long_press: true,
            approved: None,
            rejected: "Transaction rejected",
        },
    )
    .await
}

pub(super) fn show_transaction_signed(app: &mut sdk::App) {
    ux::info(app, Icon::Success, "Transaction signed");
}

const SATS_PER_BTC: u64 = 100_000_000;

fn format_amount(value: u64, ticker: &str) -> String {
    let whole_part = value / SATS_PER_BTC;
    let fractional_part = value % SATS_PER_BTC;
    // Pad fractional part with leading zeros to ensure 8 digits
    format!("{}.{:08} {}", whole_part, fractional_part, ticker)
}

/// The description of an account on the review screen.
fn account_description(account: &ReviewedAccount) -> String {
    match &account.name {
        Some(name) => format!("account: {}", name),
        None => "default account".to_string(),
    }
}

/// Build the `TagValue` pairs shown to the user during transaction review.
///
/// An account that no input or output uses isn't shown. An external output shows the address of
/// its destination: an output to a silent payment code shows the address of the code, as its
/// script, if the PSBT has one, is only checked against the code after the review.
pub(super) fn build_display_pairs(review: &Review) -> Result<Vec<TagValue>, Error> {
    let n_accounts = review.accounts.len();
    let n_external = review.external_outputs.len();

    let mut pairs: Vec<TagValue> = Vec::with_capacity(n_accounts * 2 + n_external * 2 + 1);

    let used_accounts = || review.accounts.iter().filter(|account| account.is_used);

    // Accounts we're spending from (they get back at most what they spend)
    for account in used_accounts().filter(|account| account.spent >= account.received) {
        pairs.push(TagValue {
            tag: "Spend from".into(),
            value: account_description(account),
        });
        let spent_amount = account.spent - account.received;
        pairs.push(TagValue {
            tag: "Amount".into(),
            value: if spent_amount > 0 {
                format_amount(spent_amount, COIN_TICKER)
            } else {
                "0 (self-transfer)".to_string()
            },
        });
    }

    // Accounts we're receiving to (they get back more than they spend)
    for account in used_accounts().filter(|account| account.received > account.spent) {
        pairs.push(TagValue {
            tag: "Send to".into(),
            value: account_description(account),
        });
        pairs.push(TagValue {
            tag: "Amount".into(),
            value: format_amount(account.received - account.spent, COIN_TICKER),
        });
    }

    // External outputs (show address, prefixed with identity key name if auth proof present)
    for external in &review.external_outputs {
        let address = external.destination.address()?;

        let address_value = if let Some(ref name) = external.auth_name {
            if sdk::ux::has_page_api() {
                // on large screens, go to a new line for the address
                format!("{}\n\n{}", name, address)
            } else {
                format!("{}:{}", name, address)
            }
        } else {
            address
        };

        pairs.push(TagValue {
            tag: format!("Output {}", external.output_index),
            value: address_value,
        });
        pairs.push(TagValue {
            tag: "Amount".into(),
            value: format_amount(external.amount, COIN_TICKER),
        });
    }

    // Fee
    pairs.push(TagValue {
        tag: "Fee".to_string(),
        value: format_amount(review.fee(), COIN_TICKER),
    });

    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::{fastpsbt, psbt::PsbtV2};

    use super::super::analyze::analyze_transaction;
    use super::super::test_utils::legacy_pkh_psbt;

    /// A review of a transaction whose inputs spend `inputs` sat, with a fee of `fee` sat.
    fn review_with_fee(inputs: u64, fee: u64, warn_unverified_inputs: bool) -> Review {
        Review {
            accounts: Vec::new(),
            external_outputs: Vec::new(),
            inputs_total_amount: inputs,
            outputs_total_amount: inputs - fee,
            warn_unverified_inputs,
        }
    }

    fn warnings(review: &Review) -> Vec<Warning> {
        review_plan(review).unwrap().warnings
    }

    #[test]
    fn no_warnings_for_an_ordinary_transaction() {
        assert_eq!(warnings(&review_with_fee(1_000_000, 1_000, false)), []);
    }

    /// The fee warning starts at exactly THRESHOLD_WARN_HIGH_FEES_PERCENT of the inputs, and shows
    /// the percentage rounded down.
    #[test]
    fn high_fee_warning_threshold_percent() {
        let inputs = 1_000_000;
        let at_threshold = inputs * THRESHOLD_WARN_HIGH_FEES_PERCENT / 100;
        assert_eq!(
            warnings(&review_with_fee(inputs, at_threshold - 1, false)),
            []
        );
        assert_eq!(
            warnings(&review_with_fee(inputs, at_threshold, false)),
            [Warning::HighFee {
                percent: THRESHOLD_WARN_HIGH_FEES_PERCENT
            }]
        );
        assert_eq!(
            warnings(&review_with_fee(inputs, inputs / 2 + 1, false)),
            [Warning::HighFee { percent: 50 }]
        );
        assert_eq!(
            warnings(&review_with_fee(inputs, inputs, false)),
            [Warning::HighFee { percent: 100 }]
        );
    }

    /// Below THRESHOLD_WARN_HIGH_FEES_AMOUNT of inputs, no fee is too high to warn about.
    #[test]
    fn high_fee_warning_threshold_amount() {
        let small = THRESHOLD_WARN_HIGH_FEES_AMOUNT - 1;
        assert_eq!(warnings(&review_with_fee(small, small, false)), []);
        assert_eq!(
            warnings(&review_with_fee(
                THRESHOLD_WARN_HIGH_FEES_AMOUNT,
                THRESHOLD_WARN_HIGH_FEES_AMOUNT,
                false
            )),
            [Warning::HighFee { percent: 100 }]
        );
    }

    /// The fee computation can't overflow, even with the largest amounts the analysis accepts.
    #[test]
    fn high_fee_warning_at_max_money() {
        let max = bitcoin::Amount::MAX_MONEY.to_sat();
        assert_eq!(
            warnings(&review_with_fee(max, max, false)),
            [Warning::HighFee { percent: 100 }]
        );
    }

    /// The warning about unverified inputs comes before the one about the fee.
    #[test]
    fn warnings_are_in_order() {
        assert_eq!(
            warnings(&review_with_fee(1_000_000, 1_000, true)),
            [Warning::UnverifiedInputs]
        );
        assert_eq!(
            warnings(&review_with_fee(1_000_000, 500_000, true)),
            [Warning::UnverifiedInputs, Warning::HighFee { percent: 50 }]
        );
    }

    /// The pairs of the plan are the pairs of the approval screen.
    #[test]
    fn plan_pairs_are_the_display_pairs() {
        let review = review(&legacy_pkh_psbt());
        let plan = review_plan(&review).unwrap();
        let pairs = build_display_pairs(&review).unwrap();
        assert_eq!(plan.pairs.len(), pairs.len());
        for (a, b) in plan.pairs.iter().zip(&pairs) {
            assert_eq!((&a.tag, &a.value), (&b.tag, &b.value));
        }
        assert_eq!(plan.warnings, []);
    }

    /// The review of `psbt`, serialized the way the handler receives it.
    fn review(psbt: &PsbtV2) -> Review {
        let serialized = psbt.serialize();
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        analyze_transaction(&parsed).unwrap().review
    }

    #[test]
    fn format_amount_pads_the_fractional_part() {
        assert_eq!(format_amount(0, "TEST"), "0.00000000 TEST");
        assert_eq!(format_amount(1, "TEST"), "0.00000001 TEST");
        assert_eq!(format_amount(200, "TEST"), "0.00000200 TEST");
        assert_eq!(format_amount(SATS_PER_BTC, "TEST"), "1.00000000 TEST");
        assert_eq!(format_amount(123_456_789, "TEST"), "1.23456789 TEST");
    }

    /// Every amount on the review screen must be denominated in whole coins — the fee
    /// included. It used to be rendered as a raw satoshi count under the same ticker.
    #[test]
    fn fee_is_shown_in_whole_coins() {
        let review = review(&legacy_pkh_psbt());

        assert_eq!(review.fee(), 200);

        let pairs = build_display_pairs(&review).unwrap();
        let fee = pairs.iter().find(|p| p.tag == "Fee").expect("no Fee pair");
        assert_eq!(fee.value, "0.00000200 TEST");
    }

    /// The spent amount and the external output are formatted the same way, so the
    /// screen reads consistently top to bottom.
    #[test]
    fn spend_and_output_amounts_are_shown_in_whole_coins() {
        let pairs = build_display_pairs(&review(&legacy_pkh_psbt())).unwrap();
        let tags: Vec<&str> = pairs.iter().map(|p| p.tag.as_str()).collect();
        assert_eq!(tags, ["Spend from", "Amount", "Output 0", "Amount", "Fee"]);

        assert_eq!(pairs[0].value, "account: My legacy account #0");
        assert_eq!(pairs[1].value, "0.01000000 TEST"); // 1_000_000 sat in
        assert_eq!(pairs[3].value, "0.00999800 TEST"); // 999_800 sat out
    }

    /// An account that the PSBT declares, but that no input or output uses, is not shown: it
    /// used to be shown as a self-transfer.
    #[test]
    fn unused_accounts_are_not_shown() {
        use common::{
            bip388::WalletPolicy,
            por::{ProofOfRegistration, Registerable},
            psbt::{PsbtAccount, PsbtAccountGlobalWrite},
        };

        let mut psbt = legacy_pkh_psbt();
        let unused = WalletPolicy::new(
            "wpkh(@0/**)",
            vec!["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()],
        )
        .unwrap();
        let por = ProofOfRegistration::new(&unused.registration_id("Unused")).dangerous_as_bytes();
        psbt.set_account(1, PsbtAccount::from(&unused)).unwrap();
        psbt.set_account_name(1, "Unused").unwrap();
        psbt.set_account_proof_of_registration(1, &por).unwrap();

        let review = review(&psbt);
        assert_eq!(review.accounts.len(), 2);
        assert!(!review.accounts[1].is_used);

        let pairs = build_display_pairs(&review).unwrap();
        let tags: Vec<&str> = pairs.iter().map(|p| p.tag.as_str()).collect();
        assert_eq!(tags, ["Spend from", "Amount", "Output 0", "Amount", "Fee"]);
        assert_eq!(pairs[0].value, "account: My legacy account #0");
    }
}
