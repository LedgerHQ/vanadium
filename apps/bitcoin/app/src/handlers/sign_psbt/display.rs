//! Transaction-review UI: warning dialogs, the main approval screen, and the
//! `TagValue` pairs shown on it.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use common::errors::Error;

use sdk::ux::{Icon, TagValue};

use crate::constants::COIN_TICKER;

use super::analyze::{Review, ReviewedAccount};

const AUTO_APPROVE: bool = cfg!(any(test, feature = "autoapprove"));

pub(super) async fn display_warning_high_fee(app: &mut sdk::App, fee_percent: u64) -> bool {
    if AUTO_APPROVE {
        return true;
    }
    app.show_confirm_reject(
        "High fees",
        &format!("Transaction fee fraction is higher than {}%", fee_percent),
        "Continue",
        "Reject",
    )
    .await
}

pub(super) async fn display_warning_unverified_inputs(app: &mut sdk::App) -> bool {
    if AUTO_APPROVE {
        return true;
    }
    app.show_confirm_reject(
        "Unverified inputs",
        "Some inputs could not be verified.\nReject if you're not sure.",
        "Continue",
        "Reject",
    )
    .await
}

pub(super) async fn display_transaction(app: &mut sdk::App, pairs: &[TagValue]) -> bool {
    if AUTO_APPROVE {
        return true;
    }

    // message on speculos or real device

    let button_text = if sdk::ux::has_page_api() {
        "Hold to sign"
    } else {
        "Confirm"
    };

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Review transaction\nto send Bitcoin", "")
    } else {
        ("Review transaction", "to send Bitcoin")
    };
    app.review_pairs(
        intro_text,
        intro_subtext,
        pairs,
        "Sign transaction",
        button_text,
        true,
    )
    .await
}

pub(super) fn show_transaction_rejected(app: &mut sdk::App) {
    if AUTO_APPROVE {
        return;
    }
    app.show_info(Icon::Failure, "Transaction rejected");
}

pub(super) fn show_transaction_signed(app: &mut sdk::App) {
    if AUTO_APPROVE {
        return;
    }
    app.show_info(Icon::Success, "Transaction signed");
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
