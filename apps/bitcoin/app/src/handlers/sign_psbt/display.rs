//! Transaction-review UI: warning dialogs, the main approval screen, and the
//! `TagValue` pairs shown on it.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use common::{errors::Error, fastpsbt};

use bitcoin::{Address, ScriptBuf};
use sdk::ux::TagValue;

use crate::constants::COIN_TICKER;

use super::analyze::TransactionSummary;

#[cfg(not(any(test, feature = "autoapprove")))]
pub(super) async fn display_warning_high_fee(app: &mut sdk::App, fee_percent: u64) -> bool {
    app.show_confirm_reject(
        "High fees",
        &format!("Transaction fee fraction is higher than {}%", fee_percent),
        "Continue",
        "Reject",
    )
    .await
}

#[cfg(any(test, feature = "autoapprove"))]
pub(super) async fn display_warning_high_fee(_app: &mut sdk::App, _fee_percent: u64) -> bool {
    true
}

#[cfg(not(any(test, feature = "autoapprove")))]
pub(super) async fn display_warning_unverified_inputs(app: &mut sdk::App) -> bool {
    app.show_confirm_reject(
        "Unverified inputs",
        "Some inputs could not be verified.\nReject if you're not sure.",
        "Continue",
        "Reject",
    )
    .await
}

#[cfg(any(test, feature = "autoapprove"))]
pub(super) async fn display_warning_unverified_inputs(_app: &mut sdk::App) -> bool {
    true
}

#[cfg(not(any(test, feature = "autoapprove")))]
pub(super) async fn display_transaction(app: &mut sdk::App, pairs: &[TagValue]) -> bool {
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

#[cfg(any(test, feature = "autoapprove"))]
pub(super) async fn display_transaction(_app: &mut sdk::App, _pairs: &[TagValue]) -> bool {
    true
}

const SATS_PER_BTC: u64 = 100_000_000;

fn format_amount(value: u64, ticker: &str) -> String {
    let whole_part = value / SATS_PER_BTC;
    let fractional_part = value % SATS_PER_BTC;
    // Pad fractional part with leading zeros to ensure 8 digits
    format!("{}.{:08} {}", whole_part, fractional_part, ticker)
}

/// Build the `TagValue` pairs shown to the user during transaction review.
pub(super) fn build_display_pairs(
    psbt: &fastpsbt::Psbt,
    summary: &TransactionSummary,
) -> Result<Vec<TagValue>, Error> {
    let fee = summary.fee();
    let n_accounts = summary.accounts.len();
    let n_external = summary.external_outputs_indexes.len();

    let mut pairs: Vec<TagValue> = Vec::with_capacity(n_accounts * 2 + n_external * 2 + 1);

    // Accounts we're spending from (non-negative spent amount)
    for (account_id, spent_amount) in summary.account_spent_amounts.iter().enumerate() {
        let account_description = match &summary.account_names[account_id] {
            Some(name) => format!("account: {}", name),
            None => "default account".to_string(),
        };
        if *spent_amount >= 0 {
            pairs.push(TagValue {
                tag: "Spend from".into(),
                value: account_description,
            });
            if *spent_amount > 0 {
                pairs.push(TagValue {
                    tag: "Amount".into(),
                    value: format_amount(*spent_amount as u64, COIN_TICKER),
                });
            } else {
                pairs.push(TagValue {
                    tag: "Amount".into(),
                    value: "0 (self-transfer)".to_string(),
                });
            }
        }
    }

    // Accounts we're receiving to (negative spent amount)
    for (account_id, spent_amount) in summary.account_spent_amounts.iter().enumerate() {
        let account_description = match &summary.account_names[account_id] {
            Some(name) => format!("account: {}", name),
            None => "default account".to_string(),
        };
        if *spent_amount < 0 {
            pairs.push(TagValue {
                tag: "Send to".into(),
                value: account_description,
            });
            pairs.push(TagValue {
                tag: "Amount".into(),
                value: format_amount(-*spent_amount as u64, COIN_TICKER),
            });
        }
    }

    // External outputs (show address, prefixed with identity key name if auth proof present)
    for (i, &output_index) in summary.external_outputs_indexes.iter().enumerate() {
        let output = &psbt.outputs[output_index];
        let out_script_pubkey = output.script.ok_or(Error::OutputScriptMissing)?;
        let out_script_pubkey = ScriptBuf::from_bytes(out_script_pubkey.to_vec());
        let amount = output.amount.ok_or(Error::OutputAmountMissing)?;
        let address = Address::from_script(&out_script_pubkey, bitcoin::Network::Testnet)
            .map_err(|_| Error::AddressFromScriptFailed)?;

        let address_value = if let Some(ref name) = summary.external_output_auth_names[i] {
            if sdk::ux::has_page_api() {
                // on large screens, go to a new line for the address
                format!("{}\n\n{}", name, address)
            } else {
                format!("{}:{}", name, address)
            }
        } else {
            format!("{}", address)
        };

        pairs.push(TagValue {
            tag: format!("Output {}", output_index),
            value: address_value,
        });
        pairs.push(TagValue {
            tag: "Amount".into(),
            value: format_amount(amount, COIN_TICKER),
        });
    }

    // Fee
    pairs.push(TagValue {
        tag: "Fee".to_string(),
        value: format!("{} {}", fee, COIN_TICKER),
    });

    Ok(pairs)
}
