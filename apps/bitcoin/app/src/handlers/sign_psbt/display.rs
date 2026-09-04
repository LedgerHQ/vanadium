//! Transaction-review UI: warning dialogs, the main approval screen, and the
//! `TagValue` pairs shown on it.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use common::{errors::Error, fastpsbt};

use bitcoin::{Address, ScriptBuf};
use sdk::ux::{Icon, TagValue};

use crate::constants::COIN_TICKER;

use super::analyze::{TransactionSummary, TrustSource};

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

/// Formats a UNIX timestamp as a `YYYY-MM-DD` date, in UTC.
///
/// Used to show the user which date a DNSSEC proof was validated against. Days are converted with
/// Howard Hinnant's `civil_from_days`, which avoids pulling in a date library for one screen.
fn format_unix_date(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    // Shift the epoch to 0000-03-01, so that leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], with March as 0
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
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

        let label = summary.external_output_auth_names[i].as_ref();
        let address_value = if let Some(label) = label {
            let name = label.display_name();
            if sdk::ux::has_page_api() {
                // on large screens, go to a new line for the address
                format!("{}\n\n{}", name, address)
            } else {
                format!("{}:{}", name, address)
            }
        } else {
            format!("{}", address)
        };

        // State the provenance in the tag as well as in the name. The tag is plain ASCII, so it
        // renders on every device, and it keeps the two trust sources distinguishable in a
        // transaction that mixes them.
        let tag = match label.map(|l| l.source) {
            Some(TrustSource::Dnssec) => format!("Output {} (DNS)", output_index),
            _ => format!("Output {}", output_index),
        };

        pairs.push(TagValue {
            tag,
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
        value: format_amount(fee, COIN_TICKER),
    });

    // The device has no clock, so the date the DNS proofs were checked against was supplied by the
    // host. Show it: a host replaying a long-expired proof is otherwise undetectable.
    if let Some(now) = summary.dnssec_validation_time {
        pairs.push(TagValue {
            tag: "DNS checked on".to_string(),
            value: format!("{} (per host)", format_unix_date(now)),
        });
    }

    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::analyze::analyze_transaction;
    use super::super::test_utils::{legacy_pkh_psbt, serialize_as_psbtv2};

    #[test]
    fn format_amount_pads_the_fractional_part() {
        assert_eq!(format_amount(0, "TEST"), "0.00000000 TEST");
        assert_eq!(format_amount(1, "TEST"), "0.00000001 TEST");
        assert_eq!(format_amount(200, "TEST"), "0.00000200 TEST");
        assert_eq!(format_amount(SATS_PER_BTC, "TEST"), "1.00000000 TEST");
        assert_eq!(format_amount(123_456_789, "TEST"), "1.23456789 TEST");
    }

    #[test]
    fn format_unix_date_handles_leap_years() {
        assert_eq!(format_unix_date(0), "1970-01-01");
        assert_eq!(format_unix_date(86_399), "1970-01-01");
        assert_eq!(format_unix_date(86_400), "1970-01-02");
        // 2000-02-29: a leap year divisible by 400.
        assert_eq!(format_unix_date(951_782_400), "2000-02-29");
        // 2100-03-01: the day after 2100-02-28, which is not a leap year.
        assert_eq!(format_unix_date(4_107_542_400), "2100-03-01");
        assert_eq!(format_unix_date(1_754_000_000), "2025-07-31");
    }

    /// Every amount on the review screen must be denominated in whole coins — the fee
    /// included. It used to be rendered as a raw satoshi count under the same ticker.
    #[test]
    fn fee_is_shown_in_whole_coins() {
        let psbt = legacy_pkh_psbt();
        let serialized = serialize_as_psbtv2(&psbt);
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        let (summary, _) = analyze_transaction(&parsed, None).unwrap();

        assert_eq!(summary.fee(), 200);

        let pairs = build_display_pairs(&parsed, &summary).unwrap();
        let fee = pairs.iter().find(|p| p.tag == "Fee").expect("no Fee pair");
        assert_eq!(fee.value, "0.00000200 TEST");
    }

    /// The spent amount and the external output are formatted the same way, so the
    /// screen reads consistently top to bottom.
    #[test]
    fn spend_and_output_amounts_are_shown_in_whole_coins() {
        let psbt = legacy_pkh_psbt();
        let serialized = serialize_as_psbtv2(&psbt);
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        let (summary, _) = analyze_transaction(&parsed, None).unwrap();

        let pairs = build_display_pairs(&parsed, &summary).unwrap();
        let tags: Vec<&str> = pairs.iter().map(|p| p.tag.as_str()).collect();
        assert_eq!(tags, ["Spend from", "Amount", "Output 0", "Amount", "Fee"]);

        assert_eq!(pairs[0].value, "account: My legacy account #0");
        assert_eq!(pairs[1].value, "0.01000000 TEST"); // 1_000_000 sat in
        assert_eq!(pairs[3].value, "0.00999800 TEST"); // 999_800 sat out
    }
}
