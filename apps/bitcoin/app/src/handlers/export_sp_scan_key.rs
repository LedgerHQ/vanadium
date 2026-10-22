use common::{errors::Error, message::Response};

use crate::sp_keys;

const AUTO_APPROVE: bool = cfg!(any(test, feature = "autoapprove"));

async fn display_export(app: &mut sdk::App, account_index: u32) -> bool {
    if AUTO_APPROVE {
        return true;
    }

    use alloc::{string::ToString, vec};
    use sdk::ux::{Icon, TagValue};

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Export silent\npayment scan key", "")
    } else {
        ("Export silent", "payment scan key")
    };

    let pairs = vec![
        TagValue {
            tag: "Account index".into(),
            value: account_index.to_string(),
        },
        TagValue {
            tag: "Privacy".into(),
            value: "The scan key reveals every payment to this account. It cannot spend them."
                .into(),
        },
    ];

    let approved = app
        .review_pairs(
            intro_text,
            intro_subtext,
            &pairs,
            "Export the scan key",
            "Export",
            false,
        )
        .await;
    app.show_info(
        if approved {
            Icon::Success
        } else {
            Icon::Failure
        },
        if approved {
            "Scan key exported"
        } else {
            "Export rejected"
        },
    );
    approved
}

/// Returns the BIP-392 `tspscan` key of the silent payment account `account_index`: its scan
/// private key and its spend public key, which is what a wallet needs to find its payments, and to
/// register the account.
pub async fn handle_export_sp_scan_key(
    app: &mut sdk::App,
    account_index: u32,
) -> Result<Response, Error> {
    app.show_spinner("Processing...");

    let account = sp_keys::account(account_index)?;

    if !display_export(app, account_index).await {
        return Err(Error::UserRejected);
    }

    Ok(Response::SilentPaymentScanKey {
        scan_key: account.to_spscan(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::account::SilentPaymentAccount;

    #[test]
    fn test_export_sp_scan_key() {
        let response =
            sdk::executor::block_on(handle_export_sp_scan_key(&mut sdk::App::singleton(), 5))
                .unwrap();
        let Response::SilentPaymentScanKey { scan_key } = response else {
            panic!("unexpected response: {response:?}");
        };
        assert_eq!(
            SilentPaymentAccount::from_spscan(5, &scan_key).unwrap(),
            sp_keys::account(5).unwrap()
        );

        assert_eq!(
            sdk::executor::block_on(handle_export_sp_scan_key(
                &mut sdk::App::singleton(),
                0x8000_0000
            )),
            Err(Error::InvalidParameter)
        );
    }
}
