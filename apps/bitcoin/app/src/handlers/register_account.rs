use common::{account::Account, bip388, message::Response};

#[cfg(not(test))]
fn display_wallet_policy(name: &str, wallet_policy: &bip388::WalletPolicy) -> bool {
    use alloc::{format, string::ToString, vec::Vec};
    use sdk::ux::TagValue;

    let mut pairs = Vec::with_capacity(2 + wallet_policy.key_information.len());

    pairs.push(TagValue {
        tag: "Account".into(),
        value: name.into(),
    });
    pairs.push(TagValue {
        tag: "Descriptor template".into(),
        value: wallet_policy.descriptor_template_raw().to_string(),
    });

    for (i, key_info) in wallet_policy.key_information.iter().enumerate() {
        pairs.push(TagValue {
            tag: format!("Key #{}", i),
            value: key_info.to_string(),
        });
    }

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Register Bitcoin\naccount", "")
    } else {
        ("Register Bitcoin", "account")
    };
    sdk::ux::review_pairs(
        intro_text,
        intro_subtext,
        &pairs,
        "Confirm registration",
        "Register",
        false,
    )
}

#[cfg(test)]
fn display_wallet_policy(_name: &str, _wallet_policy: &bip388::WalletPolicy) -> bool {
    true
}

pub fn handle_register_account(
    _app: &mut sdk::App,
    name: &str,
    account: &common::message::Account,
) -> Result<Response, &'static str> {
    let wallet_policy: bip388::WalletPolicy = account.try_into()?;

    // TODO: necessary sanity checks on the wallet policy

    if !display_wallet_policy(name, &wallet_policy) {
        return Err("Rejected by the user");
    }

    // TODO: compute the correct HMAC

    Ok(Response::AccountRegistered {
        account_id: wallet_policy.get_id(name),
        hmac: [42u8; 32], // TODO
    })
}
