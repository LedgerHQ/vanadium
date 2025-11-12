use common::{
    account::{Account, ProofOfRegistration},
    bip388,
    message::Response,
};

use common::errors::Error;

#[cfg(not(any(test, feature = "autoapprove")))]
fn display_wallet_policy(
    app: &mut sdk::App,
    name: &str,
    wallet_policy: &bip388::WalletPolicy,
) -> bool {
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
    app.review_pairs(
        intro_text,
        intro_subtext,
        &pairs,
        "Confirm registration",
        "Register",
        false,
    )
}

#[cfg(any(test, feature = "autoapprove"))]
fn display_wallet_policy(
    _app: &mut sdk::App,
    _name: &str,
    _wallet_policy: &bip388::WalletPolicy,
) -> bool {
    true
}

pub fn handle_register_account(
    app: &mut sdk::App,
    name: &str,
    account: &common::message::Account,
) -> Result<Response, Error> {
    let wallet_policy: bip388::WalletPolicy =
        account.try_into().map_err(|_| Error::InvalidWalletPolicy)?;

    // TODO: necessary sanity checks on the wallet policy

    if !display_wallet_policy(app, name, &wallet_policy) {
        return Err(Error::UserRejected);
    }

    let id = wallet_policy.get_id(name);
    let por = ProofOfRegistration::new(&id);

    Ok(Response::AccountRegistered {
        account_id: id,
        hmac: por.dangerous_as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        account::{KeyInformation, ProofOfRegistration},
        bip388,
        message::{self, Response},
    };

    fn ki(key_info_str: &str) -> message::PubkeyInfo {
        let info = KeyInformation::try_from(key_info_str).unwrap();

        let origin = info.origin_info.map(|info| message::KeyOrigin {
            fingerprint: info.fingerprint,
            path: message::Bip32Path(
                info.derivation_path
                    .iter()
                    .map(|step| u32::from(*step))
                    .collect(),
            ),
        });

        message::PubkeyInfo {
            pubkey: info.pubkey.encode().to_vec(),
            origin,
        }
    }

    #[test]
    fn test_register_account() {
        let account_name = "My Test Account";
        let account = message::Account::WalletPolicy(message::WalletPolicy {
            template: "wpkh(@0/**)".into(),
            keys_info: vec![ki(
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
            )],
        });

        let wallet_policy: bip388::WalletPolicy = (&account).try_into().unwrap();
        let expected_account_id = wallet_policy.get_id(account_name);

        let resp = handle_register_account(&mut sdk::App::singleton(), account_name, &account);

        assert_eq!(
            resp,
            Ok(Response::AccountRegistered {
                account_id: expected_account_id,
                // can't really test the hmac here, so we duplicate the app's logic
                hmac: ProofOfRegistration::new(&expected_account_id).dangerous_as_bytes(),
            })
        );
    }
}
