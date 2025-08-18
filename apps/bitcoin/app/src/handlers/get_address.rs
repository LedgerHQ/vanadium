use common::{
    account::{Account, ProofOfRegistration},
    bip388,
    message::Response,
};

use common::errors::Error;

#[cfg(not(test))]
fn display_address(account_name: Option<&str>, addr: &str) -> bool {
    use alloc::vec;
    use sdk::ux::TagValue;

    let mut pairs = match account_name {
        Some(account_name) => {
            vec![TagValue {
                tag: "Account".into(),
                value: account_name.into(),
            }]
        }
        None => {
            vec![]
        }
    };
    pairs.push(TagValue {
        tag: "Address".into(),
        value: addr.into(),
    });
    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Verify Bitcoin\naddress", "")
    } else {
        ("Verify Bitcoin", "address")
    };
    sdk::ux::review_pairs(
        intro_text,
        intro_subtext,
        &pairs,
        "The address is correct",
        "Confirm",
        false,
    )
}

#[cfg(test)]
fn display_address(_account_name: Option<&str>, _addr: &str) -> bool {
    true
}

pub fn handle_get_address(
    _app: &mut sdk::App,
    name: Option<&str>,
    account: &common::message::Account,
    por: &[u8],
    coordinates: &common::message::AccountCoordinates,
    display: bool,
) -> Result<Response, Error> {
    let wallet_policy: bip388::WalletPolicy =
        account.try_into().map_err(|_| Error::InvalidWalletPolicy)?;

    // hmac should be empty or a 32 byte vector; if not, give an error, otherwise convert to Option<[u8; 32]>
    let hmac: Option<&[u8; 32]> = match por.len() {
        0 => None,
        32 => Some(por.try_into().unwrap()),
        _ => return Err(Error::InvalidProofOfRegistrationLength),
    };

    let hmac = hmac.ok_or(Error::DefaultAccountsNotSupported)?;

    let id = wallet_policy.get_id(name.unwrap_or(""));
    let por = common::account::ProofOfRegistration::from_bytes(*hmac);
    if por != ProofOfRegistration::new(&id) {
        return Err(Error::InvalidProofOfRegistration);
    }

    let common::message::AccountCoordinates::WalletPolicy(coordinates) = coordinates;
    let address = wallet_policy
        .get_address(&common::account::WalletPolicyCoordinates {
            is_change: coordinates.is_change,
            address_index: coordinates.address_index,
        })
        .map_err(|_| Error::InvalidWalletPolicy)?;

    if display {
        if !display_address(name, &address) {
            return Err(Error::UserRejected);
        }
    }

    Ok(Response::Address(address))
}

#[cfg(test)]
mod tests {
    use common::{account::KeyInformation, message};

    use super::*;

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
    fn test_get_address_singlesig_wit() {
        let account = message::Account::WalletPolicy(message::WalletPolicy {
            template: "wpkh(@0/**)".into(),
            keys_info: vec![ki(
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
            )],
        });

        // default wallet accounts are not supported yet, so we simulate registration
        let account_name = "Segwit account";
        let wallet_policy: bip388::WalletPolicy = (&account).try_into().unwrap();
        let hmac =
            ProofOfRegistration::new(&wallet_policy.get_id(account_name)).dangerous_as_bytes();

        let resp = handle_get_address(
            &mut sdk::App::singleton(),
            Some(account_name),
            &account,
            &hmac,
            &message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                is_change: false,
                address_index: 0,
            }),
            false,
        )
        .unwrap();

        assert_eq!(
            resp,
            Response::Address("tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk".into())
        );
    }
}
