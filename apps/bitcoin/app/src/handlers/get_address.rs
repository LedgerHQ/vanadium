use common::{
    account::{Account, SilentPaymentCoordinates},
    errors::Error,
    identity,
    message::{self, Response},
    por::{ProofOfRegistration, Registerable},
    script::ToScript,
};

use crate::identity::compute_identity_signature;

const AUTO_APPROVE: bool = cfg!(any(test, feature = "autoapprove"));

async fn display_address(
    app: &mut sdk::App,
    account_name: Option<&str>,
    label: Option<u32>,
    addr: &str,
) -> bool {
    if AUTO_APPROVE {
        return true;
    }

    use alloc::{string::ToString, vec};
    use sdk::ux::{Icon, TagValue};

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
    if let Some(label) = label {
        pairs.push(TagValue {
            tag: "Label".into(),
            value: label.to_string(),
        });
    }
    pairs.push(TagValue {
        tag: "Address".into(),
        value: addr.into(),
    });
    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Verify Bitcoin\naddress", "")
    } else {
        ("Verify Bitcoin", "address")
    };
    let approved = app
        .review_pairs(
            intro_text,
            intro_subtext,
            &pairs,
            "The address is correct",
            "Confirm",
            false,
        )
        .await;

    if approved {
        app.show_info(Icon::Success, "Address verified");
    } else {
        app.show_info(Icon::Failure, "Address rejected");
    }

    approved
}

/// Checks that `por` is the proof of registration of `account` with the name `name`.
fn check_proof_of_registration<T: Account>(
    account: &T,
    name: Option<&str>,
    por: &[u8],
) -> Result<(), Error> {
    // hmac should be empty or a 32 byte vector; if not, give an error, otherwise convert to Option<[u8; 32]>
    let hmac: Option<&[u8; 32]> = match por.len() {
        0 => None,
        32 => Some(por.try_into().unwrap()),
        _ => return Err(Error::InvalidProofOfRegistrationLength),
    };

    let hmac = hmac.ok_or(Error::DefaultAccountsNotSupported)?;

    let id = account.registration_id(name.unwrap_or(""));
    if ProofOfRegistration::<T>::from_bytes(*hmac) != ProofOfRegistration::new(&id) {
        return Err(Error::InvalidProofOfRegistration);
    }
    Ok(())
}

pub async fn handle_get_address(
    app: &mut sdk::App,
    name: Option<&str>,
    account: &message::Account,
    por: &[u8],
    coordinates: &message::AccountCoordinates,
    display: bool,
    identity_index: Option<u32>,
) -> Result<Response, Error> {
    app.show_spinner("Processing...");

    let (address, label, identity_sig) = match (account, coordinates) {
        (
            message::Account::WalletPolicy(wallet_policy),
            message::AccountCoordinates::WalletPolicy(coordinates),
        ) => {
            check_proof_of_registration(wallet_policy, name, por)?;
            let address = wallet_policy
                .get_address(coordinates)
                .map_err(|_| Error::InvalidWalletPolicy)?;

            let identity_sig = match identity_index {
                Some(i) => {
                    // Derive the scriptPubKey to sign over
                    let script = wallet_policy
                        .to_script(coordinates.is_change, coordinates.address_index)
                        .map_err(|_| Error::InvalidWalletPolicy)?;
                    Some(compute_identity_signature(
                        identity::MSG_TYPE_OUTPUT,
                        script.as_bytes(),
                        i,
                    )?)
                }
                None => None,
            };
            (address, None, identity_sig)
        }
        (
            message::Account::SilentPayment(account),
            message::AccountCoordinates::SilentPayment(coordinates),
        ) => {
            // an address to hand out is a code, and identity signatures are over scripts
            let SilentPaymentCoordinates::Code { label } = *coordinates else {
                return Err(Error::InvalidParameter);
            };
            if identity_index.is_some() {
                return Err(Error::InvalidParameter);
            }
            if label == Some(0) {
                return Err(Error::SilentPaymentChangeLabel);
            }
            check_proof_of_registration(account, name, por)?;
            (account.get_address(coordinates)?, label, None)
        }
        _ => return Err(Error::InvalidParameter),
    };

    if display {
        if !display_address(app, name, label, &address).await {
            return Err(Error::UserRejected);
        }
    }

    Ok(Response::Address {
        address,
        identity_sig,
    })
}

#[cfg(test)]
mod tests {
    use common::{account::KeyInformation, bip388, message};

    use super::*;

    fn make_account(template: &str, keys_info_strs: &[&str]) -> message::Account {
        let keys = keys_info_strs
            .iter()
            .map(|s| KeyInformation::try_from(*s).unwrap())
            .collect();
        message::Account::WalletPolicy(bip388::WalletPolicy::new(template, keys).unwrap())
    }

    fn wallet_policy_of(account: &message::Account) -> &bip388::WalletPolicy {
        let message::Account::WalletPolicy(wp) = account else {
            panic!("not a wallet policy");
        };
        wp
    }

    #[test]
    fn test_get_address_singlesig_wit() {
        let account = make_account(
            "wpkh(@0/**)",
            &["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"],
        );

        // default wallet accounts are not supported yet, so we simulate registration
        let account_name = "Segwit account";
        let hmac =
            ProofOfRegistration::new(&wallet_policy_of(&account).registration_id(account_name))
                .dangerous_as_bytes();

        let resp = sdk::executor::block_on(handle_get_address(
            &mut sdk::App::singleton(),
            Some(account_name),
            &account,
            &hmac,
            &message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                is_change: false,
                address_index: 0,
            }),
            false,
            None,
        ))
        .unwrap();

        assert_eq!(
            resp,
            Response::Address {
                address: "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk".into(),
                identity_sig: None,
            }
        );
    }

    #[test]
    fn test_get_address_silent_payments() {
        let account = crate::sp_keys::account(2).unwrap();
        let name = "Silent payments";
        let hmac = ProofOfRegistration::new(&account.registration_id(name)).dangerous_as_bytes();
        let get_address =
            |coords: SilentPaymentCoordinates, hmac: &[u8], identity_index: Option<u32>| {
                sdk::executor::block_on(handle_get_address(
                    &mut sdk::App::singleton(),
                    Some(name),
                    &message::Account::SilentPayment(account.clone()),
                    hmac,
                    &message::AccountCoordinates::SilentPayment(coords),
                    false,
                    identity_index,
                ))
            };

        for label in [None, Some(1), Some(42)] {
            let coords = SilentPaymentCoordinates::Code { label };
            let address = get_address(coords.clone(), &hmac, None).unwrap();
            assert_eq!(
                address,
                Response::Address {
                    address: account.get_address(&coords).unwrap(),
                    identity_sig: None,
                }
            );
        }

        let code = SilentPaymentCoordinates::Code { label: Some(1) };
        // the change label is never handed out
        assert_eq!(
            get_address(
                SilentPaymentCoordinates::Code { label: Some(0) },
                &hmac,
                None
            ),
            Err(Error::SilentPaymentChangeLabel)
        );
        // an address to hand out is a code
        assert_eq!(
            get_address(SilentPaymentCoordinates::Tweak([1; 32]), &hmac, None),
            Err(Error::InvalidParameter)
        );
        // identity signatures are over scripts
        assert_eq!(
            get_address(code.clone(), &hmac, Some(0)),
            Err(Error::InvalidParameter)
        );
        assert_eq!(
            get_address(code.clone(), &[0; 32], None),
            Err(Error::InvalidProofOfRegistration)
        );
        assert_eq!(
            get_address(code, &[], None),
            Err(Error::DefaultAccountsNotSupported)
        );

        // coordinates of another account type
        assert_eq!(
            sdk::executor::block_on(handle_get_address(
                &mut sdk::App::singleton(),
                Some(name),
                &message::Account::SilentPayment(account.clone()),
                &hmac,
                &message::AccountCoordinates::WalletPolicy(message::WalletPolicyCoordinates {
                    is_change: false,
                    address_index: 0,
                }),
                false,
                None,
            )),
            Err(Error::InvalidParameter)
        );
    }
}
