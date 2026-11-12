use common::{
    account::{Account, Destination, SilentPaymentCoordinates},
    errors::Error,
    identity,
    message::{self, Response},
    script::ToScript,
};

use crate::{identity::compute_identity_signature, registration, ux};

async fn display_address(
    app: &mut sdk::App,
    account_name: Option<&str>,
    label: Option<u32>,
    addr: &str,
) -> bool {
    use alloc::{string::ToString, vec};
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
    ux::review(
        app,
        ux::Review {
            intro: ux::intro("Verify Bitcoin", "address"),
            pairs: &pairs,
            final_text: "The address is correct",
            button_text: "Confirm",
            long_press: false,
            approved: Some("Address verified"),
            rejected: "Address rejected",
        },
    )
    .await
}

/// Checks that `por` is the proof of registration of `account` with the name `name`.
fn check_proof_of_registration<T: Account>(
    account: &T,
    name: Option<&str>,
    por: &[u8],
) -> Result<(), Error> {
    registration::check_registered(account, name.unwrap_or(""), &registration::parse_por(por)?)
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
            let script = wallet_policy
                .to_script(coordinates.is_change, coordinates.address_index)
                .map_err(|_| Error::InvalidWalletPolicy)?;
            // the identity key signs the scriptPubKey of the address
            let identity_sig = identity_index
                .map(|i| {
                    compute_identity_signature(identity::MSG_TYPE_OUTPUT, script.as_bytes(), i)
                })
                .transpose()?;
            let address = Destination::Script(script)
                .address()
                .map_err(|_| Error::InvalidWalletPolicy)?;
            (address, None, identity_sig)
        }
        (
            message::Account::SilentPayment(account),
            message::AccountCoordinates::SilentPayment(coordinates),
        ) => {
            // an address to hand out is a code, and identity signatures are over scripts
            let SilentPaymentCoordinates::Code { label } = *coordinates else {
                return Err(Error::AccountCoordinatesMismatch);
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
        _ => return Err(Error::AccountCoordinatesMismatch),
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
    use common::{
        account::KeyInformation,
        bip388, message,
        por::{ProofOfRegistration, Registerable},
    };

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
            Err(Error::AccountCoordinatesMismatch)
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
            Err(Error::AccountCoordinatesMismatch)
        );
    }
}
