//! Proofs of registration: checking the proofs that requests carry, and issuing new ones.

use common::{
    errors::Error,
    identity::IdentityKey,
    por::{ProofOfRegistration, Registerable},
};

/// The proof of registration `por` that a request carries. It must have 32 bytes: an empty one
/// would be for a default account, which isn't supported.
pub fn parse_por(por: &[u8]) -> Result<[u8; 32], Error> {
    if por.is_empty() {
        return Err(Error::DefaultAccountsNotSupported);
    }
    por.try_into()
        .map_err(|_| Error::InvalidProofOfRegistrationLength)
}

/// Whether `por` is the proof of registration of `item` in the context `ctx`, such as the name of
/// an account.
pub fn is_registered<T: Registerable>(item: &T, ctx: &T::Context, por: &[u8; 32]) -> bool {
    ProofOfRegistration::<T>::from_bytes(*por)
        == ProofOfRegistration::new(&item.registration_id(ctx))
}

/// Fails unless `por` is the proof of registration of `item` in the context `ctx`.
pub fn check_registered<T: Registerable>(
    item: &T,
    ctx: &T::Context,
    por: &[u8; 32],
) -> Result<(), Error> {
    if !is_registered(item, ctx, por) {
        return Err(Error::InvalidProofOfRegistration);
    }
    Ok(())
}

/// The identity key `pubkey`, if `por` is its proof of registration with the name `name`.
pub fn registered_identity_key(
    pubkey: [u8; 33],
    name: &str,
    por: &[u8; 32],
) -> Result<IdentityKey, Error> {
    let identity_key = IdentityKey::new(pubkey).map_err(|_| Error::InvalidIdentitySignature)?;
    check_registered(&identity_key, name, por)?;
    Ok(identity_key)
}

/// The registration of an item: its id, and its proof of registration.
pub struct Registration {
    pub id: [u8; 32],
    pub por: [u8; 32],
}

/// Registers `item` in the context `ctx`, once the user approved it.
pub fn register<T: Registerable>(item: &T, ctx: &T::Context) -> Registration {
    let id = item.registration_id(ctx);
    Registration {
        id: *id.as_bytes(),
        por: ProofOfRegistration::new(&id).dangerous_as_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::bip388::WalletPolicy;

    fn wallet_policy() -> WalletPolicy {
        WalletPolicy::new(
            "wpkh(@0/**)",
            alloc::vec!["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn parse_por_lengths() {
        assert_eq!(parse_por(&[]), Err(Error::DefaultAccountsNotSupported));
        assert_eq!(
            parse_por(&[7; 31]),
            Err(Error::InvalidProofOfRegistrationLength)
        );
        assert_eq!(
            parse_por(&[7; 33]),
            Err(Error::InvalidProofOfRegistrationLength)
        );
        assert_eq!(parse_por(&[7; 32]), Ok([7; 32]));
    }

    /// A registration checks only with the item and the context it was issued for.
    #[test]
    fn register_then_check() {
        let policy = wallet_policy();
        let registration = register(&policy, "Name");
        assert_eq!(registration.id, *policy.registration_id("Name").as_bytes());
        assert_eq!(check_registered(&policy, "Name", &registration.por), Ok(()));
        assert_eq!(
            check_registered(&policy, "Other name", &registration.por),
            Err(Error::InvalidProofOfRegistration)
        );
        assert_eq!(
            check_registered(&policy, "Name", &registration.id),
            Err(Error::InvalidProofOfRegistration)
        );
    }
}
