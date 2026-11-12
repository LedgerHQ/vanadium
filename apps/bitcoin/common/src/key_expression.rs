//! The keys of the key expressions of a wallet policy (BIP-388): a plain key `@i/<num1;num2>/*`,
//! or a `musig(@i,@j,…)/<num1;num2>/*`, whose root is the BIP-388 aggregate of its participants.

use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, Xpub};

use crate::bip388::{KeyExpression, KeyInformation};
use crate::errors::Error;
use crate::musig;

/// The last two BIP-32 steps of `kp` at the change `is_change` and the address index
/// `address_index`: the step that `kp`'s `/<num1;num2>` gives for `is_change`, then the address
/// index.
pub fn child_steps(kp: &KeyExpression, is_change: bool, address_index: u32) -> [u32; 2] {
    let change_step = if is_change { kp.num2 } else { kp.num1 };
    [change_step, address_index]
}

/// The keys of `kp` in `key_information`: its key for a plain key, its participants for a musig.
pub fn keys<'a>(
    kp: &KeyExpression,
    key_information: &'a [KeyInformation],
) -> Result<Vec<&'a KeyInformation>, Error> {
    let key = |i: &u32| {
        key_information
            .get(*i as usize)
            .ok_or(Error::InvalidKeyIndex)
    };
    if let Some(i) = kp.plain_key_index() {
        Ok(alloc::vec![key(&i)?])
    } else if let Some(indices) = kp.musig_key_indices() {
        indices.iter().map(key).collect()
    } else {
        Err(Error::UnsupportedWalletPolicy)
    }
}

/// The root xpub of `kp`: its key's for a plain key, the BIP-388 aggregate of its participants'
/// for a musig.
pub fn root_xpub(kp: &KeyExpression, key_information: &[KeyInformation]) -> Result<Xpub, Error> {
    let keys = keys(kp, key_information)?;
    if !kp.is_musig() {
        return Ok(keys[0].pubkey);
    }
    let participants: Vec<Xpub> = keys.iter().map(|key| key.pubkey).collect();
    musig::aggregate_xpub(&participants).map_err(|_| Error::InvalidKey)
}

/// The key of a key expression at some coordinates.
pub struct DerivedKey {
    /// The xpub at the coordinates.
    pub xpub: Xpub,
    /// The BIP-32 tweaks of the two steps from the root xpub: a musig applies them to its
    /// aggregate key (BIP-388).
    pub tweaks: [[u8; 32]; 2],
}

/// The key of `kp` at the change `is_change` and the address index `address_index`: two
/// unhardened steps from its [`root_xpub`].
pub fn derive(
    kp: &KeyExpression,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
) -> Result<DerivedKey, Error> {
    let [change_step, address_step] = child_steps(kp, is_change, address_index);
    let step = |xpub: &Xpub, child: u32| {
        musig::ckdpub_with_tweak(xpub, ChildNumber::from(child))
            .map_err(|_| Error::KeyDerivationFailed)
    };
    let (child, tweak0) = step(&root_xpub(kp, key_information)?, change_step)?;
    let (xpub, tweak1) = step(&child, address_step)?;
    Ok(DerivedKey {
        xpub,
        tweaks: [tweak0, tweak1],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bip388::WalletPolicy;

    const XPUB_0: &str = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
    const XPUB_1: &str = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm";

    fn policy(descriptor: &str) -> WalletPolicy {
        WalletPolicy::new(
            descriptor,
            alloc::vec![XPUB_0.try_into().unwrap(), XPUB_1.try_into().unwrap()],
        )
        .unwrap()
    }

    fn first_key_expression(policy: &WalletPolicy) -> KeyExpression {
        policy
            .descriptor_template()
            .placeholders()
            .next()
            .unwrap()
            .0
            .clone()
    }

    #[test]
    fn child_steps_follow_the_change() {
        let policy = policy("wsh(multi(1,@1/<3;7>/*,@0/**))");
        let kp = first_key_expression(&policy);
        assert_eq!(child_steps(&kp, false, 5), [3, 5]);
        assert_eq!(child_steps(&kp, true, 5), [7, 5]);
    }

    /// A plain key derives as with BIP-32, and its tweaks are those of each step.
    #[test]
    fn plain_key_derives_as_bip32() {
        let policy = policy("wsh(multi(1,@1/**,@0/**))");
        let kp = first_key_expression(&policy);
        assert_eq!(keys(&kp, policy.key_information()).unwrap().len(), 1);

        let derived = derive(&kp, policy.key_information(), true, 9).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let root: Xpub = XPUB_1.parse().unwrap();
        let expected = root
            .derive_pub(&secp, &[ChildNumber::from(1), ChildNumber::from(9)])
            .unwrap();
        assert_eq!(derived.xpub, expected);

        let (_, tweak0) = musig::ckdpub_with_tweak(&root, ChildNumber::from(1)).unwrap();
        assert_eq!(derived.tweaks[0], tweak0);
    }

    /// A musig derives from the aggregate of its participants.
    #[test]
    fn musig_derives_from_the_aggregate() {
        let policy = policy("tr(musig(@0,@1)/**)");
        let kp = first_key_expression(&policy);
        assert_eq!(keys(&kp, policy.key_information()).unwrap().len(), 2);

        let aggregate =
            musig::aggregate_xpub(&[XPUB_0.parse().unwrap(), XPUB_1.parse().unwrap()]).unwrap();
        assert_eq!(root_xpub(&kp, policy.key_information()).unwrap(), aggregate);

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let expected = aggregate
            .derive_pub(&secp, &[ChildNumber::from(0), ChildNumber::from(4)])
            .unwrap();
        let derived = derive(&kp, policy.key_information(), false, 4).unwrap();
        assert_eq!(derived.xpub, expected);
    }

    #[test]
    fn missing_keys_are_rejected() {
        let policy = policy("tr(musig(@0,@1)/**)");
        let kp = first_key_expression(&policy);
        let only_one = &policy.key_information()[..1];
        assert_eq!(keys(&kp, only_one).err(), Some(Error::InvalidKeyIndex));
        assert_eq!(
            derive(&kp, only_one, false, 0).err(),
            Some(Error::InvalidKeyIndex)
        );
    }
}
