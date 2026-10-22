//! The keys of the silent payment accounts (BIP-352): for the account `n`, the scan key at
//! `m/352'/1'/n'/1'/0` and the spend key at `m/352'/1'/n'/0'/0`, in the standard tree (coin type 1,
//! for the test networks).

use common::{account::SilentPaymentAccount, errors::Error};
use sdk::curve::{Secp256k1, Secp256k1Scalar};

use crate::bip32::{derive_hd_node, KeyTree};

const H: u32 = 0x8000_0000;

/// The private key at `m/352'/1'/account_index'/branch'/0`.
fn derive(account_index: u32, branch: u32) -> Result<Secp256k1Scalar, Error> {
    if account_index >= H {
        return Err(Error::InvalidParameter);
    }
    let path = [352 | H, 1 | H, account_index | H, branch | H, 0];
    let hd_node = derive_hd_node(KeyTree::Standard, &path)?;
    Secp256k1Scalar::from_be_bytes(&hd_node.privkey).ok_or(Error::KeyDerivationFailed)
}

/// The spend private key `b_spend` of the account `account_index`.
pub fn spend_key(account_index: u32) -> Result<Secp256k1Scalar, Error> {
    derive(account_index, 0)
}

/// The account `account_index` of the device: its scan private key and its spend public key.
pub fn account(account_index: u32) -> Result<SilentPaymentAccount, Error> {
    let scan_key = derive(account_index, 1)?;
    let spend_key = &Secp256k1::get_generator() * &spend_key(account_index)?;
    SilentPaymentAccount::new(account_index, scan_key, spend_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1 as Secp;
    use hex_literal::hex;

    // the seed of the native tests, the default seed of Speculos
    const SEED: [u8; 64] = hex!("b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564");

    fn derive_independently(path: &str) -> [u8; 32] {
        let secp = Secp::new();
        let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &SEED).unwrap();
        let path: DerivationPath = path.parse().unwrap();
        master
            .derive_priv(&secp, &path)
            .unwrap()
            .private_key
            .secret_bytes()
    }

    #[test]
    fn test_keys() {
        for n in [0, 1, 0x7fff_ffff] {
            let account = account(n).unwrap();
            assert_eq!(account.account_index(), n);
            assert_eq!(
                account.scan_key().as_be_bytes(),
                &derive_independently(&alloc::format!("m/352'/1'/{n}'/1'/0"))
            );
            let b_spend = derive_independently(&alloc::format!("m/352'/1'/{n}'/0'/0"));
            assert_eq!(spend_key(n).unwrap().as_be_bytes(), &b_spend);
            assert_eq!(
                account.spend_key(),
                &(&Secp256k1::get_generator() * &Secp256k1Scalar::from_be_bytes(&b_spend).unwrap())
            );
        }
        assert_eq!(account(0x8000_0000), Err(Error::InvalidParameter));
        assert_eq!(spend_key(0x8000_0000), Err(Error::InvalidParameter));
    }
}
