//! Silent payment accounts: the receiving side of BIP-352, as an [`Account`].

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::consensus::{encode, Decodable};
use bitcoin::io::Read;
use bitcoin::ScriptBuf;
use sdk::curve::{Secp256k1, Secp256k1Point, Secp256k1Scalar};

use super::{decode_spscan, encode_spscan, labeled_spend_key, SilentPaymentCode};
use crate::account::{Account, AccountCoordinates, Destination};
use crate::errors::Error;

/// The human-readable part of the BIP-392 keys of the accounts, for the test networks.
const SPSCAN_HRP: &str = "tspscan";

/// A silent payment account: the BIP-352 account `account_index` of a wallet, with its scan
/// private key `b_scan` and its spend public key `B_spend`.
///
/// That is what a watch-only wallet needs to find the account's payments (the keys of a BIP-392
/// `spscan` key), and all that the destinations of the account depend on. The spend private key,
/// which spends the payments, is never part of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentAccount {
    account_index: u32,
    scan_key: Secp256k1Scalar,
    spend_key: Secp256k1Point,
}

/// The coordinates of a silent payment account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SilentPaymentCoordinates {
    /// The account's silent payment code, or the code of one of its labels: what an output pays
    /// to. Label 0 is the change label (BIP-352), that wallets never hand out.
    Code { label: Option<u32> },
    /// One output that the account received, by its tweak: the tweak to add to the spend private
    /// key to spend it (BIP-376), the label's included. That is what an input spends.
    Tweak([u8; 32]),
}

impl SilentPaymentAccount {
    /// Fails if `account_index` is not below 2^31, as the hardened derivation step of BIP-352
    /// requires, if `scan_key` is 0, or if `spend_key` is the point at infinity.
    pub fn new(
        account_index: u32,
        scan_key: Secp256k1Scalar,
        spend_key: Secp256k1Point,
    ) -> Result<Self, Error> {
        if account_index >= 0x8000_0000 {
            return Err(Error::InvalidParameter);
        }
        if scan_key.is_zero() || spend_key.is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            account_index,
            scan_key,
            spend_key,
        })
    }

    /// The account `account_index` with the keys of the BIP-392 `tspscan` key `spscan`.
    pub fn from_spscan(account_index: u32, spscan: &str) -> Result<Self, Error> {
        let (hrp, scan_key, spend_key) = decode_spscan(spscan).map_err(|_| Error::InvalidKey)?;
        if hrp != SPSCAN_HRP {
            return Err(Error::InvalidKey);
        }
        Self::new(account_index, scan_key, spend_key)
    }

    /// The account's keys, as a BIP-392 `tspscan` key.
    pub fn to_spscan(&self) -> String {
        encode_spscan(SPSCAN_HRP, &self.scan_key, &self.spend_key)
            .expect("the keys of an account are valid")
    }

    pub fn account_index(&self) -> u32 {
        self.account_index
    }

    pub fn scan_key(&self) -> &Secp256k1Scalar {
        &self.scan_key
    }

    pub fn spend_key(&self) -> &Secp256k1Point {
        &self.spend_key
    }
}

impl AccountCoordinates for SilentPaymentCoordinates {
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(33);
        match self {
            Self::Code { label: None } => result.extend_from_slice(&[0, 0]),
            Self::Code { label: Some(m) } => {
                result.extend_from_slice(&[0, 1]);
                result.extend_from_slice(&m.to_le_bytes());
            }
            Self::Tweak(tweak) => {
                result.push(1);
                result.extend_from_slice(tweak);
            }
        }
        result
    }

    fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        match u8::consensus_decode(r)? {
            0 => match u8::consensus_decode(r)? {
                0 => Ok(Self::Code { label: None }),
                1 => Ok(Self::Code {
                    label: Some(u32::consensus_decode(r)?),
                }),
                _ => Err(encode::Error::ParseFailed("Invalid label")),
            },
            1 => {
                let mut tweak = [0u8; 32];
                r.read_exact(&mut tweak)?;
                Ok(Self::Tweak(tweak))
            }
            _ => Err(encode::Error::ParseFailed(
                "Invalid silent payment coordinates",
            )),
        }
    }
}

impl Account for SilentPaymentAccount {
    type Coordinates = SilentPaymentCoordinates;

    const VERSION: u32 = 2;

    fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(4 + 4 + 32 + 33);
        res.extend_from_slice(&Self::VERSION.to_le_bytes());
        res.extend_from_slice(&self.account_index.to_le_bytes());
        res.extend_from_slice(self.scan_key.as_be_bytes());
        res.extend_from_slice(
            &self
                .spend_key
                .to_compressed()
                .expect("the spend key is not the point at infinity"),
        );
        res
    }

    fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u32::consensus_decode(r)?;
        if version != Self::VERSION {
            return Err(encode::Error::ParseFailed("Unsupported version"));
        }
        let account_index = u32::consensus_decode(r)?;
        let mut scan_key = zeroize::Zeroizing::new([0u8; 32]);
        r.read_exact(&mut scan_key[..])?;
        let mut spend_key = [0u8; 33];
        r.read_exact(&mut spend_key)?;

        let scan_key = Secp256k1Scalar::from_be_bytes(&scan_key)
            .ok_or(encode::Error::ParseFailed("Invalid scan key"))?;
        let spend_key = Secp256k1Point::from_compressed(&spend_key)
            .map_err(|_| encode::Error::ParseFailed("Invalid spend key"))?;
        Self::new(account_index, scan_key, spend_key)
            .map_err(|_| encode::Error::ParseFailed("Invalid silent payment account"))
    }

    /// The code `(B_scan, B_m)` of `Code` coordinates, or the script of the output that `Tweak`
    /// coordinates spend, `OP_1 x(B_spend + tweak·G)`.
    ///
    /// A code is not a script: the script of an output that pays to a code depends on the whole
    /// transaction (BIP-352), and the signer computes it once it knows the inputs' private keys.
    fn destination(&self, coords: &SilentPaymentCoordinates) -> Result<Destination, Error> {
        let g = Secp256k1::get_generator();
        match coords {
            SilentPaymentCoordinates::Code { label } => {
                let spend = match label {
                    None => self.spend_key,
                    Some(m) => labeled_spend_key(&self.spend_key, &self.scan_key, *m)
                        .map_err(|_| Error::InvalidKey)?,
                };
                let code = SilentPaymentCode::new(&g * &self.scan_key, spend)
                    .map_err(|_| Error::InvalidKey)?;
                Ok(Destination::SilentPaymentCode(code))
            }
            SilentPaymentCoordinates::Tweak(tweak) => {
                let tweak = Secp256k1Scalar::from_be_bytes(tweak).ok_or(Error::InvalidKey)?;
                let output_key = &self.spend_key + &(&g * &tweak);
                if output_key.is_zero() {
                    return Err(Error::InvalidKey);
                }
                Ok(Destination::Script(ScriptBuf::from_bytes(
                    [&[0x51, 0x20][..], output_key.x()].concat(),
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    // the keys of the BIP-352 receiving vectors
    const SCAN_KEY: [u8; 32] =
        hex!("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
    const SPEND_KEY: [u8; 32] =
        hex!("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");

    fn account(account_index: u32) -> SilentPaymentAccount {
        let spend_key =
            &Secp256k1::get_generator() * &Secp256k1Scalar::from_be_bytes(&SPEND_KEY).unwrap();
        SilentPaymentAccount::new(
            account_index,
            Secp256k1Scalar::from_be_bytes(&SCAN_KEY).unwrap(),
            spend_key,
        )
        .unwrap()
    }

    #[test]
    fn test_new() {
        let account = account(7);
        let (scan_key, spend_key) = (account.scan_key().clone(), *account.spend_key());
        assert!(SilentPaymentAccount::new(0x7fff_ffff, scan_key.clone(), spend_key).is_ok());
        assert_eq!(
            SilentPaymentAccount::new(0x8000_0000, scan_key.clone(), spend_key),
            Err(Error::InvalidParameter)
        );
        assert_eq!(
            SilentPaymentAccount::new(0, Secp256k1Scalar::zero(), spend_key),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            SilentPaymentAccount::new(0, scan_key, Secp256k1Point::default()),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn test_serialization() {
        let account = account(7);
        let serialized = Account::serialize(&account);
        assert_eq!(serialized.len(), 73);
        assert_eq!(serialized[..8], [2, 0, 0, 0, 7, 0, 0, 0]);
        assert_eq!(serialized[8..40], SCAN_KEY);
        assert_eq!(
            serialized[40..],
            account.spend_key().to_compressed().unwrap()
        );
        assert_eq!(
            <SilentPaymentAccount as Account>::deserialize(&mut &serialized[..]).unwrap(),
            account
        );

        // another version, an index too large, a scan key of 0 or not below the curve order, and
        // a spend key not on the curve are rejected
        let invalid = |at: usize, bytes: &[u8]| {
            let mut serialized = serialized.clone();
            serialized[at..at + bytes.len()].copy_from_slice(bytes);
            <SilentPaymentAccount as Account>::deserialize(&mut &serialized[..]).is_err()
        };
        assert!(invalid(0, &[1]));
        assert!(invalid(4, &[0, 0, 0, 0x80]));
        assert!(invalid(8, &[0; 32]));
        assert!(invalid(8, &[0xff; 32]));
        assert!(invalid(40, &[0x05]));
        // truncated
        assert!(<SilentPaymentAccount as Account>::deserialize(&mut &serialized[..72]).is_err());
    }

    #[test]
    fn test_spscan() {
        let account = account(3);
        let spscan = account.to_spscan();
        assert!(spscan.starts_with("tspscan1"));
        assert_eq!(
            SilentPaymentAccount::from_spscan(3, &spscan).unwrap(),
            account
        );
        // a mainnet key is not a key of the test networks
        let mainnet = encode_spscan("spscan", account.scan_key(), account.spend_key()).unwrap();
        assert_eq!(
            SilentPaymentAccount::from_spscan(3, &mainnet),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn test_coordinates_serialization() {
        for (coords, serialized) in [
            (SilentPaymentCoordinates::Code { label: None }, &[0, 0][..]),
            (
                SilentPaymentCoordinates::Code { label: Some(3) },
                &[0, 1, 3, 0, 0, 0][..],
            ),
            (
                SilentPaymentCoordinates::Tweak([0x42; 32]),
                &[[1].as_slice(), &[0x42; 32]].concat()[..],
            ),
        ] {
            assert_eq!(coords.serialize(), serialized);
            assert_eq!(
                SilentPaymentCoordinates::deserialize(&mut &serialized[..]).unwrap(),
                coords
            );
        }
        for invalid in [
            &[][..],
            &[0, 2][..],
            &[0, 1, 3][..],
            &[1, 0x42][..],
            &[2][..],
        ] {
            assert!(SilentPaymentCoordinates::deserialize(&mut &invalid[..]).is_err());
        }
    }

    #[test]
    fn test_destination() {
        let account = account(0);
        let address = |label| {
            account
                .get_address(&SilentPaymentCoordinates::Code { label })
                .unwrap()
        };
        // the first two addresses of the BIP-352 receiving vectors, on the test networks
        let (_, code) = SilentPaymentCode::from_address("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").unwrap();
        assert_eq!(address(None), code.to_address("tsp").unwrap());
        let (_, code) = SilentPaymentCode::from_address("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq").unwrap();
        assert_eq!(address(Some(2)), code.to_address("tsp").unwrap());

        // the change label is an address of the account like the others
        assert_ne!(address(Some(0)), address(None));

        // a tweak that is not below the curve order is not a tweak
        assert_eq!(
            account.destination(&SilentPaymentCoordinates::Tweak([0xff; 32])),
            Err(Error::InvalidKey)
        );
    }
}
