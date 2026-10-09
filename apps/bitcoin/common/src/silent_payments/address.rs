//! Silent payment addresses (BIP-352), and the encoding of the scan key for watch-only wallets
//! (BIP-392).

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bitcoin::bech32::{Bech32m, Fe32, Hrp};
use sdk::curve::{Secp256k1Point, Secp256k1Scalar};

use super::{ser_p, Error};

/// A silent payment code: the scan key of a recipient, and its spend key, which a label may have
/// tweaked (`B_m` in BIP-352). Neither key is the point at infinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentPaymentCode {
    scan: Secp256k1Point,
    spend: Secp256k1Point,
}

/// Encodes `data` with bech32m, the human-readable part `hrp`, and the version character `q`.
fn encode(hrp: &str, data: &[u8]) -> Result<String, Error> {
    let hrp = Hrp::parse(hrp).map_err(|_| Error::InvalidEncoding)?;
    Ok(data
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(Fe32::Q)
        .chars()
        .collect())
}

/// Decodes a bech32m string with a version character, returning the human-readable part (in
/// lowercase), the version, and the data.
fn decode(s: &str) -> Result<(String, u8, Vec<u8>), Error> {
    let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|_| Error::InvalidEncoding)?;
    // The version can go up to 31, so it is not read as a segwit witness version, which stops at
    // 16. The checksum validated every character.
    let fe = |c: &u8| Fe32::from_char(char::from(*c)).expect("a valid bech32 character");
    let (version, data) = checked
        .data_part_ascii_no_checksum()
        .split_first()
        .ok_or(Error::InvalidEncoding)?;
    // As in BIP-173, the bits left over after the last byte are fewer than 5, and all zero: else,
    // different strings would decode to the same data.
    let padding = data.len() * 5 % 8;
    if padding > 4
        || data
            .last()
            .is_some_and(|c| fe(c).to_u8() & ((1 << padding) - 1) != 0)
    {
        return Err(Error::InvalidEncoding);
    }
    let data = data.iter().map(fe).fes_to_bytes().collect();
    Ok((checked.hrp().to_lowercase(), fe(version).to_u8(), data))
}

impl SilentPaymentCode {
    /// The code with scan key `scan` and spend key `spend`, which must not be the point at
    /// infinity.
    pub fn new(scan: Secp256k1Point, spend: Secp256k1Point) -> Result<Self, Error> {
        if scan.is_zero() || spend.is_zero() {
            return Err(Error::InvalidKey);
        }
        Ok(Self { scan, spend })
    }

    /// The scan key, `B_scan`.
    pub fn scan(&self) -> &Secp256k1Point {
        &self.scan
    }

    /// The spend key, `B_m`.
    pub fn spend(&self) -> &Secp256k1Point {
        &self.spend
    }

    /// The point encodings of the code, `ser_P(B_scan) || ser_P(B_m)`, as in a silent payment
    /// address and in the PSBT fields of BIP-375.
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut res = [0u8; 66];
        res[..33].copy_from_slice(&ser_p(&self.scan));
        res[33..].copy_from_slice(&ser_p(&self.spend));
        res
    }

    /// Decodes the 66 bytes of [`SilentPaymentCode::to_bytes`].
    pub fn from_bytes(bytes: &[u8; 66]) -> Result<Self, Error> {
        let point = |b: &[u8]| {
            Secp256k1Point::from_compressed(b.try_into().unwrap())
                .map_err(|_| Error::InvalidEncoding)
        };
        Self::new(point(&bytes[..33])?, point(&bytes[33..])?).map_err(|_| Error::InvalidEncoding)
    }

    /// The silent payment address (version 0) with the human-readable part `hrp`: `sp` on
    /// mainnet, `tsp` on the test networks.
    pub fn to_address(&self, hrp: &str) -> Result<String, Error> {
        encode(hrp, &self.to_bytes())
    }

    /// Decodes a silent payment address, returning its human-readable part and its code.
    ///
    /// As BIP-352 specifies, version 0 must carry exactly 66 bytes, versions 1 to 30 at least 66
    /// (the rest is ignored), and version 31 is invalid.
    pub fn from_address(address: &str) -> Result<(String, Self), Error> {
        let (hrp, version, data) = decode(address)?;
        let valid = match version {
            0 => data.len() == 66,
            1..=30 => data.len() >= 66,
            _ => false,
        };
        if !valid {
            return Err(Error::InvalidEncoding);
        }
        Ok((hrp, Self::from_bytes(data[..66].try_into().unwrap())?))
    }
}

/// The BIP-392 encoding of the material a watch-only wallet needs to find payments: the scan
/// private key and the spend public key, with the human-readable part `hrp` (`spscan` on
/// mainnet, `tspscan` on the test networks).
pub fn encode_spscan(
    hrp: &str,
    b_scan: &Secp256k1Scalar,
    spend: &Secp256k1Point,
) -> Result<String, Error> {
    if b_scan.is_zero() || spend.is_zero() {
        return Err(Error::InvalidKey);
    }
    let mut data = zeroize::Zeroizing::new([0u8; 65]);
    data[..32].copy_from_slice(b_scan.as_be_bytes());
    data[32..].copy_from_slice(&ser_p(spend));
    encode(hrp, &data[..])
}

/// Decodes a BIP-392 `spscan` key, returning its human-readable part, the scan private key and the
/// spend public key.
pub fn decode_spscan(s: &str) -> Result<(String, Secp256k1Scalar, Secp256k1Point), Error> {
    let (hrp, version, data) = decode(s)?;
    let data = zeroize::Zeroizing::new(data);
    if version != 0 || data.len() != 65 {
        return Err(Error::InvalidEncoding);
    }
    let b_scan = Secp256k1Scalar::from_be_bytes(data[..32].try_into().unwrap())
        .filter(|b| !b.is_zero())
        .ok_or(Error::InvalidEncoding)?;
    let spend = Secp256k1Point::from_compressed(data[32..].try_into().unwrap())
        .map_err(|_| Error::InvalidEncoding)?;
    Ok((hrp, b_scan, spend))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdk::curve::Secp256k1;

    fn code() -> SilentPaymentCode {
        let g = Secp256k1::get_generator();
        SilentPaymentCode::new(
            &g * &Secp256k1Scalar::from_u32(2),
            &g * &Secp256k1Scalar::from_u32(3),
        )
        .unwrap()
    }

    #[test]
    fn address_round_trip() {
        let code = code();
        for hrp in ["sp", "tsp"] {
            let address = code.to_address(hrp).unwrap();
            assert!(address.starts_with(&alloc::format!("{hrp}1q")));
            assert_eq!(
                SilentPaymentCode::from_address(&address).unwrap(),
                (hrp.into(), code)
            );
            // case-insensitive
            let upper = address.to_uppercase();
            assert_eq!(
                SilentPaymentCode::from_address(&upper).unwrap(),
                (hrp.into(), code)
            );
        }
    }

    #[test]
    fn address_versions() {
        let hrp = Hrp::parse("sp").unwrap();
        let with_version = |version: u8, data: &[u8]| -> String {
            data.iter()
                .copied()
                .bytes_to_fes()
                .with_checksum::<Bech32m>(&hrp)
                .with_witness_version(Fe32::try_from(version).unwrap())
                .chars()
                .collect()
        };
        let bytes = code().to_bytes();
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[7u8; 10]);

        // version 0: exactly 66 bytes
        assert!(SilentPaymentCode::from_address(&with_version(0, &bytes)).is_ok());
        assert!(SilentPaymentCode::from_address(&with_version(0, &longer)).is_err());
        // versions 1 to 30: the first 66 bytes
        assert_eq!(
            SilentPaymentCode::from_address(&with_version(1, &longer))
                .unwrap()
                .1,
            code()
        );
        assert!(SilentPaymentCode::from_address(&with_version(30, &bytes)).is_ok());
        assert!(SilentPaymentCode::from_address(&with_version(1, &bytes[..65])).is_err());
        // version 31 is reserved
        assert!(SilentPaymentCode::from_address(&with_version(31, &longer)).is_err());
    }

    #[test]
    fn address_padding() {
        let hrp = Hrp::parse("sp").unwrap();
        let encode = |fes: &[Fe32]| -> String {
            fes.iter()
                .copied()
                .with_checksum::<Bech32m>(&hrp)
                .with_witness_version(Fe32::Q)
                .chars()
                .collect()
        };
        // 66 bytes take 106 characters, whose last 2 bits are padding
        let fes: Vec<Fe32> = code().to_bytes().iter().copied().bytes_to_fes().collect();
        assert_eq!(fes.len(), 106);
        assert!(SilentPaymentCode::from_address(&encode(&fes)).is_ok());

        let mut non_zero = fes.clone();
        let last = non_zero.last_mut().unwrap();
        *last = Fe32::try_from(last.to_u8() | 1).unwrap();
        assert!(SilentPaymentCode::from_address(&encode(&non_zero)).is_err());

        let mut extra_group = fes.clone();
        extra_group.push(Fe32::Q);
        assert!(SilentPaymentCode::from_address(&encode(&extra_group)).is_err());
    }

    #[test]
    fn codes_have_no_infinity() {
        let point = *code().scan();
        let infinity = Secp256k1Point::default();
        assert_eq!(
            SilentPaymentCode::new(infinity, point),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            SilentPaymentCode::new(point, infinity),
            Err(Error::InvalidKey)
        );
    }

    #[test]
    fn spscan_round_trip() {
        let b_scan = Secp256k1Scalar::from_u32(42);
        let spend = code().spend;
        let encoded = encode_spscan("tspscan", &b_scan, &spend).unwrap();
        assert!(encoded.starts_with("tspscan1q"));
        let (hrp, b, s) = decode_spscan(&encoded).unwrap();
        assert_eq!((hrp.as_str(), &b, s), ("tspscan", &b_scan, spend));
        // invalid keys
        let infinity = Secp256k1Point::default();
        assert_eq!(
            encode_spscan("tspscan", &Secp256k1Scalar::zero(), &spend),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            encode_spscan("tspscan", &b_scan, &infinity),
            Err(Error::InvalidKey)
        );
        // not an spscan key
        assert!(decode_spscan(&code().to_address("tsp").unwrap()).is_err());
    }
}
