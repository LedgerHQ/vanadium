//! Custom minicbor codec for [`SilentPaymentAccount`].
//!
//! ```text
//! SilentPaymentAccount = { 0: uint account_index, 1: bstr scan_key, 2: bstr spend_key }
//! ```
//!
//! The scan key is the 32-byte private key, and the spend key the 33-byte compressed public key.
//! Used via `#[cbor(with = "silent_payment_codec")]` on the `Account::SilentPayment` variant's
//! inner field.

use minicbor::{
    decode as cbor_decode,
    encode::{self, Write},
    Decoder, Encoder,
};
use sdk::curve::{Secp256k1Point, Secp256k1Scalar};

use crate::silent_payments::SilentPaymentAccount;

pub fn encode<C, W: Write>(
    account: &SilentPaymentAccount,
    e: &mut Encoder<W>,
    _ctx: &mut C,
) -> Result<(), encode::Error<W::Error>> {
    e.map(3)?;
    e.u8(0)?;
    e.u32(account.account_index())?;
    e.u8(1)?;
    e.bytes(account.scan_key().as_be_bytes())?;
    e.u8(2)?;
    e.bytes(
        &account
            .spend_key()
            .to_compressed()
            .expect("the spend key is not the point at infinity"),
    )?;
    Ok(())
}

pub fn decode<'b, C>(
    d: &mut Decoder<'b>,
    _ctx: &mut C,
) -> Result<SilentPaymentAccount, cbor_decode::Error> {
    let n = d
        .map()?
        .ok_or_else(|| cbor_decode::Error::message("indefinite-length maps not supported"))?;
    let mut account_index: Option<u32> = None;
    let mut scan_key: Option<Secp256k1Scalar> = None;
    let mut spend_key: Option<Secp256k1Point> = None;
    for _ in 0..n {
        match d.u8()? {
            0 => account_index = Some(d.u32()?),
            1 => {
                let bytes: &[u8; 32] = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| cbor_decode::Error::message("invalid scan key"))?;
                scan_key = Some(
                    Secp256k1Scalar::from_be_bytes(bytes)
                        .ok_or_else(|| cbor_decode::Error::message("invalid scan key"))?,
                );
            }
            2 => {
                let bytes: &[u8; 33] = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| cbor_decode::Error::message("invalid spend key"))?;
                spend_key = Some(
                    Secp256k1Point::from_compressed(bytes)
                        .map_err(|_| cbor_decode::Error::message("invalid spend key"))?,
                );
            }
            _ => d.skip()?,
        }
    }
    let account_index =
        account_index.ok_or_else(|| cbor_decode::Error::message("missing account index"))?;
    let scan_key = scan_key.ok_or_else(|| cbor_decode::Error::message("missing scan key"))?;
    let spend_key = spend_key.ok_or_else(|| cbor_decode::Error::message("missing spend key"))?;
    SilentPaymentAccount::new(account_index, scan_key, spend_key)
        .map_err(|_| cbor_decode::Error::message("invalid silent payment account"))
}
