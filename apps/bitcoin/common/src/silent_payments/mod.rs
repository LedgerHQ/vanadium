//! BIP-352 silent payments.
//!
//! Everything works on the SDK's points and scalars, so it runs both on the device and on the
//! host. Scalars that hold secrets (input keys, the scan and spend keys) are zeroized on drop.

mod address;
mod receiver;
mod sender;
mod tags;

pub use address::{decode_spscan, encode_spscan, SilentPaymentCode};
pub use receiver::{label_tweak, labeled_spend_key, scan, spending_key, FoundOutput, Labels};
pub use sender::{
    assign_k, create_outputs, ecdh_share, input_hash, input_private_key, outpoint_bytes,
    output_key, shared_secret,
};

/// The maximum number of outputs to the same scan key that a transaction can have
/// (`K_max` in BIP-352).
pub const K_MAX: u32 = 2323;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a valid silent payment address, or BIP-392 key encoding.
    InvalidEncoding,
    /// A tagged hash that is used as a scalar is 0 or not smaller than the curve order, which
    /// BIP-352 and BIP-374 treat as a failure.
    InvalidHash,
    /// The private keys of the eligible inputs sum to 0.
    ZeroInputSum,
    /// The transaction has no inputs.
    NoInputs,
    /// More than [`K_MAX`] outputs pay to the same scan key.
    TooManyRecipients,
    /// A derived key is 0 or the point at infinity.
    InvalidKey,
}

/// The 33-byte compressed encoding of a point that is known not to be the point at infinity.
fn ser_p(p: &sdk::curve::Secp256k1Point) -> [u8; 33] {
    p.to_compressed()
        .expect("the point is not the point at infinity")
}
