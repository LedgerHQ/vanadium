extern crate bitcoin;

mod client;

pub use client::{BitcoinClient, BitcoinClientError, SignedPsbtResponse};

// Re-export from the sdk
pub use sdk::vanadium_client::{client_utils::*, VAppTransport};

// Re-exports from the `common` module that are useful for users of this library.
pub use common::{
    account::{SilentPaymentAccount, SilentPaymentCoordinates},
    bip388::{self, WalletPolicy},
    identity::{self, IdentityKey},
    message::{self, IdentitySignature, RegisteredIdentityEntry},
    por::{ProofOfRegistration, RegistrationId},
    psbt::PsbtV2,
};
