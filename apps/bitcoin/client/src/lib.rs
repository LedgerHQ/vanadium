extern crate bitcoin;

mod client;
mod psbt;

pub use client::{BitcoinClient, BitcoinClientError, SignedPsbtResponse};
pub use psbt::{insert_signing_policies, InsertSigningPoliciesError};

// Re-export from the sdk
pub use sdk::vanadium_client::{client_utils::*, VAppTransport};

// Re-exports from the `common` module that are useful for users of this library.
pub use common::{
    bip388::{self, KeyInformation, KeyOrigin, WalletPolicy},
    identity::{self, IdentityKey},
    message::{self, IdentitySignature, RegisteredIdentityEntry},
    por::{ProofOfRegistration, RegistrationId},
    psbt::{build_signing_policy_value, psbt_v0_to_v2, SigningPolicy, ENGINE_ID_PROGRAM},
};
