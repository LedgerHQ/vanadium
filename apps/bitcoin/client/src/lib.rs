extern crate bitcoin;

mod client;
pub mod psbt;

pub use client::BitcoinClient;
pub use psbt::{insert_signing_policies, InsertSigningPoliciesError};

// Re-export from the sdk
pub use sdk::vanadium_client::{client_utils::*, VAppTransport};

// Re-exports from the `common` module that are useful for users of this library.
pub use common::{
    bip388::{self, WalletPolicy},
    identity::{self, IdentityKey},
    message::{self, IdentitySignature, RegisteredIdentityEntry},
    por::{ProofOfRegistration, RegistrationId},
    psbt::psbt_v0_to_v2,
    psbt::signing_policy::{
        build_signing_policy_value, parse_signing_policy_path, signing_policy_chunks,
        signing_policy_key_path, SigningPolicy, ENGINE_ID_RISCV, SIGNING_POLICY_PURPOSE,
    },
};
