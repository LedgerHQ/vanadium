use core::fmt;
use minicbor::{Decode, Encode};

// Central error type used across the app; variants stay small and descriptive.
//
// Each variant carries a stable CBOR index. NEVER reuse an index; only ever
// append new variants at fresh indices.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(index_only)]
pub enum Error {
    // Generic / request
    #[n(0)]
    InvalidRequest,
    #[n(1)]
    InvalidParameter,

    // Wallet policy / account
    #[n(2)]
    InvalidWalletPolicy,
    #[n(3)]
    DefaultAccountsNotSupported,
    #[n(4)]
    InvalidProofOfRegistrationLength,
    #[n(5)]
    InvalidProofOfRegistration,
    #[n(6)]
    InvalidAccountId,
    #[n(7)]
    InvalidKeyIndex,
    #[n(8)]
    InvalidScriptContext,
    #[n(9)]
    TooManyKeys,
    #[n(10)]
    InvalidMultisigQuorum,
    #[n(11)]
    UnsupportedWalletPolicy,

    // Derivation / crypto
    #[n(12)]
    DerivationPathTooLong,
    #[n(13)]
    KeyDerivationFailed,
    #[n(14)]
    HardenedDerivationNotSupported,
    #[n(15)]
    InvalidKey,
    #[n(16)]
    ErrorComputingSighash,
    #[n(17)]
    SigningFailed,

    // PSBT / UTXO checks
    #[n(18)]
    FailedToDeserializePsbt,
    #[n(19)]
    FailedToGetAccounts,
    #[n(20)]
    ExternalInputsNotSupported,
    #[n(21)]
    WitnessUtxoNotAllowedForLegacy,
    #[n(22)]
    InvalidNonWitnessUtxo,
    #[n(23)]
    NonWitnessUtxoMismatch,
    #[n(24)]
    NonWitnessUtxoRequired,
    #[n(25)]
    WitnessUtxoRequiredForSegwit,
    #[n(26)]
    InvalidWitnessUtxo,
    #[n(27)]
    RedeemScriptMismatchWitness,
    #[n(28)]
    WitnessScriptRequiredForP2WSH,
    #[n(29)]
    WitnessScriptMismatchWitness,
    #[n(30)]
    RedeemScriptMismatch,
    #[n(31)]
    MissingPreviousOutputIndex,
    #[n(32)]
    MissingInputUtxo,
    #[n(33)]
    InputScriptMismatch,
    #[n(34)]
    OutputScriptMissing,
    #[n(35)]
    OutputAmountMissing,
    #[n(36)]
    OutputScriptMismatch,
    #[n(37)]
    InputsLessThanOutputs,
    #[n(38)]
    FailedUnsignedTransaction,
    #[n(39)]
    AddressFromScriptFailed,

    // Identity authentication
    #[n(40)]
    InvalidIdentitySignature,
    #[n(41)]
    IdentityMessageFieldTooLong,

    // Unexpected states
    #[n(42)]
    UnexpectedTaprootPolicy,
    #[n(43)]
    UnexpectedSegwitVersion,

    // Storage errors
    #[n(44)]
    StorageError,

    // User rejections (separate to keep enum small and avoid strings)
    #[n(45)]
    UserRejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            InvalidRequest => write!(f, "Invalid request"),
            InvalidParameter => write!(f, "Invalid parameter"),

            InvalidWalletPolicy => write!(f, "Invalid wallet policy"),
            DefaultAccountsNotSupported => write!(f, "Default accounts are not supported yet"),
            InvalidProofOfRegistrationLength => {
                write!(f, "Invalid Proof of Registration length")
            }
            InvalidProofOfRegistration => write!(f, "Invalid proof of registration"),
            InvalidAccountId => write!(f, "Invalid account ID"),
            InvalidKeyIndex => write!(f, "Invalid key index"),
            InvalidScriptContext => write!(f, "Invalid script context"),
            TooManyKeys => write!(f, "Too many keys"),
            InvalidMultisigQuorum => write!(f, "Invalid multisig quorum"),
            UnsupportedWalletPolicy => write!(f, "Unsupported wallet policy"),
            DerivationPathTooLong => write!(f, "Derivation path is too long"),
            KeyDerivationFailed => write!(f, "Failed to derive key for the given path"),
            HardenedDerivationNotSupported => write!(f, "Hardened derivation is not supported for resident keys"),
            InvalidKey => write!(f, "Invalid key"),
            ErrorComputingSighash => write!(f, "Error computing sighash"),
            SigningFailed => write!(f, "Failed to produce signature"),

            FailedToDeserializePsbt => write!(f, "Failed to deserialize PSBT"),
            FailedToGetAccounts => write!(f, "Failed to get accounts from PSBT"),
            ExternalInputsNotSupported => write!(f, "External inputs are not supported"),
            WitnessUtxoNotAllowedForLegacy => {
                write!(f, "Witness UTXO is not allowed for Legacy transaction")
            }
            InvalidNonWitnessUtxo => write!(f, "Invalid non-witness UTXO"),
            NonWitnessUtxoMismatch => {
                write!(f, "Non-witness UTXO does not match the previous output")
            }
            NonWitnessUtxoRequired => write!(f, "Non-witness UTXO is required for legacy transactions"),
            WitnessUtxoRequiredForSegwit => write!(f, "Witness UTXO is required for SegWit"),
            InvalidWitnessUtxo => write!(f, "Invalid witness UTXO"),
            RedeemScriptMismatchWitness => {
                write!(f, "Redeem script does not match the witness UTXO")
            }
            WitnessScriptRequiredForP2WSH => write!(f, "Witness script is required for P2WSH"),
            WitnessScriptMismatchWitness => {
                write!(f, "Witness script does not match the witness UTXO")
            }
            RedeemScriptMismatch => {
                write!(f, "Redeem script does not match the non-witness UTXO")
            }
            MissingPreviousOutputIndex => write!(f, "Missing previous output index"),
            MissingInputUtxo => write!(f, "Each input must have a witness UTXO or a non-witness UTXO"),
            InputScriptMismatch => write!(f, "Script does not match the account at the coordinates indicated in the PSBT for this input"),
            OutputScriptMissing => write!(f, "Output script is missing"),
            OutputAmountMissing => write!(f, "Output amount is missing"),
            OutputScriptMismatch => write!(f, "Script does not match the account at the coordinates indicated in the PSBT for this output"),
            InputsLessThanOutputs => write!(f, "Transaction outputs total amount is greater than inputs total amount"),
            FailedUnsignedTransaction => write!(f, "Failed to get unsigned transaction"),
            AddressFromScriptFailed => write!(f, "Failed to convert script to address"),

            InvalidIdentitySignature => write!(f, "Invalid identity signature on output or xpub"),
            IdentityMessageFieldTooLong => write!(f, "Identity message field exceeds maximum length of 255 bytes"),

            UnexpectedTaprootPolicy => write!(f, "Unexpected state: should be a Taproot wallet policy"),
            UnexpectedSegwitVersion => write!(f, "Unexpected state: should be SegwitV0 or Taproot"),

            StorageError => write!(f, "Storage error"),

            UserRejected => write!(f, "Rejected by the user"),
        }
    }
}
