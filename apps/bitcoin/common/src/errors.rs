use core::fmt;
use minicbor::{Decode, Encode};

// Central error type used across the app; variants stay small and descriptive.
//
// Each variant carries a CBOR index, which is how a client tells them apart. The indices are
// stable from the first release; until then, they are renumbered to keep each section contiguous.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(index_only)]
pub enum Error {
    // Generic
    #[n(0)]
    InvalidRequest,
    #[n(1)]
    InvalidParameter,
    #[n(2)]
    UserRejected,
    #[n(3)]
    StorageError,
    #[n(4)]
    RandomGenerationFailed,

    // Accounts and wallet policies
    #[n(5)]
    InvalidWalletPolicy,
    #[n(6)]
    UnsupportedWalletPolicy,
    #[n(7)]
    DefaultAccountsNotSupported,
    #[n(8)]
    InvalidProofOfRegistrationLength,
    #[n(9)]
    InvalidProofOfRegistration,
    #[n(10)]
    InvalidAccountId,
    #[n(11)]
    AccountCoordinatesMismatch,
    #[n(12)]
    InvalidKeyIndex,
    #[n(13)]
    InvalidScriptContext,
    #[n(14)]
    TooManyKeys,
    #[n(15)]
    InvalidMultisigQuorum,

    // Keys and signatures
    #[n(16)]
    DerivationPathTooLong,
    #[n(17)]
    KeyDerivationFailed,
    #[n(18)]
    InvalidKey,
    #[n(19)]
    ErrorComputingSighash,
    #[n(20)]
    UnsupportedSighashType,
    #[n(21)]
    SigningFailed,
    #[n(22)]
    UnexpectedTaprootPolicy,

    // PSBT and UTXO checks
    #[n(23)]
    FailedToDeserializePsbt,
    #[n(24)]
    FailedToGetAccounts,
    #[n(25)]
    FailedUnsignedTransaction,
    #[n(26)]
    ExternalInputsNotSupported,
    #[n(27)]
    MissingInputUtxo,
    #[n(28)]
    MissingPreviousOutputIndex,
    #[n(29)]
    WitnessUtxoNotAllowedForLegacy,
    #[n(30)]
    InvalidNonWitnessUtxo,
    #[n(31)]
    NonWitnessUtxoMismatch,
    #[n(32)]
    NonWitnessUtxoRequired,
    #[n(33)]
    WitnessUtxoRequiredForSegwit,
    #[n(34)]
    InvalidWitnessUtxo,
    #[n(35)]
    RedeemScriptMismatch,
    #[n(36)]
    RedeemScriptMismatchWitness,
    #[n(37)]
    WitnessScriptRequiredForP2WSH,
    #[n(38)]
    WitnessScriptMismatchWitness,
    #[n(39)]
    InputScriptMismatch,
    #[n(40)]
    OutputScriptMissing,
    #[n(41)]
    OutputAmountMissing,
    #[n(42)]
    OutputScriptMismatch,
    #[n(43)]
    InvalidAmount,
    #[n(44)]
    InputsLessThanOutputs,
    #[n(45)]
    AddressFromScriptFailed,

    // Identity keys
    #[n(46)]
    InvalidIdentityKey,
    #[n(47)]
    InvalidIdentitySignature,
    #[n(48)]
    InvalidIdentityEntry,
    #[n(49)]
    IdentityMessageFieldTooLong,
    #[n(50)]
    InvalidKeySignatureCount,

    // MuSig2
    #[n(51)]
    MissingMusigSession,
    #[n(52)]
    MissingMusigPubnonce,
    #[n(53)]
    MixedMusigRounds,
    #[n(54)]
    MusigPubnonceMismatch,

    // Silent payments
    #[n(55)]
    UnsupportedSilentPayment,
    #[n(56)]
    InvalidSilentPayment,
    #[n(57)]
    SilentPaymentInputNotHeld,
    #[n(58)]
    SilentPaymentNoEligibleInputs,
    #[n(59)]
    SilentPaymentSegwitVersion,
    #[n(60)]
    SilentPaymentSighashType,
    #[n(61)]
    SilentPaymentShareMismatch,
    #[n(62)]
    SilentPaymentOutputScriptMismatch,
    #[n(63)]
    SilentPaymentAccountKeyMismatch,
    #[n(64)]
    SilentPaymentChangeLabel,
    #[n(65)]
    SilentPaymentTweakMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            InvalidRequest => write!(f, "Invalid request"),
            InvalidParameter => write!(f, "Invalid parameter"),
            UserRejected => write!(f, "Rejected by the user"),
            StorageError => write!(f, "Storage error"),
            RandomGenerationFailed => write!(f, "Failed to generate randomness"),

            InvalidWalletPolicy => write!(f, "Invalid wallet policy"),
            UnsupportedWalletPolicy => write!(f, "Unsupported wallet policy"),
            DefaultAccountsNotSupported => write!(f, "Default accounts are not supported yet"),
            InvalidProofOfRegistrationLength => {
                write!(f, "Invalid Proof of Registration length")
            }
            InvalidProofOfRegistration => write!(f, "Invalid proof of registration"),
            InvalidAccountId => write!(f, "Invalid account ID"),
            AccountCoordinatesMismatch => {
                write!(f, "The coordinates don't fit the account, or the input or output")
            }
            InvalidKeyIndex => write!(f, "Invalid key index"),
            InvalidScriptContext => write!(f, "Invalid script context"),
            TooManyKeys => write!(f, "Too many keys"),
            InvalidMultisigQuorum => write!(f, "Invalid multisig quorum"),

            DerivationPathTooLong => write!(f, "Derivation path is too long"),
            KeyDerivationFailed => write!(f, "Failed to derive key for the given path"),
            InvalidKey => write!(f, "Invalid key"),
            ErrorComputingSighash => write!(f, "Error computing sighash"),
            UnsupportedSighashType => write!(f, "Unsupported sighash type"),
            SigningFailed => write!(f, "Failed to produce signature"),
            UnexpectedTaprootPolicy => write!(f, "Unexpected state: should be a Taproot wallet policy"),

            FailedToDeserializePsbt => write!(f, "Failed to deserialize PSBT"),
            FailedToGetAccounts => write!(f, "Failed to get accounts from PSBT"),
            FailedUnsignedTransaction => write!(f, "Failed to get unsigned transaction"),
            ExternalInputsNotSupported => write!(f, "External inputs are not supported"),
            MissingInputUtxo => write!(f, "Each input must have a witness UTXO or a non-witness UTXO"),
            MissingPreviousOutputIndex => write!(f, "Missing previous output index"),
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
            RedeemScriptMismatch => {
                write!(f, "Redeem script does not match the non-witness UTXO")
            }
            RedeemScriptMismatchWitness => {
                write!(f, "Redeem script does not match the witness UTXO")
            }
            WitnessScriptRequiredForP2WSH => write!(f, "Witness script is required for P2WSH"),
            WitnessScriptMismatchWitness => {
                write!(f, "Witness script does not match the witness UTXO")
            }
            InputScriptMismatch => write!(f, "Script does not match the account at the coordinates indicated in the PSBT for this input"),
            OutputScriptMissing => write!(f, "Output script is missing"),
            OutputAmountMissing => write!(f, "Output amount is missing"),
            OutputScriptMismatch => write!(f, "Script does not match the account at the coordinates indicated in the PSBT for this output"),
            InvalidAmount => write!(f, "An amount, or a sum of amounts, is above 21M bitcoins"),
            InputsLessThanOutputs => write!(f, "Transaction outputs total amount is greater than inputs total amount"),
            AddressFromScriptFailed => write!(f, "Failed to convert script to address"),

            InvalidIdentityKey => write!(f, "Invalid identity key"),
            InvalidIdentitySignature => write!(f, "Invalid identity signature on output or xpub"),
            InvalidIdentityEntry => {
                write!(f, "Malformed identity key or identity signature entry in the PSBT")
            }
            IdentityMessageFieldTooLong => write!(f, "Identity message field exceeds maximum length of 255 bytes"),
            InvalidKeySignatureCount => {
                write!(f, "The number of key signatures is not the number of keys")
            }

            MissingMusigSession => write!(
                f,
                "MuSig2 PSBT contains a pubnonce but the device has no record of the session"
            ),
            MissingMusigPubnonce => write!(
                f,
                "MuSig2 round 2 requires this device's pubnonce in the PSBT but it is missing"
            ),
            MixedMusigRounds => write!(
                f,
                "The PSBT has the MuSig2 pubnonces of some inputs only: run a single round"
            ),
            MusigPubnonceMismatch => write!(
                f,
                "The device's MuSig2 pubnonce in the PSBT is not the one of its session"
            ),

            UnsupportedSilentPayment => write!(f, "Unsupported silent payment"),
            InvalidSilentPayment => write!(f, "Invalid silent payment output"),
            SilentPaymentInputNotHeld => write!(
                f,
                "Silent payments need the private key of an input that the device doesn't fully hold"
            ),
            SilentPaymentNoEligibleInputs => {
                write!(f, "No input of the transaction can pay to silent payment addresses")
            }
            SilentPaymentSegwitVersion => write!(
                f,
                "An input spends a segwit version above 1, which silent payments don't allow"
            ),
            SilentPaymentSighashType => {
                write!(f, "Silent payments require SIGHASH_ALL or no sighash type")
            }
            SilentPaymentShareMismatch => write!(
                f,
                "The PSBT has an ECDH share or a DLEQ proof that doesn't match the device's"
            ),
            SilentPaymentOutputScriptMismatch => {
                write!(f, "Silent payment output script does not match its code")
            }
            SilentPaymentAccountKeyMismatch => {
                write!(f, "The keys of the silent payment account are not the device's")
            }
            SilentPaymentChangeLabel => write!(
                f,
                "The change label of a silent payment account is not an address to hand out"
            ),
            SilentPaymentTweakMismatch => write!(
                f,
                "The tweak of a silent payment input is missing, or not the one of its coordinates"
            ),
        }
    }
}

/// An account field of a PSBT that can't be read.
impl From<crate::psbt::PsbtAccountError> for Error {
    fn from(_: crate::psbt::PsbtAccountError) -> Self {
        Error::FailedToGetAccounts
    }
}

/// An identity key or identity signature field of a PSBT that can't be read.
impl From<crate::psbt::PsbtIdAuthError> for Error {
    fn from(_: crate::psbt::PsbtIdAuthError) -> Self {
        Error::InvalidIdentityEntry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The indices are contiguous, and each decodes back to its variant.
    #[test]
    fn indices_are_contiguous() {
        use Error::*;
        let all = [
            InvalidRequest,
            InvalidParameter,
            UserRejected,
            StorageError,
            RandomGenerationFailed,
            InvalidWalletPolicy,
            UnsupportedWalletPolicy,
            DefaultAccountsNotSupported,
            InvalidProofOfRegistrationLength,
            InvalidProofOfRegistration,
            InvalidAccountId,
            AccountCoordinatesMismatch,
            InvalidKeyIndex,
            InvalidScriptContext,
            TooManyKeys,
            InvalidMultisigQuorum,
            DerivationPathTooLong,
            KeyDerivationFailed,
            InvalidKey,
            ErrorComputingSighash,
            UnsupportedSighashType,
            SigningFailed,
            UnexpectedTaprootPolicy,
            FailedToDeserializePsbt,
            FailedToGetAccounts,
            FailedUnsignedTransaction,
            ExternalInputsNotSupported,
            MissingInputUtxo,
            MissingPreviousOutputIndex,
            WitnessUtxoNotAllowedForLegacy,
            InvalidNonWitnessUtxo,
            NonWitnessUtxoMismatch,
            NonWitnessUtxoRequired,
            WitnessUtxoRequiredForSegwit,
            InvalidWitnessUtxo,
            RedeemScriptMismatch,
            RedeemScriptMismatchWitness,
            WitnessScriptRequiredForP2WSH,
            WitnessScriptMismatchWitness,
            InputScriptMismatch,
            OutputScriptMissing,
            OutputAmountMissing,
            OutputScriptMismatch,
            InvalidAmount,
            InputsLessThanOutputs,
            AddressFromScriptFailed,
            InvalidIdentityKey,
            InvalidIdentitySignature,
            InvalidIdentityEntry,
            IdentityMessageFieldTooLong,
            InvalidKeySignatureCount,
            MissingMusigSession,
            MissingMusigPubnonce,
            MixedMusigRounds,
            MusigPubnonceMismatch,
            UnsupportedSilentPayment,
            InvalidSilentPayment,
            SilentPaymentInputNotHeld,
            SilentPaymentNoEligibleInputs,
            SilentPaymentSegwitVersion,
            SilentPaymentSighashType,
            SilentPaymentShareMismatch,
            SilentPaymentOutputScriptMismatch,
            SilentPaymentAccountKeyMismatch,
            SilentPaymentChangeLabel,
            SilentPaymentTweakMismatch,
        ];
        for (index, error) in all.iter().enumerate() {
            let encoded = minicbor::to_vec(error).unwrap();
            assert_eq!(
                encoded,
                minicbor::to_vec(index as u32).unwrap(),
                "{:?}",
                error
            );
            assert_eq!(&minicbor::decode::<Error>(&encoded).unwrap(), error);
        }
        // one past the last index decodes to no variant
        let past = minicbor::to_vec(all.len() as u32).unwrap();
        assert!(minicbor::decode::<Error>(&past).is_err());
    }
}
