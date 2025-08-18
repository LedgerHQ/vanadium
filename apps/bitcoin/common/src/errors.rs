use core::fmt;

// Central error type used across the app; variants stay small and descriptive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // Generic / request
    InvalidRequest,

    // Wallet policy / account
    InvalidWalletPolicy,
    DefaultAccountsNotSupported,
    InvalidProofOfRegistrationLength,
    InvalidProofOfRegistration,
    InvalidAccountId,

    // Derivation / crypto
    DerivationPathTooLong,
    KeyDerivationFailed,
    InvalidKey,
    ErrorComputingSighash,
    SigningFailed,

    // PSBT / UTXO checks
    FailedToGetAccounts,
    ExternalInputsNotSupported,
    WitnessUtxoNotAllowedForLegacy,
    InvalidNonWitnessUtxo,
    NonWitnessUtxoMismatch,
    NonWitnessUtxoRequired,
    WitnessUtxoRequiredForSegwit,
    InvalidWitnessUtxo,
    RedeemScriptMismatchWitness,
    WitnessScriptRequiredForP2WSH,
    WitnessScriptMismatchWitness,
    RedeemScriptMismatch,
    MissingPreviousOutputIndex,
    MissingInputUtxo,
    InputScriptMismatch,
    OutputScriptMissing,
    OutputAmountMissing,
    OutputScriptMismatch,
    InputsLessThanOutputs,
    FailedUnsignedTransaction,
    AddressFromScriptFailed,

    // Unexpected states
    UnexpectedTaprootPolicy,
    UnexpectedSegwitVersion,

    // User rejections (separate to keep enum small and avoid strings)
    UserRejected,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
			InvalidRequest => write!(f, "Invalid request"),

			InvalidWalletPolicy => write!(f, "Invalid wallet policy"),
			DefaultAccountsNotSupported => write!(f, "Default accounts are not supported yet"),
			InvalidProofOfRegistrationLength => {
				write!(f, "Invalid Proof of Registration length")
			}
			InvalidProofOfRegistration => write!(f, "Invalid proof of registration"),
			InvalidAccountId => write!(f, "Invalid account ID"),

			DerivationPathTooLong => write!(f, "Derivation path is too long"),
			KeyDerivationFailed => write!(f, "Failed to derive key for the given path"),
			InvalidKey => write!(f, "Invalid key"),
			ErrorComputingSighash => write!(f, "Error computing sighash"),
			SigningFailed => write!(f, "Failed to produce signature"),

            FailedToGetAccounts => write!(f, "Failed to get accounts from PSBT"),
			ExternalInputsNotSupported => write!(f, "External inputs are not supported"),
			WitnessUtxoNotAllowedForLegacy => {
				write!(f, "Witness UTXO is not allowed for Legacy transaction")
			}
			InvalidNonWitnessUtxo => write!(f, "Invalid non-witness UTXO"),
			NonWitnessUtxoMismatch => {
				write!(f, "Non-witness UTXO does not match the previous output")
			}
			NonWitnessUtxoRequired => write!(f, "Non-witness UTXO is required for SegWit version 0"),
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

			UnexpectedTaprootPolicy => write!(f, "Unexpected state: should be a Taproot wallet policy"),
			UnexpectedSegwitVersion => write!(f, "Unexpected state: should be SegwitV0 or Taproot"),

			UserRejected => write!(f, "Rejected by the user"),
		}
    }
}
