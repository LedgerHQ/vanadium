use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use common::message::{
    self, IdentitySignature, MuSig2PartialSignature, MuSig2Pubnonce, PartialSignature, Request,
    Response,
};
use common::por::{ProofOfRegistration, RegistrationId};
use sdk::vanadium_client::{VAppExecutionError, VAppTransport};

use sdk::comm::SendMessageError;

#[derive(Debug)]
pub enum BitcoinClientError {
    VAppExecutionError(VAppExecutionError),
    SendMessageError(SendMessageError),
    AppError(common::errors::Error), // the V-App returned an error response
    InvalidResponse(String),         // the V-App response was an unexpected type
    GenericError(String),
}

impl From<VAppExecutionError> for BitcoinClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<SendMessageError> for BitcoinClientError {
    fn from(e: SendMessageError) -> Self {
        Self::SendMessageError(e)
    }
}

impl From<&'static str> for BitcoinClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e.to_string())
    }
}

impl From<common::bip388::ParseError> for BitcoinClientError {
    fn from(e: common::bip388::ParseError) -> Self {
        Self::GenericError(format!("{:?}", e))
    }
}

impl From<String> for BitcoinClientError {
    fn from(e: String) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for BitcoinClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            BitcoinClientError::SendMessageError(e) => write!(f, "SendMessageError: {}", e),
            BitcoinClientError::AppError(e) => write!(f, "AppError: {}", e),
            BitcoinClientError::InvalidResponse(e) => write!(f, "InvalidResponse: {}", e),
            BitcoinClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for BitcoinClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BitcoinClientError::VAppExecutionError(e) => Some(e),
            BitcoinClientError::SendMessageError(e) => Some(e),
            Self::AppError(_) => None,
            BitcoinClientError::InvalidResponse(_) => None,
            BitcoinClientError::GenericError(_) => None,
        }
    }
}

pub struct BitcoinClient {
    vapp_transport: Box<dyn VAppTransport + Send>,
}

impl<'a> BitcoinClient {
    pub fn new(vapp_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { vapp_transport }
    }

    async fn send_message(&mut self, out: &[u8]) -> Result<Vec<u8>, BitcoinClientError> {
        sdk::comm::send_message(&mut self.vapp_transport, out)
            .await
            .map_err(BitcoinClientError::from)
    }

    // Parse app response; if the response is a Response::Error, it is converted to BitcoinClientError::AppError.
    async fn parse_response(response_raw: &'a [u8]) -> Result<Response, BitcoinClientError> {
        let mut decoder = minicbor::Decoder::new(response_raw);
        let resp: Response = decoder.decode().map_err(|_| {
            BitcoinClientError::GenericError("Failed to parse response".to_string())
        })?;
        if decoder.position() != response_raw.len() {
            return Err(BitcoinClientError::GenericError(
                "Failed to parse response".to_string(),
            ));
        }
        if let Response::Error { error } = resp {
            return Err(BitcoinClientError::AppError(error));
        }
        Ok(resp)
    }

    pub async fn exit(&mut self) -> Result<i32, BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::Exit).map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize Exit request".to_string())
        })?;

        match self.send_message(&msg).await {
            Ok(_) => {
                return Err(BitcoinClientError::GenericError(
                    "exit shouldn't return a response".to_string(),
                ));
            }
            Err(e) => match e {
                BitcoinClientError::SendMessageError(SendMessageError::VAppExecutionError(
                    VAppExecutionError::AppExited(status),
                )) => Ok(status),
                e => Err(BitcoinClientError::InvalidResponse(format!(
                    "Unexpected error on exit: {:?}",
                    e
                ))),
            },
        }
    }

    pub async fn get_master_fingerprint(
        &mut self,
        tree: message::KeyTree,
    ) -> Result<u32, BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::GetMasterFingerprint { tree }).map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetMasterFingerprint request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::MasterFingerprint { fingerprint } => Ok(fingerprint),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn get_extended_pubkey(
        &mut self,
        tree: message::KeyTree,
        bip32_path: &str,
        display: bool,
        identity_index: Option<u32>,
    ) -> Result<([u8; 78], Option<IdentitySignature>), BitcoinClientError> {
        let path = DerivationPath::from_str(bip32_path)
            .map_err(|e| format!("Failed to convert bip32_path: {}", e))?;

        let msg = minicbor::to_vec(&Request::GetExtendedPubkey {
            tree,
            display,
            path: message::Bip32Path(path.to_u32_vec()),
            identity_index,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetExtendedPubkey request".to_string(),
            )
        })?;
        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::ExtendedPubkey { xpub, identity_sig } => {
                let arr: [u8; 78] = xpub.as_slice().try_into().map_err(|_| {
                    BitcoinClientError::InvalidResponse("Invalid pubkey length".to_string())
                })?;
                Ok((arr, identity_sig))
            }
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Gets the i-th identity public key (xpub at path `m/1229210958'/i`).
    pub async fn get_identity_key(
        &mut self,
        index: Option<u32>,
        display: bool,
    ) -> Result<[u8; 78], BitcoinClientError> {
        let path = common::identity::identity_derivation_path(index);
        let msg = minicbor::to_vec(&Request::GetExtendedPubkey {
            tree: message::KeyTree::Standard,
            display,
            path: message::Bip32Path(path),
            identity_index: None,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetExtendedPubkey request".to_string(),
            )
        })?;
        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::ExtendedPubkey { xpub, .. } => {
                let arr: [u8; 78] = xpub.as_slice().try_into().map_err(|_| {
                    BitcoinClientError::InvalidResponse("Invalid pubkey length".to_string())
                })?;
                Ok(arr)
            }
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn register_account(
        &mut self,
        name: &str,
        account: &message::Account,
        registered_identities: Option<Vec<message::RegisteredIdentityEntry>>,
        key_signatures: Option<Vec<Option<message::IdentitySignature>>>,
        show_cleartext: bool,
    ) -> Result<
        (
            RegistrationId<common::bip388::WalletPolicy>,
            ProofOfRegistration<common::bip388::WalletPolicy>,
        ),
        BitcoinClientError,
    > {
        let msg = minicbor::to_vec(&Request::RegisterAccount {
            name: name.into(),
            account: account.clone(),
            registered_identities,
            key_signatures,
            show_cleartext,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize RegisterAccount request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::AccountRegistered { account_id, hmac } => Ok((
                RegistrationId::from_bytes(account_id),
                ProofOfRegistration::from_bytes(hmac),
            )),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn register_identity_key(
        &mut self,
        name: &str,
        pubkey: &[u8; 33],
    ) -> Result<
        (
            RegistrationId<common::identity::IdentityKey>,
            ProofOfRegistration<common::identity::IdentityKey>,
        ),
        BitcoinClientError,
    > {
        let msg = minicbor::to_vec(&Request::RegisterIdentityKey {
            name: name.into(),
            pubkey: pubkey.to_vec(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize RegisterIdentityKey request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::IdentityKeyRegistered { key_id, hmac } => Ok((
                RegistrationId::from_bytes(key_id),
                ProofOfRegistration::from_bytes(hmac),
            )),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn get_address(
        &mut self,
        account: &message::Account,
        name: &str,
        coords: &message::AccountCoordinates,
        por: Option<&ProofOfRegistration<common::bip388::WalletPolicy>>,
        display: bool,
        identity_index: Option<u32>,
    ) -> Result<(String, Option<IdentitySignature>), BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::GetAddress {
            display,
            name: Some(name.to_string()),
            account: account.clone(),
            por: por
                .map(|p| p.dangerous_as_bytes().to_vec())
                .unwrap_or(vec![]),
            coordinates: coords.clone(),
            identity_index,
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetAddress request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::Address {
                address,
                identity_sig,
            } => Ok((address, identity_sig)),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    /// Calls the V-App's `SignPsbt`. Behaviour depends on the PSBT contents:
    /// - Inputs whose wallet policy uses plain placeholders the device
    ///   controls → ECDSA / Schnorr partial signatures land in `signatures`.
    /// - Inputs with a `musig(...)` placeholder the device participates in →
    ///   - if the PSBT already carries this device's pubnonce
    ///     (BIP-373 `PSBT_IN_MUSIG2_PUB_NONCE`) → a round-2 partial signature
    ///     lands in `musig_partial_sigs`;
    ///   - otherwise → a round-1 pubnonce lands in `musig_pubnonces`, and the
    ///     host is expected to merge it with cosigners' nonces into the PSBT
    ///     and re-send for round 2.
    pub async fn sign_psbt(
        &mut self,
        psbt: &[u8],
    ) -> Result<SignedPsbtResponse, BitcoinClientError> {
        let msg = minicbor::to_vec(&Request::SignPsbt {
            psbt: psbt.to_vec(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize SignPsbt request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::PsbtSigned {
                signatures,
                musig_pubnonces,
                musig_partial_sigs,
            } => Ok(SignedPsbtResponse {
                signatures,
                musig_pubnonces,
                musig_partial_sigs,
            }),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }
}

/// All signing material the V-App can return from a single `SignPsbt` request.
///
/// `signatures` covers ECDSA and Schnorr partial signatures for plain key
/// placeholders. The two `musig_*` fields are non-empty only for PSBTs that
/// involve `musig(...)` placeholders this device participates in — see
/// [`BitcoinClient::sign_psbt`] for the round 1 / round 2 dispatch.
#[derive(Debug, Clone)]
pub struct SignedPsbtResponse {
    pub signatures: Vec<PartialSignature>,
    pub musig_pubnonces: Vec<MuSig2Pubnonce>,
    pub musig_partial_sigs: Vec<MuSig2PartialSignature>,
}
