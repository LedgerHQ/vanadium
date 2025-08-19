use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use common::account::ProofOfRegistration;
use common::message::{self, PartialSignature, Request, Response};
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
    app_transport: Box<dyn VAppTransport + Send>,
}

impl<'a> BitcoinClient {
    pub fn new(app_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { app_transport }
    }

    async fn send_message(&mut self, out: &[u8]) -> Result<Vec<u8>, BitcoinClientError> {
        sdk::comm::send_message(&mut self.app_transport, out)
            .await
            .map_err(BitcoinClientError::from)
    }

    // Parse app response; if the response is a Response::Error, it is converted to BitcoinClientError::AppError.
    async fn parse_response(response_raw: &'a [u8]) -> Result<Response, BitcoinClientError> {
        let resp: Response = postcard::from_bytes(response_raw).map_err(|_| {
            BitcoinClientError::GenericError("Failed to parse response".to_string())
        })?;
        if let Response::Error(e) = resp {
            return Err(BitcoinClientError::AppError(e));
        }
        Ok(resp)
    }

    pub async fn get_version(&mut self) -> Result<String, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::GetVersion).map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetVersion request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::Version(version) => Ok(version),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn exit(&mut self) -> Result<i32, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::Exit).map_err(|_| {
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

    pub async fn get_master_fingerprint(&mut self) -> Result<u32, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::GetMasterFingerprint).map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetMasterFingerprint request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::MasterFingerprint(fpr) => Ok(fpr),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn get_extended_pubkey(
        &mut self,
        bip32_path: &str,
        display: bool,
    ) -> Result<[u8; 78], BitcoinClientError> {
        let path = DerivationPath::from_str(bip32_path)
            .map_err(|e| format!("Failed to convert bip32_path: {}", e))?;

        let msg = postcard::to_allocvec(&Request::GetExtendedPubkey {
            display,
            path: message::Bip32Path(path.to_u32_vec()),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize GetExtendedPubkey request".to_string(),
            )
        })?;
        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::ExtendedPubkey(pubkey) => {
                let arr: [u8; 78] = pubkey.as_slice().try_into().map_err(|_| {
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
    ) -> Result<([u8; 32], ProofOfRegistration), BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::RegisterAccount {
            name: name.into(),
            account: account.clone(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError(
                "Failed to serialize RegisterAccount request".to_string(),
            )
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::AccountRegistered { account_id, hmac } => {
                Ok((account_id, ProofOfRegistration::from_bytes(hmac)))
            }
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
        por: Option<&ProofOfRegistration>,
        display: bool,
    ) -> Result<String, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::GetAddress {
            display,
            name: Some(name.to_string()),
            account: account.clone(),
            por: por
                .map(|p| p.dangerous_as_bytes().to_vec())
                .unwrap_or(vec![]),
            coordinates: coords.clone(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetAddress request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::Address(addr) => Ok(addr),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }

    pub async fn sign_psbt(
        &mut self,
        psbt: &[u8],
    ) -> Result<Vec<PartialSignature>, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::SignPsbt {
            psbt: psbt.to_vec(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize SignPsbt request".to_string())
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::PsbtSigned(partial_sigs) => Ok(partial_sigs),
            e => Err(BitcoinClientError::InvalidResponse(format!(
                "Invalid response: {:?}",
                e
            ))),
        }
    }
}
