use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use common::message::{self, PartialSignature, Request, Response};
use sdk::vanadium_client::{VAppClient, VAppExecutionError};

use sdk::comm::SendMessageError;

#[derive(Debug)]
pub enum BitcoinClientError {
    VAppExecutionError(VAppExecutionError),
    SendMessageError(SendMessageError),
    InvalidResponse(&'static str),
    GenericError(&'static str),
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
        Self::GenericError(e)
    }
}

impl std::fmt::Display for BitcoinClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            BitcoinClientError::SendMessageError(e) => write!(f, "SendMessageError: {}", e),
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
            BitcoinClientError::InvalidResponse(_) => None,
            BitcoinClientError::GenericError(_) => None,
        }
    }
}

pub struct BitcoinClient {
    app_client: Box<dyn VAppClient + Send + Sync>,
}

impl<'a> BitcoinClient {
    pub fn new(app_client: Box<dyn VAppClient + Send + Sync>) -> Self {
        Self { app_client }
    }

    async fn send_message(&mut self, out: &[u8]) -> Result<Vec<u8>, BitcoinClientError> {
        sdk::comm::send_message(&mut self.app_client, out)
            .await
            .map_err(BitcoinClientError::from)
    }

    async fn parse_response(response_raw: &'a [u8]) -> Result<Response, BitcoinClientError> {
        let resp: Response = postcard::from_bytes(response_raw)
            .map_err(|_| BitcoinClientError::GenericError("Failed to parse response"))?;
        Ok(resp)
    }

    pub async fn get_version(&mut self) -> Result<String, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::GetVersion).map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetVersion request")
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::Version(version) => Ok(version),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn exit(&mut self) -> Result<i32, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::Exit)
            .map_err(|_| BitcoinClientError::GenericError("Failed to serialize Exit request"))?;

        match self.send_message(&msg).await {
            Ok(_) => {
                return Err(BitcoinClientError::GenericError(
                    "exit shouldn't return a response",
                ));
            }
            Err(e) => match e {
                BitcoinClientError::SendMessageError(SendMessageError::VAppExecutionError(
                    VAppExecutionError::AppExited(status),
                )) => Ok(status),
                _ => Err(BitcoinClientError::InvalidResponse(
                    "Unexpected error on exit",
                )),
            },
        }
    }

    pub async fn get_master_fingerprint(&mut self) -> Result<u32, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::GetMasterFingerprint).map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetMasterFingerprint request")
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::MasterFingerprint(fpr) => Ok(fpr),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn get_extended_pubkey(
        &mut self,
        bip32_path: &str,
        display: bool,
    ) -> Result<[u8; 78], BitcoinClientError> {
        let path =
            DerivationPath::from_str(bip32_path).map_err(|_| "Failed to convert bip32_path")?;

        let msg = postcard::to_allocvec(&Request::GetExtendedPubkey {
            display,
            path: message::Bip32Path(path.to_u32_vec()),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize GetExtendedPubkey request")
        })?;
        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::ExtendedPubkey(pubkey) => {
                let arr: [u8; 78] = pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| BitcoinClientError::InvalidResponse("Invalid pubkey length"))?;
                Ok(arr)
            }
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn register_account(
        &mut self,
        name: &str,
        account: &message::Account,
    ) -> Result<([u8; 32], [u8; 32]), BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::RegisterAccount {
            name: name.into(),
            account: account.clone(),
        })
        .map_err(|_| {
            BitcoinClientError::GenericError("Failed to serialize RegisterAccount request")
        })?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::AccountRegistered { account_id, hmac } => Ok((account_id, hmac)),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn get_address(
        &mut self,
        account: &message::Account,
        name: &str,
        coords: &message::AccountCoordinates,
        hmac: &[u8],
        display: bool,
    ) -> Result<String, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::GetAddress {
            display,
            name: Some(name.to_string()),
            account: account.clone(),
            hmac: hmac.to_vec(),
            coordinates: coords.clone(),
        })
        .map_err(|_| BitcoinClientError::GenericError("Failed to serialize GetAddress request"))?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::Address(addr) => Ok(addr),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }

    pub async fn sign_psbt(
        &mut self,
        psbt: &[u8],
    ) -> Result<Vec<PartialSignature>, BitcoinClientError> {
        let msg = postcard::to_allocvec(&Request::SignPsbt {
            psbt: psbt.to_vec(),
        })
        .map_err(|_| BitcoinClientError::GenericError("Failed to serialize SignPsbt request"))?;

        let response_raw = self.send_message(&msg).await?;
        match Self::parse_response(&response_raw).await? {
            Response::PsbtSigned(partial_sigs) => Ok(partial_sigs),
            _ => Err(BitcoinClientError::InvalidResponse("Invalid response")),
        }
    }
}
