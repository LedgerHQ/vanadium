//! This module provides functionality for sending messages to a V-App and receiving responses
//! according to a specific communication protocol.
//! See the documentation of the V-App SDK's `comm` module for more details.

use crate::vanadium_client::{VAppExecutionError, VAppTransport};

use common::comm::{ACK, CHUNK_LENGTH};

/// Error types that can occur during message transmission.
#[derive(Debug)]
pub enum SendMessageError {
    /// Error when an ACK was expected but a different message was received.
    NotAckReceived,
    /// Error returned from the VM.
    VAppExecutionError(VAppExecutionError),
    /// Error returned when the response is less than the expected 4 bytes.
    ResponseTooShort,
}

impl core::fmt::Display for SendMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendMessageError::NotAckReceived => write!(f, "ACK was expected but not received"),
            SendMessageError::ResponseTooShort => write!(f, "Response shorter than 4 bytes"),
            SendMessageError::VAppExecutionError(v) => write!(f, "Error from the VM: {}", v),
        }
    }
}

impl core::error::Error for SendMessageError {}

/// Sends a message and receives a response according to the protocol of the `comm` module of the SDK.
///
/// This function sends a message to a V-App and waits for a response.
/// The message is length-prefixed, then sent in chunks. After each chunk, an acknowledgment
/// message is expected from the V-App. If the acknowledgment is not received, an error is returned.
/// The response must start with a 4-byte length prefix, followed by the actual response data, which
/// is also split in chunks with the same approach.
///
/// # Arguments
///
/// * `transport` - The V-App transport.
/// * `message` - A byte slice containing the message to be sent.
///
/// # Returns
///
/// A `Result` containing a vector of bytes representing the response data if successful, or a
/// `SendMessageError` if an error occurs during the communication protocol.
///
/// # Errors
///
/// This function will return a `SendMessageError` if:
///
/// * An acknowledgment (ACK) is expected but not received.
/// * The response length is less than 4 bytes.
/// * An error occurs during the execution of the virtual application client.
///
pub async fn send_message(
    transport: &mut Box<dyn VAppTransport + Send + Sync>,
    message: &[u8],
) -> Result<Vec<u8>, SendMessageError> {
    // concatenate the length of the message (as a 4-byte big-endian) and the message itself
    let mut full_message: Vec<u8> = Vec::with_capacity(message.len() + 4);
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(message);

    let mut resp = ACK.to_vec();
    for chunk in full_message.chunks(CHUNK_LENGTH) {
        if resp != ACK {
            return Err(SendMessageError::NotAckReceived);
        }
        resp = transport
            .send_message(chunk)
            .await
            .map_err(SendMessageError::VAppExecutionError)?;
    }

    // The first 4 bytes contain the length of the data in the response.
    // All the remaining data is the response data.
    if resp.len() < 4 {
        return Err(SendMessageError::ResponseTooShort);
    }
    let response_data_len = u32::from_be_bytes(
        resp[0..4]
            .try_into()
            .map_err(|_| SendMessageError::ResponseTooShort)?,
    ) as usize;

    let mut response_data = resp[4..].to_vec();
    while response_data.len() < response_data_len {
        let resp = transport
            .send_message(&ACK)
            .await
            .map_err(SendMessageError::VAppExecutionError)?;
        response_data.extend_from_slice(&resp);
    }
    Ok(response_data)
}
