//! Module for sending and receiving messages using a custom protocol with alternating acknowledgments.
//!
//! This module provides functions to send and receive messages with error handling, chunking, and
//! acknowledgment control to manage message transmission between endpoints.
//! The protocol alternates between sending and receiving chunks of data, as expected from the xsend
//! and xrecv functions.

use crate::{xrecv, xsend};
use alloc::vec::Vec;
use core::cmp::min;
use core::convert::TryInto;

/// ACK is a single-byte acknowledgment message.
const ACK: [u8; 1] = [0x42];

/// The length of each chunk of data to be sent or received when calling xrecv/xsend.
const CHUNK_LENGTH: usize = 256;

/// Error types that can occur during message transmission or reception.
#[derive(Debug)]
pub enum MessageError {
    /// Error when the received message length does not match expectations.
    InvalidLength,
    /// Error when more bytes are received than expected.
    TooManyBytesReceived,
    /// Error when a chunk fails to be received.
    FailedToReadMessage,
    /// Error when the message length cannot be determined due to insufficient bytes.
    FailedToReadLength,
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            MessageError::InvalidLength => write!(f, "Invalid message length"),
            MessageError::TooManyBytesReceived => write!(f, "Too many bytes received"),
            MessageError::FailedToReadMessage => write!(f, "Failed to read message"),
            MessageError::FailedToReadLength => write!(f, "Failed to read message length"),
        }
    }
}

impl core::error::Error for MessageError {}

/// Receives a message, handling chunked data reception and error management.
///
/// The function starts by attempting to read a fixed-size chunk to extract the message length.
/// It then continues reading in chunks until the entire message is received, sending an
/// acknowledgment (`ACK`) byte for each chunk received. Errors occur if any unexpected
/// conditions are encountered, such as insufficient bytes or extra bytes in a chunk.
///
/// # Errors
///
/// - Returns `MessageError::FailedToReadLength` if the initial chunk is too small to contain the
///   message length.
/// - Returns `MessageError::TooManyBytesReceived` if unexpected extra bytes are received.
/// - Returns `MessageError::FailedToReadMessage` if a chunk is empty or fails to be read.
///
/// # Returns
///
/// - On success, returns `Ok(Vec<u8>)` with the received message data.
pub fn receive_message() -> Result<Vec<u8>, MessageError> {
    let first_chunk = xrecv(256);

    // Ensure we have at least 4 bytes for the length.
    if first_chunk.len() < 4 {
        return Err(MessageError::FailedToReadLength);
    }

    // Extract the message length.
    let length = u32::from_be_bytes(first_chunk[0..4].try_into().unwrap()) as usize;

    // Check for unexpected extra bytes.
    if first_chunk.len() > 4 + length {
        return Err(MessageError::TooManyBytesReceived);
    }

    // Initialize the result with the data from the first chunk.
    let mut result = first_chunk[4..].to_vec();

    // Calculate the remaining bytes to read.
    let mut remaining_bytes = length - result.len();

    while remaining_bytes > 0 {
        // Send ACK to maintain the alternating protocol.
        xsend(&ACK);

        let chunk = xrecv(CHUNK_LENGTH);

        if chunk.is_empty() {
            return Err(MessageError::FailedToReadMessage);
        }

        if chunk.len() > remaining_bytes {
            return Err(MessageError::TooManyBytesReceived);
        }

        result.extend_from_slice(&chunk);
        remaining_bytes -= chunk.len();
    }

    Ok(result)
}

/// Sends a message, managing chunking and acknowledgment control for transmission.
///
/// The function begins by encoding the message length in big-endian format and sending an initial
/// chunk containing this length along with part of the message (if any). It then continues sending
/// chunks, waiting for an acknowledgment (`ACK`) byte from the receiver before each chunk is sent.
/// The process ensures that messages are transmitted sequentially and fully.
///
/// # Parameters
///
/// - `msg`: A reference to the message bytes (`&[u8]`) that should be sent.
///
/// The function does not return a value, nor any error.
/// On native execution, the function will panic if the underlying calls to `xsend` or `xrecv` panic.
/// On Risc-V targets, communication failure causes the ECALL to fail, which will arrest the execution of the VM.
pub fn send_message(msg: &[u8]) {
    // Encode the message length in big-endian format.
    let length_be = (msg.len() as u32).to_be_bytes();

    // Calculate how much of the message fits in the first chunk.
    let first_chunk_msg_bytes = min(CHUNK_LENGTH - 4, msg.len());

    // Send the initial chunk containing the length and part of the message.
    xsend(&[&length_be, &msg[..first_chunk_msg_bytes]].concat());

    let mut total_bytes_sent = first_chunk_msg_bytes;

    // Send the remaining chunks.
    while total_bytes_sent < msg.len() {
        // Wait for ACK to maintain the alternating protocol.
        let _ = xrecv(CHUNK_LENGTH);

        let end_idx = min(total_bytes_sent + CHUNK_LENGTH, msg.len());
        let chunk = &msg[total_bytes_sent..end_idx];

        xsend(chunk);
        total_bytes_sent = end_idx;
    }
}
