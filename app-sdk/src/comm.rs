//! Module for sending and receiving messages using a custom protocol with alternating acknowledgments.
//!
//! This module provides an efficient way to handle message transmission between endpoints by using
//! length-prefix ed messages. This allows applications to use a fixed-length buffer for short messages,
//! reducing the need for large preallocated buffers. Large vectors are only allocated if necessary.
//!
//! The protocol alternates between sending and receiving chunks of data, ensuring reliable communication
//! through acknowledgment control. Each chunk sent or received is acknowledged by the other endpoint,
//! maintaining synchronization and error management throughout the transmission process.
//!
//! Key features of this module include:
//! - **Chunked Data Transmission**: Messages are divided into manageable chunks, allowing for efficient
//!   transmission and reception without requiring large buffers.
//! - **Length-Prefixing**: Messages are prefixed with their length, enabling dynamic buffer allocation
//!   only when necessary.
//!
//! Note: This module is not thread-safe. It is designed for single-threaded execution due to the use of
//! a static mutable buffer for chunk reuse.

use crate::{xrecv_to, xsend};
use alloc::{vec, vec::Vec};
use core::cmp::min;
use core::convert::TryInto;

use common::comm::{ACK, CHUNK_LENGTH};

/// Error types that can occur during message transmission.
#[derive(Debug)]
pub enum MessageError {
    /// When no message is received. Not an actual error.
    NoMessage,
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
            MessageError::NoMessage => write!(f, "No message received"),
            MessageError::InvalidLength => write!(f, "Invalid message length"),
            MessageError::TooManyBytesReceived => write!(f, "Too many bytes received"),
            MessageError::FailedToReadMessage => write!(f, "Failed to read message"),
            MessageError::FailedToReadLength => write!(f, "Failed to read message length"),
        }
    }
}

impl core::error::Error for MessageError {}

// Define a static mutable buffer for chunk reuse, in order to avoid unnecessary allocations.
static mut CHUNK_BUFFER: [u8; CHUNK_LENGTH] = [0u8; CHUNK_LENGTH];

/// Receives a message, handling chunked data reception and error management.
///
/// The function starts by attempting to read a fixed-size chunk to extract the message length.
/// It then continues reading in chunks until the entire message is received, sending an
/// acknowledgment (`ACK`) byte for each chunk received. Errors occur if any unexpected
/// conditions are encountered, such as insufficient bytes or extra bytes in a chunk.
///
/// # Errors
///
/// - Returns `MessageError::NoMessage` if the initial chunk has length 0.
/// - Returns `MessageError::FailedToReadLength` if the initial chunk is too small to contain the
///   message length.
/// - Returns `MessageError::TooManyBytesReceived` if unexpected extra bytes are received.
/// - Returns `MessageError::FailedToReadMessage` if a chunk is empty or fails to be read.
///
/// # Returns
///
/// - On success, returns `Ok(Vec<u8>)` with the received message data.
///
/// # Safety
///
/// This function is only safe in single-threaded execution due to the use of a static mutable buffer.
pub fn receive_message() -> Result<Vec<u8>, MessageError> {
    let chunk = &raw mut CHUNK_BUFFER;

    let first_chunk_len = xrecv_to(unsafe { &mut *chunk });

    if first_chunk_len == 0 {
        return Err(MessageError::NoMessage);
    }

    // Ensure we have at least 4 bytes for the length.
    if first_chunk_len < 4 {
        return Err(MessageError::FailedToReadLength);
    }

    // Extract the message length.
    let length = u32::from_be_bytes(unsafe { &*chunk }[0..4].try_into().unwrap()) as usize;

    // Check for unexpected extra bytes.
    if first_chunk_len > 4 + length {
        return Err(MessageError::TooManyBytesReceived);
    }

    // Initialize the result with the data from the first chunk.
    let mut result = Vec::with_capacity(length);
    result.extend_from_slice(&unsafe { &*chunk }[4..first_chunk_len]);

    while result.len() < length {
        // Send ACK to maintain the alternating protocol.
        xsend(&ACK);

        let chunk_len = loop {
            // TODO: this is a workaround for a bug in VanadiumAsyncClient: while returning a 0-length message
            // is expected when idle, this shouldn't happen when we are in the middle of receiving a message.
            // This makes it tolerate the occasional 0-length chunk, but ideally this should be fixed in the client.
            let len = xrecv_to(unsafe { &mut *chunk });
            if len != 0 {
                break len;
            }
        };

        if chunk_len == 0 {
            return Err(MessageError::FailedToReadMessage);
        }

        if chunk_len > length - result.len() {
            return Err(MessageError::TooManyBytesReceived);
        }

        result.extend_from_slice(&unsafe { &*chunk }[0..chunk_len]);
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

    let mut acc_chunk = vec![0u8];
    // Send the remaining chunks.
    while total_bytes_sent < msg.len() {
        // Wait for ACK to maintain the alternating protocol.
        let acc_len = xrecv_to(&mut acc_chunk);
        if acc_len != 1 || acc_chunk != ACK {
            panic!("Unexpected byte received: {}", acc_chunk[0]);
        }

        let end_idx = min(total_bytes_sent + CHUNK_LENGTH, msg.len());
        let chunk = &msg[total_bytes_sent..end_idx];

        xsend(chunk);
        total_bytes_sent = end_idx;
    }
}
