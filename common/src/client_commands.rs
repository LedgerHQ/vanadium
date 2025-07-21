// Vanadium VM client commands (responses to InterruptedExecution status word), and other related types

use crate::constants::PAGE_SIZE;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "device_sdk")]
use ledger_device_sdk::io::Comm;

#[derive(Debug)]
pub enum MessageDeserializationError {
    InvalidClientCommandCode,
    MismatchingClientCommandCode,
    InvalidSectionKind,
    InvalidDataLength,
    UnexpectedCommandCode,
}

impl fmt::Display for MessageDeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageDeserializationError::InvalidClientCommandCode => {
                write!(f, "Invalid client command code")
            }
            MessageDeserializationError::MismatchingClientCommandCode => {
                write!(f, "Mismatching client command code")
            }
            MessageDeserializationError::InvalidSectionKind => write!(f, "Invalid section kind"),
            MessageDeserializationError::InvalidDataLength => write!(f, "Invalid data length"),
            MessageDeserializationError::UnexpectedCommandCode => {
                write!(f, "Unexpected command code")
            }
        }
    }
}

impl core::error::Error for MessageDeserializationError {}

pub trait Message<'a>: Sized {
    fn serialize_with<F: FnMut(&[u8])>(&self, f: F);

    #[cfg(feature = "device_sdk")]
    #[inline]
    fn serialize_to_comm(&self, comm: &mut Comm) {
        self.serialize_with(|data| comm.append(data));
    }

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.serialize_with(|data| result.extend_from_slice(data));
        result
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError>;
}

// Commands from the VM to the client
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ClientCommandCode {
    GetPage = 0,
    GetPageProof = 1,
    GetPageProofContinued = 2,
    CommitPage = 3,
    CommitPageContent = 4,
    CommitPageProofContinued = 5,
    SendBuffer = 6,
    ReceiveBuffer = 7,
    SendPanicBuffer = 8,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientCommandCode::GetPage),
            1 => Ok(ClientCommandCode::GetPageProof),
            2 => Ok(ClientCommandCode::GetPageProofContinued),
            3 => Ok(ClientCommandCode::CommitPage),
            4 => Ok(ClientCommandCode::CommitPageContent),
            5 => Ok(ClientCommandCode::CommitPageProofContinued),
            6 => Ok(ClientCommandCode::SendBuffer),
            7 => Ok(ClientCommandCode::ReceiveBuffer),
            8 => Ok(ClientCommandCode::SendPanicBuffer),
            _ => Err("Invalid value for ClientCommandCode"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SectionKind {
    Code = 0,
    Data = 1,
    Stack = 2,
}

impl TryFrom<u8> for SectionKind {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SectionKind::Code),
            1 => Ok(SectionKind::Data),
            2 => Ok(SectionKind::Stack),
            _ => Err("Invalid section kind"),
        }
    }
}

// We use the _Message ending for messages from the VM to the host, and the _Response ending for messages from the host to the VM.

/// Message sent by the VM to request a page from the host
#[derive(Debug, Clone)]
pub struct GetPageMessage {
    pub command_code: ClientCommandCode,
    pub section_kind: SectionKind,
    pub page_index: u32,
}

impl GetPageMessage {
    #[inline]
    pub fn new(section_kind: SectionKind, page_index: u32) -> Self {
        GetPageMessage {
            command_code: ClientCommandCode::GetPage,
            section_kind,
            page_index,
        }
    }
}

impl<'a> Message<'a> for GetPageMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&[self.section_kind as u8]);
        f(&self.page_index.to_be_bytes());
    }

    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 6 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::GetPage) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }
        let section_kind = SectionKind::try_from(data[1])
            .map_err(|_| MessageDeserializationError::InvalidSectionKind)?;
        let page_index = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);

        Ok(GetPageMessage {
            command_code,
            section_kind,
            page_index,
        })
    }
}

/// Message sent by the VM to request a proof after getting a page
#[derive(Debug, Clone)]
pub struct GetPageProofMessage {
    pub command_code: ClientCommandCode,
}

impl GetPageProofMessage {
    #[inline]
    pub fn new() -> Self {
        GetPageProofMessage {
            command_code: ClientCommandCode::GetPageProof,
        }
    }
}

impl<'a> Message<'a> for GetPageProofMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
    }

    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::GetPageProof) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        Ok(GetPageProofMessage { command_code })
    }
}

/// Message sent by client in response to the VM's GetPageProofMessage
/// It contains the page's metadata, and the merkle proof of the page (or part of it)
#[derive(Debug, Clone)]
pub struct GetPageProofResponse<'a> {
    pub is_encrypted: bool,    // whether the page is encrypted
    pub nonce: [u8; 12],       // nonce of the page encryption (all zeros if not encrypted)
    pub n: u8,                 // number of element in the proof
    pub t: u8,                 // number of proof elements in this message
    pub proof: &'a [[u8; 32]], // hashes of the proof
}

impl<'a> GetPageProofResponse<'a> {
    #[inline]
    pub fn new(is_encrypted: bool, nonce: [u8; 12], n: u8, t: u8, proof: &'a [[u8; 32]]) -> Self {
        GetPageProofResponse {
            is_encrypted,
            nonce,
            n,
            t,
            proof,
        }
    }
}

impl<'a> Message<'a> for GetPageProofResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.n]);
        f(&[self.t]);
        f(&[self.is_encrypted as u8]);
        f(&self.nonce);
        for p in self.proof {
            f(p);
        }
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 1 + 1 + 1 + 12 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let n = data[0];
        let t = data[1];
        let is_encrypted = data[2] == 1;
        let nonce = if is_encrypted {
            let mut arr = [0; 12];
            arr.copy_from_slice(&data[3..15]);
            arr
        } else {
            [0; 12]
        };
        let proof_len = data.len() - (1 + 1 + 1 + 12);
        if proof_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = proof_len / 32;
        let proof = unsafe {
            let ptr = data.as_ptr().add(1 + 1 + 1 + 12) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(GetPageProofResponse {
            is_encrypted,
            nonce,
            n,
            t,
            proof,
        })
    }
}

/// Message sent by the VM to request the rest of the proof, if it didn't fit
/// in a single GetPageProofResponse
#[derive(Debug, Clone)]
pub struct GetPageProofContinuedMessage {
    pub command_code: ClientCommandCode,
}

impl GetPageProofContinuedMessage {
    #[inline]
    pub fn new() -> Self {
        GetPageProofContinuedMessage {
            command_code: ClientCommandCode::GetPageProofContinued,
        }
    }
}

impl<'a> Message<'a> for GetPageProofContinuedMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
    }

    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::GetPageProofContinued) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        Ok(GetPageProofContinuedMessage { command_code })
    }
}

#[derive(Debug, Clone)]
pub struct GetPageProofContinuedResponse<'a> {
    pub t: u8,                 // number of proof elements in this message
    pub proof: &'a [[u8; 32]], // hashes of the proof
}

impl<'a> GetPageProofContinuedResponse<'a> {
    #[inline]
    pub fn new(t: u8, proof: &'a [[u8; 32]]) -> Self {
        GetPageProofContinuedResponse { t, proof }
    }
}

impl<'a> Message<'a> for GetPageProofContinuedResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.t]);
        for p in self.proof {
            f(p);
        }
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let t = data[0];
        let proof_len = data.len() - 1;
        if proof_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = proof_len / 32;
        let proof = unsafe {
            let ptr = data.as_ptr().add(1) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(GetPageProofContinuedResponse { t, proof })
    }
}

/// Message sent by the VM to commit a page to the host
#[derive(Debug, Clone)]
pub struct CommitPageMessage {
    pub command_code: ClientCommandCode,
    pub section_kind: SectionKind,
    pub page_index: u32,
    pub is_encrypted: bool, // whether the page is encrypted
    pub nonce: [u8; 12],    // nonce of the page encryption (all zeros if not encrypted)
}

impl CommitPageMessage {
    #[inline]
    pub fn new(
        section_kind: SectionKind,
        page_index: u32,
        is_encrypted: bool,
        nonce: [u8; 12],
    ) -> Self {
        CommitPageMessage {
            command_code: ClientCommandCode::CommitPage,
            section_kind,
            page_index,
            is_encrypted,
            nonce,
        }
    }
}

impl<'a> Message<'a> for CommitPageMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&[self.section_kind as u8]);
        f(&self.page_index.to_be_bytes());
        if self.is_encrypted {
            f(&[1]);
            f(&self.nonce);
        } else {
            f(&[0; 13]); // 0 byte, followed by 12 zero bytes for the (unused) nonce
        }
    }

    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 1 + 1 + 4 + 1 + 12 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::CommitPage) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        let section_kind = SectionKind::try_from(data[1])
            .map_err(|_| MessageDeserializationError::InvalidSectionKind)?;
        let page_index = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);

        let is_encrypted = data[6] == 1;
        let nonce = if is_encrypted {
            let mut arr = [0; 12];
            arr.copy_from_slice(&data[7..19]);
            arr
        } else {
            [0; 12]
        };

        Ok(CommitPageMessage {
            command_code,
            section_kind,
            page_index,
            is_encrypted,
            nonce,
        })
    }
}

/// Part of the flow started with a CommitPageMessage; it contains the content of the page
#[derive(Debug, Clone)]
pub struct CommitPageContentMessage<'a> {
    pub command_code: ClientCommandCode,
    pub data: &'a [u8],
}

impl<'a> CommitPageContentMessage<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        if data.len() != PAGE_SIZE {
            panic!("Invalid data length for CommitPageContentMessage");
        }
        CommitPageContentMessage {
            command_code: ClientCommandCode::CommitPageContent,
            data,
        }
    }
}

impl<'a> Message<'a> for CommitPageContentMessage<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(self.data);
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != PAGE_SIZE + 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }

        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::CommitPageContent) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }
        Ok(CommitPageContentMessage {
            command_code,
            data: &data[1..],
        })
    }
}

/// Message sent by client in response to the VM's CommitPageContentMessage
#[derive(Debug, Clone)]
pub struct CommitPageProofResponse<'a> {
    pub n: u8, // number of element in the Merkle tree of proof (not counting new_root)
    pub t: u8, // number of proof elements in this message
    pub new_root: &'a [u8; 32], // new root hash
    pub proof: &'a [[u8; 32]], // hashes of Merkle proof of the update proof
}

impl<'a> CommitPageProofResponse<'a> {
    #[inline]
    pub fn new(n: u8, t: u8, new_root: &'a [u8; 32], proof: &'a [[u8; 32]]) -> Self {
        CommitPageProofResponse {
            n,
            t,
            new_root,
            proof,
        }
    }
}

impl<'a> Message<'a> for CommitPageProofResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.n]);
        f(&[self.t]);
        f(self.new_root);
        for p in self.proof {
            f(p);
        }
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 2 + 32 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let n = data[0];
        let t = data[1];

        let new_root = unsafe {
            let ptr = data.as_ptr().add(2) as *const [u8; 32];
            &*ptr
        };

        let proof_len = data.len() - (2 + 32);
        if proof_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = proof_len / 32;
        let proof = unsafe {
            let ptr = data.as_ptr().add(2 + 32) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(CommitPageProofResponse {
            n,
            t,
            new_root,
            proof,
        })
    }
}

/// Message sent by the VM to request the rest of the proof, if it didn't fit
/// in a single CommitPageProofResponse
#[derive(Debug, Clone)]
pub struct CommitPageProofContinuedMessage {
    pub command_code: ClientCommandCode,
}

impl CommitPageProofContinuedMessage {
    #[inline]
    pub fn new() -> Self {
        CommitPageProofContinuedMessage {
            command_code: ClientCommandCode::CommitPageProofContinued,
        }
    }
}

impl<'a> Message<'a> for CommitPageProofContinuedMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
    }

    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::CommitPageProofContinued) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        Ok(CommitPageProofContinuedMessage { command_code })
    }
}

#[derive(Debug, Clone)]
pub struct CommitPageProofContinuedResponse<'a> {
    pub t: u8,                 // number of proof elements in this message
    pub proof: &'a [[u8; 32]], // hashes of the proof
}

impl<'a> CommitPageProofContinuedResponse<'a> {
    #[inline]
    pub fn new(t: u8, proof: &'a [[u8; 32]]) -> Self {
        CommitPageProofContinuedResponse { t, proof }
    }
}

impl<'a> Message<'a> for CommitPageProofContinuedResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.t]);
        for p in self.proof {
            f(p);
        }
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let t = data[0];
        let proof_len = data.len() - 1;
        if proof_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = proof_len / 32;

        let proof = unsafe {
            let ptr = data.as_ptr().add(1) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(CommitPageProofContinuedResponse { t, proof })
    }
}

/// Message sent by the VM to send a buffer (or the first chunk of it) to the host during an ECALL_XSEND.
#[derive(Debug, Clone)]
pub struct SendBufferMessage<'a> {
    pub command_code: ClientCommandCode,
    pub total_remaining_size: u32,
    pub data: &'a [u8],
}

impl<'a> SendBufferMessage<'a> {
    #[inline]
    pub fn new(total_remaining_size: u32, data: &'a [u8]) -> Self {
        if data.len() > total_remaining_size as usize {
            panic!("Data size exceeds total remaining size");
        }

        SendBufferMessage {
            command_code: ClientCommandCode::SendBuffer,
            total_remaining_size,
            data,
        }
    }
}

impl<'a> Message<'a> for SendBufferMessage<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&self.total_remaining_size.to_be_bytes());
        f(self.data);
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if (!matches!(command_code, ClientCommandCode::SendBuffer)) || (data.len() < 5) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }
        let total_remaining_size = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let data = &data[5..];

        if data.len() > total_remaining_size as usize {
            return Err(MessageDeserializationError::InvalidDataLength);
        }

        Ok(SendBufferMessage {
            command_code,
            total_remaining_size,
            data,
        })
    }
}

/// Message sent by the VM to receive a buffer during an ECALL_XRECV.
#[derive(Debug, Clone)]
pub struct ReceiveBufferMessage {
    pub command_code: ClientCommandCode,
}

impl ReceiveBufferMessage {
    #[inline]
    pub fn new() -> Self {
        ReceiveBufferMessage {
            command_code: ClientCommandCode::ReceiveBuffer,
        }
    }
}

impl<'a> Message<'a> for ReceiveBufferMessage {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
    }
    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::ReceiveBuffer) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        Ok(ReceiveBufferMessage { command_code })
    }
}

/// The host's response to a ReceiveBufferMessage.
#[derive(Debug, Clone)]
pub struct ReceiveBufferResponse<'a> {
    pub remaining_length: u32,
    pub content: &'a [u8],
}

impl<'a> ReceiveBufferResponse<'a> {
    #[inline]
    pub fn new(remaining_length: u32, content: &'a [u8]) -> Self {
        ReceiveBufferResponse {
            remaining_length,
            content,
        }
    }
}

impl<'a> Message<'a> for ReceiveBufferResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&self.remaining_length.to_be_bytes());
        f(self.content);
    }

    #[inline]
    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 4 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let remaining_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if data.len() - 4 > remaining_length as usize {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        Ok(ReceiveBufferResponse {
            remaining_length,
            content: &data[4..],
        })
    }
}

/// Identical to SendBufferMessage, except for the different command code; used for panics.
#[derive(Debug, Clone)]
pub struct SendPanicBufferMessage<'a> {
    pub command_code: ClientCommandCode,
    pub total_remaining_size: u32,
    pub data: &'a [u8],
}

impl<'a> SendPanicBufferMessage<'a> {
    #[inline]
    pub fn new(total_remaining_size: u32, data: &'a [u8]) -> Self {
        if data.len() > total_remaining_size as usize {
            panic!("Data size exceeds total remaining size");
        }

        SendPanicBufferMessage {
            command_code: ClientCommandCode::SendPanicBuffer,
            total_remaining_size,
            data,
        }
    }
}

impl<'a> Message<'a> for SendPanicBufferMessage<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&self.total_remaining_size.to_be_bytes());
        f(self.data);
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::SendPanicBuffer) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        if data.len() < 5 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let total_remaining_size = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let data = &data[5..];

        if data.len() > total_remaining_size as usize {
            return Err(MessageDeserializationError::InvalidDataLength);
        }

        Ok(SendPanicBufferMessage {
            command_code,
            total_remaining_size,
            data,
        })
    }
}
