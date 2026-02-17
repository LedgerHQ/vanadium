// Vanadium VM client commands (responses to InterruptedExecution status word), and other related types

use crate::constants::PAGE_SIZE;
use alloc::vec::Vec;
use core::fmt;

const MAX_APDU_DATA_SIZE: usize = 590;

#[derive(Debug)]
pub enum MessageDeserializationError {
    InvalidClientCommandCode,
    MismatchingClientCommandCode,
    InvalidSectionKind,
    InvalidDataLength,
    UnexpectedCommandCode,
    InvalidBufferType,
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
            MessageDeserializationError::InvalidBufferType => {
                write!(f, "Invalid buffer type")
            }
        }
    }
}

impl core::error::Error for MessageDeserializationError {}

pub trait Message<'a>: Sized {
    fn serialize_with<F: FnMut(&[u8])>(&self, f: F);

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
    GetPageProofContinued = 1,
    CommitPage = 2,
    CommitPageProofContinued = 3,
    SendBuffer = 4,
    SendBufferContinued = 5,
    ReceiveBuffer = 6,
    GetCodePageHashes = 7,
}

impl TryFrom<u8> for ClientCommandCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClientCommandCode::GetPage),
            1 => Ok(ClientCommandCode::GetPageProofContinued),
            2 => Ok(ClientCommandCode::CommitPage),
            3 => Ok(ClientCommandCode::CommitPageProofContinued),
            4 => Ok(ClientCommandCode::SendBuffer),
            5 => Ok(ClientCommandCode::SendBufferContinued),
            6 => Ok(ClientCommandCode::ReceiveBuffer),
            7 => Ok(ClientCommandCode::GetCodePageHashes),
            _ => Err("Invalid value for ClientCommandCode"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageProofKind {
    Merkle = 0,
    Hmac = 1,
}

impl TryFrom<u8> for PageProofKind {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PageProofKind::Merkle),
            1 => Ok(PageProofKind::Hmac),
            _ => Err("Invalid page proof kind"),
        }
    }
}

/// Message sent by client in response to the VM's GetPageProofMessage
/// It contains the page's metadata, and either
/// - the Merkle proof of the page (or part of it), if using Merkle proofs
/// - the HMAC of the page, if using HMAC-based integrity verification
#[derive(Debug, Clone)]
pub struct GetPageResponse<'a> {
    pub page_data: &'a [u8; PAGE_SIZE],
    pub is_encrypted: bool, // whether the page is encrypted
    pub nonce: [u8; 12],    // nonce of the page encryption (all zeros if not encrypted)
    pub n: u8,              // number of element in the proof
    pub t: u8,              // number of proof elements in this message
    pub proof_kind: PageProofKind,
    pub proof: &'a [[u8; 32]], // Merkle proof elements OR single HMAC (length is 1 if HMAC)
}

impl<'a> GetPageResponse<'a> {
    #[inline]
    pub fn new(
        page_data: &'a [u8; PAGE_SIZE],
        is_encrypted: bool,
        nonce: [u8; 12],
        n: u8,
        t: u8,
        proof_kind: PageProofKind,
        proof: &'a [[u8; 32]],
    ) -> Self {
        GetPageResponse {
            page_data,
            is_encrypted,
            nonce,
            n,
            t,
            proof_kind,
            proof,
        }
    }

    pub const fn max_proof_size() -> usize {
        // page_data | n | t | is_encrypted | nonce(12) | proof_kind | proof elements
        (MAX_APDU_DATA_SIZE - PAGE_SIZE - 1 - 1 - 1 - 12 - 1) / 32
    }
}

impl<'a> Message<'a> for GetPageResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(self.page_data);
        f(&[self.n]);
        f(&[self.t]);
        f(&[self.is_encrypted as u8]);
        f(&self.nonce);
        f(&[self.proof_kind as u8]);
        for p in self.proof {
            f(p);
        }
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < PAGE_SIZE + 1 + 1 + 1 + 12 + 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let page_data = data[0..PAGE_SIZE].try_into().unwrap();
        let n = data[PAGE_SIZE];
        let t = data[PAGE_SIZE + 1];
        let is_encrypted = data[PAGE_SIZE + 2] == 1;
        let nonce = if is_encrypted {
            let mut arr = [0; 12];
            arr.copy_from_slice(&data[PAGE_SIZE + 3..PAGE_SIZE + 15]);
            arr
        } else {
            [0; 12]
        };
        let pk_byte = data[PAGE_SIZE + 15];
        let proof_kind = PageProofKind::try_from(pk_byte)
            .map_err(|_| MessageDeserializationError::InvalidDataLength)?;
        let proof_len = data.len() - (PAGE_SIZE + 1 + 1 + 1 + 12 + 1);
        if proof_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = proof_len / 32;
        let proof = unsafe {
            let ptr = data.as_ptr().add(PAGE_SIZE + 1 + 1 + 1 + 12 + 1) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(GetPageResponse {
            page_data,
            is_encrypted,
            nonce,
            n,
            t,
            proof_kind,
            proof,
        })
    }
}

/// Message sent by the VM to request the rest of the Merkle proof, if it didn't fit
/// in GetPageResponse
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

    pub const fn max_proof_size() -> usize {
        (MAX_APDU_DATA_SIZE - 1) / 32
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
pub struct CommitPageMessage<'a> {
    pub command_code: ClientCommandCode,
    pub section_kind: SectionKind,
    pub page_index: u32,
    pub is_encrypted: bool,        // whether the page is encrypted
    pub nonce: [u8; 12],           // nonce of the page encryption (all zeros if not encrypted)
    pub data: &'a [u8; PAGE_SIZE], // content of the page
}

impl<'a> CommitPageMessage<'a> {
    #[inline]
    pub fn new(
        section_kind: SectionKind,
        page_index: u32,
        is_encrypted: bool,
        nonce: [u8; 12],
        data: &'a [u8; PAGE_SIZE],
    ) -> Self {
        CommitPageMessage {
            command_code: ClientCommandCode::CommitPage,
            section_kind,
            page_index,
            is_encrypted,
            nonce,
            data,
        }
    }
}

impl<'a> Message<'a> for CommitPageMessage<'a> {
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
        f(self.data);
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() != 1 + 1 + 4 + 1 + 12 + PAGE_SIZE {
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

        // Safe extraction of the page data (starts after 1+1+4+1+12 = 19 bytes)
        let data: &'a [u8; PAGE_SIZE] = data[1 + 1 + 4 + 1 + 12..1 + 1 + 4 + 1 + 12 + PAGE_SIZE]
            .try_into()
            .map_err(|_| MessageDeserializationError::InvalidDataLength)?;

        Ok(CommitPageMessage {
            command_code,
            section_kind,
            page_index,
            is_encrypted,
            nonce,
            data,
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

    pub const fn max_proof_size() -> usize {
        (MAX_APDU_DATA_SIZE - 2 - 32) / 32
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

    pub const fn max_proof_size() -> usize {
        (MAX_APDU_DATA_SIZE - 1) / 32
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BufferType {
    VAppMessage = 0, // data buffer sent from the VApp to the host
    Panic = 1,       // the VApp panicked
    Print = 2,       // the VApp printed a message
}

impl TryFrom<u8> for BufferType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BufferType::VAppMessage),
            1 => Ok(BufferType::Panic),
            2 => Ok(BufferType::Print),
            _ => Err("Invalid buffer type"),
        }
    }
}

/// Message sent by the VM to send a buffer (or the first chunk of it) to the host during an ECALL_XSEND.
#[derive(Debug, Clone)]
pub struct SendBufferMessage<'a> {
    pub command_code: ClientCommandCode,
    pub buffer_type: BufferType,
    pub total_size: u32,
    pub data: &'a [u8],
}

impl<'a> SendBufferMessage<'a> {
    #[inline]
    pub fn new(total_size: u32, buffer_type: BufferType, data: &'a [u8]) -> Self {
        if data.len() > total_size as usize {
            panic!("Data size exceeds total size");
        }

        SendBufferMessage {
            command_code: ClientCommandCode::SendBuffer,
            buffer_type,
            total_size,
            data,
        }
    }

    pub const fn max_data_size() -> usize {
        MAX_APDU_DATA_SIZE - 6
    }
}

impl<'a> Message<'a> for SendBufferMessage<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&[self.buffer_type as u8]);
        f(&self.total_size.to_be_bytes());
        f(self.data);
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if (!matches!(command_code, ClientCommandCode::SendBuffer)) || (data.len() < 6) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }
        let buffer_type = BufferType::try_from(data[1])
            .map_err(|_| MessageDeserializationError::InvalidBufferType)?;
        let total_size = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let data = &data[6..];

        if data.len() > total_size as usize {
            return Err(MessageDeserializationError::InvalidDataLength);
        }

        Ok(SendBufferMessage {
            command_code,
            buffer_type,
            total_size,
            data,
        })
    }
}

pub struct SendBufferContinuedMessage<'a> {
    pub command_code: ClientCommandCode,
    pub data: &'a [u8],
}

impl<'a> SendBufferContinuedMessage<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        SendBufferContinuedMessage {
            command_code: ClientCommandCode::SendBufferContinued,
            data,
        }
    }

    pub const fn max_data_size() -> usize {
        MAX_APDU_DATA_SIZE - 1
    }
}

impl<'a> Message<'a> for SendBufferContinuedMessage<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(self.data);
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 1 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::SendBufferContinued) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }

        Ok(SendBufferContinuedMessage {
            command_code,
            data: &data[1..],
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

    pub const fn max_chunk_size() -> usize {
        MAX_APDU_DATA_SIZE - 4
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

/// Message sent by the Vanadium App to request the rest of the proof, if it didn't fit
/// in GetPageResponse
#[derive(Debug, Clone)]
pub struct GetCodePageHashes<'a> {
    pub command_code: ClientCommandCode,
    pub n_prev_batch_pages: u32, // number of code pages for which the host already sent the hashes in the previous batch
    pub prev_batch_enc_hmacs: &'a [[u8; 32]],
}

impl<'a> GetCodePageHashes<'a> {
    #[inline]
    pub fn new(n_prev_batch_pages: u32, prev_batch_enc_hmacs: &'a [[u8; 32]]) -> Self {
        GetCodePageHashes {
            command_code: ClientCommandCode::GetCodePageHashes,
            n_prev_batch_pages,
            prev_batch_enc_hmacs,
        }
    }

    pub const fn max_hashes() -> usize {
        (MAX_APDU_DATA_SIZE - 4 - 1) / 32
    }
}

impl<'a> Message<'a> for GetCodePageHashes<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&[self.command_code as u8]);
        f(&self.n_prev_batch_pages.to_be_bytes());
        for h in self.prev_batch_enc_hmacs {
            f(h);
        }
    }

    fn deserialize(data: &[u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 1 + 4 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let command_code = ClientCommandCode::try_from(data[0])
            .map_err(|_| MessageDeserializationError::InvalidClientCommandCode)?;
        if !matches!(command_code, ClientCommandCode::GetCodePageHashes) {
            return Err(MessageDeserializationError::MismatchingClientCommandCode);
        }
        let n_prev_batch_pages = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let hmacs_len = data.len() - 5;
        if hmacs_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = hmacs_len / 32;
        let prev_batch_enc_hmacs = unsafe {
            let ptr = data.as_ptr().add(5) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(GetCodePageHashes {
            command_code,
            n_prev_batch_pages,
            prev_batch_enc_hmacs,
        })
    }
}

/// The host's response to a GetCodePageHashes message.
#[derive(Debug, Clone)]
pub struct GetCodePageHashesResponse<'a> {
    pub n_code_pages: u32,
    pub code_page_hashes: &'a [[u8; 32]],
}

impl<'a> GetCodePageHashesResponse<'a> {
    #[inline]
    pub fn new(n_code_pages: u32, code_page_hashes: &'a [[u8; 32]]) -> Self {
        GetCodePageHashesResponse {
            n_code_pages,
            code_page_hashes,
        }
    }

    pub const fn max_hashes() -> usize {
        GetCodePageHashes::max_hashes()
    }
}

impl<'a> Message<'a> for GetCodePageHashesResponse<'a> {
    #[inline]
    fn serialize_with<F: FnMut(&[u8])>(&self, mut f: F) {
        f(&self.n_code_pages.to_be_bytes());
        for h in self.code_page_hashes {
            f(h);
        }
    }

    fn deserialize(data: &'a [u8]) -> Result<Self, MessageDeserializationError> {
        if data.len() < 4 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let n_code_pages = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let hashes_len = data.len() - 4;
        if hashes_len % 32 != 0 {
            return Err(MessageDeserializationError::InvalidDataLength);
        }
        let slice_len = hashes_len / 32;

        if slice_len != n_code_pages as usize {
            return Err(MessageDeserializationError::InvalidDataLength);
        }

        let code_page_hashes = unsafe {
            let ptr = data.as_ptr().add(4) as *const [u8; 32];
            core::slice::from_raw_parts(ptr, slice_len)
        };

        Ok(GetCodePageHashesResponse {
            n_code_pages,
            code_page_hashes,
        })
    }
}
