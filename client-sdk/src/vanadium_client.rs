use async_trait::async_trait;
use common::vm::MemoryError;
use std::cmp::min;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use common::accumulator::{
    AccumulatorError, HashOutput, Hasher, MerkleAccumulator, VectorAccumulator,
};
use common::client_commands::{
    ClientCommandCode, CommitPageContentMessage, CommitPageMessage,
    CommitPageProofContinuedMessage, CommitPageProofContinuedResponse, CommitPageProofResponse,
    GetPageMessage, GetPageProofContinuedMessage, GetPageProofContinuedResponse,
    GetPageProofMessage, GetPageProofResponse, Message, MessageDeserializationError,
    ReceiveBufferMessage, ReceiveBufferResponse, SectionKind, SendBufferMessage,
    SendPanicBufferMessage,
};
use common::constants::{page_start, DEFAULT_STACK_START, PAGE_SIZE};
use common::manifest::Manifest;
use sha2::{Digest, Sha256};

use crate::apdu::{
    apdu_continue, apdu_continue_with_p1, apdu_register_vapp, apdu_run_vapp, APDUCommand,
    StatusWord,
};
use crate::elf::{self, ElfFile};
use crate::transport::Transport;

pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Hasher<32> for Sha256Hasher {
    fn new() -> Self {
        Sha256Hasher {
            hasher: Sha256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.hasher.update(data);
        self
    }

    fn digest(self, out: &mut [u8; 32]) {
        let result = self.hasher.finalize();
        out.copy_from_slice(&result);
    }
}

// Serializes a page in the format expected for the content of the leaf in the MerkleAccumulator, as follows:
// - Clear-text pages are serialized as a 0 byte, followed by 12 0 bytes, followed by PAGE_SIZE bytes (page plaintext).
// - Encrypted pages are serialized as a 1 byte, followed by 12 bytes for the nonce, followed by PAGE_SIZE bytes (page ciphertext).
fn get_serialized_page(data: &[u8], nonce: Option<&[u8; 12]>) -> Vec<u8> {
    let mut serialized_page = Vec::<u8>::with_capacity(1 + 12 + PAGE_SIZE);
    if let Some(nonce) = nonce {
        serialized_page.push(1); // is_encrypted
        serialized_page.extend_from_slice(nonce);
    } else {
        serialized_page.extend_from_slice(&[0; 13]); // 1 byte for is_encrypted, 12 bytes for nonce
    }
    serialized_page.extend_from_slice(data);
    serialized_page
}

#[derive(Debug)]
enum MemorySegmentError {
    PageNotFound,
    InvalidPageSize,
    MemoryError(MemoryError),
    AccumulatorError(AccumulatorError),
}

impl From<MemoryError> for MemorySegmentError {
    fn from(e: MemoryError) -> Self {
        MemorySegmentError::MemoryError(e)
    }
}

impl From<AccumulatorError> for MemorySegmentError {
    fn from(e: AccumulatorError) -> Self {
        MemorySegmentError::AccumulatorError(e)
    }
}

impl std::fmt::Display for MemorySegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MemorySegmentError::PageNotFound => write!(f, "Page not found"),
            MemorySegmentError::InvalidPageSize => write!(f, "Invalid page size"),
            MemorySegmentError::MemoryError(e) => write!(f, "Memory error: {}", e),
            MemorySegmentError::AccumulatorError(e) => write!(f, "Accumulator error: {}", e),
        }
    }
}

impl std::error::Error for MemorySegmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemorySegmentError::MemoryError(e) => Some(e),
            MemorySegmentError::AccumulatorError(e) => Some(e),
            _ => None,
        }
    }
}

// Represents a memory segment stored by the client, using a MerkleAccumulator to provide proofs of integrity.
pub struct MemorySegment {
    content: MerkleAccumulator<Sha256Hasher, Vec<u8>, 32>,
}

impl MemorySegment {
    pub fn new(start: u32, data: &[u8]) -> Self {
        let end = start + data.len() as u32;

        let mut pages: Vec<Vec<u8>> = Vec::new();

        // current position, in terms of address; `start` needs to be subtracted for the position in `data`
        let mut current_addr = start;
        loop {
            if current_addr >= end {
                break;
            }
            let mut page_content: Vec<u8> = Vec::with_capacity(PAGE_SIZE);
            let page_start_addr = page_start(current_addr as u32);
            let page_end_addr = page_start_addr + PAGE_SIZE as u32;
            let content_end_addr = min(page_end_addr, end);

            // 0-pad with current_addr - page_start_addr bytes (always 0, except for the first page if unaligned to PAGE_SIZE)
            page_content.extend_from_slice(&vec![0; (current_addr - page_start_addr) as usize]);

            // copy content_end_addr - current_addr bytes from data
            page_content.extend_from_slice(
                &data[(current_addr - start) as usize..(content_end_addr - start) as usize],
            );

            // 0-pad with page_end_addr - content_end_addr bytes bytes (always 0, except possibly for last page)
            page_content.extend_from_slice(&vec![0; (page_end_addr - content_end_addr) as usize]);

            current_addr = page_end_addr;

            let serialized_page = get_serialized_page(&page_content, None);

            pages.push(serialized_page);
        }

        Self {
            content: MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(pages),
        }
    }

    fn get_page(
        &self,
        page_index: u32,
    ) -> Result<(Vec<u8>, Vec<HashOutput<32>>), MemorySegmentError> {
        let content = self
            .content
            .get(page_index as usize)
            .ok_or(MemorySegmentError::PageNotFound)?
            .clone();

        let proof = self.content.prove(page_index as usize)?;

        Ok((content, proof))
    }

    fn store_page(
        &mut self,
        page_index: u32,
        content: &[u8],
    ) -> Result<(Vec<HashOutput<32>>, HashOutput<32>), MemorySegmentError> {
        if content.len() != 1 + 12 + PAGE_SIZE {
            return Err(MemorySegmentError::InvalidPageSize);
        }
        let proof = self.content.update(page_index as usize, content.to_vec())?;
        Ok(proof)
    }

    pub fn get_content_root(&self) -> &HashOutput<32> {
        self.content.root()
    }
}

enum VAppMessage {
    SendBuffer(Vec<u8>),
    SendPanicBuffer(String),
    VAppExited { status: i32 },
}

enum ClientMessage {
    ReceiveBuffer(Vec<u8>),
}

#[derive(Debug)]
pub enum VAppEngineError<E: std::fmt::Debug + Send + Sync + 'static> {
    ManifestSerializationError,
    InvalidCommandCode,
    TransportError(E),
    AccessViolation,
    InterruptedExecutionExpected,
    ResponseError(&'static str),
    VMRuntimeError,
    VAppPanic,
    GenericError(Box<dyn std::error::Error + Send + Sync>),
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::fmt::Display for VAppEngineError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VAppEngineError::ManifestSerializationError => {
                write!(f, "Manifest serialization error")
            }
            VAppEngineError::InvalidCommandCode => write!(f, "Invalid command code"),
            VAppEngineError::TransportError(e) => write!(f, "Transport error: {:?}", e),
            VAppEngineError::AccessViolation => write!(f, "Access violation"),
            VAppEngineError::InterruptedExecutionExpected => {
                write!(f, "Expected an interrupted execution status word")
            }
            VAppEngineError::ResponseError(e) => write!(f, "Invalid response: {}", e),
            VAppEngineError::VMRuntimeError => write!(f, "VM runtime error"),
            VAppEngineError::VAppPanic => write!(f, "V-App panicked"),
            VAppEngineError::GenericError(e) => write!(f, "Generic error: {}", e),
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::error::Error for VAppEngineError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VAppEngineError::ManifestSerializationError => None,
            VAppEngineError::InvalidCommandCode => None,
            VAppEngineError::TransportError(_) => None,
            VAppEngineError::AccessViolation => None,
            VAppEngineError::InterruptedExecutionExpected => None,
            VAppEngineError::ResponseError(_) => None,
            VAppEngineError::VMRuntimeError => None,
            VAppEngineError::VAppPanic => None,
            VAppEngineError::GenericError(e) => Some(&**e),
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> From<postcard::Error> for VAppEngineError<E> {
    fn from(error: postcard::Error) -> Self {
        VAppEngineError::GenericError(Box::new(error))
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> From<MemorySegmentError> for VAppEngineError<E> {
    fn from(error: MemorySegmentError) -> Self {
        VAppEngineError::GenericError(Box::new(error))
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> From<MessageDeserializationError>
    for VAppEngineError<E>
{
    fn from(error: MessageDeserializationError) -> Self {
        VAppEngineError::GenericError(Box::new(error))
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> From<Box<dyn std::error::Error + Send + Sync>>
    for VAppEngineError<E>
{
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        VAppEngineError::GenericError(error)
    }
}

struct VAppEngine<E: std::fmt::Debug + Send + Sync + 'static> {
    manifest: Manifest,
    code_seg: MemorySegment,
    data_seg: MemorySegment,
    stack_seg: MemorySegment,
    transport: Arc<dyn Transport<Error = E>>,
    engine_to_client_sender: mpsc::Sender<VAppMessage>,
    client_to_engine_receiver: mpsc::Receiver<ClientMessage>,
}

impl<E: std::fmt::Debug + Send + Sync + 'static> VAppEngine<E> {
    pub async fn run(mut self, app_hmac: [u8; 32]) -> Result<(), VAppEngineError<E>> {
        let serialized_manifest = postcard::to_allocvec(&self.manifest)?;

        let (status, result) = self
            .transport
            .exchange(&apdu_run_vapp(serialized_manifest, app_hmac))
            .await
            .map_err(VAppEngineError::TransportError)?;

        self.busy_loop(status, result).await
    }

    // Sends and APDU and repeatedly processes the response if it's a GetPage or CommitPage client command.
    // Returns as soon as a different response is received.
    async fn exchange_and_process_page_requests(
        &mut self,
        apdu: &APDUCommand,
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        let (mut status, mut result) = self
            .transport
            .exchange(apdu)
            .await
            .map_err(VAppEngineError::TransportError)?;

        loop {
            if status != StatusWord::InterruptedExecution || result.len() == 0 {
                return Ok((status, result));
            }
            let client_command_code: ClientCommandCode = result[0]
                .try_into()
                .map_err(|_| VAppEngineError::InvalidCommandCode)?;

            (status, result) = match client_command_code {
                ClientCommandCode::GetPage => self.process_get_page(&result).await?,
                ClientCommandCode::CommitPage => self.process_commit_page(&result).await?,
                _ => return Ok((status, result)),
            }
        }
    }

    async fn process_get_page(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        let GetPageMessage {
            command_code: _,
            section_kind,
            page_index,
        } = GetPageMessage::deserialize(command)?;

        let segment = match section_kind {
            SectionKind::Code => &self.code_seg,
            SectionKind::Data => &self.data_seg,
            SectionKind::Stack => &self.stack_seg,
        };

        // Get the serialized page content and its proof
        let (mut serialized_page, proof) = segment.get_page(page_index)?;

        assert!(serialized_page.len() == 1 + 12 + PAGE_SIZE);

        // split the first 13 bytes from the actual page data:
        let (header, data) = serialized_page.split_at_mut(13);

        let is_encrypted = header[0] != 0;
        let nonce: [u8; 12] = header[1..13].try_into().unwrap();

        // Convert HashOutput<32> to [u8; 32]
        let proof: Vec<[u8; 32]> = proof.into_iter().map(|h| h.0).collect();

        let p1 = data[PAGE_SIZE - 1];

        // Return the content of the page (the last byte is in p1)
        let (status, result) = self
            .transport
            .exchange(&apdu_continue_with_p1(data[0..PAGE_SIZE - 1].to_vec(), p1))
            .await
            .map_err(VAppEngineError::TransportError)?;

        // If the VM requests a proof, handle it
        if status != StatusWord::InterruptedExecution || result.is_empty() {
            return Err(VAppEngineError::InterruptedExecutionExpected);
        }

        // We expect this message from the VM
        GetPageProofMessage::deserialize(&result)?;

        // Calculate how many proof elements we can send in one message
        let max_proof_elements = (255 - 2) / 32; // 2 bytes for n and t, 32 bytes per proof element
        let t = std::cmp::min(proof.len(), max_proof_elements) as u8;

        // Create the proof response
        let response = GetPageProofResponse::new(
            is_encrypted,
            nonce,
            proof.len() as u8,
            t,
            proof[0..t as usize].to_vec(),
        )
        .serialize();

        let (status, result) = self
            .transport
            .exchange(&apdu_continue(response))
            .await
            .map_err(VAppEngineError::TransportError)?;

        // If there are more proof elements to send and VM requests them
        if t < proof.len() as u8 {
            if status != StatusWord::InterruptedExecution || result.is_empty() {
                return Err(VAppEngineError::InterruptedExecutionExpected);
            }

            GetPageProofContinuedMessage::deserialize(&result)?;

            let mut offset = t as usize;

            // Send remaining proof elements, potentially in multiple messages
            while offset < proof.len() {
                let remaining = proof.len() - offset;
                let t = std::cmp::min(remaining, max_proof_elements) as u8;

                let response = GetPageProofContinuedResponse::new(
                    t,
                    proof[offset..offset + t as usize].to_vec(),
                )
                .serialize();

                let (new_status, new_result) = self
                    .transport
                    .exchange(&apdu_continue(response))
                    .await
                    .map_err(VAppEngineError::TransportError)?;

                offset += t as usize;

                // If we've sent all proof elements, return the status and result
                if offset >= proof.len() {
                    return Ok((new_status, new_result));
                }

                // Otherwise, expect another GetPageProofContinuedMessage
                if new_status != StatusWord::InterruptedExecution {
                    return Err(VAppEngineError::InterruptedExecutionExpected);
                }

                if let Ok(GetPageProofContinuedMessage { command_code }) =
                    GetPageProofContinuedMessage::deserialize(&new_result)
                {
                    if !matches!(command_code, ClientCommandCode::GetPageProofContinued) {
                        return Err(VAppEngineError::ResponseError(
                            "Unexpected command code during proof continuation",
                        ));
                    }
                } else {
                    return Err(VAppEngineError::ResponseError(
                        "Failed to deserialize GetPageProofContinuedMessage",
                    ));
                }
            }
        }
        Ok((status, result))
    }

    async fn process_commit_page(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        let msg = CommitPageMessage::deserialize(command)?;

        let segment = match msg.section_kind {
            SectionKind::Code => {
                return Err(VAppEngineError::AccessViolation);
            }
            SectionKind::Data => &mut self.data_seg,
            SectionKind::Stack => &mut self.stack_seg,
        };

        // get the next message, which contains the content of the page
        let (tmp_status, tmp_result) = self
            .transport
            .exchange(&apdu_continue(vec![]))
            .await
            .map_err(VAppEngineError::TransportError)?;

        if tmp_status != StatusWord::InterruptedExecution {
            return Err(VAppEngineError::InterruptedExecutionExpected);
        }

        let CommitPageContentMessage {
            command_code: _,
            data,
        } = CommitPageContentMessage::deserialize(&tmp_result)?;

        assert!(data.len() == PAGE_SIZE);
        assert!(msg.is_encrypted == true); // the VM should always commit to encrypted pages

        let mut serialized_page = Vec::<u8>::with_capacity(1 + 12 + PAGE_SIZE);
        serialized_page.push(msg.is_encrypted as u8);
        serialized_page.extend_from_slice(&msg.nonce);
        serialized_page.extend_from_slice(&data);

        // Store page and get proof
        let (proof, new_root) = segment.store_page(msg.page_index, &serialized_page)?;

        // Convert HashOutput<32> to [u8; 32]
        let proof: Vec<[u8; 32]> = proof.into_iter().map(|h| h.into()).collect();

        // Calculate how many proof elements we can send in one message
        let max_proof_elements = (255 - 2 - 32) / 32; // 2 bytes for n and t, 32 bytes for new_root, then 32 bytes for each proof element
        let t = std::cmp::min(proof.len(), max_proof_elements) as u8;

        // Create the proof response
        let response = CommitPageProofResponse::new(
            proof.len() as u8,
            t,
            new_root.into(),
            proof[0..t as usize].to_vec(),
        )
        .serialize();

        let (status, result) = self
            .transport
            .exchange(&apdu_continue(response))
            .await
            .map_err(VAppEngineError::TransportError)?;

        // If there are more proof elements to send and VM requests them
        if t < proof.len() as u8 && status == StatusWord::InterruptedExecution && !result.is_empty()
        {
            // CommitPageProofContinuedMessage have a different size
            let max_proof_elements = (255 - 2) / 32; // 2 bytes for n and t, 32 bytes per proof element

            let Ok(CommitPageProofContinuedMessage { command_code: _ }) =
                CommitPageProofContinuedMessage::deserialize(&result)
            else {
                return Err(VAppEngineError::ResponseError(
                    "Failed to deserialize CommitPageProofContinuedMessage",
                ));
            };
            let mut offset = t as usize;

            // Send remaining proof elements, potentially in multiple messages
            while offset < proof.len() {
                let remaining = proof.len() - offset;
                let t = std::cmp::min(remaining, max_proof_elements) as u8;

                let response = CommitPageProofContinuedResponse::new(
                    t,
                    proof[offset..offset + t as usize].to_vec(),
                )
                .serialize();

                let (new_status, new_result) = self
                    .transport
                    .exchange(&apdu_continue(response))
                    .await
                    .map_err(VAppEngineError::TransportError)?;

                offset += t as usize;

                // If we've sent all proof elements, return the status and result
                if offset >= proof.len() {
                    return Ok((new_status, new_result));
                }

                // Otherwise, expect another CommitPageProofContinuedMessage
                if new_status != StatusWord::InterruptedExecution {
                    return Err(VAppEngineError::InterruptedExecutionExpected);
                }

                if let Ok(CommitPageProofContinuedMessage { command_code }) =
                    CommitPageProofContinuedMessage::deserialize(&new_result)
                {
                    if !matches!(command_code, ClientCommandCode::CommitPageProofContinued) {
                        return Err(VAppEngineError::ResponseError(
                            "Unexpected command code during proof continuation",
                        ));
                    }
                } else {
                    return Err(VAppEngineError::ResponseError(
                        "Failed to deserialize CommitPageProofContinuedMessage",
                    ));
                }
            }
        }

        Ok((status, result))
    }

    // receive a buffer sent by the V-App via xsend; send it to the VappEngine
    async fn process_send_buffer(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        let SendBufferMessage {
            command_code: _,
            total_remaining_size: mut remaining_len,
            data: mut buf,
        } = SendBufferMessage::deserialize(command)?;

        if (buf.len() as u32) > remaining_len {
            return Err(VAppEngineError::ResponseError(
                "Received data length exceeds expected remaining length",
            ));
        }

        remaining_len -= buf.len() as u32;

        while remaining_len > 0 {
            let (status, result) = self
                .exchange_and_process_page_requests(&apdu_continue(vec![]))
                .await?;

            if status != StatusWord::InterruptedExecution {
                return Err(VAppEngineError::InterruptedExecutionExpected);
            }
            if result.len() == 0 {
                return Err(VAppEngineError::ResponseError("Empty response"));
            }

            let msg = SendBufferMessage::deserialize(&result)?;

            if msg.total_remaining_size != remaining_len {
                return Err(VAppEngineError::ResponseError(
                    "Received total_remaining_size does not match expected",
                ));
            }

            buf.extend_from_slice(&msg.data);
            remaining_len -= msg.data.len() as u32;
        }

        // Send the buffer back to the client via engine_to_client_sender
        self.engine_to_client_sender
            .send(VAppMessage::SendBuffer(buf))
            .await
            .map_err(|e| VAppEngineError::GenericError(Box::new(e)))?;

        self.exchange_and_process_page_requests(&apdu_continue(vec![]))
            .await
    }

    // the V-App is expecting a buffer via xrecv; get it from the VAppEngine, and send it to the V-App
    async fn process_receive_buffer(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        ReceiveBufferMessage::deserialize(command)?;

        // Wait for the message from the client
        let ClientMessage::ReceiveBuffer(bytes) = self
            .client_to_engine_receiver
            .recv()
            .await
            .ok_or(VAppEngineError::ResponseError(
                "Failed to receive buffer from client",
            ))?;

        let mut remaining_len = bytes.len() as u32;
        let mut offset: usize = 0;

        loop {
            // TODO: check if correct when the buffer is long
            let chunk_len = min(remaining_len, 255 - 4);
            let data = ReceiveBufferResponse::new(
                remaining_len,
                bytes[offset..offset + chunk_len as usize].to_vec(),
            )
            .serialize();

            let (status, result) = self
                .exchange_and_process_page_requests(&apdu_continue(data))
                .await?;

            remaining_len -= chunk_len;
            offset += chunk_len as usize;

            if remaining_len == 0 {
                return Ok((status, result));
            } else {
                // the message is not over, so we expect an InterruptedExecution status word
                // and another ReceiveBufferMessage to receive the rest.
                if status != StatusWord::InterruptedExecution {
                    return Err(VAppEngineError::InterruptedExecutionExpected);
                }
                if result.len() == 0 {
                    return Err(VAppEngineError::ResponseError("Empty response"));
                }
                ReceiveBufferMessage::deserialize(&result)?;
            }
        }
    }

    // receive a buffer sent by the V-App during a panic; send it to the VAppEngine
    // TODO: almost identical to process_send_buffer; it might be nice to refactor
    async fn process_send_panic_buffer(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        let SendPanicBufferMessage {
            command_code: _,
            total_remaining_size: mut remaining_len,
            data: mut buf,
        } = SendPanicBufferMessage::deserialize(command)?;

        if (buf.len() as u32) > remaining_len {
            return Err(VAppEngineError::ResponseError(
                "Received data length exceeds expected remaining length",
            ));
        }

        remaining_len -= buf.len() as u32;

        while remaining_len > 0 {
            let (status, result) = self
                .exchange_and_process_page_requests(&apdu_continue(vec![]))
                .await?;

            if status != StatusWord::InterruptedExecution {
                return Err(VAppEngineError::InterruptedExecutionExpected);
            }
            if result.len() == 0 {
                return Err(VAppEngineError::ResponseError("Empty response"));
            }
            let msg = SendPanicBufferMessage::deserialize(&result)?;

            if msg.total_remaining_size != remaining_len {
                return Err(VAppEngineError::ResponseError(
                    "Received total_remaining_size does not match expected",
                ));
            }

            buf.extend_from_slice(&msg.data);
            remaining_len -= msg.data.len() as u32;
        }

        let panic_message =
            String::from_utf8(buf).map_err(|e| VAppEngineError::GenericError(Box::new(e)))?;

        // Send the panic message back to the client via engine_to_client_sender
        self.engine_to_client_sender
            .send(VAppMessage::SendPanicBuffer(panic_message))
            .await
            .map_err(|e| VAppEngineError::GenericError(Box::new(e)))?;

        // Continue processing
        self.exchange_and_process_page_requests(&apdu_continue(vec![]))
            .await
    }

    async fn busy_loop(
        &mut self,
        first_sw: StatusWord,
        first_result: Vec<u8>,
    ) -> Result<(), VAppEngineError<E>> {
        let mut status = first_sw;
        let mut result = first_result;

        loop {
            if status == StatusWord::OK {
                if result.len() != 4 {
                    return Err(VAppEngineError::ResponseError(
                        "The V-App should return a 4-byte exit code",
                    ));
                }
                let st = i32::from_be_bytes(result.try_into().unwrap());
                self.engine_to_client_sender
                    .send(VAppMessage::VAppExited { status: st })
                    .await
                    .map_err(|e| VAppEngineError::GenericError(Box::new(e)))?;
                return Ok(());
            }

            if status == StatusWord::VMRuntimeError {
                return Err(VAppEngineError::VMRuntimeError);
            }

            if status == StatusWord::VAppPanic {
                return Err(VAppEngineError::VAppPanic);
            }

            if status != StatusWord::InterruptedExecution {
                return Err(VAppEngineError::InterruptedExecutionExpected);
            }

            if result.len() == 0 {
                return Err(VAppEngineError::ResponseError("empty command"));
            }

            let client_command_code: ClientCommandCode = result[0]
                .try_into()
                .map_err(|_| VAppEngineError::InvalidCommandCode)?;

            (status, result) = match client_command_code {
                ClientCommandCode::GetPage => self.process_get_page(&result).await?,
                ClientCommandCode::CommitPage => self.process_commit_page(&result).await?,
                ClientCommandCode::SendBuffer => self.process_send_buffer(&result).await?,
                ClientCommandCode::ReceiveBuffer => self.process_receive_buffer(&result).await?,
                ClientCommandCode::SendPanicBuffer => {
                    self.process_send_panic_buffer(&result).await?
                }
                ClientCommandCode::CommitPageContent
                | ClientCommandCode::GetPageProof
                | ClientCommandCode::GetPageProofContinued
                | ClientCommandCode::CommitPageProofContinued => {
                    // not a top-level command, part of the handling of some other command
                    return Err(VAppEngineError::ResponseError("Unexpected command"));
                }
            }
        }
    }
}

struct GenericVanadiumClient<E: std::fmt::Debug + Send + Sync + 'static> {
    client_to_engine_sender: Option<mpsc::Sender<ClientMessage>>,
    engine_to_client_receiver: Option<Mutex<mpsc::Receiver<VAppMessage>>>,
    vapp_engine_handle: Option<JoinHandle<Result<(), VAppEngineError<E>>>>,
}

#[derive(Debug)]
enum VanadiumClientError {
    VAppPanicked(String),
    VAppExited(i32),
    GenericError(String),
}

impl From<&str> for VanadiumClientError {
    fn from(s: &str) -> Self {
        VanadiumClientError::GenericError(s.to_string())
    }
}

impl std::fmt::Display for VanadiumClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VanadiumClientError::VAppPanicked(msg) => write!(f, "VApp panicked: {}", msg),
            VanadiumClientError::VAppExited(code) => write!(f, "VApp exited with code: {}", code),
            VanadiumClientError::GenericError(msg) => write!(f, "Generic error: {}", msg),
        }
    }
}

impl std::error::Error for VanadiumClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> GenericVanadiumClient<E> {
    pub fn new() -> Self {
        Self {
            client_to_engine_sender: None,
            engine_to_client_receiver: None,
            vapp_engine_handle: None,
        }
    }

    pub async fn register_vapp(
        &self,
        transport: Arc<dyn Transport<Error = E>>,
        manifest: &Manifest,
    ) -> Result<[u8; 32], &'static str> {
        let serialized_manifest =
            postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed")?;

        let (status, result) = transport
            .exchange(&apdu_register_vapp(serialized_manifest))
            .await
            .map_err(|_| "exchange failed")?;

        match status {
            StatusWord::OK => {
                if result.len() != 32 {
                    return Err("Invalid response length");
                }
                let mut hmac = [0u8; 32];
                hmac.copy_from_slice(&result);
                Ok(hmac)
            }
            _ => Err("Failed to register vapp"),
        }
    }

    pub fn run_vapp(
        &mut self,
        transport: Arc<dyn Transport<Error = E>>,
        manifest: &Manifest,
        app_hmac: &[u8; 32],
        elf: &ElfFile,
    ) -> Result<(), VAppEngineError<E>> {
        let mut data = postcard::to_allocvec(manifest)?;
        data.extend_from_slice(app_hmac);

        // Create the memory segments for the code, data, and stack sections
        let code_seg = MemorySegment::new(elf.code_segment.start, &elf.code_segment.data);
        let data_seg = MemorySegment::new(elf.data_segment.start, &elf.data_segment.data);
        let stack_seg = MemorySegment::new(
            manifest.stack_start,
            &vec![0; (manifest.stack_end - manifest.stack_start) as usize],
        );

        let (client_to_engine_sender, client_to_engine_receiver) =
            mpsc::channel::<ClientMessage>(10);
        let (engine_to_client_sender, engine_to_client_receiver) = mpsc::channel::<VAppMessage>(10);

        let vapp_engine = VAppEngine {
            manifest: manifest.clone(),
            code_seg,
            data_seg,
            stack_seg,
            transport,
            engine_to_client_sender,
            client_to_engine_receiver,
        };

        // Start the VAppEngine in a task
        let app_hmac_clone = *app_hmac;
        let vapp_engine_handle = tokio::spawn(async move {
            let res = vapp_engine.run(app_hmac_clone).await;
            if let Err(e) = &res {
                println!("VAppEngine error: {:?}", e);
            }
            res
        });

        // Store the senders and receivers
        self.client_to_engine_sender = Some(client_to_engine_sender);
        self.engine_to_client_receiver = Some(Mutex::new(engine_to_client_receiver));
        self.vapp_engine_handle = Some(vapp_engine_handle);

        Ok(())
    }

    pub async fn send_message(&mut self, message: &[u8]) -> Result<Vec<u8>, VanadiumClientError> {
        // Send the message to VAppEngine when receive_buffer is called
        self.client_to_engine_sender
            .as_ref()
            .ok_or("VAppEngine not running")?
            .send(ClientMessage::ReceiveBuffer(message.to_vec()))
            .await
            .map_err(|_| "Failed to send message to VAppEngine")?;

        // Wait for the response from VAppEngine
        match self.engine_to_client_receiver.as_mut() {
            Some(engine_to_client_receiver) => {
                let mut receiver = engine_to_client_receiver.lock().await;
                match receiver.recv().await {
                    Some(VAppMessage::SendBuffer(buf)) => Ok(buf),
                    Some(VAppMessage::SendPanicBuffer(panic_msg)) => {
                        Err(VanadiumClientError::VAppPanicked(panic_msg))
                    }
                    Some(VAppMessage::VAppExited { status }) => {
                        Err(VanadiumClientError::VAppExited(status))
                    }
                    None => Err("VAppEngine stopped".into()),
                }
            }
            None => Err("VAppEngine not running".into()),
        }
    }
}

/// Represents errors that can occur during the execution of a V-App.
#[derive(Debug)]
pub enum VAppExecutionError {
    /// Indicates that the V-App has exited with the specific status code.
    /// Useful to handle a graceful exit of the V-App.
    AppExited(i32),
    /// Any other error.
    Other(Box<dyn std::error::Error>),
}

impl std::fmt::Display for VAppExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VAppExecutionError::AppExited(code) => write!(f, "V-App exited with status {}", code),
            VAppExecutionError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for VAppExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VAppExecutionError::Other(e) => Some(&**e),
            _ => None,
        }
    }
}

/// A trait representing an application that can send messages asynchronously.
///
/// This trait defines the behavior for sending messages to an application and
/// receiving responses.
#[async_trait]
pub trait VAppClient {
    /// Sends a message to the app and returns the response asynchronously.
    ///
    /// # Parameters
    ///
    /// - `msg`: A `&[u8]` containing the message to be sent.
    ///
    /// # Returns
    ///
    /// A `Result` containing the response message as a `Vec<u8>` if the operation is successful,
    /// or a `VAppExecutionError` if an error occurs.

    async fn send_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, VAppExecutionError>;
}

/// Implementation of a VAppClient using the Vanadium VM.
pub struct VanadiumAppClient<E: std::fmt::Debug + Send + Sync + 'static> {
    client: GenericVanadiumClient<E>,
}

#[derive(Debug)]
pub enum VanadiumAppClientError<E: std::fmt::Debug + Send + Sync + 'static> {
    VAppEngineError(VAppEngineError<E>),
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::fmt::Display for VanadiumAppClientError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VanadiumAppClientError::VAppEngineError(e) => write!(f, "VAppEngine error: {}", e),
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::error::Error for VanadiumAppClientError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VanadiumAppClientError::VAppEngineError(e) => Some(e),
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> From<VAppEngineError<E>>
    for VanadiumAppClientError<E>
{
    fn from(error: VAppEngineError<E>) -> Self {
        VanadiumAppClientError::VAppEngineError(error)
    }
}

// Helper to find the path of the Cargo.toml file based on the path of the its binary,
// assuming standard Rust project structure for the V-App.
fn get_cargo_toml_path(elf_path: &str) -> Option<PathBuf> {
    let mut path = Path::new(elf_path);

    // Loop until we find the 'target' folder
    while let Some(parent) = path.parent() {
        if path.file_name() == Some("target".as_ref()) {
            // Go up one level to the parent directory
            return Some(parent.join("Cargo.toml"));
        }
        path = parent;
    }

    None
}

impl<E: std::fmt::Debug + Send + Sync + 'static> VanadiumAppClient<E> {
    pub async fn new(
        elf_path: &str,
        transport: Arc<dyn Transport<Error = E>>,
        app_hmac: Option<[u8; 32]>,
    ) -> Result<(Self, [u8; 32]), Box<dyn std::error::Error + Send + Sync>> {
        // Create ELF file and manifest
        let elf_file = ElfFile::new(Path::new(&elf_path))?;

        let manifest = if let Some(m) = &elf_file.manifest {
            // If the elf file is a packaged V-App, we use its manifest
            m.clone()
        } else {
            // There is no Manifest in the elf file.
            // Depending on the value of the cargo_toml feature, we either return an error or
            // try to create a valid Manifest based on the Cargo.toml file.

            #[cfg(not(feature = "cargo_toml"))]
            {
                return Err("No manifest found in the ELF file".into());
            }

            #[cfg(feature = "cargo_toml")]
            {
                // We create one based on the elf file and the apps's Cargo.toml.
                // This is useful during development.

                let cargo_toml_path =
                    get_cargo_toml_path(elf_path).ok_or("Failed to find Cargo.toml")?;

                let (_, app_version, app_metadata) = elf::get_app_metadata(&cargo_toml_path)?;

                let app_name = app_metadata
                    .get("name")
                    .ok_or("App name missing in metadata")?
                    .as_str()
                    .ok_or("App name is not a string")?;

                let stack_size = app_metadata
                    .get("stack_size")
                    .ok_or("Stack size missing in metadata")?
                    .as_integer()
                    .ok_or("Stack size is not a number")?;
                let stack_size = stack_size as u32;

                let stack_start = DEFAULT_STACK_START;
                let stack_end = stack_start + stack_size;

                let code_merkle_root: [u8; 32] =
                    MemorySegment::new(elf_file.code_segment.start, &elf_file.code_segment.data)
                        .get_content_root()
                        .clone()
                        .into();
                let data_merkle_root: [u8; 32] =
                    MemorySegment::new(elf_file.data_segment.start, &elf_file.data_segment.data)
                        .get_content_root()
                        .clone()
                        .into();
                let stack_merkle_root: [u8; 32] =
                    MemorySegment::new(stack_start, &vec![0u8; (stack_end - stack_start) as usize])
                        .get_content_root()
                        .clone()
                        .into();

                Manifest::new(
                    0,
                    app_name,
                    &app_version,
                    elf_file.entrypoint,
                    elf_file.code_segment.start,
                    elf_file.code_segment.end,
                    code_merkle_root,
                    elf_file.data_segment.start,
                    elf_file.data_segment.end,
                    data_merkle_root,
                    stack_start,
                    stack_end,
                    stack_merkle_root,
                )?
            }
        };

        let mut client = GenericVanadiumClient::new();

        // Register the V-App if the hmac was not given
        let app_hmac =
            app_hmac.unwrap_or(client.register_vapp(transport.clone(), &manifest).await?);

        // run the V-App
        client.run_vapp(transport, &manifest, &app_hmac, &elf_file)?;

        Ok((Self { client }, app_hmac))
    }
}

#[async_trait]
impl<E: std::fmt::Debug + Send + Sync + 'static> VAppClient for VanadiumAppClient<E> {
    async fn send_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, VAppExecutionError> {
        match self.client.send_message(msg).await {
            Ok(response) => Ok(response),
            Err(VanadiumClientError::VAppExited(status)) => {
                Err(VAppExecutionError::AppExited(status))
            }
            Err(e) => Err(VAppExecutionError::Other(Box::new(e))),
        }
    }
}

/// Implementation of a VAppClient for a native app running on the host, and communicating
/// via standard input and output.
pub struct NativeAppClient {
    child: tokio::process::Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl NativeAppClient {
    pub async fn new(bin_path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut child = tokio::process::Command::new(bin_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().ok_or("Failed to open stdin")?;
        let stdout = child.stdout.take().ok_or("Failed to open stdout")?;
        let stdout = BufReader::new(stdout);

        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
}

#[async_trait]
impl VAppClient for NativeAppClient {
    async fn send_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, VAppExecutionError> {
        // Check if the child process has exited
        if let Some(status) = self
            .child
            .try_wait()
            .map_err(|e| VAppExecutionError::Other(Box::new(e)))?
        {
            return Err(VAppExecutionError::AppExited(status.code().unwrap_or(-1)));
        }

        // Encode message as hex and append a newline
        let hex_msg = hex::encode(msg);
        let hex_msg_newline = format!("{}\n", hex_msg);

        // Write hex-encoded message to stdin
        self.stdin
            .write_all(hex_msg_newline.as_bytes())
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    VAppExecutionError::AppExited(-1)
                } else {
                    VAppExecutionError::Other(Box::new(e))
                }
            })?;

        // Flush the stdin to ensure the message is sent
        self.stdin.flush().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                VAppExecutionError::AppExited(-1)
            } else {
                VAppExecutionError::Other(Box::new(e))
            }
        })?;

        // Read response from stdout until a newline
        let mut response_line = String::new();
        let bytes_read = self
            .stdout
            .read_line(&mut response_line)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    VAppExecutionError::AppExited(-1)
                } else {
                    VAppExecutionError::Other(Box::new(e))
                }
            })?;

        if bytes_read == 0 {
            println!("EOF reached");
            // read the exit code
            let status = self
                .child
                .wait()
                .await
                .map_err(|e| VAppExecutionError::Other(Box::new(e)))?
                .code()
                .unwrap_or(-1);

            return Err(VAppExecutionError::AppExited(status));
        }

        // Remove any trailing newline or carriage return characters
        response_line = response_line
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();

        // Decode the hex-encoded response
        let response =
            hex::decode(&response_line).map_err(|e| VAppExecutionError::Other(Box::new(e)))?;

        Ok(response)
    }
}
