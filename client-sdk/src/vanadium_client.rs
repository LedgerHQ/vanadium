#[cfg(feature = "debug")]
use log::debug;

use async_trait::async_trait;
use std::{
    cmp::min,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use common::client_commands::{
    BufferType, ClientCommandCode, CommitPageMessage, CommitPageProofContinuedMessage,
    CommitPageProofContinuedResponse, CommitPageProofResponse, GetPageMessage,
    GetPageProofContinuedMessage, GetPageProofContinuedResponse, GetPageResponse, Message,
    MessageDeserializationError, ReceiveBufferMessage, ReceiveBufferResponse, SectionKind,
    SendBufferContinuedMessage, SendBufferMessage,
};
use common::constants::{DEFAULT_STACK_START, PAGE_SIZE};
use common::manifest::Manifest;

use crate::apdu::{apdu_continue, apdu_register_vapp, apdu_run_vapp, APDUCommand, StatusWord};
use crate::memory::{MemorySegment, MemorySegmentError};
use crate::transport::Transport;
use crate::{
    elf::{self, VAppElfFile},
    linewriter::Sink,
};

enum VAppResponse {
    Message(Vec<u8>),
    Panic(String),
    Exited(i32),
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
    AppNotRegistered,
    StoreFull,
    UnexpectedStatusWord(StatusWord),
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
            VAppEngineError::AppNotRegistered => write!(f, "App not registered on device"),
            VAppEngineError::StoreFull => write!(f, "App store is full"),
            VAppEngineError::UnexpectedStatusWord(sw) => {
                write!(f, "Failed to run V-App: unexpected status word {:?}", sw)
            }
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
            VAppEngineError::AppNotRegistered => None,
            VAppEngineError::StoreFull => None,
            VAppEngineError::UnexpectedStatusWord(_) => None,
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
    print_writer: Box<dyn std::io::Write + Send + Sync>,
    pending_receive_buffer: Option<Vec<u8>>,
    current_status: StatusWord,
    current_result: Vec<u8>,
}

impl<E: std::fmt::Debug + Send + Sync + 'static> VAppEngine<E> {
    async fn start(&mut self) -> Result<(), VAppEngineError<E>> {
        let serialized_manifest = postcard::to_allocvec(&self.manifest)?;

        let (status, result) = self
            .transport
            .exchange(&apdu_run_vapp(serialized_manifest))
            .await
            .map_err(VAppEngineError::TransportError)?;

        if status != StatusWord::OK && status != StatusWord::InterruptedExecution {
            match status {
                StatusWord::SignatureFail => return Err(VAppEngineError::AppNotRegistered),
                _ => return Err(VAppEngineError::UnexpectedStatusWord(status)),
            }
        }

        self.current_status = status;
        self.current_result = result;
        Ok(())
    }

    async fn step(&mut self) -> Result<Option<VAppResponse>, VAppEngineError<E>> {
        if self.current_status == StatusWord::OK {
            if self.current_result.len() != 4 {
                return Err(VAppEngineError::ResponseError(
                    "The V-App should return a 4-byte exit code",
                ));
            }
            let st = i32::from_be_bytes(self.current_result.clone().try_into().unwrap());
            return Ok(Some(VAppResponse::Exited(st)));
        }

        if self.current_status == StatusWord::VMRuntimeError {
            return Err(VAppEngineError::VMRuntimeError);
        }

        if self.current_status == StatusWord::VAppPanic {
            return Err(VAppEngineError::VAppPanic);
        }

        if self.current_status != StatusWord::InterruptedExecution {
            return Err(VAppEngineError::InterruptedExecutionExpected);
        }

        if self.current_result.is_empty() {
            return Err(VAppEngineError::ResponseError("empty command"));
        }

        let client_command_code: ClientCommandCode = self.current_result[0]
            .try_into()
            .map_err(|_| VAppEngineError::InvalidCommandCode)?;

        let result = match client_command_code {
            ClientCommandCode::GetPage => {
                let (status, result) = self.process_get_page(&self.current_result.clone()).await?;
                self.current_status = status;
                self.current_result = result;
                None
            }
            ClientCommandCode::CommitPage => {
                let (status, result) = self
                    .process_commit_page(&self.current_result.clone())
                    .await?;
                self.current_status = status;
                self.current_result = result;
                None
            }
            ClientCommandCode::SendBuffer => {
                self.process_send_buffer(&self.current_result.clone())
                    .await?
            }
            ClientCommandCode::ReceiveBuffer => {
                let (status, result) = self
                    .process_receive_buffer(&self.current_result.clone())
                    .await?;
                self.current_status = status;
                self.current_result = result;
                None
            }
            ClientCommandCode::SendBufferContinued
            | ClientCommandCode::GetPageProofContinued
            | ClientCommandCode::CommitPageProofContinued => {
                return Err(VAppEngineError::ResponseError("Unexpected command"));
            }
        };

        Ok(result)
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

        #[cfg(feature = "debug")]
        debug!(
            "<- GetPageMessage(section_kind = {:?}, page_index = {})",
            section_kind, page_index
        );

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

        // Calculate how many proof elements we can send in one message
        let t = min(proof.len(), GetPageResponse::max_proof_size()) as u8;

        // Create the page response
        let response = GetPageResponse::new(
            (*data).try_into().unwrap(),
            is_encrypted,
            nonce,
            proof.len() as u8,
            t,
            &proof[0..t as usize],
        )
        .serialize();

        let (status, result) = self
            .transport
            .exchange(&apdu_continue(response))
            .await
            .map_err(VAppEngineError::TransportError)?;

        #[cfg(feature = "debug")]
        debug!("Proof length: {}", proof.len());

        // If there are more proof elements to send and VM requests them
        if t < proof.len() as u8 {
            if status != StatusWord::InterruptedExecution || result.is_empty() {
                return Err(VAppEngineError::InterruptedExecutionExpected);
            }

            GetPageProofContinuedMessage::deserialize(&result)?;

            #[cfg(feature = "debug")]
            debug!("<- GetPageProofContinuedMessage()");

            let mut offset = t as usize;

            // Send remaining proof elements, potentially in multiple messages
            while offset < proof.len() {
                let remaining = proof.len() - offset;
                let t = min(remaining, GetPageProofContinuedResponse::max_proof_size()) as u8;

                let response =
                    GetPageProofContinuedResponse::new(t, &proof[offset..offset + t as usize])
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

                GetPageProofContinuedMessage::deserialize(&new_result)?;

                #[cfg(feature = "debug")]
                debug!("<- GetPageProofContinuedMessage()");
            }
        }
        Ok((status, result))
    }

    async fn process_commit_page(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        let msg = CommitPageMessage::deserialize(command)?;

        #[cfg(feature = "debug")]
        debug!(
            "<- CommitPageMessage(section_kind = {:?}, page_index = {})",
            msg.section_kind, msg.page_index,
        );

        let segment = match msg.section_kind {
            SectionKind::Code => {
                return Err(VAppEngineError::AccessViolation);
            }
            SectionKind::Data => &mut self.data_seg,
            SectionKind::Stack => &mut self.stack_seg,
        };

        assert!(msg.is_encrypted == true); // the VM should always commit to encrypted pages

        let mut serialized_page = Vec::<u8>::with_capacity(1 + 12 + PAGE_SIZE);
        serialized_page.push(msg.is_encrypted as u8);
        serialized_page.extend_from_slice(&msg.nonce);
        serialized_page.extend_from_slice(msg.data);

        // Store page and get proof
        let (proof, new_root) = segment.store_page(msg.page_index, &serialized_page)?;

        // Convert HashOutput<32> to [u8; 32]
        let proof: Vec<[u8; 32]> = proof.into_iter().map(|h| h.into()).collect();

        // Calculate how many proof elements we can send in one message
        let max_proof_elements = (255 - 2 - 32) / 32; // 2 bytes for n and t, 32 bytes for new_root, then 32 bytes for each proof element
        let t = min(proof.len(), max_proof_elements) as u8;

        // Create the proof response
        let response =
            CommitPageProofResponse::new(proof.len() as u8, t, &new_root, &proof[0..t as usize])
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

            CommitPageProofContinuedMessage::deserialize(&result)?;

            #[cfg(feature = "debug")]
            debug!("<- CommitPageProofContinuedMessage()");

            let mut offset = t as usize;

            // Send remaining proof elements, potentially in multiple messages
            while offset < proof.len() {
                let remaining = proof.len() - offset;
                let t = min(remaining, max_proof_elements) as u8;

                let response =
                    CommitPageProofContinuedResponse::new(t, &proof[offset..offset + t as usize])
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

                CommitPageProofContinuedMessage::deserialize(&new_result)?;

                #[cfg(feature = "debug")]
                debug!("<- CommitPageProofContinuedMessage()");
            }
        }

        Ok((status, result))
    }

    async fn process_send_buffer_generic(
        &mut self,
        command: &[u8],
    ) -> Result<(BufferType, Vec<u8>), VAppEngineError<E>> {
        let SendBufferMessage {
            command_code: _,
            buffer_type,
            total_size: mut remaining_len,
            data,
        } = SendBufferMessage::deserialize(command)?;

        #[cfg(feature = "debug")]
        debug!(
            "<- SendBufferMessage(buffer_type = {:?}, total_size = {}, data.len() = {})",
            buffer_type,
            remaining_len,
            data.len()
        );

        let mut buf = data.to_vec();

        if buf.len() > remaining_len as usize {
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

            let msg = SendBufferContinuedMessage::deserialize(&result)?;

            #[cfg(feature = "debug")]
            debug!(
                "<- SendBufferContinuedMessage(data.len() = {})",
                msg.data.len()
            );

            if msg.data.len() > remaining_len as usize {
                return Err(VAppEngineError::ResponseError(
                    "Received total_size does not match expected",
                ));
            }

            buf.extend_from_slice(&msg.data);
            remaining_len -= msg.data.len() as u32;
        }
        Ok((buffer_type, buf))
    }

    // receive a buffer sent by the V-App via xsend
    async fn process_send_buffer(
        &mut self,
        command: &[u8],
    ) -> Result<Option<VAppResponse>, VAppEngineError<E>> {
        let (buffer_type, buf) = self.process_send_buffer_generic(command).await?;

        let response = match buffer_type {
            BufferType::VAppMessage => Some(VAppResponse::Message(buf)),
            BufferType::Panic => {
                let panic_message = String::from_utf8(buf)
                    .map_err(|e| VAppEngineError::GenericError(Box::new(e)))?;
                Some(VAppResponse::Panic(panic_message))
            }
            BufferType::Print => {
                self.print_writer
                    .write(&buf)
                    .map_err(|e| VAppEngineError::GenericError(Box::new(e)))?;
                None
            }
        };

        // Continue processing
        let (status, result) = self
            .exchange_and_process_page_requests(&apdu_continue(vec![]))
            .await?;
        self.current_status = status;
        self.current_result = result;

        Ok(response)
    }

    // the V-App is expecting a buffer via xrecv; get it from pending_receive_buffer, and send it to the V-App
    async fn process_receive_buffer(
        &mut self,
        command: &[u8],
    ) -> Result<(StatusWord, Vec<u8>), VAppEngineError<E>> {
        ReceiveBufferMessage::deserialize(command)?;

        #[cfg(feature = "debug")]
        debug!("<- ReceiveBufferMessage()");

        let bytes: Vec<u8> = if let Some(buf) = self.pending_receive_buffer.take() {
            buf
        } else {
            // if there is no data to send to the V-App, respond with an empty buffer
            let data = ReceiveBufferResponse::new(0, &[]).serialize();
            return self
                .exchange_and_process_page_requests(&apdu_continue(data))
                .await;
        };

        let mut remaining_len = bytes.len() as u32;
        let mut offset: usize = 0;

        loop {
            // TODO: check if correct when the buffer is long
            let chunk_len = min(remaining_len, 255 - 4);
            let data = ReceiveBufferResponse::new(
                remaining_len,
                &bytes[offset..offset + chunk_len as usize],
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

                #[cfg(feature = "debug")]
                debug!("<- ReceiveBufferMessage()");
            }
        }
    }

    pub async fn send_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>, VAppEngineError<E>> {
        self.pending_receive_buffer = Some(message);

        loop {
            match self.step().await? {
                Some(VAppResponse::Message(buf)) => return Ok(buf),
                Some(VAppResponse::Panic(msg)) => {
                    return Err(VAppEngineError::GenericError(
                        format!("V-App panicked: {}", msg).into(),
                    ));
                }
                Some(VAppResponse::Exited(status)) => {
                    return Err(VAppEngineError::GenericError(
                        format!("V-App exited with status {}", status).into(),
                    ));
                }
                None => continue,
            }
        }
    }
}

struct GenericVanadiumClient<E: std::fmt::Debug + Send + Sync + 'static> {
    engine: Option<VAppEngine<E>>,
}

#[derive(Debug)]
enum VanadiumClientError {
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
        Self { engine: None }
    }

    pub async fn register_vapp(
        &self,
        transport: Arc<dyn Transport<Error = E>>,
        manifest: &Manifest,
    ) -> Result<(), &'static str> {
        let serialized_manifest =
            postcard::to_allocvec(manifest).map_err(|_| "manifest serialization failed")?;

        let (status, _result) = transport
            .exchange(&apdu_register_vapp(serialized_manifest))
            .await
            .map_err(|_| "exchange failed")?;

        match status {
            StatusWord::OK => Ok(()),
            StatusWord::StoreFull => Err("App store is full"),
            StatusWord::Deny => Err("User denied registration"),
            _ => Err("Failed to register vapp"),
        }
    }

    pub async fn run_vapp(
        &mut self,
        transport: Arc<dyn Transport<Error = E>>,
        manifest: &Manifest,
        elf: &VAppElfFile,
        print_writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Result<(), VAppEngineError<E>> {
        // Create the memory segments for the code, data, and stack sections
        let code_seg = MemorySegment::new(elf.code_segment.start, &elf.code_segment.data);
        let data_seg = MemorySegment::new(elf.data_segment.start, &elf.data_segment.data);
        let stack_seg = MemorySegment::new(
            manifest.stack_start,
            &vec![0; (manifest.stack_end - manifest.stack_start) as usize],
        );

        let mut vapp_engine = VAppEngine {
            manifest: manifest.clone(),
            code_seg,
            data_seg,
            stack_seg,
            transport,
            print_writer,
            pending_receive_buffer: None,
            current_status: StatusWord::OK,
            current_result: Vec::new(),
        };

        vapp_engine.start().await?;
        self.engine = Some(vapp_engine);

        Ok(())
    }

    pub async fn send_message(&mut self, message: &[u8]) -> Result<Vec<u8>, VanadiumClientError> {
        let engine = self.engine.as_mut().ok_or("VAppEngine not running")?;

        engine
            .send_message(message.to_vec())
            .await
            .map_err(|e| VanadiumClientError::GenericError(e.to_string()))
    }

    /// Replaces the print writer used by the engine.
    pub fn set_print_writer(&mut self, print_writer: Box<dyn std::io::Write + Send + Sync>) {
        if let Some(engine) = self.engine.as_mut() {
            engine.print_writer = print_writer;
        }
    }
}

/// Represents errors that can occur during the execution of a V-App.
#[derive(Debug)]
pub enum VAppExecutionError {
    /// Indicates that the V-App has panicked with the specific message.
    AppPanicked(String),
    /// Indicates that the V-App has exited with the specific status code.
    /// Useful to handle a graceful exit of the V-App.
    AppExited(i32),
    /// Any other error.
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for VAppExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VAppExecutionError::AppPanicked(msg) => write!(f, "V-App panicked: {}", msg),
            VAppExecutionError::AppExited(code) => write!(f, "V-App exited with status {}", code),
            VAppExecutionError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for VAppExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VAppExecutionError::AppPanicked(_) => None,
            VAppExecutionError::AppExited(_) => None,
            VAppExecutionError::Other(e) => Some(&**e),
        }
    }
}

/// A trait representing an application that can send messages asynchronously.
///
/// This trait defines the behavior for sending messages to an application and
/// receiving responses.
#[async_trait]
pub trait VAppTransport {
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

/// Implementation of a VAppTransport using the Vanadium VM (synchronous version).
pub struct SyncVanadiumAppClient<E: std::fmt::Debug + Send + Sync + 'static> {
    client: GenericVanadiumClient<E>,
}

#[derive(Debug)]
pub enum SyncVanadiumAppClientError<E: std::fmt::Debug + Send + Sync + 'static> {
    VAppEngineError(VAppEngineError<E>),
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::fmt::Display
    for SyncVanadiumAppClientError<E>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncVanadiumAppClientError::VAppEngineError(e) => write!(f, "VAppEngine error: {}", e),
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::error::Error
    for SyncVanadiumAppClientError<E>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SyncVanadiumAppClientError::VAppEngineError(e) => Some(e),
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> From<VAppEngineError<E>>
    for SyncVanadiumAppClientError<E>
{
    fn from(error: VAppEngineError<E>) -> Self {
        SyncVanadiumAppClientError::VAppEngineError(error)
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

impl<E: std::fmt::Debug + Send + Sync + 'static> SyncVanadiumAppClient<E> {
    pub async fn new(
        elf_path: &str,
        transport: Arc<dyn Transport<Error = E>>,
        print_writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create ELF file and manifest
        let elf_file = VAppElfFile::new(Path::new(&elf_path))
            .map_err(|e| format!("Failed to create ELF file from path '{}': {}", elf_path, e))?;

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

        // Try to run the V-App first (in case it's already registered)
        // Use a dummy Sink writer for this speculative attempt, preserving the real writer for later
        let sink_writer: Box<dyn std::io::Write + Send + Sync> =
            Box::new(crate::linewriter::Sink::default());
        match client
            .run_vapp(transport.clone(), &manifest, &elf_file, sink_writer)
            .await
        {
            Ok(()) => {
                // App was already registered, replace the Sink with the real print_writer
                client.set_print_writer(print_writer);
                Ok(Self { client })
            }
            Err(VAppEngineError::AppNotRegistered) => {
                // App not registered, need to register first
                client.register_vapp(transport.clone(), &manifest).await?;

                // Now run the V-App
                client
                    .run_vapp(transport, &manifest, &elf_file, print_writer)
                    .await?;

                Ok(Self { client })
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl<E: std::fmt::Debug + Send + Sync + 'static> VAppTransport for SyncVanadiumAppClient<E> {
    async fn send_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, VAppExecutionError> {
        self.client
            .send_message(msg)
            .await
            .map_err(|e| VAppExecutionError::Other(Box::new(e)))
    }
}

/// This client runs a background task that continuously steps the V-App engine,
/// preventing the device from appearing frozen when waiting for messages from the host.
pub struct VanadiumAppClient<E: std::fmt::Debug + Send + Sync + 'static> {
    message_tx: tokio::sync::mpsc::UnboundedSender<(
        Vec<u8>,
        tokio::sync::oneshot::Sender<Result<Vec<u8>, VAppExecutionError>>,
    )>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    worker_handle: Option<tokio::task::JoinHandle<()>>,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: std::fmt::Debug + Send + Sync + 'static> VanadiumAppClient<E> {
    /// Creates a new VanadiumAppClient.
    ///
    /// This creates a Vanadium client with a background task that
    /// continuously steps the engine to keep the device responsive.
    pub async fn new(
        elf_path: &str,
        transport: Arc<dyn Transport<Error = E>>,
        print_writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sync_client = SyncVanadiumAppClient::new(elf_path, transport, print_writer).await?;
        Ok(Self::from_sync(sync_client))
    }

    /// Creates a new VanadiumAppClient from an existing SyncVanadiumAppClient.
    ///
    /// The provided client will be moved into a background task that
    /// continuously steps the engine to keep the device responsive.
    fn from_sync(client: SyncVanadiumAppClient<E>) -> Self {
        let (message_tx, message_rx) = tokio::sync::mpsc::unbounded_channel::<(
            Vec<u8>,
            tokio::sync::oneshot::Sender<Result<Vec<u8>, VAppExecutionError>>,
        )>();

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // Spawn a background task that continuously steps the engine
        let worker_handle = tokio::spawn(Self::worker_loop(client, message_rx, shutdown_rx));

        Self {
            message_tx,
            shutdown_tx: Some(shutdown_tx),
            worker_handle: Some(worker_handle),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Background worker loop that continuously steps the V-App engine.
    async fn worker_loop(
        mut client: SyncVanadiumAppClient<E>,
        mut message_rx: tokio::sync::mpsc::UnboundedReceiver<(
            Vec<u8>,
            tokio::sync::oneshot::Sender<Result<Vec<u8>, VAppExecutionError>>,
        )>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) {
        let mut pending_response: Option<
            tokio::sync::oneshot::Sender<Result<Vec<u8>, VAppExecutionError>>,
        > = None;

        loop {
            // Check for shutdown signal (non-blocking)
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            // Only accept new messages when there's no pending response
            // This enforces strict message-response pattern and prevents race conditions
            if pending_response.is_none() {
                if let Ok((msg, resp_tx)) = message_rx.try_recv() {
                    // Set the pending message on the engine
                    if let Some(engine) = client.client.engine.as_mut() {
                        // Check if there's already a pending message that hasn't been consumed by the device
                        if engine.pending_receive_buffer.is_some() {
                            #[cfg(feature = "debug")]
                            log::warn!("Message sent before device called xrecv - previous queued message will be lost");
                        }
                        engine.pending_receive_buffer = Some(msg);
                        pending_response = Some(resp_tx);
                    } else if resp_tx
                        .send(Err(VAppExecutionError::Other("Engine not running".into())))
                        .is_err()
                    {
                        #[cfg(feature = "debug")]
                        log::debug!("Failed to send error response: receiver dropped");
                    }
                }
            }

            // Step the engine
            if let Some(engine) = client.client.engine.as_mut() {
                match engine.step().await {
                    Ok(Some(VAppResponse::Message(response))) => {
                        // We got a response - send it to the pending request
                        if let Some(resp_tx) = pending_response.take() {
                            if resp_tx.send(Ok(response)).is_err() {
                                #[cfg(feature = "debug")]
                                log::debug!("Failed to send response: receiver dropped");
                            }
                        } else {
                            // Received a message without a pending request - this shouldn't happen
                            // in a strict message-response pattern
                            #[cfg(feature = "debug")]
                            log::debug!(
                                "Warning: Received unsolicited message from V-App, dropping it"
                            );
                        }
                    }
                    Ok(Some(VAppResponse::Panic(msg))) => {
                        // V-App panicked
                        if let Some(resp_tx) = pending_response.take() {
                            if resp_tx
                                .send(Err(VAppExecutionError::AppPanicked(msg)))
                                .is_err()
                            {
                                #[cfg(feature = "debug")]
                                log::debug!("Failed to send app panic error: receiver dropped");
                            }
                        }
                        break;
                    }
                    Ok(Some(VAppResponse::Exited(status))) => {
                        // V-App exited
                        if let Some(resp_tx) = pending_response.take() {
                            if resp_tx
                                .send(Err(VAppExecutionError::AppExited(status)))
                                .is_err()
                            {
                                #[cfg(feature = "debug")]
                                log::debug!("Failed to send app exited error: receiver dropped");
                            }
                        }
                        break;
                    }
                    Ok(None) => {
                        // No response yet, continue stepping
                    }
                    Err(e) => {
                        // Error occurred - send it to pending request and exit
                        if let Some(resp_tx) = pending_response.take() {
                            if resp_tx
                                .send(Err(VAppExecutionError::Other(Box::new(e))))
                                .is_err()
                            {
                                #[cfg(feature = "debug")]
                                log::debug!("Failed to send engine error: receiver dropped");
                            }
                        }
                        break;
                    }
                }
            } else {
                break;
            }

            // Small yield to avoid busy-waiting and allow other tasks to run
            tokio::task::yield_now().await;
        }
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> Drop for VanadiumAppClient<E> {
    fn drop(&mut self) {
        // Signal the worker task to shutdown
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            // Send shutdown signal; if it fails, the task already exited
            let _ = shutdown_tx.send(());
        }

        // Abort the worker task if it's still running
        if let Some(handle) = self.worker_handle.take() {
            handle.abort();
        }
    }
}

#[async_trait]
impl<E: std::fmt::Debug + Send + Sync + 'static> VAppTransport for VanadiumAppClient<E> {
    async fn send_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, VAppExecutionError> {
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        self.message_tx
            .send((msg.to_vec(), resp_tx))
            .map_err(|_| VAppExecutionError::Other("Worker task died".into()))?;
        resp_rx
            .await
            .map_err(|_| VAppExecutionError::Other("Worker task died".into()))?
    }
}

/// Client that talks to the V-App over a length-prefixed TCP stream.
pub struct NativeAppClient {
    stream: TcpStream,
    print_writer: Box<dyn std::io::Write + Send + Sync>,
}

impl NativeAppClient {
    /// `addr` is something like `"127.0.0.1:5555"`.
    pub async fn new(
        addr: &str,
        print_writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            print_writer,
        })
    }

    /// Convenience for turning any I/O error into the right enum.
    fn map_err(e: std::io::Error) -> VAppExecutionError {
        use std::io::ErrorKind::*;
        match e.kind() {
            UnexpectedEof | ConnectionReset | BrokenPipe => VAppExecutionError::AppExited(-1),
            _ => VAppExecutionError::Other(Box::new(e)),
        }
    }
}

#[async_trait]
impl VAppTransport for NativeAppClient {
    async fn send_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, VAppExecutionError> {
        // ---------- WRITE ----------
        let len = msg.len() as u32;
        self.stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(Self::map_err)?;
        self.stream.write_all(msg).await.map_err(Self::map_err)?;
        self.stream.flush().await.map_err(Self::map_err)?;

        loop {
            // ---------- READ ----------
            let mut len_buf = [0u8; 5];
            self.stream
                .read_exact(&mut len_buf)
                .await
                .map_err(Self::map_err)?;

            let buffer_type: BufferType = len_buf[0]
                .try_into()
                .map_err(|_| VAppExecutionError::Other("Invalid buffer type".into()))?;
            let resp_len =
                u32::from_be_bytes([len_buf[1], len_buf[2], len_buf[3], len_buf[4]]) as usize;

            let mut resp = vec![0u8; resp_len];
            self.stream
                .read_exact(&mut resp)
                .await
                .map_err(Self::map_err)?;

            match buffer_type {
                BufferType::Print => {
                    // Print the message to the print writer
                    self.print_writer
                        .write_all(&resp)
                        .map_err(|e| VAppExecutionError::Other(Box::new(e)))?;
                    self.print_writer
                        .flush()
                        .map_err(|e| VAppExecutionError::Other(Box::new(e)))?;
                    continue; // Wait for the next message
                }
                BufferType::VAppMessage => return Ok(resp),
                BufferType::Panic => {
                    panic!("V-App panicked: {}", String::from_utf8_lossy(&resp));
                }
            }
        }
    }
}

/// Utility functions to simplify client creation
///
/// This module provides convenient functions to create different types of VApp clients
/// without the boilerplate of setting up transports and wrappers manually.
///
pub mod client_utils {
    use super::*;
    use crate::transport::{TransportHID, TransportTcp, TransportWrapper};
    use crate::transport_native_hid::TransportNativeHID;

    struct SharedWriter(Arc<std::sync::Mutex<Box<dyn std::io::Write + Send + Sync>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Lock poisoned"))?
                .write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Lock poisoned"))?
                .flush()
        }
    }

    #[derive(Debug, Clone)]
    pub enum ClientUtilsError {
        /// Failed to connect to native app
        NativeConnectionFailed(String),
        /// Failed to create TCP transport
        TcpTransportFailed(String),
        /// Failed to create HID transport
        HidTransportFailed(String),
        /// Hid, Tcp and Native interfaces all failed
        AllInterfacesFailed {
            hid_error: Box<ClientUtilsError>,
            tcp_error: Box<ClientUtilsError>,
            native_error: Box<ClientUtilsError>,
        },
        /// Failed to create Vanadium app client
        VanadiumClientFailed(String),
    }

    impl std::fmt::Display for ClientUtilsError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ClientUtilsError::NativeConnectionFailed(msg) => {
                    write!(f, "Native connection failed: {}", msg)
                }
                ClientUtilsError::TcpTransportFailed(msg) => {
                    write!(f, "TCP transport failed: {}", msg)
                }
                ClientUtilsError::HidTransportFailed(msg) => {
                    write!(f, "HID transport failed: {}", msg)
                }
                ClientUtilsError::AllInterfacesFailed {
                    hid_error,
                    tcp_error,
                    native_error,
                } => write!(
                    f,
                    "Failed to connect to a device or speculos running vanadium, or the native app.\n\
                    HID error: {}\n\
                    TCP error: {}\n\
                    Native error: {}",
                    hid_error, tcp_error, native_error
                ),
                ClientUtilsError::VanadiumClientFailed(msg) => {
                    write!(f, "Vanadium client failed: {}", msg)
                }
            }
        }
    }

    impl std::error::Error for ClientUtilsError {}

    /// Creates a client for a V-App compiled using the native target. Uses TCP for communication
    pub async fn create_native_client(
        tcp_addr: Option<&str>,
        print_writer: Option<Box<dyn std::io::Write + Send + Sync>>,
    ) -> Result<Box<dyn VAppTransport + Send>, ClientUtilsError> {
        let addr = tcp_addr.unwrap_or("127.0.0.1:2323");

        // if no print_writer is provided, default to Sink
        let print_writer = print_writer.unwrap_or_else(|| Box::new(Sink::default()));
        let client = NativeAppClient::new(addr, print_writer)
            .await
            .map_err(|e| ClientUtilsError::NativeConnectionFailed(e.to_string()))?;
        Ok(Box::new(client))
    }

    /// Creates a Vanadium client using TCP transport (for Speculos)
    pub async fn create_tcp_client(
        app_path: &str,
        print_writer: Option<Box<dyn std::io::Write + Send + Sync>>,
    ) -> Result<Box<dyn VAppTransport + Send>, ClientUtilsError> {
        let transport_raw = Arc::new(TransportTcp::new_default().await.map_err(|e| {
            ClientUtilsError::TcpTransportFailed(format!(
                "Unable to get TCP transport. Is speculos running? {}",
                e
            ))
        })?);
        let transport = TransportWrapper::new(transport_raw);

        // if no print_writer is provided, default to Sink
        let print_writer = print_writer.unwrap_or_else(|| Box::new(Sink::default()));
        let client = VanadiumAppClient::new(app_path, Arc::new(transport), print_writer)
            .await
            .map_err(|e| ClientUtilsError::VanadiumClientFailed(e.to_string()))?;
        Ok(Box::new(client))
    }

    /// Creates a Vanadium client using HID transport (for real device)
    pub async fn create_hid_client(
        app_path: &str,
        print_writer: Option<Box<dyn std::io::Write + Send + Sync>>,
    ) -> Result<Box<dyn VAppTransport + Send>, ClientUtilsError> {
        let hid_api = hidapi::HidApi::new().map_err(|e| {
            ClientUtilsError::HidTransportFailed(format!("Unable to create HID API: {}", e))
        })?;
        let transport_raw = Arc::new(TransportHID::new(
            TransportNativeHID::new(&hid_api).map_err(|e| {
                ClientUtilsError::HidTransportFailed(format!(
                    "Unable to connect to the device: {}",
                    e
                ))
            })?,
        ));
        let transport = TransportWrapper::new(transport_raw);

        // if no print_writer is provided, default to Sink
        let print_writer = print_writer.unwrap_or_else(|| Box::new(Sink::default()));
        let client = VanadiumAppClient::new(app_path, Arc::new(transport), print_writer)
            .await
            .map_err(|e| ClientUtilsError::VanadiumClientFailed(e.to_string()))?;
        Ok(Box::new(client))
    }

    pub enum ClientType {
        /// Try in sequence Hid, Tcp (Speculos), then native
        Any,
        /// Native client using TCP transport
        Native,
        /// Vanadium client using TCP transport (for Speculos)
        Tcp,
        /// Vanadium client using HID transport (for real device)
        Hid,
    }

    /// Creates a default client based on the specified `ClientType`, using the default paths or environment variables.
    /// This function simplifies the process of creating a client for a V-App, allowing it to run the client for an
    /// app running either natively, with Vanadium or Speculos using TCP transport, or with Vanadium on a real device
    /// using HID transport.
    ///
    /// When running natively, it uses the `VAPP_ADDRESS` environment variable to determine the TCP address, or defaults
    /// to "127.0.0.1:2323" if not set
    /// When running with Vanadium, it expects the app to be compiled to a specific path, following the standard
    /// project structure used for V-Apps in the Vanadium repository.
    ///
    /// This function is mostly meant for testing and development purposes, as a production release would likely
    /// have more specific requirements.
    pub async fn create_default_client(
        app_name: &str,
        client_type: ClientType,
        print_writer: Option<Box<dyn std::io::Write + Send + Sync>>,
    ) -> Result<Box<dyn VAppTransport + Send>, ClientUtilsError> {
        let app_path = format!(
            "../app/target/riscv32imc-unknown-none-elf/release/{}",
            app_name
        );

        let tcp_addr = std::env::var("VAPP_ADDRESS").unwrap_or_else(|_| "127.0.0.1:2323".into());

        let shared_writer = print_writer.map(|w| std::sync::Arc::new(std::sync::Mutex::new(w)));

        let get_writer = || {
            shared_writer
                .as_ref()
                .map(|w| Box::new(SharedWriter(w.clone())) as Box<dyn std::io::Write + Send + Sync>)
        };

        match client_type {
            ClientType::Any => {
                let hid_error = match create_hid_client(&app_path, get_writer()).await {
                    Ok(client) => return Ok(client),
                    Err(e) => e,
                };
                let tcp_error = match create_tcp_client(&app_path, get_writer()).await {
                    Ok(client) => return Ok(client),
                    Err(e) => e,
                };
                let native_error = match create_native_client(Some(&tcp_addr), get_writer()).await {
                    Ok(client) => return Ok(client),
                    Err(e) => e,
                };
                Err(ClientUtilsError::AllInterfacesFailed {
                    hid_error: Box::new(hid_error),
                    tcp_error: Box::new(tcp_error),
                    native_error: Box::new(native_error),
                })
            }
            ClientType::Native => create_native_client(Some(&tcp_addr), get_writer()).await,
            ClientType::Tcp => create_tcp_client(&app_path, get_writer()).await,
            ClientType::Hid => create_hid_client(&app_path, get_writer()).await,
        }
    }
}
