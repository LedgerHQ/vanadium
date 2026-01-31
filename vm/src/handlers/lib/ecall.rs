use core::{
    cell::{RefCell, RefMut},
    cmp::min,
    fmt,
    mem::MaybeUninit,
};

use alloc::{format, rc::Rc, string::String, vec, vec::Vec};
use common::{
    client_commands::{
        BufferType, Message, MessageDeserializationError, ReceiveBufferMessage,
        ReceiveBufferResponse, SendBufferContinuedMessage, SendBufferMessage,
    },
    constants::PAGE_SIZE,
    ecall_constants::{self, *},
    ux::Deserializable,
    vm::{Cpu, CpuError, EcallHandler, MemoryError},
};
use ledger_device_sdk::sys::{
    self, cx_ripemd160_t, cx_sha256_t, cx_sha512_t, CX_OK, CX_RIPEMD160, CX_SHA256, CX_SHA512,
};
use ledger_device_sdk::{hash::HashInit, io::DecodedEventType};

use crate::io::interrupt;

use super::{outsourced_mem::OutsourcedMemory, SerializeToComm};

use zeroize::Zeroizing;

mod ux_handler;

mod bitmaps;

mod slip21;

use ux_handler::*;

const VENDOR_ID: u16 = 0x2C97; // Ledger vendor ID

#[cfg(target_os = "nanox")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x40;
    pub const SCREEN_WIDTH: u16 = 128;
    pub const SCREEN_HEIGHT: u16 = 64;
}

#[cfg(target_os = "nanosplus")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x50;
    pub const SCREEN_WIDTH: u16 = 128;
    pub const SCREEN_HEIGHT: u16 = 64;
}

#[cfg(target_os = "stax")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x60;
    pub const SCREEN_WIDTH: u16 = 400;
    pub const SCREEN_HEIGHT: u16 = 672;
}

#[cfg(target_os = "flex")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x70;
    pub const SCREEN_WIDTH: u16 = 480;
    pub const SCREEN_HEIGHT: u16 = 600;
}

#[cfg(target_os = "apex_p")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x80;
    pub const SCREEN_WIDTH: u16 = 300;
    pub const SCREEN_HEIGHT: u16 = 400;
}

#[cfg(not(any(
    target_os = "nanox",
    target_os = "nanosplus",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
)))]
compile_error!("Unsupported target OS. Only nanox, nanosplus, stax, and flex are supported.");

use device_props::*;

// BIP32 supports up to 255, but we don't want that many, and it would be very slow anyway
const MAX_BIP32_PATH: usize = 16;

const MAX_UX_STEP_LEN: usize = 512;
const MAX_UX_PAGE_LEN: usize = 512;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum Register {
    Zero, // x0, constant zero
    Ra,   // x1, return address
    Sp,   // x2, stack pointer
    Gp,   // x3, global pointer
    Tp,   // x4, thread pointer
    T0,   // x5, temporary register
    T1,   // x6, temporary register
    T2,   // x7, temporary register
    S0,   // x8, saved register (frame pointer)
    S1,   // x9, saved register
    A0,   // x10, function argument/return value
    A1,   // x11, function argument/return value
    A2,   // x12, function argument
    A3,   // x13, function argument
    A4,   // x14, function argument
    A5,   // x15, function argument
    A6,   // x16, function argument
    A7,   // x17, function argument
    S2,   // x18, saved register
    S3,   // x19, saved register
    S4,   // x20, saved register
    S5,   // x21, saved register
    S6,   // x22, saved register
    S7,   // x23, saved register
    S8,   // x24, saved register
    S9,   // x25, saved register
    S10,  // x26, saved register
    S11,  // x27, saved register
    T3,   // x28, temporary register
    T4,   // x29, temporary register
    T5,   // x30, temporary register
    T6,   // x31, temporary register
}

impl Register {
    // To get the register's index as a number (x0 to x31)
    pub fn as_index(&self) -> u8 {
        match self {
            Register::Zero => 0,
            Register::Ra => 1,
            Register::Sp => 2,
            Register::Gp => 3,
            Register::Tp => 4,
            Register::T0 => 5,
            Register::T1 => 6,
            Register::T2 => 7,
            Register::S0 => 8,
            Register::S1 => 9,
            Register::A0 => 10,
            Register::A1 => 11,
            Register::A2 => 12,
            Register::A3 => 13,
            Register::A4 => 14,
            Register::A5 => 15,
            Register::A6 => 16,
            Register::A7 => 17,
            Register::S2 => 18,
            Register::S3 => 19,
            Register::S4 => 20,
            Register::S5 => 21,
            Register::S6 => 22,
            Register::S7 => 23,
            Register::S8 => 24,
            Register::S9 => 25,
            Register::S10 => 26,
            Register::S11 => 27,
            Register::T3 => 28,
            Register::T4 => 29,
            Register::T5 => 30,
            Register::T6 => 31,
        }
    }
}

pub fn pack_u16(high: u16, low: u16) -> u32 {
    ((high as u32) << 16) | (low as u32)
}

// A pointer in the V-app's address space
#[derive(Debug, Clone, Copy)]
struct GuestPointer(pub u32);

impl GuestPointer {
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LedgerHashContextError {
    InvalidHashId,
    UnsupportedHashId,
}

impl fmt::Display for LedgerHashContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerHashContextError::InvalidHashId => write!(f, "Invalid hash id"),
            LedgerHashContextError::UnsupportedHashId => write!(f, "Unsupported hash id"),
        }
    }
}

impl core::error::Error for LedgerHashContextError {}

// Compile-time size validation for EventData union
// Ensures that EventData is exactly 16 bytes with no unexpected padding
const _: () = assert!(
    core::mem::size_of::<common::ux::EventData>() == 16,
    "EventData must be exactly 16 bytes for safe transmutation to [u8; 16]"
);

// A union of all the supported hash contexts, in the same memory layout used in the Ledger SDK
#[repr(C)]
union LedgerHashContext {
    ripemd160: cx_ripemd160_t,
    sha256: cx_sha256_t,
    sha512: cx_sha512_t,
}

impl LedgerHashContext {
    const MAX_HASH_CONTEXT_SIZE: usize = core::mem::size_of::<LedgerHashContext>();
    const MAX_DIGEST_LEN: usize = 64;

    // in-memory size of the hash context struct for the corresponding hash type
    fn get_size_from_id(hash_id: u32) -> Result<usize, LedgerHashContextError> {
        if hash_id > 255 {
            return Err(LedgerHashContextError::InvalidHashId);
        }
        let res = match hash_id as u8 {
            CX_RIPEMD160 => core::mem::size_of::<cx_ripemd160_t>(),
            CX_SHA256 => core::mem::size_of::<cx_sha256_t>(),
            CX_SHA512 => core::mem::size_of::<cx_sha512_t>(),
            _ => return Err(LedgerHashContextError::UnsupportedHashId),
        };

        assert!(res <= Self::MAX_HASH_CONTEXT_SIZE);

        Ok(res)
    }

    fn get_digest_len_from_id(hash_id: u32) -> Result<usize, LedgerHashContextError> {
        if hash_id > 255 {
            return Err(LedgerHashContextError::InvalidHashId);
        }
        let res = match hash_id as u8 {
            CX_RIPEMD160 => 20,
            CX_SHA256 => 32,
            CX_SHA512 => 64,
            _ => return Err(LedgerHashContextError::UnsupportedHashId),
        };

        assert!(res <= Self::MAX_DIGEST_LEN);

        Ok(res)
    }
}

// Wraps the cx_ecfp_private_key_t struct to make sure that it is zeroed on drop
struct ZeroizingPrivateKey(sys::cx_ecfp_private_key_t);

impl Drop for ZeroizingPrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.d.zeroize();
        self.0.d_len.zeroize();
        self.0.curve.zeroize();
    }
}

impl core::ops::Deref for ZeroizingPrivateKey {
    type Target = sys::cx_ecfp_private_key_t;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for ZeroizingPrivateKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub enum CommEcallError {
    Exit(i32),
    Panic,
    InvalidParameters(&'static str),
    GenericError(&'static str),
    Overflow,
    HashError(LedgerHashContextError),
    MessageDeserializationError(MessageDeserializationError),
    InvalidResponse(&'static str),
    CpuError(String),
    MemoryError(MemoryError),
    UnhandledEcall,
}

impl core::fmt::Display for CommEcallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CommEcallError::Exit(code) => write!(f, "Exit with code {}", code),
            CommEcallError::Panic => write!(f, "Panic occurred"),
            CommEcallError::InvalidParameters(msg) => {
                write!(f, "Invalid parameters: {}", msg)
            }
            CommEcallError::GenericError(msg) => write!(f, "Error: {}", msg),
            CommEcallError::Overflow => write!(f, "Buffer overflow"),
            CommEcallError::HashError(e) => write!(f, "Hash error: {:?}", e),
            CommEcallError::MessageDeserializationError(e) => {
                write!(f, "Message deserialization error: {:?}", e)
            }
            CommEcallError::InvalidResponse(msg) => {
                write!(f, "Invalid response from host: {}", msg)
            }
            CommEcallError::CpuError(e) => write!(f, "Cpu error: {:?}", e),
            CommEcallError::MemoryError(e) => write!(f, "Memory error: {:?}", e),
            CommEcallError::UnhandledEcall => write!(f, "Unhandled ecall"),
        }
    }
}

impl core::fmt::Debug for CommEcallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl<E: fmt::Debug> From<CpuError<E>> for CommEcallError {
    fn from(error: CpuError<E>) -> Self {
        CommEcallError::CpuError(format!("{:?}", error))
    }
}

impl From<LedgerHashContextError> for CommEcallError {
    fn from(error: LedgerHashContextError) -> Self {
        CommEcallError::HashError(error)
    }
}

impl From<MemoryError> for CommEcallError {
    fn from(error: MemoryError) -> Self {
        CommEcallError::MemoryError(error)
    }
}

impl From<MessageDeserializationError> for CommEcallError {
    fn from(error: MessageDeserializationError) -> Self {
        CommEcallError::MessageDeserializationError(error)
    }
}

impl From<alloc::ffi::NulError> for CommEcallError {
    fn from(_: alloc::ffi::NulError) -> Self {
        CommEcallError::InvalidParameters("CString contains a null byte")
    }
}

impl core::error::Error for CommEcallError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            CommEcallError::MemoryError(e) => Some(e),
            CommEcallError::MessageDeserializationError(e) => Some(e),
            CommEcallError::HashError(e) => Some(e),
            // since we convert CpuError to a string, we don't keep the original error
            _ => None,
        }
    }
}

pub struct CommEcallHandler<'a, const N: usize> {
    comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm<N>>>,
    ux_handler: &'static mut UxHandler,
}

impl<'a, const N: usize> CommEcallHandler<'a, N> {
    pub fn new(comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm<N>>>) -> Self {
        Self {
            comm,
            ux_handler: init_ux_handler(),
        }
    }

    fn handle_send_buffer<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        mut size: usize,
        buffer_type: BufferType,
    ) -> Result<(), CommEcallError> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            let mut resp = comm.begin_response();
            SendBufferMessage::new(size as u32, buffer_type, &[]).serialize_to_comm(&mut resp);
            interrupt(resp)?;
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err(CommEcallError::Overflow);
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        let mut buffer = [0u8; 256];
        let mut first_chunk = true;
        // loop while size > 0
        while size > 0 {
            if first_chunk {
                let copy_size = min(size, 255 - 6); // send maximum 249 bytes in the first chunk
                segment.read_buffer(g_ptr, &mut buffer[0..copy_size])?;

                let mut comm = self.comm.borrow_mut();
                let mut resp = comm.begin_response();
                SendBufferMessage::new(size as u32, buffer_type, &buffer[0..copy_size])
                    .serialize_to_comm(&mut resp);
                interrupt(resp)?;
                size -= copy_size;
                g_ptr += copy_size as u32;
                first_chunk = false;
            } else {
                let copy_size = min(size, 255 - 1); // send maximum 255 bytes in each subsequent chunk
                segment.read_buffer(g_ptr, &mut buffer[0..copy_size])?;
                let mut comm = self.comm.borrow_mut();
                let mut resp = comm.begin_response();
                SendBufferContinuedMessage::new(&buffer[0..copy_size]).serialize_to_comm(&mut resp);
                interrupt(resp)?;
                size -= copy_size;
                g_ptr += copy_size as u32;
            }
        }

        Ok(())
    }

    // Sends a panic message
    fn handle_panic<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<(), CommEcallError> {
        self.handle_send_buffer::<E>(cpu, buffer, size, BufferType::Panic)
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    fn handle_xsend<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<(), CommEcallError> {
        self.handle_send_buffer::<E>(cpu, buffer, size, BufferType::VAppMessage)
    }

    // Receives up to max_size bytes from the host into the buffer in the V-app memory
    // Returns the catual of bytes received.
    fn handle_xrecv<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        max_size: usize,
    ) -> Result<usize, CommEcallError> {
        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        let mut remaining_length = None;
        let mut total_received: usize = 0;
        while remaining_length != Some(0) {
            let response_content = {
                let mut comm = self.comm.borrow_mut();
                let mut resp = comm.begin_response();
                ReceiveBufferMessage::new().serialize_to_comm(&mut resp);

                let command = interrupt(resp)?;

                let raw_data = command.get_data();
                let response = ReceiveBufferResponse::deserialize(raw_data)?;

                match remaining_length {
                    None => {
                        // first chunk, check if the total length is acceptable
                        if response.remaining_length > max_size as u32 {
                            return Err(CommEcallError::InvalidResponse(
                                "Received data is too large",
                            ));
                        }
                        remaining_length = Some(response.remaining_length);
                    }
                    Some(remaining) => {
                        if remaining != response.remaining_length {
                            return Err(CommEcallError::InvalidResponse(
                                "Mismatching remaining length",
                            ));
                        }
                    }
                }

                // We need to clone the content, since it is tied to the `comm` borrow.
                response.content.to_vec()
            };

            segment.write_buffer(g_ptr, &response_content)?;

            // make sure chunk doesn't exceed remaining length
            let chunk_len = response_content.len() as u32;
            let curr_remaining = remaining_length.unwrap();
            if chunk_len > curr_remaining {
                return Err(CommEcallError::InvalidResponse(
                    "Chunk exceeds declared remaining length",
                ));
            }
            remaining_length = Some(curr_remaining - chunk_len);
            g_ptr += chunk_len;
            total_received += response_content.len();
        }
        Ok(total_received)
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    fn handle_print<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<(), CommEcallError> {
        self.handle_send_buffer::<E>(cpu, buffer, size, BufferType::Print)
    }

    fn handle_bn_modm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        n: GuestPointer,
        len: usize,
        m: GuestPointer,
        m_len: usize,
    ) -> Result<(), CommEcallError> {
        if len > MAX_BIGNUMBER_SIZE || m_len > MAX_BIGNUMBER_SIZE {
            return Err(CommEcallError::InvalidParameters(
                "len or m_len is too large",
            ));
        }

        // copy inputs to local memory
        // we use r_local both for the input and for the result
        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(n.0)?
            .read_buffer(n.0, &mut r_local[0..len])?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(m.0)?
            .read_buffer(m.0, &mut m_local[0..m_len])?;

        unsafe {
            let res =
                sys::cx_math_modm_no_throw(r_local.as_mut_ptr(), len, m_local.as_ptr(), m_len);
            if res != CX_OK {
                return Err(CommEcallError::GenericError("modm failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local[0..len])?;
        Ok(())
    }

    fn handle_bn_addm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), CommEcallError> {
        if len > MAX_BIGNUMBER_SIZE {
            return Err(CommEcallError::InvalidParameters("len is too large"));
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(a.0)?
            .read_buffer(a.0, &mut a_local[0..len])?;
        let mut b_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(b.0)?
            .read_buffer(b.0, &mut b_local[0..len])?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(m.0)?
            .read_buffer(m.0, &mut m_local[0..len])?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = sys::cx_math_addm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                b_local.as_ptr(),
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError("addm failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local[0..len])?;
        Ok(())
    }

    fn handle_bn_subm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), CommEcallError> {
        if len > MAX_BIGNUMBER_SIZE {
            return Err(CommEcallError::InvalidParameters("len is too large"));
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(a.0)?
            .read_buffer(a.0, &mut a_local[0..len])?;
        let mut b_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(b.0)?
            .read_buffer(b.0, &mut b_local[0..len])?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(m.0)?
            .read_buffer(m.0, &mut m_local[0..len])?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = sys::cx_math_subm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                b_local.as_ptr(),
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError("subm failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local[0..len])?;
        Ok(())
    }

    fn handle_bn_multm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), CommEcallError> {
        if len > MAX_BIGNUMBER_SIZE {
            return Err(CommEcallError::InvalidParameters("len is too large"));
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(a.0)?
            .read_buffer(a.0, &mut a_local[0..len])?;
        let mut b_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(b.0)?
            .read_buffer(b.0, &mut b_local[0..len])?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(m.0)?
            .read_buffer(m.0, &mut m_local[0..len])?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = sys::cx_math_multm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                b_local.as_ptr(),
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError("multm failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local[0..len])?;
        Ok(())
    }

    fn handle_bn_powm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        a: GuestPointer,
        e: GuestPointer,
        len_e: usize,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), CommEcallError> {
        if len_e > MAX_BIGNUMBER_SIZE {
            return Err(CommEcallError::InvalidParameters("len_e is too large"));
        }
        if len > MAX_BIGNUMBER_SIZE {
            return Err(CommEcallError::InvalidParameters("len is too large"));
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(a.0)?
            .read_buffer(a.0, &mut a_local[0..len])?;
        let mut e_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(e.0)?
            .read_buffer(e.0, &mut e_local[0..len_e])?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment::<E>(m.0)?
            .read_buffer(m.0, &mut m_local[0..len])?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = sys::cx_math_powm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                e_local.as_ptr(),
                len_e,
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError("addm failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local[0..len])?;
        Ok(())
    }

    fn handle_hash_init<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        hash_id: u32,
        ctx: GuestPointer,
    ) -> Result<(), CommEcallError> {
        // in-memory size of the hash context struct
        let ctx_size = LedgerHashContext::get_size_from_id(hash_id)?;

        // copy context to local memory
        let mut ctx_local: [u8; LedgerHashContext::MAX_HASH_CONTEXT_SIZE] =
            [0; LedgerHashContext::MAX_HASH_CONTEXT_SIZE];

        cpu.get_segment::<E>(ctx.0)?
            .read_buffer(ctx.0, &mut ctx_local[0..ctx_size])?;

        unsafe {
            sys::cx_hash_init(
                ctx_local.as_mut_ptr() as *mut sys::cx_hash_header_s,
                hash_id as u8,
            );
        }

        // copy context back to V-App memory
        let segment = cpu.get_segment::<E>(ctx.0)?;
        segment.write_buffer(ctx.0, &ctx_local[0..ctx_size])?;

        Ok(())
    }

    fn handle_hash_update<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        hash_id: u32,
        ctx: GuestPointer,
        data: GuestPointer,
        data_len: usize,
    ) -> Result<(), CommEcallError> {
        // in-memory size of the hash context struct
        let ctx_size = LedgerHashContext::get_size_from_id(hash_id)?;

        if data_len == 0 {
            return Ok(());
        }

        // copy context to local memory
        let mut ctx_local: [u8; LedgerHashContext::MAX_HASH_CONTEXT_SIZE] =
            [0; LedgerHashContext::MAX_HASH_CONTEXT_SIZE];

        cpu.get_segment::<E>(ctx.0)?
            .read_buffer(ctx.0, &mut ctx_local[0..ctx_size])?;

        // copy data to local memory in chanks of at most 256 bytes
        let mut data_local: [u8; 256] = [0; 256];
        let mut data_remaining = data_len;
        let mut data_ptr = data.0;
        let data_seg = cpu.get_segment::<E>(data_ptr)?;
        while data_remaining > 0 {
            let copy_size = min(data_remaining, 256);
            data_seg.read_buffer(data_ptr, &mut data_local[0..copy_size])?;

            unsafe {
                let err = sys::cx_hash_update(
                    ctx_local.as_mut_ptr() as *mut sys::cx_hash_header_s,
                    data_local.as_ptr(),
                    copy_size as usize,
                );
                if err != CX_OK {
                    return Err(CommEcallError::GenericError("hash update failed"));
                }
            }

            data_remaining -= copy_size;
            data_ptr += copy_size as u32;
        }

        // copy context back to V-App memory
        cpu.get_segment::<E>(ctx.0)?
            .write_buffer(ctx.0, &ctx_local[0..ctx_size])?;

        Ok(())
    }

    fn handle_hash_digest<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        hash_id: u32,
        ctx: GuestPointer,
        digest: GuestPointer,
    ) -> Result<(), CommEcallError> {
        // in-memory size of the hash context struct
        let ctx_size = LedgerHashContext::get_size_from_id(hash_id)?;

        // copy context to local memory
        let mut ctx_local: [u8; LedgerHashContext::MAX_HASH_CONTEXT_SIZE] =
            [0; LedgerHashContext::MAX_HASH_CONTEXT_SIZE];

        cpu.get_segment::<E>(ctx.0)?
            .read_buffer(ctx.0, &mut ctx_local[0..ctx_size])?;

        // compute the digest; no supported hash function has a digest bigger than 64 bytes
        let mut digest_local: [u8; 64] = [0; 64];

        unsafe {
            let err = sys::cx_hash_final(
                ctx_local.as_mut_ptr() as *mut sys::cx_hash_header_s,
                digest_local.as_mut_ptr(),
            );
            if err != CX_OK {
                return Err(CommEcallError::GenericError("hash final failed"));
            }
        }

        // actual length of the digest
        let digest_len = LedgerHashContext::get_digest_len_from_id(hash_id)?;
        // copy digest to V-App memory
        let segment = cpu.get_segment::<E>(digest.0)?;
        segment.write_buffer(digest.0, &digest_local[0..digest_len])?;

        Ok(())
    }

    fn handle_derive_hd_node<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        path: GuestPointer,
        path_len: usize,
        private_key: GuestPointer,
        chain_code: GuestPointer,
    ) -> Result<(), CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }
        if path_len > MAX_BIP32_PATH {
            return Err(CommEcallError::InvalidParameters("path_len is too large"));
        }

        // copy path to local memory (if path_len == 0, the pointer is invalid,
        // so we don't want to read from the segment)
        let mut path_local_raw: [u8; MAX_BIP32_PATH * 4] = [0; MAX_BIP32_PATH * 4];
        if path_len > 0 {
            cpu.get_segment::<E>(path.0)?
                .read_buffer(path.0, &mut path_local_raw[0..(path_len * 4)])?;
        }

        // read bytes and combine into u32 values safely (avoid unaligned access)
        let mut path_local = Vec::with_capacity(path_len as usize);
        for i in 0..path_len {
            let idx = (i * 4) as usize;
            let bytes = &path_local_raw[idx..idx + 4];
            path_local.push(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        }

        // derive the key
        let mut private_key_local = Zeroizing::new([0u8; 32]);
        let mut chain_code_local: [u8; 32] = [0; 32];
        unsafe {
            sys::os_perso_derive_node_bip32(
                curve as u8,
                path_local.as_ptr(),
                path_len as u32,
                private_key_local.as_mut_ptr(),
                chain_code_local.as_mut_ptr(),
            );
        }

        // copy private_key and chain_code to V-App memory
        cpu.get_segment::<E>(private_key.0)?
            .write_buffer(private_key.0, &private_key_local[..])?;
        cpu.get_segment::<E>(chain_code.0)?
            .write_buffer(chain_code.0, &chain_code_local)?;

        Ok(())
    }

    fn handle_get_master_fingerprint<E: fmt::Debug>(
        &self,
        _cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        // derive the key
        let mut private_key_local = Zeroizing::new([0u8; 32]);
        let mut chain_code_local: [u8; 32] = [0; 32];

        let mut pubkey: sys::cx_ecfp_public_key_t = Default::default();

        // Hack: we're passing an empty path, but [].as_ptr() would return a fixed non-zero constant that is
        // not a valid pointer, which would make os_perso_derive_node_bip32 crash on the real device (but not
        // on speculos).
        // Therefore, we use a local non-empty array instead, but still pass 0 for the pathLength parameter.
        let empty_path = [0u32; 1];

        unsafe {
            sys::os_perso_derive_node_bip32(
                CurveKind::Secp256k1 as u8,
                empty_path.as_ptr(),
                0,
                private_key_local.as_mut_ptr(),
                chain_code_local.as_mut_ptr(),
            );

            // generate the corresponding public key
            let mut privkey: sys::cx_ecfp_private_key_t = Default::default();

            let ret1 = sys::cx_ecfp_init_private_key_no_throw(
                curve as u8,
                private_key_local.as_ptr(),
                private_key_local.len(),
                &mut privkey,
            );

            let ret2 =
                sys::cx_ecfp_generate_pair_no_throw(curve as u8, &mut pubkey, &mut privkey, true);

            if ret1 != CX_OK || ret2 != CX_OK {
                return Err(CommEcallError::GenericError("Failed to generate key pair"));
            }
        }

        // Validate that pubkey.W has the expected 65-byte uncompressed public key format.
        if pubkey.W_len != 65 {
            return Err(CommEcallError::GenericError("Invalid public key length"));
        }

        let mut sha_hasher = ledger_device_sdk::hash::sha2::Sha2_256::new();
        sha_hasher.update(&[02u8 + (pubkey.W[64] % 2)]).unwrap();
        sha_hasher.update(&pubkey.W[1..33]).unwrap();
        let mut sha256hash = [0u8; 32];
        sha_hasher.finalize(&mut sha256hash).unwrap();
        let mut ripemd160_hasher = ledger_device_sdk::hash::ripemd::Ripemd160::new();
        ripemd160_hasher.update(&sha256hash).unwrap();
        let mut rip = [0u8; 20];
        ripemd160_hasher.finalize(&mut rip).unwrap();
        Ok(u32::from_be_bytes([rip[0], rip[1], rip[2], rip[3]]))
    }

    fn handle_derive_slip21_node<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        labels: GuestPointer,
        labels_len: usize,
        out: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        // copy label to a local buffer
        if labels_len > 256 {
            return Err(CommEcallError::InvalidParameters("labels_len is too large"));
        }

        // bolos expects the first byte to be 0, and the label actually starts at index 1
        let mut labels_local: [u8; 256] = [0; 256];
        cpu.get_segment::<E>(labels.0)?
            .read_buffer(labels.0, &mut labels_local[0..labels_len])?;

        let mut slices = Vec::<&[u8]>::new();
        let mut offset = 0;
        while offset < labels_len {
            let label_len = labels_local[offset] as usize;
            offset += 1;

            if offset + label_len > labels_len {
                return Err(CommEcallError::InvalidParameters("Invalid labels format"));
            }

            slices.push(&labels_local[offset..offset + label_len]);
            offset += label_len;
        }

        let out_node = slip21::get_custom_slip21_node(&slices);

        // copy the result to the V-App memory
        let segment = cpu.get_segment::<E>(out.0).unwrap();
        segment.write_buffer(out.0, &out_node).unwrap();

        Ok(1)
    }

    fn handle_ecfp_add_point<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        r: GuestPointer,
        p: GuestPointer,
        q: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        // copy inputs to local memory
        let mut p_local: sys::cx_ecfp_public_key_t = Default::default();
        p_local.curve = curve as u8;
        p_local.W_len = 65;
        cpu.get_segment::<E>(p.0)?
            .read_buffer(p.0, &mut p_local.W)?;

        let mut q_local: sys::cx_ecfp_public_key_t = Default::default();
        q_local.curve = curve as u8;
        q_local.W_len = 65;
        cpu.get_segment::<E>(q.0)?
            .read_buffer(q.0, &mut q_local.W)?;

        let mut r_local: sys::cx_ecfp_public_key_t = Default::default();

        // Check for point at infinity cases (first byte is 0)
        let p_is_infinity = p_local.W[0] == 0;
        let q_is_infinity = q_local.W[0] == 0;

        if p_is_infinity && q_is_infinity {
            // Both are infinity - return infinity
            r_local.W = [0u8; 65];
        } else if p_is_infinity {
            // p is infinity - return q
            r_local.W = q_local.W;
        } else if q_is_infinity {
            // q is infinity - return p
            r_local.W = p_local.W;
        } else {
            // Neither is infinity - perform the addition
            unsafe {
                let res = sys::cx_ecfp_add_point_no_throw(
                    curve as u8,
                    r_local.W.as_mut_ptr(),
                    p_local.W.as_ptr(),
                    q_local.W.as_ptr(),
                );
                if res == sys::CX_EC_INFINITE_POINT {
                    // Point at infinity - represent as 65 bytes of 0x00
                    r_local.W = [0u8; 65];
                } else if res != CX_OK {
                    return Err(CommEcallError::GenericError("add_point failed"));
                }
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local.W)?;

        Ok(1)
    }

    fn handle_ecfp_scalar_mult<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        r: GuestPointer,
        p: GuestPointer,
        k: GuestPointer,
        k_len: usize,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if k_len > 32 {
            return Err(CommEcallError::InvalidParameters("k_len is too large"));
        }

        // copy inputs to local memory
        // we use r_local also for the final result
        let mut r_local: sys::cx_ecfp_public_key_t = Default::default();
        r_local.curve = curve as u8;
        r_local.W_len = 65;
        cpu.get_segment::<E>(p.0)?
            .read_buffer(p.0, &mut r_local.W)?;

        // Check if p is the point at infinity (first byte is 0)
        if r_local.W[0] == 0 {
            // Point at infinity - return directly
            let segment = cpu.get_segment::<E>(r.0)?;
            segment.write_buffer(r.0, &r_local.W)?;
            return Ok(1);
        }

        let mut k_local: [u8; 32] = [0; 32];
        cpu.get_segment::<E>(k.0)?
            .read_buffer(k.0, &mut k_local[0..k_len])?;

        // Check if scalar is identically 0
        let mut any_nonzero = 0u8;
        for &b in &k_local[0..k_len] {
            any_nonzero |= b;
        }
        if any_nonzero == 0 {
            // Return point at infinity directly
            r_local.W = [0u8; 65];
        } else {
            unsafe {
                let res = sys::cx_ecfp_scalar_mult_no_throw(
                    curve as u8,
                    r_local.W.as_mut_ptr(),
                    k_local.as_ptr(),
                    k_len,
                );
                if res == sys::CX_EC_INFINITE_POINT {
                    // Point at infinity - represent as 65 bytes of 0x00
                    r_local.W = [0u8; 65];
                } else if res != CX_OK {
                    return Err(CommEcallError::GenericError("scalar_mult failed"));
                }
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local.W)?;

        Ok(1)
    }

    fn handle_get_random_bytes<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<u32, CommEcallError> {
        if size == 0 {
            return Ok(1); // nothing to do
        }
        if size > 256 {
            return Err(CommEcallError::InvalidParameters(
                "size is too large, must be <= 256",
            ));
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err(CommEcallError::Overflow);
        }

        let segment = cpu.get_segment::<E>(buffer.0)?;

        // generate random bytes
        let mut random_bytes = vec![0u8; size];
        unsafe {
            sys::cx_rng_no_throw(random_bytes.as_mut_ptr(), size);
        }

        // copy random bytes to V-App memory
        segment.write_buffer(buffer.0, &random_bytes)?;

        Ok(1)
    }

    fn handle_ecdsa_sign<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: GuestPointer,
        msg_hash: GuestPointer,
        signature: GuestPointer,
    ) -> Result<usize, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if mode != ecall_constants::EcdsaSignMode::RFC6979 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported ecdsa signing mode",
            ));
        }

        if hash_id != ecall_constants::HashId::Sha256 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported hash id",
            ));
        }

        // copy inputs to local memory
        let mut privkey_local = ZeroizingPrivateKey(sys::cx_ecfp_private_key_t::default());
        privkey_local.curve = curve as u8;
        privkey_local.d_len = 32;
        cpu.get_segment::<E>(privkey.0)?
            .read_buffer(privkey.0, &mut privkey_local.d)?;

        let mut msg_hash_local: [u8; 32] = [0; 32];
        cpu.get_segment::<E>(msg_hash.0)?
            .read_buffer(msg_hash.0, &mut msg_hash_local)?;

        // ECDSA signatures are at most 72 bytes long.
        let mut signature_local: [u8; 72] = [0; 72];
        let mut signature_len: usize = signature_local.len();
        let mut info: u32 = 0; // will get the parity bit

        unsafe {
            let res = sys::cx_ecdsa_sign_no_throw(
                &mut *privkey_local,
                ecall_constants::EcdsaSignMode::RFC6979 as u32,
                ecall_constants::HashId::Sha256 as u8,
                msg_hash_local.as_ptr(),
                msg_hash_local.len(),
                signature_local.as_mut_ptr(),
                &mut signature_len,
                &mut info,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError(
                    "cx_ecdsa_sign_no_throw failed",
                ));
            }
        }

        // validate signature length before writing
        if signature_len as usize > signature_local.len() {
            return Err(CommEcallError::GenericError(
                "Signature length exceeds buffer size",
            ));
        }

        // copy signature to V-App memory
        cpu.get_segment::<E>(signature.0)?
            .write_buffer(signature.0, &signature_local[0..signature_len as usize])?;

        Ok(signature_len)
    }

    fn handle_ecdsa_verify<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        pubkey: GuestPointer,
        msg_hash: GuestPointer,
        signature: GuestPointer,
        signature_len: usize,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if signature_len > 72 {
            return Err(CommEcallError::InvalidParameters(
                "signature_len is too large",
            ));
        }

        // copy inputs to local memory
        let mut pubkey_local: sys::cx_ecfp_public_key_t = Default::default();
        pubkey_local.curve = curve as u8;
        pubkey_local.W_len = 65;
        cpu.get_segment::<E>(pubkey.0)?
            .read_buffer(pubkey.0, &mut pubkey_local.W)?;

        let mut msg_hash_local: [u8; 32] = [0; 32];
        cpu.get_segment::<E>(msg_hash.0)?
            .read_buffer(msg_hash.0, &mut msg_hash_local)?;

        let mut signature_local: [u8; 72] = [0; 72];
        cpu.get_segment::<E>(signature.0)?
            .read_buffer(signature.0, &mut signature_local[0..signature_len])?;

        // verify the signature
        let res = unsafe {
            sys::cx_ecdsa_verify_no_throw(
                &pubkey_local,
                msg_hash_local.as_ptr(),
                msg_hash_local.len(),
                signature_local.as_ptr(),
                signature_len,
            )
        };

        Ok(res as u32)
    }

    fn handle_schnorr_sign<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: GuestPointer,
        msg: GuestPointer,
        msg_len: usize,
        signature: GuestPointer,
        entropy: GuestPointer,
    ) -> Result<usize, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if mode != ecall_constants::SchnorrSignMode::BIP340 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported schnorr signing mode",
            ));
        }

        if msg_len > 128 {
            return Err(CommEcallError::InvalidParameters("msg_len is too large"));
        }

        if hash_id != ecall_constants::HashId::Sha256 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported hash id",
            ));
        }

        // copy inputs to local memory
        let mut privkey_local = ZeroizingPrivateKey(sys::cx_ecfp_private_key_t::default());
        privkey_local.curve = curve as u8;
        privkey_local.d_len = 32;
        cpu.get_segment::<E>(privkey.0)?
            .read_buffer(privkey.0, &mut privkey_local.d)?;

        let mut msg_local = vec![0; 128];
        cpu.get_segment::<E>(msg.0)?
            .read_buffer(msg.0, &mut msg_local)?;

        // Schnorr signatures are at most 64 bytes long.
        let mut signature_local: [u8; 64] = [0; 64];
        let mut signature_len: usize = signature_local.len();

        unsafe {
            // We don't expose this, but cx_ecschnorr_sign_no_throw requires one of
            // CX_RND_TRNG or CX_RND_PROVIDED to be provided. We use `entropy` if it's provided,
            // CX_RND_TRNG  otherwise.
            const CX_RND_TRNG: u32 = 2 << 9;
            const CX_RND_PROVIDED: u32 = 4 << 9;

            let mode = if entropy.is_null() {
                mode | CX_RND_TRNG
            } else {
                cpu.get_segment::<E>(entropy.0)?
                    .read_buffer(entropy.0, &mut signature_local[..32])?;
                mode | CX_RND_PROVIDED
            };

            let res = sys::cx_ecschnorr_sign_no_throw(
                &mut *privkey_local,
                mode,
                ecall_constants::HashId::Sha256 as u8,
                msg_local.as_ptr(),
                msg_len,
                signature_local.as_mut_ptr(),
                &mut signature_len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError(
                    "cx_schnorr_sign_no_throw failed",
                ));
            }
        }

        // signatures returned per BIP340 are always exactly 64 bytes
        if signature_len != 64 {
            return Err(CommEcallError::GenericError(
                "cx_schnorr_sign_no_throw returned a signature of unexpected length",
            ));
        }

        // validate signature length before writing
        if signature_len as usize > signature_local.len() {
            return Err(CommEcallError::GenericError(
                "Signature length exceeds buffer size",
            ));
        }

        // copy signature to V-App memory
        cpu.get_segment::<E>(signature.0)?
            .write_buffer(signature.0, &signature_local[0..signature_len as usize])?;

        Ok(signature_len)
    }

    fn handle_schnorr_verify<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        pubkey: GuestPointer,
        msg: GuestPointer,
        msg_len: usize,
        signature: GuestPointer,
        signature_len: usize,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if mode != ecall_constants::SchnorrSignMode::BIP340 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported schnorr signing mode",
            ));
        }

        if msg_len > 128 {
            return Err(CommEcallError::InvalidParameters("msg_len is too large"));
        }

        if hash_id != ecall_constants::HashId::Sha256 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported hash id",
            ));
        }

        if signature_len != 64 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid signature length",
            ));
        }

        // copy inputs to local memory
        let mut pubkey_local: sys::cx_ecfp_public_key_t = Default::default();
        pubkey_local.curve = curve as u8;
        pubkey_local.W_len = 65;
        cpu.get_segment::<E>(pubkey.0)?
            .read_buffer(pubkey.0, &mut pubkey_local.W)?;

        let mut msg_local = vec![0; msg_len];
        cpu.get_segment::<E>(msg.0)?
            .read_buffer(msg.0, &mut msg_local)?;

        let mut signature_local: [u8; 64] = [0; 64];
        cpu.get_segment::<E>(signature.0)?
            .read_buffer(signature.0, &mut signature_local)?;

        // verify the signature
        let res = unsafe {
            sys::cx_ecschnorr_verify(
                &pubkey_local,
                mode,
                ecall_constants::HashId::Sha256 as u8,
                msg_local.as_ptr(),
                msg_len,
                signature_local.as_ptr(),
                signature_len,
            )
        };

        Ok(res as u32)
    }

    fn handle_memcpy<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        dest: GuestPointer,
        src: GuestPointer,
        len: usize,
    ) -> Result<u32, CommEcallError> {
        let mut buf: MaybeUninit<[u8; PAGE_SIZE]> = MaybeUninit::uninit();

        // SAFETY: We will fully initialize any parts of the buffer we read.
        let buf_slice: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, PAGE_SIZE) };

        let mut offset = 0;
        while offset < len {
            let src_segment = cpu.get_segment::<E>(src.0)?;
            let copy_size = min(PAGE_SIZE, len - offset);
            src_segment.read_buffer(src.0 + offset as u32, &mut buf_slice[..copy_size])?;

            let dest_segment = cpu.get_segment::<E>(dest.0)?;
            dest_segment.write_buffer(dest.0 + offset as u32, &buf_slice[..copy_size])?;
            offset += copy_size;
        }
        Ok(dest.0)
    }

    fn handle_memset<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        dest: GuestPointer,
        ch: i32,
        len: usize,
    ) -> Result<u32, CommEcallError> {
        let mut buf: MaybeUninit<[u8; PAGE_SIZE]> = MaybeUninit::uninit();

        // SAFETY: We will fully initialize any parts of the buffer we write.
        // TODO: maybe we should just use a static buffer for all the ecalls?
        let buf_slice: &mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, PAGE_SIZE) };

        let mut offset = 0;
        while offset < len {
            let copy_size = min(PAGE_SIZE, len - offset);
            buf_slice[..copy_size].fill(ch as u8); // TODO: very redundant, optimize this

            let dest_segment = cpu.get_segment::<E>(dest.0)?;
            dest_segment.write_buffer(dest.0 + offset as u32, &buf_slice[..copy_size])?;
            offset += copy_size;
        }
        Ok(dest.0)
    }

    fn handle_get_event<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        event_data_ptr: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if let Some((event_code, event_data)) = get_last_event() {
            // transmute the EventData as a [u8]
            // SAFETY: EventData is #[repr(C)] with size 16 bytes. All event data is initialized
            // via EventData::default() which zeros all 16 bytes before setting specific fields.
            // This ensures no uninitialized padding bytes exist when transmuting to &[u8].
            let event_data_raw = unsafe {
                core::slice::from_raw_parts(
                    &event_data as *const _ as *const u8,
                    core::mem::size_of::<common::ux::EventData>(),
                )
            };

            // copy event data to guest pointer
            cpu.get_segment::<E>(event_data_ptr.0)?
                .write_buffer(event_data_ptr.0, &event_data_raw)?;

            Ok(event_code as u32)
        } else {
            // if there's no stored event, wait for the next ticker and return it
            let mut comm = self.comm.borrow_mut();

            wait_for_ticker(&mut comm);

            Ok(common::ux::EventCode::Ticker as u32)
        }
    }

    fn handle_show_page<E: fmt::Debug>(
        &mut self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        page_ptr: GuestPointer,
        page_len: usize,
    ) -> Result<u32, CommEcallError> {
        if page_len > MAX_UX_PAGE_LEN {
            return Err(CommEcallError::InvalidParameters("page_len is too large"));
        }

        let mut page_local: [u8; MAX_UX_PAGE_LEN] = [0; MAX_UX_PAGE_LEN];

        cpu.get_segment::<E>(page_ptr.0)?
            .read_buffer(page_ptr.0, &mut page_local[0..page_len])?;

        let page = common::ux::Page::deserialize_full(&page_local[0..page_len])
            .map_err(|_| CommEcallError::InvalidParameters("Failed to deserialize page"))?;

        self.ux_handler.show_page(&page)?;
        Ok(1)
    }

    fn handle_show_step<E: fmt::Debug>(
        &mut self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        step_ptr: GuestPointer,
        step_len: usize,
    ) -> Result<u32, CommEcallError> {
        if step_len > MAX_UX_STEP_LEN {
            return Err(CommEcallError::InvalidParameters("step_len is too large"));
        }

        let mut step_local: [u8; MAX_UX_STEP_LEN] = [0; MAX_UX_STEP_LEN];

        cpu.get_segment::<E>(step_ptr.0)?
            .read_buffer(step_ptr.0, &mut step_local[0..step_len])?;

        let step = common::ux::Step::deserialize_full(&step_local[0..step_len])
            .map_err(|_| CommEcallError::InvalidParameters("Failed to deserialize step"))?;

        self.ux_handler.show_step(&step)?;
        Ok(1)
    }

    fn handle_get_device_property<E: fmt::Debug>(
        &mut self,
        _cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        property: u32,
    ) -> Result<u32, CommEcallError> {
        match property {
            DEVICE_PROPERTY_ID => Ok(pack_u16(VENDOR_ID, PRODUCT_ID)),
            DEVICE_PROPERTY_SCREEN_SIZE => Ok(pack_u16(SCREEN_WIDTH, SCREEN_HEIGHT)),
            DEVICE_PROPERTY_FEATURES => Ok(0),
            _ => Err(CommEcallError::InvalidParameters("Unknown device property")),
        }
    }
}

// Processes all events until a ticker is received, then returns
fn wait_for_ticker<const N: usize>(comm: &mut RefMut<'_, &mut ledger_device_sdk::io::Comm<N>>) {
    loop {
        let ety = comm.try_next_event().into_type();
        if matches!(ety, DecodedEventType::Ticker) {
            return;
        }
    }
}

#[cfg(feature = "trace_ecalls")]
fn get_ecall_name(ecall_code: u32) -> String {
    match ecall_code {
        ECALL_EXIT => "exit".into(),
        ECALL_FATAL => "fatal".into(),
        ECALL_XSEND => "xsend".into(),
        ECALL_XRECV => "xrecv".into(),
        ECALL_PRINT => "print".into(),
        ECALL_GET_EVENT => "get_event".into(),
        ECALL_SHOW_PAGE => "show_page".into(),
        ECALL_SHOW_STEP => "show_step".into(),
        ECALL_GET_DEVICE_PROPERTY => "get_device_property".into(),
        ECALL_MODM => "modm".into(),
        ECALL_ADDM => "addm".into(),
        ECALL_SUBM => "subm".into(),
        ECALL_MULTM => "multm".into(),
        ECALL_POWM => "powm".into(),
        ECALL_HASH_INIT => "hash_init".into(),
        ECALL_HASH_UPDATE => "hash_update".into(),
        ECALL_HASH_DIGEST => "hash_digest".into(),
        ECALL_DERIVE_HD_NODE => "derive_hd_node".into(),
        ECALL_GET_MASTER_FINGERPRINT => "get_master_fingerprint".into(),
        ECALL_DERIVE_SLIP21_KEY => "derive_slip21_key".into(),
        ECALL_ECFP_ADD_POINT => "ecfp_add_point".into(),
        ECALL_ECFP_SCALAR_MULT => "ecfp_scalar_mult".into(),
        ECALL_GET_RANDOM_BYTES => "get_random_bytes".into(),
        ECALL_ECDSA_SIGN => "ecdsa_sign".into(),
        ECALL_ECDSA_VERIFY => "ecdsa_verify".into(),
        ECALL_SCHNORR_SIGN => "schnorr_sign".into(),
        ECALL_SCHNORR_VERIFY => "schnorr_verify".into(),
        _ => alloc::format!("unknown: {}", ecall_code),
    }
}

impl<'a, const N: usize> EcallHandler for CommEcallHandler<'a, N> {
    type Memory = OutsourcedMemory<'a, N>;
    type Error = CommEcallError;

    fn handle_ecall(
        &mut self,
        cpu: &mut Cpu<OutsourcedMemory<'a, N>>,
    ) -> Result<(), CommEcallError> {
        macro_rules! reg {
            ($reg:ident) => {
                cpu.regs[Register::$reg.as_index() as usize]
            };
        }

        macro_rules! GPreg {
            ($reg:ident) => {
                GuestPointer(cpu.regs[Register::$reg.as_index() as usize] as u32)
            };
        }

        let ecall_code = reg!(T0);

        #[cfg(feature = "trace_ecalls")]
        crate::trace!(
            "ecall",
            "light_blue",
            "code: {}",
            get_ecall_name(ecall_code)
        );

        match ecall_code {
            ECALL_EXIT => return Err(CommEcallError::Exit(reg!(A0) as i32)),
            ECALL_FATAL => {
                self.handle_panic::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("xsend failed"))?;
                return Err(CommEcallError::Panic);
            }
            ECALL_XSEND => self
                .handle_xsend::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                .map_err(|_| CommEcallError::GenericError("xsend failed"))?,
            ECALL_XRECV => {
                let ret = self
                    .handle_xrecv::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("xrecv failed"))?;
                reg!(A0) = ret as u32;
            }
            ECALL_PRINT => {
                self.handle_print::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("print failed"))?;
                reg!(A0) = 1;
            }
            ECALL_MEMCPY => {
                crate::println!("@@@ memcpy, {} bytes", reg!(A2));
                reg!(A0) = self.handle_memcpy::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                )?;
            }
            ECALL_MEMSET => {
                crate::println!("@@@ memset, {} bytes", reg!(A2));
                reg!(A0) = self.handle_memset::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    reg!(A1) as i32,
                    reg!(A2) as usize,
                )?;
            }
            ECALL_GET_EVENT => {
                reg!(A0) = self.handle_get_event::<CommEcallError>(cpu, GPreg!(A0))?;
            }
            ECALL_SHOW_PAGE => {
                self.handle_show_page::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)?;

                reg!(A0) = 1;
            }
            ECALL_SHOW_STEP => {
                self.handle_show_step::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("show_step failed"))?;
                reg!(A0) = 1;
            }
            ECALL_GET_DEVICE_PROPERTY => {
                reg!(A0) = self
                    .handle_get_device_property::<CommEcallError>(cpu, reg!(A0))
                    .map_err(|_| CommEcallError::GenericError("get_device_property failed"))?;
            }
            ECALL_MODM => {
                self.handle_bn_modm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;

                reg!(A0) = 1;
            }
            ECALL_ADDM => {
                self.handle_bn_addm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;

                reg!(A0) = 1;
            }
            ECALL_SUBM => {
                self.handle_bn_subm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("bn_subm failed"))?;

                reg!(A0) = 1;
            }
            ECALL_MULTM => {
                self.handle_bn_multm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;

                reg!(A0) = 1;
            }
            ECALL_POWM => {
                self.handle_bn_powm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    reg!(A3) as usize,
                    GPreg!(A4),
                    reg!(A5) as usize,
                )?;

                reg!(A0) = 1;
            }
            ECALL_HASH_INIT => self
                .handle_hash_init::<CommEcallError>(cpu, reg!(A0), GPreg!(A1))
                .map_err(|_| CommEcallError::GenericError("hash_init failed"))?,
            ECALL_HASH_UPDATE => self
                .handle_hash_update::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    reg!(A3) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("hash_update failed"))?,
            ECALL_HASH_DIGEST => self
                .handle_hash_digest::<CommEcallError>(cpu, reg!(A0), GPreg!(A1), GPreg!(A2))
                .map_err(|_| CommEcallError::GenericError("hash_digest failed"))?,

            ECALL_DERIVE_HD_NODE => {
                self.handle_derive_hd_node::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                    GPreg!(A3),
                    GPreg!(A4),
                )?;

                reg!(A0) = 1;
            }
            ECALL_GET_MASTER_FINGERPRINT => {
                reg!(A0) = self.handle_get_master_fingerprint::<CommEcallError>(cpu, reg!(A0))?;
            }
            ECALL_DERIVE_SLIP21_KEY => {
                reg!(A0) = self.handle_derive_slip21_node::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    reg!(A1) as usize,
                    GPreg!(A2),
                )?;
            }

            ECALL_ECFP_ADD_POINT => {
                reg!(A0) = self.handle_ecfp_add_point::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                )?;
            }
            ECALL_ECFP_SCALAR_MULT => {
                reg!(A0) = self.handle_ecfp_scalar_mult::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;
            }

            ECALL_GET_RANDOM_BYTES => {
                reg!(A0) = self.handle_get_random_bytes::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    reg!(A1) as usize,
                )? as u32;
            }

            ECALL_ECDSA_SIGN => {
                reg!(A0) = self.handle_ecdsa_sign::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    reg!(A1),
                    reg!(A2),
                    GPreg!(A3),
                    GPreg!(A4),
                    GPreg!(A5),
                )? as u32;
            }
            ECALL_ECDSA_VERIFY => {
                reg!(A0) = self.handle_ecdsa_verify::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;
            }
            ECALL_SCHNORR_SIGN => {
                reg!(A0) = self.handle_schnorr_sign::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    reg!(A1),
                    reg!(A2),
                    GPreg!(A3),
                    GPreg!(A4),
                    reg!(A5) as usize,
                    GPreg!(A6),
                    GPreg!(A7),
                )? as u32;
            }
            ECALL_SCHNORR_VERIFY => {
                reg!(A0) = self.handle_schnorr_verify::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    reg!(A1),
                    reg!(A2),
                    GPreg!(A3),
                    GPreg!(A4),
                    reg!(A5) as usize,
                    GPreg!(A6),
                    reg!(A7) as usize,
                )?;
            }

            // Any other ecall is unhandled and will case the CPU to abort
            _ => {
                return Err(CommEcallError::UnhandledEcall);
            }
        }

        Ok(())
    }
}

impl<'a, const N: usize> Drop for CommEcallHandler<'a, N> {
    fn drop(&mut self) {
        drop_ux_handler();
    }
}
