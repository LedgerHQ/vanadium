use core::{
    cell::{RefCell, RefMut},
    cmp::min,
    fmt,
};

use alloc::{format, rc::Rc, string::String, vec};
use common::{
    client_commands::{
        Message, MessageDeserializationError, ReceiveBufferMessage, ReceiveBufferResponse,
        SendBufferMessage, SendPanicBufferMessage,
    },
    ecall_constants::{self, *},
    manifest::Manifest,
    ux::Serializable,
    vm::{Cpu, CpuError, EcallHandler, MemoryError},
};
use ledger_device_sdk::hash::HashInit;
use ledger_secure_sdk_sys::{
    self as sys, cx_ripemd160_t, cx_sha256_t, cx_sha512_t, seph as sys_seph, CX_OK, CX_RIPEMD160,
    CX_SHA256, CX_SHA512,
};

use crate::{AppSW, Instruction};

use super::outsourced_mem::OutsourcedMemory;

use zeroize::Zeroizing;

mod ux_handler;

#[cfg(any(target_os = "stax", target_os = "flex"))]
mod bitmaps;

use ux_handler::*;

// BIP32 supports up to 255, but we don't want that many, and it would be very slow anyway
const MAX_BIP32_PATH: usize = 16;

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

// A pointer in the V-app's address space
#[derive(Debug, Clone, Copy)]
struct GuestPointer(pub u32);

#[derive(Debug, Clone, Copy)]
enum LedgerHashContextError {
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

pub enum CommEcallError {
    Exit(i32),
    Panic,
    InvalidParameters(&'static str),
    GenericError(&'static str),
    WrongINS,
    WrongP1P2,
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
            CommEcallError::WrongINS => write!(f, "Wrong INS"),
            CommEcallError::WrongP1P2 => write!(f, "Wrong P1/P2"),
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

pub struct CommEcallHandler<'a> {
    comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm>>,
    manifest: &'a Manifest,
    ux_handler: &'static mut UxHandler,
}

impl<'a> CommEcallHandler<'a> {
    pub fn new(
        comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm>>,
        manifest: &'a Manifest,
    ) -> Self {
        Self {
            comm,
            manifest,
            ux_handler: init_ux_handler(),
        }
    }

    // TODO: can we refactor this and handle_xsend? They are almost identical
    fn handle_panic<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        mut size: usize,
    ) -> Result<(), CommEcallError> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            SendPanicBufferMessage::new(size as u32, vec![]).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err(CommEcallError::WrongINS); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err(CommEcallError::WrongP1P2);
            }
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err(CommEcallError::Overflow);
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        // loop while size > 0
        while size > 0 {
            let copy_size = min(size, 255 - 4); // send maximum 251 bytes per message

            let mut buffer = vec![0; copy_size];
            segment.read_buffer(g_ptr, &mut buffer)?;

            let mut comm = self.comm.borrow_mut();
            SendPanicBufferMessage::new(size as u32, buffer).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err(CommEcallError::WrongINS); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err(CommEcallError::WrongP1P2);
            }

            size -= copy_size;
            g_ptr += copy_size as u32;
        }

        Ok(())
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    // TODO: we might want to revise the protocol, not as optimized as it could be
    fn handle_xsend<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        mut size: usize,
    ) -> Result<(), CommEcallError> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            SendBufferMessage::new(size as u32, vec![]).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err(CommEcallError::WrongINS); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err(CommEcallError::WrongP1P2);
            }
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err(CommEcallError::Overflow);
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        // loop while size > 0
        while size > 0 {
            let copy_size = min(size, 255 - 4); // send maximum 251 bytes per message

            let mut buffer = vec![0; copy_size];
            segment.read_buffer(g_ptr, &mut buffer)?;

            let mut comm = self.comm.borrow_mut();
            SendBufferMessage::new(size as u32, buffer).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err(CommEcallError::WrongINS); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err(CommEcallError::WrongP1P2);
            }

            size -= copy_size;
            g_ptr += copy_size as u32;
        }

        Ok(())
    }

    // Receives up to max_size bytes from the host into the buffer in the V-app memory
    // Returns the catual of bytes received.
    fn handle_xrecv<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        max_size: usize,
    ) -> Result<usize, CommEcallError> {
        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        let mut remaining_length = None;
        let mut total_received: usize = 0;
        while remaining_length != Some(0) {
            let mut comm = self.comm.borrow_mut();
            ReceiveBufferMessage::new().serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err(CommEcallError::WrongINS); // expected "Data"
            };

            if (p1, p2) != (0, 0) {
                return Err(CommEcallError::WrongP1P2);
            }

            let raw_data = comm
                .get_data()
                .map_err(|_| CommEcallError::InvalidResponse(""))?;
            let response = ReceiveBufferResponse::deserialize(raw_data)?;

            drop(comm); // TODO: figure out how to avoid having to deal with this drop explicitly

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

            segment.write_buffer(g_ptr, &response.content)?;

            remaining_length = Some(remaining_length.unwrap() - response.content.len() as u32);
            g_ptr += response.content.len() as u32;
            total_received += response.content.len();
        }
        Ok(total_received)
    }

    fn handle_bn_modm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
                sys::cx_hash_update(
                    ctx_local.as_mut_ptr() as *mut sys::cx_hash_header_s,
                    data_local.as_ptr(),
                    copy_size as usize,
                );
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
            sys::cx_hash_final(
                ctx_local.as_mut_ptr() as *mut sys::cx_hash_header_s,
                digest_local.as_mut_ptr(),
            );
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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

        // convert to a slice of u32, by taking 4 bytes at the time as big-endian integers
        let path_local = unsafe {
            core::slice::from_raw_parts(path_local_raw.as_ptr() as *const u32, path_len as usize)
        };

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
        _cpu: &mut Cpu<OutsourcedMemory<'_>>,
        curve: u32,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        // derive the key
        let mut private_key_local = Zeroizing::new([0u8; 32]);
        let mut chain_code_local: [u8; 32] = [0; 32];

        let mut pubkey: sys::cx_ecfp_public_key_t = Default::default();
        unsafe {
            sys::os_perso_derive_node_bip32(
                CurveKind::Secp256k1 as u8,
                [].as_ptr(),
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

    fn handle_ecfp_add_point<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        unsafe {
            let res = sys::cx_ecfp_add_point_no_throw(
                curve as u8,
                r_local.W.as_mut_ptr(),
                p_local.W.as_ptr(),
                q_local.W.as_ptr(),
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError("add_point failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local.W)?;

        Ok(1)
    }

    fn handle_ecfp_scalar_mult<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
            // TODO: do we need to support any larger?
            return Err(CommEcallError::InvalidParameters("k_len is too large"));
        }

        // copy inputs to local memory
        // we use r_local also for the final result
        let mut r_local: sys::cx_ecfp_public_key_t = Default::default();
        r_local.curve = curve as u8;
        r_local.W_len = 65;
        cpu.get_segment::<E>(p.0)?
            .read_buffer(p.0, &mut r_local.W)?;

        let mut k_local: [u8; 32] = [0; 32];
        cpu.get_segment::<E>(k.0)?
            .read_buffer(k.0, &mut k_local[0..k_len])?;

        unsafe {
            let res = sys::cx_ecfp_scalar_mult_no_throw(
                curve as u8,
                r_local.W.as_mut_ptr(),
                k_local.as_ptr(),
                k_len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError("scalar_mult failed"));
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment::<E>(r.0)?;
        segment.write_buffer(r.0, &r_local.W)?;

        Ok(1)
    }

    fn handle_ecdsa_sign<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        // TODO: we should zeroize the private key after use
        let mut privkey_local: sys::cx_ecfp_private_key_t = Default::default();
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
                &mut privkey_local,
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

        // copy signature to V-App memory
        cpu.get_segment::<E>(signature.0)?
            .write_buffer(signature.0, &signature_local[0..signature_len as usize])?;

        Ok(signature_len)
    }

    fn handle_ecdsa_verify<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: GuestPointer,
        msg: GuestPointer,
        msg_len: usize,
        signature: GuestPointer,
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
        // TODO: we should zeroize the private key after use
        let mut privkey_local: sys::cx_ecfp_private_key_t = Default::default();
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
            // CX_RND_TRNG or CX_RND_PROVIDED to be provided. We just use CX_RND_TRNG for now.
            const CX_RND_TRNG: u32 = 2 << 9;

            let res = sys::cx_ecschnorr_sign_no_throw(
                &mut privkey_local,
                mode | CX_RND_TRNG,
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

        // copy signature to V-App memory
        cpu.get_segment::<E>(signature.0)?
            .write_buffer(signature.0, &signature_local[0..signature_len as usize])?;

        Ok(signature_len)
    }

    fn handle_schnorr_verify<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
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

        let mut msg_local = vec![0; 128];
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

    fn handle_get_event<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        event_data_ptr: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        // for now, the only supported event is the ticker. So we wait for a ticker event,
        // and return it. Once UX functionalities are added, button presses would also be
        // returned here.
        if let Some((event_code, event_data)) = get_last_event() {
            // transmute the EventData as a [u8]
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
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        page_ptr: GuestPointer,
        page_len: usize,
    ) -> Result<u32, CommEcallError> {
        if page_len > MAX_UX_PAGE_LEN {
            return Err(CommEcallError::InvalidParameters("page_len is too large"));
        }

        let mut page_local: [u8; MAX_UX_PAGE_LEN] = [0; MAX_UX_PAGE_LEN];

        cpu.get_segment::<E>(page_ptr.0)?
            .read_buffer(page_ptr.0, &mut page_local[0..page_len])?;

        let page = common::ux::Page::deserialize_full(&page_local[0..page_len]).map_err(|e| {
            crate::println!("Failed to deserialize page: {:?}", e);
            CommEcallError::InvalidParameters("Failed to deserialize page")
        })?;

        self.ux_handler.show_page(&page)?;
        Ok(1)
    }
}

// Processes all events until a ticker is received, then returns
fn wait_for_ticker(comm: &mut RefMut<'_, &mut ledger_device_sdk::io::Comm>) {
    loop {
        let mut spi_buffer = [0u8; 256];

        let event: ledger_device_sdk::io::Event<crate::ApduHeader> = loop {
            // Signal end of command stream from SE to MCU
            // And prepare reception
            if !sys_seph::is_status_sent() {
                sys_seph::send_general_status();
            }

            // Fetch the next message from the MCU
            let _rx = sys_seph::seph_recv(&mut spi_buffer, 0);

            // decode and process event
            if let Some(e) = comm.process_event(&mut spi_buffer) {
                break e;
            }
        };

        match event {
            ledger_device_sdk::io::Event::Command(_e) => {
                // TODO: how to avoid receiving APDUs is we're not expecting it?
                panic!("We actually don't want to receive commands here.");
            }
            #[cfg(not(any(target_os = "stax", target_os = "flex")))]
            ledger_device_sdk::io::Event::Button(_button) => {
                // nothing to do, we don't yet handle buttons
                crate::println!("Button event. Unhandled");
            }
            #[cfg(any(target_os = "stax", target_os = "flex"))]
            ledger_device_sdk::io::Event::TouchEvent => {
                crate::println!("Touch event. Unhandled");
                // nothing to do, we don't yet know how to handle them
            }
            ledger_device_sdk::io::Event::Ticker => {
                return;
            }
        }
    }
}

impl<'a> EcallHandler for CommEcallHandler<'a> {
    type Memory = OutsourcedMemory<'a>;
    type Error = CommEcallError;

    fn handle_ecall(&mut self, cpu: &mut Cpu<OutsourcedMemory<'a>>) -> Result<(), CommEcallError> {
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
            ECALL_UX_IDLE => {
                #[cfg(not(any(target_os = "stax", target_os = "flex")))]
                {
                    ledger_device_sdk::ui::gadgets::clear_screen();
                    let page = ledger_device_sdk::ui::gadgets::Page::from((
                        [self.manifest.get_app_name(), "is ready"],
                        false,
                    ));
                    page.place();
                }

                #[cfg(any(target_os = "stax", target_os = "flex"))]
                {
                    use include_gif::include_gif;
                    const FERRIS: ledger_device_sdk::nbgl::NbglGlyph =
                        ledger_device_sdk::nbgl::NbglGlyph::from_include(include_gif!(
                            "crab_64x64.gif",
                            NBGL
                        ));

                    ledger_device_sdk::nbgl::NbglHomeAndSettings::new()
                        .glyph(&FERRIS)
                        .infos(
                            self.manifest.get_app_name(),
                            self.manifest.get_app_version(),
                            "", // TODO
                        )
                        .show_and_return();
                }
            }
            ECALL_GET_EVENT => {
                reg!(A0) = self.handle_get_event::<CommEcallError>(cpu, GPreg!(A0))?;
            }
            ECALL_SHOW_PAGE => {
                self.handle_show_page::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)?;

                reg!(A0) = 1;
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
