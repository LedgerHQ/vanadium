use core::{cell::RefCell, cmp::min};

use alloc::{rc::Rc, vec};
use common::{
    client_commands::{
        Message, ReceiveBufferMessage, ReceiveBufferResponse, SendBufferMessage,
        SendPanicBufferMessage,
    },
    ecall_constants::*,
    manifest::Manifest,
    vm::{Cpu, EcallHandler},
};
use ledger_secure_sdk_sys::CX_OK;

use crate::{AppSW, Instruction};

use super::outsourced_mem::OutsourcedMemory;

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

pub struct CommEcallHandler<'a> {
    comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm>>,
    manifest: &'a Manifest,
}

impl<'a> CommEcallHandler<'a> {
    pub fn new(
        comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm>>,
        manifest: &'a Manifest,
    ) -> Self {
        Self { comm, manifest }
    }

    // TODO: can we refactor this and handle_xsend? They are almost identical
    fn handle_panic(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        mut size: usize,
    ) -> Result<(), &'static str> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            SendPanicBufferMessage::new(size as u32, vec![]).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err("Buffer overflow");
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment(g_ptr)?;

        // loop while size > 0
        while size > 0 {
            let copy_size = min(size, 255 - 4); // send maximum 251 bytes per message

            let mut buffer = vec![0; copy_size];
            segment.read_buffer(g_ptr, &mut buffer)?;

            let mut comm = self.comm.borrow_mut();
            SendPanicBufferMessage::new(size as u32, buffer).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }

            size -= copy_size;
            g_ptr += copy_size as u32;
        }

        Ok(())
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    // TODO: we might want to revise the protocol, not as optimized as it could be
    fn handle_xsend(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        mut size: usize,
    ) -> Result<(), &'static str> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            SendBufferMessage::new(size as u32, vec![]).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err("Buffer overflow");
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment(g_ptr)?;

        // loop while size > 0
        while size > 0 {
            let copy_size = min(size, 255 - 4); // send maximum 251 bytes per message

            let mut buffer = vec![0; copy_size];
            segment.read_buffer(g_ptr, &mut buffer)?;

            let mut comm = self.comm.borrow_mut();
            SendBufferMessage::new(size as u32, buffer).serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Continue"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }

            size -= copy_size;
            g_ptr += copy_size as u32;
        }

        Ok(())
    }

    // Receives up to max_size bytes from the host into the buffer in the V-app memory
    // Returns the catual of bytes received.
    fn handle_xrecv(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        buffer: GuestPointer,
        max_size: usize,
    ) -> Result<usize, &'static str> {
        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment(g_ptr)?;

        let mut remaining_length = None;
        let mut total_received: usize = 0;
        while remaining_length != Some(0) {
            let mut comm = self.comm.borrow_mut();
            ReceiveBufferMessage::new().serialize_to_comm(&mut comm);
            comm.reply(AppSW::InterruptedExecution);

            let Instruction::Continue(p1, p2) = comm.next_command() else {
                return Err("INS not supported"); // expected "Data"
            };

            if (p1, p2) != (0, 0) {
                return Err("Wrong P1/P2");
            }

            let raw_data = comm.get_data().map_err(|_| "Invalid response from host")?;
            let response = ReceiveBufferResponse::deserialize(raw_data)?;

            drop(comm); // TODO: figure out how to avoid having to deal with this drop explicitly

            match remaining_length {
                None => {
                    // first chunk, check if the total length is acceptable
                    if response.remaining_length > max_size as u32 {
                        return Err("Received data is too large");
                    }
                    remaining_length = Some(response.remaining_length);
                }
                Some(remaining) => {
                    if remaining != response.remaining_length {
                        return Err("Mismatching remaining length");
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

    fn handle_bn_modm(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        r: GuestPointer,
        n: GuestPointer,
        len: usize,
        m: GuestPointer,
        m_len: usize,
    ) -> Result<(), &'static str> {
        if len > MAX_BIGNUMBER_SIZE || m_len > MAX_BIGNUMBER_SIZE {
            return Err("len or m_len is too large");
        }

        // copy inputs to local memory
        // we use r_local both for the input and for the result
        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(n.0)?.read_buffer(n.0, &mut r_local)?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(m.0)?.read_buffer(m.0, &mut m_local)?;

        unsafe {
            let res = ledger_secure_sdk_sys::cx_math_modm_no_throw(
                r_local.as_mut_ptr(),
                len,
                m_local.as_ptr(),
                m_len,
            );
            if res != CX_OK {
                return Err("modm failed");
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment(r.0)?;
        segment.write_buffer(r.0, &r_local)?;
        Ok(())
    }

    fn handle_bn_addm(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), &'static str> {
        if len > MAX_BIGNUMBER_SIZE {
            return Err("len is too large");
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(a.0)?.read_buffer(a.0, &mut a_local)?;
        let mut b_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(b.0)?.read_buffer(b.0, &mut b_local)?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(m.0)?.read_buffer(m.0, &mut m_local)?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = ledger_secure_sdk_sys::cx_math_addm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                b_local.as_ptr(),
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err("addm failed");
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment(r.0)?;
        segment.write_buffer(r.0, &r_local)?;
        Ok(())
    }

    fn handle_bn_subm(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), &'static str> {
        if len > MAX_BIGNUMBER_SIZE {
            return Err("len is too large");
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(a.0)?.read_buffer(a.0, &mut a_local)?;
        let mut b_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(b.0)?.read_buffer(b.0, &mut b_local)?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(m.0)?.read_buffer(m.0, &mut m_local)?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = ledger_secure_sdk_sys::cx_math_subm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                b_local.as_ptr(),
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err("addm failed");
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment(r.0)?;
        segment.write_buffer(r.0, &r_local)?;
        Ok(())
    }

    fn handle_bn_multm(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), &'static str> {
        if len > MAX_BIGNUMBER_SIZE {
            return Err("len is too large");
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(a.0)?.read_buffer(a.0, &mut a_local)?;
        let mut b_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(b.0)?.read_buffer(b.0, &mut b_local)?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(m.0)?.read_buffer(m.0, &mut m_local)?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = ledger_secure_sdk_sys::cx_math_multm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                b_local.as_ptr(),
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err("addm failed");
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment(r.0)?;
        segment.write_buffer(r.0, &r_local)?;
        Ok(())
    }

    fn handle_bn_powm(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_>>,
        r: GuestPointer,
        a: GuestPointer,
        e: GuestPointer,
        len_e: usize,
        m: GuestPointer,
        len: usize,
    ) -> Result<(), &'static str> {
        if len_e > MAX_BIGNUMBER_SIZE {
            return Err("len_e is too large");
        }
        if len > MAX_BIGNUMBER_SIZE {
            return Err("len is too large");
        }

        // copy inputs to local memory
        let mut a_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(a.0)?.read_buffer(a.0, &mut a_local)?;
        let mut e_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(e.0)?.read_buffer(e.0, &mut e_local)?;
        let mut m_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        cpu.get_segment(m.0)?.read_buffer(m.0, &mut m_local)?;

        let mut r_local: [u8; MAX_BIGNUMBER_SIZE] = [0; MAX_BIGNUMBER_SIZE];
        unsafe {
            let res = ledger_secure_sdk_sys::cx_math_powm_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                e_local.as_ptr(),
                len_e,
                m_local.as_ptr(),
                len,
            );
            if res != CX_OK {
                return Err("addm failed");
            }
        }

        // copy r_local to r
        let segment = cpu.get_segment(r.0)?;
        segment.write_buffer(r.0, &r_local)?;
        Ok(())
    }
}

// make an error type for the CommEcallHandler<'a>
pub enum CommEcallError {
    Exit(i32),
    Panic,
    GenericError(&'static str),
    UnhandledEcall,
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
                self.handle_panic(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("xsend failed"))?;
                return Err(CommEcallError::Panic);
            }
            ECALL_XSEND => self
                .handle_xsend(cpu, GPreg!(A0), reg!(A1) as usize)
                .map_err(|_| CommEcallError::GenericError("xsend failed"))?,
            ECALL_XRECV => {
                let ret = self
                    .handle_xrecv(cpu, GPreg!(A0), reg!(A1) as usize)
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
            ECALL_MODM => self
                .handle_bn_modm(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                    GPreg!(A3),
                    reg!(A4) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("bn_modm failed"))?,
            ECALL_ADDM => self
                .handle_bn_addm(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("bn_addm failed"))?,
            ECALL_SUBM => self
                .handle_bn_subm(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("bn_subm failed"))?,
            ECALL_MULTM => self
                .handle_bn_multm(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("bn_multm failed"))?,
            ECALL_POWM => self
                .handle_bn_powm(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    reg!(A3) as usize,
                    GPreg!(A4),
                    reg!(A5) as usize,
                )
                .map_err(|_| CommEcallError::GenericError("bn_powm failed"))?,
            _ => {
                return Err(CommEcallError::UnhandledEcall);
            }
        }

        Ok(())
    }
}
