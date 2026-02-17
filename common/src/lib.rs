#![no_std]

extern crate alloc;

pub mod accumulator;
#[cfg(feature = "target_vanadium_ledger")]
pub mod client_commands;
pub mod comm;
pub mod constants;
pub mod ecall_constants;
pub mod manifest;
#[cfg(feature = "target_vanadium_ledger")]
pub mod metrics;
pub mod ux;
pub mod vm;

pub mod riscv;

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
