//! This module provides traits to represent memory segments that are split into pages, and a
//! simple CPU model that can execute instructions from these memory segments.

use core::{
    cmp::min,
    fmt,
    ops::{Deref, DerefMut},
};

use crate::{
    constants::{page_start, PAGE_SIZE},
    riscv::op::Op,
};
use alloc::{format, vec::Vec};

#[derive(Debug)]
pub enum MemoryError {
    PageNotFound,
    AddressOutOfBounds,
    UnalignedAddress,
    ZeroSize,
    StartAddressNotAligned,
    Overflow,
    GenericError(&'static str),
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryError::PageNotFound => write!(f, "Page not found"),
            MemoryError::AddressOutOfBounds => write!(f, "Address out of bounds"),
            MemoryError::UnalignedAddress => write!(f, "Unaligned address"),
            MemoryError::ZeroSize => write!(f, "size cannot be 0"),
            MemoryError::StartAddressNotAligned => {
                write!(f, "start_address must be divisible by 4")
            }
            MemoryError::Overflow => write!(f, "end address too large for a u32"),
            MemoryError::GenericError(msg) => write!(f, "{msg}"),
        }
    }
}

impl core::error::Error for MemoryError {}

/// Represents a single page of memory.
#[derive(Clone, Debug)]
pub struct Page {
    pub data: [u8; PAGE_SIZE],
}

/// A generic trait representing a memory that is split into pages.
/// This allows abstracting over different ways of storing pages.
pub trait PagedMemory: fmt::Debug {
    type PageRef<'a>: Deref<Target = Page> + DerefMut<Target = Page> + 'a
    where
        Self: 'a;

    /// Retrieves a mutable reference to the page at the given index.
    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, MemoryError>;
}

/// A simple implementation of `PagedMemory` using a vector of pages.
#[derive(Clone, Debug)]
pub struct VecMemory {
    pages: Vec<Page>,
}

impl PagedMemory for VecMemory {
    type PageRef<'a>
        = &'a mut Page
    where
        Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, MemoryError> {
        self.pages
            .get_mut(page_index as usize)
            .ok_or(MemoryError::PageNotFound)
    }
}

impl VecMemory {
    /// Creates a new `VecMemory` with the specified number of pages.
    pub fn new(n_pages: usize) -> VecMemory {
        let mut pages = Vec::with_capacity(n_pages);
        for _ in 0..n_pages {
            pages.push(Page {
                data: [0; PAGE_SIZE],
            });
        }
        VecMemory { pages }
    }
}

/// Represents a contiguous region of memory, implemented via a paged memory.
#[derive(Debug)]
pub struct MemorySegment<'a, M: PagedMemory> {
    start_address: u32,
    size: u32,
    paged_memory: &'a mut M,
}

impl<'a, M: PagedMemory> MemorySegment<'a, M> {
    /// Creates a new `MemorySegment`.
    pub fn new(
        start_address: u32,
        size: u32,
        paged_memory: &'a mut M,
    ) -> Result<Self, MemoryError> {
        if size == 0 {
            return Err(MemoryError::ZeroSize);
        }

        if start_address % 2 != 0 {
            return Err(MemoryError::StartAddressNotAligned);
        }

        if start_address.checked_add(size - 1).is_none() {
            return Err(MemoryError::Overflow);
        }

        Ok(Self {
            start_address,
            size,
            paged_memory,
        })
    }

    #[inline]
    /// Returns true if this segment contains the byte at the specified address.
    pub fn contains(&self, address: u32) -> bool {
        address >= self.start_address && address < self.start_address + self.size
    }

    /// Reads a byte from the specified address.
    #[inline]
    pub fn read_u8(&mut self, address: u32) -> Result<u8, MemoryError> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err(MemoryError::AddressOutOfBounds);
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        Ok(page.data[offset])
    }

    /// Reads a 16-bit value from the specified address.
    #[inline]
    pub fn read_u16(&mut self, address: u32) -> Result<u16, MemoryError> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err(MemoryError::AddressOutOfBounds);
        }

        if address % 2 != 0 {
            return Err(MemoryError::UnalignedAddress);
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        let value = u16::from_le_bytes([page.data[offset], page.data[offset + 1]]);

        Ok(value)
    }

    /// Reads a 32-bit value from the specified address.
    #[inline]
    pub fn read_u32(&mut self, address: u32) -> Result<u32, MemoryError> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err(MemoryError::AddressOutOfBounds);
        }

        if address % 4 != 0 {
            return Err(MemoryError::UnalignedAddress);
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        let value = u32::from_le_bytes([
            page.data[offset],
            page.data[offset + 1],
            page.data[offset + 2],
            page.data[offset + 3],
        ]);

        Ok(value)
    }

    /// Writes a byte to the specified address.
    #[inline]
    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<(), MemoryError> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err(MemoryError::AddressOutOfBounds);
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value;

        Ok(())
    }

    /// Writes a 16-bit value to the specified address.
    #[inline]
    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<(), MemoryError> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err(MemoryError::AddressOutOfBounds);
        }

        if address % 2 != 0 {
            return Err(MemoryError::UnalignedAddress);
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value as u8;
        page.data[offset + 1] = (value >> 8) as u8;

        Ok(())
    }

    /// Writes a 32-bit value to the specified address.
    #[inline]
    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<(), MemoryError> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err(MemoryError::AddressOutOfBounds);
        }

        if address % 4 != 0 {
            return Err(MemoryError::UnalignedAddress);
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let mut page = self.paged_memory.get_page(page_index)?;

        page.data[offset] = value as u8;
        page.data[offset + 1] = (value >> 8) as u8;
        page.data[offset + 2] = (value >> 16) as u8;
        page.data[offset + 3] = (value >> 24) as u8;

        Ok(())
    }

    /// Reads a buffer from the memory segment.
    ///
    /// This method reads a buffer of data from the memory segment starting at the specified address.
    /// The method takes care of page boundary crossing while reading data from pages.
    pub fn read_buffer(&mut self, address: u32, buffer: &mut [u8]) -> Result<(), MemoryError> {
        let mut current_address = address;
        let mut bytes_read = 0;

        // Check if the entire buffer is within the bounds of the memory segment
        let end_address = address
            .checked_add(buffer.len() as u32)
            .ok_or(MemoryError::Overflow)?;
        if address < self.start_address || end_address > self.start_address + self.size {
            return Err(MemoryError::AddressOutOfBounds);
        }

        while bytes_read < buffer.len() {
            // Calculate the relative address within the page and the page index
            let relative_address = current_address - page_start(self.start_address);
            let page_index = relative_address / (PAGE_SIZE as u32);
            let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

            // Get the remaining space in the current page
            let remaining_in_page = PAGE_SIZE - offset;
            let bytes_to_read = min(remaining_in_page, buffer.len() - bytes_read);

            // Read data from the page into the buffer
            let page = self.paged_memory.get_page(page_index)?;
            buffer[bytes_read..bytes_read + bytes_to_read]
                .copy_from_slice(&page.data[offset..offset + bytes_to_read]);

            // Update counters and move to the next portion of the buffer (in the next page, if any)
            bytes_read += bytes_to_read;
            current_address += bytes_to_read as u32;
        }

        Ok(())
    }

    /// Writes a buffer to the memory segment.
    ///
    /// This method writes a buffer of data to the memory segment starting at the specified address.
    /// The method takes care of page boundary crossing and flushes the content to the page.
    pub fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> Result<(), MemoryError> {
        let mut current_address = address;
        let mut bytes_written = 0;

        // Check if the entire buffer is within the bounds of the memory segment
        let end_address = address
            .checked_add(buffer.len() as u32)
            .ok_or(MemoryError::Overflow)?;
        if address < self.start_address || end_address > self.start_address + self.size {
            return Err(MemoryError::AddressOutOfBounds);
        }

        while bytes_written < buffer.len() {
            // Calculate the relative address within the page and the page index
            let relative_address = current_address - page_start(self.start_address);
            let page_index = relative_address / (PAGE_SIZE as u32);
            let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

            // Get the remaining space in the current page
            let remaining_in_page = PAGE_SIZE - offset;
            let bytes_to_write = min(remaining_in_page, buffer.len() - bytes_written);

            // Write data into the page
            let mut page = self.paged_memory.get_page(page_index)?;
            page.data[offset..offset + bytes_to_write]
                .copy_from_slice(&buffer[bytes_written..bytes_written + bytes_to_write]);

            // Update counters and move to the next portion of the buffer (in the next page, if any)
            bytes_written += bytes_to_write;
            current_address += bytes_to_write as u32;
        }

        Ok(())
    }
}

/// Represents the state of the Risc-V CPU, with registers and three memory segments
/// for code, data and stack.
pub struct Cpu<'a, M: PagedMemory> {
    pub pc: u32,
    pub regs: [u32; 32],
    pub code_seg: MemorySegment<'a, M>,
    pub data_seg: MemorySegment<'a, M>,
    pub stack_seg: MemorySegment<'a, M>,
}

pub trait EcallHandler {
    type Memory: PagedMemory;
    type Error: fmt::Debug;

    fn handle_ecall(&mut self, cpu: &mut Cpu<'_, Self::Memory>) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum CpuError<E: fmt::Debug> {
    EcallError(E),
    MemoryError(MemoryError),
    GenericError(&'static str), // TODO: make errors more specific
}

impl<E: fmt::Debug> core::error::Error for CpuError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            CpuError::EcallError(_) => None,
            CpuError::MemoryError(err) => Some(err),
            CpuError::GenericError(_) => None,
        }
    }
}

impl<E: fmt::Debug> From<&'static str> for CpuError<E> {
    fn from(err: &'static str) -> Self {
        CpuError::GenericError(err)
    }
}

impl<E: fmt::Debug> fmt::Display for CpuError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpuError::EcallError(_) => {
                write!(f, "Error returned from the ECALL handler")
            }
            CpuError::MemoryError(err) => write!(f, "Memory error: {err}"),
            CpuError::GenericError(msg) => write!(f, "{msg}"),
        }
    }
}

impl<E: fmt::Debug> From<MemoryError> for CpuError<E> {
    fn from(err: MemoryError) -> Self {
        CpuError::MemoryError(err)
    }
}

impl<'a, M: PagedMemory> fmt::Debug for Cpu<'a, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Array of register names in RISC-V
        let reg_names = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
            "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6",
        ];

        let mut debug_struct = f.debug_struct("Cpu");
        debug_struct.field("pc", &format!("{:08x}", self.pc));

        // Add the registers with names and values
        for (i, reg) in self.regs.iter().enumerate() {
            debug_struct.field(reg_names[i], &format!("{}", reg));
        }

        // Finish up the debug struct
        debug_struct.finish()
    }
}

impl<'a, M: PagedMemory> Cpu<'a, M> {
    /// Creates a new `Cpu` instance.
    pub fn new(
        entrypoint: u32,
        code_seg: MemorySegment<'a, M>,
        data_seg: MemorySegment<'a, M>,
        stack_seg: MemorySegment<'a, M>,
    ) -> Cpu<'a, M> {
        Cpu {
            pc: entrypoint,
            regs: [0; 32],
            code_seg,
            data_seg,
            stack_seg,
        }
    }

    #[inline]
    fn read_u8<E: fmt::Debug>(&mut self, address: u32) -> Result<u8, CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(self.stack_seg.read_u8(address)?);
        } else if self.data_seg.contains(address) {
            return Ok(self.data_seg.read_u8(address)?);
        } else if self.code_seg.contains(address) {
            return Ok(self.code_seg.read_u8(address)?);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline]
    fn read_u16<E: fmt::Debug>(&mut self, address: u32) -> Result<u16, CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(self.stack_seg.read_u16(address)?);
        } else if self.data_seg.contains(address) {
            return Ok(self.data_seg.read_u16(address)?);
        } else if self.code_seg.contains(address) {
            return Ok(self.code_seg.read_u16(address)?);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline]
    fn read_u32<E: fmt::Debug>(&mut self, address: u32) -> Result<u32, CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(self.stack_seg.read_u32(address)?);
        } else if self.data_seg.contains(address) {
            return Ok(self.data_seg.read_u32(address)?);
        } else if self.code_seg.contains(address) {
            return Ok(self.code_seg.read_u32(address)?);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline]
    fn write_u8<E: fmt::Debug>(&mut self, address: u32, value: u8) -> Result<(), CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(self.stack_seg.write_u8(address, value)?);
        } else if self.data_seg.contains(address) {
            return Ok(self.data_seg.write_u8(address, value)?);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline]
    fn write_u16<E: fmt::Debug>(&mut self, address: u32, value: u16) -> Result<(), CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(self.stack_seg.write_u16(address, value)?);
        } else if self.data_seg.contains(address) {
            return Ok(self.data_seg.write_u16(address, value)?);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline]
    fn write_u32<E: fmt::Debug>(&mut self, address: u32, value: u32) -> Result<(), CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(self.stack_seg.write_u32(address, value)?);
        } else if self.data_seg.contains(address) {
            return Ok(self.data_seg.write_u32(address, value)?);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline(always)]
    pub fn get_segment<E: fmt::Debug>(
        &mut self,
        address: u32,
    ) -> Result<&mut MemorySegment<'a, M>, CpuError<E>> {
        if self.stack_seg.contains(address) {
            return Ok(&mut self.stack_seg);
        } else if self.data_seg.contains(address) {
            return Ok(&mut self.data_seg);
        } else if self.code_seg.contains(address) {
            return Ok(&mut self.code_seg);
        }
        Err(MemoryError::AddressOutOfBounds.into())
    }

    #[inline(always)]
    /// Fetches the next instruction to be executed.
    pub fn fetch_instruction<E: fmt::Debug>(&mut self) -> Result<u32, CpuError<E>> {
        if self.pc % 4 == 0 && self.code_seg.contains(self.pc + 3) {
            // if the address is aligned and within boundaries, we can read four bytes at once
            Ok(self.code_seg.read_u32(self.pc)?)
        } else {
            // as the address is not 4-bytes aligned, we have to read each half separately,
            // and consider the case where the second half might not be readable
            // (which is fine if the instruction is compressed)
            let inst_lo: u16 = self.code_seg.read_u16(self.pc)?;
            let inst_hi = if inst_lo & 0b11 != 0b11 {
                // compressed instruction, ignore the second half
                0u16
            } else {
                // not a compressed instruction, we have to read the next two bytes
                self.code_seg.read_u16(self.pc + 2)?
            };
            Ok(u32::from(inst_hi) << 16 | u32::from(inst_lo))
        }
    }

    #[rustfmt::skip]
    #[inline(always)]
    pub fn execute<E: fmt::Debug>(&mut self, inst: u32, ecall_handler: Option<&mut dyn EcallHandler<Memory = M, Error = E>>) -> Result<(), CpuError<E>> {
        let (op, inst_size) = crate::riscv::decode::decode(inst);
        let mut pc_inc: u32 = inst_size;
        match op {
            Op::Add { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize].wrapping_add(self.regs[rs2 as usize]); },
            Op::Sub { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize].wrapping_sub(self.regs[rs2 as usize]); },
            Op::Sll { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize] << (self.regs[rs2 as usize] & 0x1f); },
            Op::Slt { rd, rs1, rs2 } => { self.regs[rd as usize] = ((self.regs[rs1 as usize] as i32) < (self.regs[rs2 as usize] as i32)) as u32; },
            Op::Sltu { rd, rs1, rs2 } => { self.regs[rd as usize] = (self.regs[rs1 as usize] < self.regs[rs2 as usize]) as u32; },
            Op::Xor { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize] ^ self.regs[rs2 as usize]; },
            Op::Srl { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize] >> (self.regs[rs2 as usize] & 0x1f); },
            Op::Sra { rd, rs1, rs2 } => { self.regs[rd as usize] = ((self.regs[rs1 as usize] as i32) >> (self.regs[rs2 as usize] & 0x1f)) as u32; },
            Op::Or { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize] | self.regs[rs2 as usize]; },
            Op::And { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize] & self.regs[rs2 as usize]; },
            Op::Mul { rd, rs1, rs2 } => { self.regs[rd as usize] = self.regs[rs1 as usize].wrapping_mul(self.regs[rs2 as usize]); },
            Op::Mulh { rd, rs1, rs2 } => {
                let result = ((self.regs[rs1 as usize] as i64) * (self.regs[rs2 as usize] as i64)) >> 32;
                self.regs[rd as usize] = result as u32;
            },
            Op::Mulhsu { rd, rs1, rs2 } => {
                let signed_val = self.regs[rs1 as usize] as i32 as i64;
                let unsigned_val = self.regs[rs2 as usize] as u64;
                let result = (signed_val * (unsigned_val as i64)) >> 32;
                self.regs[rd as usize] = result as u32;
            },
            Op::Mulhu { rd, rs1, rs2 } => {
                let result = ((self.regs[rs1 as usize] as u64) * (self.regs[rs2 as usize] as u64)) >> 32;
                self.regs[rd as usize] = result as u32;
            },
            Op::Div { rd, rs1, rs2 } => {
                if self.regs[rs2 as usize] == 0 {
                    self.regs[rd as usize] = u32::MAX;
                } else {
                    self.regs[rd as usize] = ((self.regs[rs1 as usize] as i32).wrapping_div(self.regs[rs2 as usize] as i32)) as u32;
                }
            },
            Op::Divu { rd, rs1, rs2 } => {
                if self.regs[rs2 as usize] == 0 {
                    self.regs[rd as usize] = u32::MAX;
                } else {
                    self.regs[rd as usize] = self.regs[rs1 as usize] / self.regs[rs2 as usize];
                }
            },
            Op::Rem { rd, rs1, rs2 } => {
                if self.regs[rs2 as usize] == 0 {
                    self.regs[rd as usize] = self.regs[rs1 as usize];
                } else {
                    self.regs[rd as usize] = ((self.regs[rs1 as usize] as i32).wrapping_rem(self.regs[rs2 as usize] as i32)) as u32;
                }
            },
            Op::Remu { rd, rs1, rs2 } => {
                if self.regs[rs2 as usize] == 0 {
                    self.regs[rd as usize] = self.regs[rs1 as usize];
                } else {
                    self.regs[rd as usize] = self.regs[rs1 as usize] % self.regs[rs2 as usize];
                }
            },
            Op::Addi { rd, rs1, imm } => { self.regs[rd as usize] = self.regs[rs1 as usize].wrapping_add(imm as u32); },
            Op::Andi { rd, rs1, imm } => { self.regs[rd as usize] = self.regs[rs1 as usize] & (imm as u32); },
            Op::Auipc { rd, imm } => { self.regs[rd as usize] = self.pc.wrapping_add(imm as u32); },
            Op::Beq { rs1, rs2, imm } => {
                if self.regs[rs1 as usize] == self.regs[rs2 as usize] {
                    pc_inc = imm as u32;
                }
            },
            Op::Bne { rs1, rs2, imm } => {
                if self.regs[rs1 as usize] != self.regs[rs2 as usize] {
                    pc_inc = imm as u32;
                }
            },
            Op::Blt { rs1, rs2, imm } => {
                if (self.regs[rs1 as usize] as i32) < (self.regs[rs2 as usize] as i32) {
                    pc_inc = imm as u32;
                }
            },
            Op::Bge { rs1, rs2, imm } => {
                if (self.regs[rs1 as usize] as i32) >= (self.regs[rs2 as usize] as i32) {
                    pc_inc = imm as u32;
                }
            },
            Op::Bltu { rs1, rs2, imm } => {
                if self.regs[rs1 as usize] < self.regs[rs2 as usize] {
                    pc_inc = imm as u32;
                }
            },
            Op::Bgeu { rs1, rs2, imm } => {
                if self.regs[rs1 as usize] >= self.regs[rs2 as usize] {
                    pc_inc = imm as u32;
                }
            },
            Op::Jal { rd, imm } => {
                pc_inc = imm as u32;
                self.regs[rd as usize] = self.pc.wrapping_add(inst_size);
            },
            Op::Jalr { rd, rs1, imm } => {
                let new_pc = self.regs[rs1 as usize].wrapping_add(imm as u32) & !1;
                self.regs[rd as usize] = self.pc.wrapping_add(inst_size);
                self.pc = new_pc;
                pc_inc = 0;
            },
            Op::Lb { rd, rs1, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                let value = self.read_u8(addr)?;
                self.regs[rd as usize] = value as i8 as i32 as u32;
            },
            Op::Lh { rd, rs1, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 1 != 0 {
                    return Err("Unaligned 16-bit read".into());
                }
                let value = self.read_u16(addr)?;
                self.regs[rd as usize] = value as i16 as i32 as u32;
            },
            Op::Lw { rd, rs1, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 3 != 0 {
                    return Err("Unaligned 32-bit read".into());
                }
                let value = self.read_u32(addr)?;
                self.regs[rd as usize] = value;
            },
            Op::Lbu { rd, rs1, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                let value = self.read_u8(addr)?;
                self.regs[rd as usize] = value as u32;
            },
            Op::Lhu { rd, rs1, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 1 != 0 {
                    return Err("Unaligned 16-bit read".into());
                }
                let value = self.read_u16(addr)?;
                self.regs[rd as usize] = value as u32;
            },
            Op::Lui { rd, imm } => { self.regs[rd as usize] = imm as u32; },
            Op::Ori { rd, rs1, imm } => { self.regs[rd as usize] = self.regs[rs1 as usize] | (imm as u32); },
            Op::Sb { rs1, rs2, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                let value = self.regs[rs2 as usize] as u8;
                self.write_u8(addr, value)?;
            },
            Op::Sh { rs1, rs2, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 1 != 0 {
                    return Err("Unaligned 16-bit write".into());
                }
                let value = self.regs[rs2 as usize] as u16;
                self.write_u16(addr, value)?;
            },
            Op::Sw { rs1, rs2, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 3 != 0 {
                    return Err("Unaligned 32-bit write".into());
                }
                let value = self.regs[rs2 as usize];
                self.write_u32(addr, value)?;
            },
            Op::Slli { rd, rs1, imm } => { self.regs[rd as usize] = self.regs[rs1 as usize] << (imm & 0x1f); },
            Op::Slti { rd, rs1, imm } => { self.regs[rd as usize] = ((self.regs[rs1 as usize] as i32) < imm) as u32; },
            Op::Sltiu { rd, rs1, imm } => { self.regs[rd as usize] = (self.regs[rs1 as usize] < imm as u32) as u32; },
            Op::Srli { rd, rs1, imm } => { self.regs[rd as usize] = self.regs[rs1 as usize] >> (imm & 0x1f); },
            Op::Srai { rd, rs1, imm } => { self.regs[rd as usize] = ((self.regs[rs1 as usize] as i32) >> (imm & 0x1f)) as u32; },
            Op::Xori { rd, rs1, imm } => { self.regs[rd as usize] = self.regs[rs1 as usize] ^ (imm as u32); },

            Op::Ecall => {
                if let Some(ecall_handler) = ecall_handler {
                    ecall_handler.handle_ecall(self).map_err(CpuError::EcallError)?;
                } else {
                    return Err("No ECALL handler".into());
                }
            },
            Op::Break => {
                return Err("BREAK instruction is not supported".into());
            },
            Op::Unknown => {
                return Err("Unknown instruction".into());
            },
        }

        self.pc = self.pc.wrapping_add(pc_inc);
        self.regs[0] = 0;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_vec_memory_new() {
        let n_pages = 5;
        let vec_memory = VecMemory::new(n_pages);

        assert_eq!(vec_memory.pages.len(), n_pages);
        for page in vec_memory.pages.iter() {
            assert_eq!(page.data, [0; PAGE_SIZE]);
        }
    }

    #[test]
    fn test_vec_memory_get_page() {
        let n_pages = 3;
        let mut vec_memory = VecMemory::new(n_pages);

        // Test valid page access
        for i in 0..n_pages {
            let page = vec_memory.get_page(i as u32).expect("Page should exist");
            assert_eq!(page.data, [0; PAGE_SIZE]);
        }

        // Test out-of-bounds page access
        assert!(vec_memory.get_page(n_pages as u32).is_err());
    }

    #[test]
    fn test_vec_memory_modify_page() {
        let n_pages = 3;
        let mut vec_memory = VecMemory::new(n_pages);

        // Modify a page and verify the change
        let page_index = 1;
        {
            let page = vec_memory.get_page(page_index).expect("Page should exist");
            page.data[42] = 42;
        }

        let page = vec_memory.get_page(page_index).expect("Page should exist");
        assert_eq!(page.data[42], 42);
    }

    #[test]
    fn test_memory_segment_new() {
        let mut paged_memory = VecMemory::new(16);
        let size = (PAGE_SIZE * 16) as u32;
        let segment = MemorySegment::new(0, size, &mut paged_memory);
        assert!(segment.is_ok());

        // Failure cases

        // 0-sized memory
        let mut paged_memory = VecMemory::new(1);
        assert!(MemorySegment::new(1, 0, &mut paged_memory).is_err());

        // Test unaligned start addresses
        let mut paged_memory = VecMemory::new(16);
        assert!(MemorySegment::new(1, size, &mut paged_memory).is_err());

        let mut paged_memory = VecMemory::new(16);
        assert!(MemorySegment::new(3, size, &mut paged_memory).is_err());

        // Overflow: ending address is too large
        let mut paged_memory = VecMemory::new(16);
        assert!(MemorySegment::new(-(size as i32 - 1) as u32, size, &mut paged_memory).is_err());

        // This one is ok, the last byte has address 0xffffffff
        let mut paged_memory = VecMemory::new(16);
        assert!(MemorySegment::new(-(size as i32) as u32, size, &mut paged_memory).is_ok());
    }

    #[test]
    fn test_memory_segment_contains() {
        let mut paged_memory = VecMemory::new(16);
        let size = (PAGE_SIZE * 16) as u32;
        let segment = MemorySegment::new(0, size, &mut paged_memory).unwrap();
        assert!(segment.contains(0));
        assert!(segment.contains(size - 1));

        // out of bounds
        assert!(!segment.contains(size));
        assert!(!segment.contains(size + 1));
        assert!(!segment.contains(0xffffffffu32));
    }

    #[test]
    fn test_memory_segment_read() {
        let mut paged_memory = VecMemory::new(16);

        let first_page = paged_memory.get_page(0).unwrap();
        first_page.data[0] = 1;
        first_page.data[1] = 2;
        first_page.data[2] = 3;
        first_page.data[3] = 4;

        let mut segment = MemorySegment::new(0, 4096, &mut paged_memory).unwrap();

        // Test read_u8
        assert_eq!(segment.read_u8(0).unwrap(), 1);

        // Test read_u16
        assert_eq!(segment.read_u16(0).unwrap(), 0x0201);

        // Test read_u32
        assert_eq!(segment.read_u32(0).unwrap(), 0x04030201);
    }

    #[test]
    fn test_memory_segment_write() {
        let mut paged_memory = VecMemory::new(16);
        let mut segment = MemorySegment::new(0, 4096, &mut paged_memory).unwrap();

        // Test write_u8
        segment.write_u8(0, 42).unwrap();
        assert_eq!(segment.read_u8(0).unwrap(), 42);

        // Test write_u16
        segment.write_u16(0, 0x0201).unwrap();
        assert_eq!(segment.read_u16(0).unwrap(), 0x0201);

        // Test write_u32
        segment.write_u32(0, 0x04030201).unwrap();
        assert_eq!(segment.read_u32(0).unwrap(), 0x04030201);
    }

    #[test]
    fn test_memory_segment_write_buffer_single_page() {
        let mut paged_memory = VecMemory::new(1); // Single page of memory
        let mut segment = MemorySegment::new(0, PAGE_SIZE as u32, &mut paged_memory).unwrap();

        assert!(PAGE_SIZE == 256); // this test would need to be adapted for different page sizes

        let buffer: Vec<u8> = (0..=(PAGE_SIZE - 1) as u8).collect(); // A buffer with values 0..PAGE_SIZE - 1
        segment.write_buffer(0, &buffer).unwrap(); // Write the buffer to memory

        assert_eq!(segment.paged_memory.get_page(0).unwrap().data, &buffer[..]);

        // Read back each byte and verify it matches the buffer
        let mut read_buffer = vec![0; PAGE_SIZE];
        segment.read_buffer(0, &mut read_buffer).unwrap();
        assert_eq!(read_buffer, buffer);
    }

    #[test]
    fn test_memory_segment_write_buffer_cross_page_boundary() {
        let mut paged_memory = VecMemory::new(2); // Two pages of memory
        let mut segment = MemorySegment::new(0, (PAGE_SIZE * 2) as u32, &mut paged_memory).unwrap();

        let buffer: Vec<u8> = (0..32).collect(); // Buffer that spans across two pages
        let start_address = PAGE_SIZE as u32 - 16; // 16 bytes away from the page boundary
        segment.write_buffer(start_address, &buffer).unwrap();

        assert_eq!(
            segment.paged_memory.get_page(0).unwrap().data[PAGE_SIZE - 16..PAGE_SIZE],
            buffer[0..16]
        );
        assert_eq!(
            segment.paged_memory.get_page(1).unwrap().data[0..16],
            buffer[16..32]
        );

        // Read back each byte and verify it matches the buffer
        let mut read_buffer = vec![0; 32];
        segment
            .read_buffer(start_address, &mut read_buffer)
            .unwrap();
        assert_eq!(read_buffer, buffer);
    }

    #[test]
    fn test_memory_segment_write_buffer_multiple_pages() {
        let mut paged_memory = VecMemory::new(4); // Three pages of memory
        let mut segment =
            MemorySegment::new(44, (PAGE_SIZE * 3) as u32, &mut paged_memory).unwrap();

        let start_address = 56u32;

        let buffer_size = PAGE_SIZE * 2;

        let buffer: Vec<u8> = (0..buffer_size).map(|i| (i % 256) as u8).collect(); // Buffer that spans three pages (due to misalignment)
        segment.write_buffer(start_address, &buffer).unwrap(); // Write buffer to memory

        // Read back the entire buffer and verify it matches the original
        let mut read_buffer = vec![0; buffer_size];
        segment
            .read_buffer(start_address, &mut read_buffer)
            .unwrap();
        assert_eq!(read_buffer, buffer);
    }

    #[test]
    fn test_memory_segment_write_read_empty_buffer() {
        let mut paged_memory = VecMemory::new(1);
        let mut segment = MemorySegment::new(0, PAGE_SIZE as u32, &mut paged_memory).unwrap();

        // Empty buffer write should succeed without doing anything
        let write_result = segment.write_buffer(0, &[]);
        assert!(write_result.is_ok());

        // Empty buffer read should also succeed without doing anything
        let mut read_buffer = vec![0; 0];
        let read_result = segment.read_buffer(0, &mut read_buffer);
        assert!(read_result.is_ok());
    }
}
