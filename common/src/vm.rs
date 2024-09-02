//! This module provides traits to represent memory segments that are split into pages, and a
//! simple CPU model that can execute instructions from these memory segments.

use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use crate::{constants::PAGE_SIZE, riscv::op::Op};
use alloc::{format, vec::Vec};

/// Represents a single page of memory.
#[derive(Clone, Debug)]
pub struct Page {
    pub data: [u8; PAGE_SIZE],
}

/// Calculates the start address of the page containing the given address.
#[inline(always)]
fn page_start(address: u32) -> u32 {
    address & !((PAGE_SIZE as u32) - 1)
}

/// A generic trait representing a memory that is split into pages.
/// This allows abstracting over different ways of storing pages.
pub trait PagedMemory {
    type PageRef<'a>: Deref<Target = Page> + DerefMut<Target = Page> + 'a
    where
        Self: 'a;

    /// Retrieves a mutable reference to the page at the given index.
    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, &'static str>;
}

/// A simple implementation of `PagedMemory` using a vector of pages.
#[derive(Clone, Debug)]
pub struct VecMemory {
    pages: Vec<Page>,
}

impl PagedMemory for VecMemory {
    type PageRef<'a> = &'a mut Page where Self: 'a;

    fn get_page(&mut self, page_index: u32) -> Result<Self::PageRef<'_>, &'static str> {
        self.pages
            .get_mut(page_index as usize)
            .ok_or("Page not found")
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
pub struct MemorySegment<M: PagedMemory> {
    start_address: u32,
    size: u32,
    paged_memory: M,
}

impl<M: PagedMemory> MemorySegment<M> {
    /// Creates a new `MemorySegment`.
    pub fn new(start_address: u32, size: u32, paged_memory: M) -> Result<Self, &'static str> {
        if start_address.checked_add(size).is_none() {
            return Err("start_address + size does not fit in a u32");
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
    pub fn read_u8(&mut self, address: u32) -> Result<u8, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err("Address out of bounds");
        }

        let relative_address = address - page_start(self.start_address);
        let page_index = relative_address / (PAGE_SIZE as u32);
        let offset = (relative_address % (PAGE_SIZE as u32)) as usize;

        let page = self.paged_memory.get_page(page_index)?;

        Ok(page.data[offset])
    }

    /// Reads a 16-bit value from the specified address.
    #[inline]
    pub fn read_u16(&mut self, address: u32) -> Result<u16, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err("Address out of bounds");
        }

        if address % 2 != 0 {
            return Err("Unaligned address");
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
    pub fn read_u32(&mut self, address: u32) -> Result<u32, &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err("Address out of bounds");
        }

        if address % 4 != 0 {
            return Err("Unaligned address");
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
    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 1 {
            return Err("Address out of bounds");
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
    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 2 {
            return Err("Address out of bounds");
        }

        if address % 2 != 0 {
            return Err("Unaligned address");
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
    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<(), &'static str> {
        if address < self.start_address || address > self.start_address + self.size - 4 {
            return Err("Address out of bounds");
        }

        if address % 4 != 0 {
            return Err("Unaligned address");
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
}

/// Represents the state of the Risc-V CPU, with registers and three memory segments
/// for code, data and stack.
pub struct Cpu<M: PagedMemory> {
    pub pc: u32,
    pub regs: [u32; 32],
    pub code_seg: MemorySegment<M>,
    pub data_seg: MemorySegment<M>,
    pub stack_seg: MemorySegment<M>,
}

impl<M: PagedMemory> fmt::Debug for Cpu<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cpu")
            .field("pc", &format!("{:08x}", self.pc))
            .field("regs", &self.regs)
            .finish()
    }
}

impl<M: PagedMemory> Cpu<M> {
    /// Creates a new `Cpu` instance.
    pub fn new(
        entrypoint: u32,
        code_seg: MemorySegment<M>,
        data_seg: MemorySegment<M>,
        stack_seg: MemorySegment<M>,
    ) -> Cpu<M> {
        Cpu {
            pc: entrypoint,
            regs: [0; 32],
            code_seg,
            data_seg,
            stack_seg,
        }
    }

    fn read_u8(&mut self, address: u32) -> Result<u8, &'static str> {
        if self.stack_seg.contains(address) {
            return self.stack_seg.read_u8(address);
        } else if self.data_seg.contains(address) {
            return self.data_seg.read_u8(address);
        } else if self.code_seg.contains(address) {
            return self.code_seg.read_u8(address);
        }
        Err("Address out of bounds")
    }

    fn read_u16(&mut self, address: u32) -> Result<u16, &'static str> {
        if self.stack_seg.contains(address) {
            return self.stack_seg.read_u16(address);
        } else if self.data_seg.contains(address) {
            return self.data_seg.read_u16(address);
        } else if self.code_seg.contains(address) {
            return self.code_seg.read_u16(address);
        }
        Err("Address out of bounds")
    }

    fn read_u32(&mut self, address: u32) -> Result<u32, &'static str> {
        if self.stack_seg.contains(address) {
            return self.stack_seg.read_u32(address);
        } else if self.data_seg.contains(address) {
            return self.data_seg.read_u32(address);
        } else if self.code_seg.contains(address) {
            return self.code_seg.read_u32(address);
        }
        Err("Address out of bounds")
    }

    fn write_u8(&mut self, address: u32, value: u8) -> Result<(), &'static str> {
        if self.stack_seg.contains(address) {
            return self.stack_seg.write_u8(address, value);
        } else if self.data_seg.contains(address) {
            return self.data_seg.write_u8(address, value);
        }
        Err("Address out of bounds")
    }

    fn write_u16(&mut self, address: u32, value: u16) -> Result<(), &'static str> {
        if self.stack_seg.contains(address) {
            return self.stack_seg.write_u16(address, value);
        } else if self.data_seg.contains(address) {
            return self.data_seg.write_u16(address, value);
        }
        Err("Address out of bounds")
    }

    fn write_u32(&mut self, address: u32, value: u32) -> Result<(), &'static str> {
        if self.stack_seg.contains(address) {
            return self.stack_seg.write_u32(address, value);
        } else if self.data_seg.contains(address) {
            return self.data_seg.write_u32(address, value);
        }
        Err("Address out of bounds")
    }

    #[inline(always)]
    /// Fetches the next instruction to be executed.
    pub fn fetch_instruction(&mut self) -> Result<u32, &'static str> {
        self.code_seg.read_u32(self.pc)
    }

    #[rustfmt::skip]
    #[inline(always)]
    pub fn execute(&mut self, inst: u32) -> Result<(), &'static str> {
        // TODO: for now, treat everything as a NOP
        // This is a placeholder for actual instruction decoding and execution logic
        // match inst {
        //     0x00 => self.regs[0] = 0, // Example: NOP
        //     _ => panic!("Unknown instruction"),
        // }

        let mut pc_inc: u32 = 4;
        const INST_SIZE: u32 = 4;

        let op = crate::riscv::decode::decode(inst);
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
                    self.pc = self.pc.wrapping_add(imm as u32);
                }
            },
            Op::Jal { rd, imm } => {
                pc_inc = imm as u32;
                self.regs[rd as usize] = self.pc.wrapping_add(INST_SIZE);
            },
            Op::Jalr { rd, rs1, imm } => {
                let new_pc = self.regs[rs1 as usize].wrapping_add(imm as u32) & !1;
                self.regs[rd as usize] = self.pc.wrapping_add(INST_SIZE);
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
                    return Err("Unaligned 16-bit read");
                }
                let value = self.read_u16(addr)?;
                self.regs[rd as usize] = value as i16 as i32 as u32;
            },
            Op::Lw { rd, rs1, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 3 != 0 {
                    return Err("Unaligned 32-bit read");
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
                    return Err("Unaligned 16-bit read");
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
                    return Err("Unaligned 16-bit write");
                }
                let value = self.regs[rs2 as usize] as u16;
                self.write_u16(addr, value)?;
            },
            Op::Sw { rs1, rs2, imm } => {
                let addr = self.regs[rs1 as usize].wrapping_add(imm as u32);
                if addr & 3 != 0 {
                    return Err("Unaligned 32-bit write");
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
                todo!();
            },
            Op::Break => {
                todo!();
            },
            Op::Unknown => {
                return Err("Unknown instruction");
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
}
