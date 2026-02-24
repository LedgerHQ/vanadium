//! Test runner for the RISC-V architectural tests.
//!
//! The single public entry-point is [`run_test`].  Everything else is
//! internal scaffolding for loading an ELF binary, executing it through the
//! Vanadium CPU, reading the signature region and comparing it against the
//! golden reference.

use common::constants::{page_start, PAGE_SIZE};
use common::vm::{Cpu, CpuError, EcallHandler, MemoryError, MemorySegment, VecMemory};
use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
use goblin::elf::Elf;
use goblin::Object;

// ── ELF address-space layout ─────────────────────────────────────────────────
// These match the MEMORY regions in model/link.ld.
const STACK_BASE: u32 = 0x80200000; // bottom of stack
const STACK_SIZE: u32 = 0x10000; //  64 KiB

// ── Halt sentinel ────────────────────────────────────────────────────────────
// RVMODEL_HALT does  "li t0, 93; ecall".  t0 = x5 = regs[5].
const HALT_CODE: u32 = 93;

// ── Instruction step limit ───────────────────────────────────────────────────
// Upper bound on the number of instructions executed before we declare
// a test as hung.  Generous enough for the largest arch test.
const MAX_STEPS: u64 = 50_000_000;

// ─────────────────────────────────────────────────────────────────────────────

/// Load *elf_bytes*, run the test on the Vanadium CPU, dump the signature
/// region, and compare it (normalised) against *ref_output*.
///
/// Returns `Ok(())` on a match; `Err(message)` with a human-readable
/// explanation otherwise.
pub fn run_test(elf_bytes: &[u8], ref_output: &str) -> Result<(), String> {
    // ── 1. Parse ELF ─────────────────────────────────────────────────────────
    let elf = match Object::parse(elf_bytes).map_err(|e| format!("ELF parse error: {e}"))? {
        Object::Elf(e) => e,
        _ => return Err("Not an ELF file".into()),
    };

    if elf.is_64 {
        return Err("Expected a 32-bit ELF".into());
    }
    let entry = elf.entry as u32;

    // ── 2. Identify segments ─────────────────────────────────────────────────
    let mut code_phdr = None;
    let mut data_phdr = None;
    for phdr in elf.program_headers.iter() {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if phdr.p_flags & PF_X != 0 {
            code_phdr = Some(phdr);
        } else if phdr.p_flags & PF_W != 0 {
            data_phdr = Some(phdr);
        }
    }
    let code_phdr = code_phdr.ok_or("ELF lacks an executable (code) PT_LOAD segment")?;
    let data_phdr = data_phdr.ok_or("ELF lacks a writable (data) PT_LOAD segment")?;

    // ── 3. Allocate and populate VecMemory ───────────────────────────────────
    let mut code_mem = alloc_segment_memory(code_phdr.p_vaddr as u32, code_phdr.p_memsz as u32);
    let mut data_mem = alloc_segment_memory(data_phdr.p_vaddr as u32, data_phdr.p_memsz as u32);
    let mut stack_mem = alloc_raw_memory(STACK_SIZE);

    // Write file bytes (p_filesz); BSS tail stays zeroed from VecMemory::new.
    {
        let start = code_phdr.p_vaddr as u32;
        let size = code_phdr.p_memsz as u32;
        let mut seg = make_seg(start, size, &mut code_mem)?;
        let file_slice = elf_slice(
            elf_bytes,
            code_phdr.p_offset as usize,
            code_phdr.p_filesz as usize,
        )?;
        seg.write_buffer(start, file_slice).map_err(mem_err)?;
    }
    {
        let start = data_phdr.p_vaddr as u32;
        let size = data_phdr.p_memsz as u32;
        let mut seg = make_seg(start, size, &mut data_mem)?;
        let file_slice = elf_slice(
            elf_bytes,
            data_phdr.p_offset as usize,
            data_phdr.p_filesz as usize,
        )?;
        seg.write_buffer(start, file_slice).map_err(mem_err)?;
    }

    // ── 4. Locate signature symbols ──────────────────────────────────────────
    let (sig_begin, sig_end) =
        find_sig_bounds(&elf).ok_or("ELF missing rvtest_sig_begin / rvtest_sig_end symbols")?;
    if sig_begin >= sig_end {
        return Err(format!(
            "Invalid signature bounds: sig_begin={:#010x} sig_end={:#010x}",
            sig_begin, sig_end
        ));
    }

    // ── 5. Build CPU and run ─────────────────────────────────────────────────
    let code_seg = make_seg(
        code_phdr.p_vaddr as u32,
        code_phdr.p_memsz as u32,
        &mut code_mem,
    )?;
    let data_seg = make_seg(
        data_phdr.p_vaddr as u32,
        data_phdr.p_memsz as u32,
        &mut data_mem,
    )?;
    let stack_seg = make_seg(STACK_BASE, STACK_SIZE, &mut stack_mem)?;

    let mut cpu = Cpu::new(entry, code_seg, data_seg, stack_seg);
    // sp = top of stack (stack grows downward)
    cpu.regs[2] = STACK_BASE + STACK_SIZE;

    let mut handler = HaltHandler { halted: false };

    let mut steps: u64 = 0;
    loop {
        let inst = cpu
            .fetch_instruction::<String>()
            .map_err(|e| format!("Fetch error at pc={:#010x}: {e:?}", cpu.pc))?;

        match cpu.execute::<String>(inst, Some(&mut handler)) {
            Ok(()) => {}
            // Treat unsupported/unknown instructions as no-ops (e.g. FENCE).
            // execute() did NOT advance pc on error, so we do it here.
            Err(CpuError::GenericError("Unknown instruction")) => {
                let inst_size: u32 = if inst & 0b11 == 0b11 { 4 } else { 2 };
                cpu.pc = cpu.pc.wrapping_add(inst_size);
            }
            Err(e) => return Err(format!("CPU error at pc={:#010x}: {e:?}", cpu.pc)),
        }

        if handler.halted {
            break;
        }

        steps += 1;
        if steps >= MAX_STEPS {
            return Err(format!(
                "Test did not halt after {MAX_STEPS} instructions (last pc={:#010x})",
                cpu.pc
            ));
        }
    }

    // ── 6. Dump signature ────────────────────────────────────────────────────
    if sig_begin < data_phdr.p_vaddr as u32
        || sig_end > data_phdr.p_vaddr as u32 + data_phdr.p_memsz as u32
    {
        return Err(format!(
            "Signature [{:#010x}, {:#010x}) is outside the data segment",
            sig_begin, sig_end
        ));
    }

    let mut got_lines: Vec<String> = Vec::new();
    let mut addr = sig_begin;
    while addr < sig_end {
        let word = cpu
            .data_seg
            .read_u32(addr)
            .map_err(|e| format!("Signature read error at {addr:#010x}: {e:?}"))?;
        got_lines.push(format!("{:08x}", word));
        addr = addr.wrapping_add(4);
    }

    let got_sig = got_lines.join("\n") + "\n";

    // ── 7. Compare against golden reference ──────────────────────────────────
    let ref_sig = normalise_sig(ref_output);

    if got_sig != ref_sig {
        return Err(build_diff_message(&got_sig, &ref_sig));
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Symbol halt: set when ECALL with t0==HALT_CODE is seen.
struct HaltHandler {
    halted: bool,
}

impl EcallHandler for HaltHandler {
    type Memory = VecMemory;
    type Error = String;

    fn handle_ecall(&mut self, cpu: &mut Cpu<'_, VecMemory>) -> Result<(), String> {
        // t0 = x5 = regs[5]
        if cpu.regs[5] == HALT_CODE {
            self.halted = true;
        }
        Ok(())
    }
}

/// Allocate a `VecMemory` large enough to back a `MemorySegment` starting at
/// *start* with *size* bytes (handles non-page-aligned starts).
fn alloc_segment_memory(start: u32, size: u32) -> VecMemory {
    let page_base = page_start(start);
    let needed = (start - page_base) as usize + size as usize;
    let n_pages = needed.div_ceil(PAGE_SIZE);
    VecMemory::new(n_pages.max(1))
}

/// Allocate a `VecMemory` of *size* bytes starting at page 0.
fn alloc_raw_memory(size: u32) -> VecMemory {
    let n_pages = (size as usize).div_ceil(PAGE_SIZE);
    VecMemory::new(n_pages.max(1))
}

/// Convenience wrapper: `MemorySegment::new` + convert error.
fn make_seg(
    start: u32,
    size: u32,
    mem: &mut VecMemory,
) -> Result<MemorySegment<'_, VecMemory>, String> {
    MemorySegment::new(start, size, mem).map_err(mem_err)
}

fn mem_err(e: MemoryError) -> String {
    format!("Memory error: {e:?}")
}

/// Returns a `&[u8]` slice into *bytes* at *offset* of *len* bytes.
fn elf_slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], String> {
    bytes
        .get(offset..offset + len)
        .ok_or_else(|| format!("ELF file data out of bounds: offset={offset} len={len}"))
}

/// Walk the ELF symbol table to find `rvtest_sig_begin` and `rvtest_sig_end`.
fn find_sig_bounds(elf: &Elf<'_>) -> Option<(u32, u32)> {
    let mut sig_begin: Option<u32> = None;
    let mut sig_end: Option<u32> = None;

    for sym in elf.syms.iter() {
        let name = match elf.strtab.get_at(sym.st_name) {
            Some(n) => n,
            None => continue,
        };
        match name {
            "rvtest_sig_begin" => sig_begin = Some(sym.st_value as u32),
            "rvtest_sig_end" => sig_end = Some(sym.st_value as u32),
            _ => {}
        }
    }

    Some((sig_begin?, sig_end?))
}

/// Normalise a signature string: strip optional `0x` prefix, lowercase,
/// drop empty lines, collect one word per line, add trailing newline.
fn normalise_sig(s: &str) -> String {
    let mut lines: Vec<String> = s
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let t = l.trim();
            let hex = t.strip_prefix("0x").unwrap_or(t).to_lowercase();
            // Pad / truncate to exactly 8 hex digits.
            format!("{:0>8}", &hex[hex.len().saturating_sub(8)..])
        })
        .collect();
    lines.push(String::new()); // trailing newline
    lines.join("\n")
}

/// Produce a readable diff between the two aligned signature dumps.
fn build_diff_message(got: &str, expected: &str) -> String {
    let got_lines: Vec<&str> = got.lines().collect();
    let exp_lines: Vec<&str> = expected.lines().collect();
    let max = got_lines.len().max(exp_lines.len());

    let mut diffs: Vec<String> = Vec::new();
    for i in 0..max {
        let g = got_lines.get(i).copied().unwrap_or("<missing>");
        let e = exp_lines.get(i).copied().unwrap_or("<missing>");
        if g != e {
            diffs.push(format!("  word {:>4}: got {g}, expected {e}", i));
        }
    }

    let preview: String = diffs
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    let extra = if diffs.len() > 20 {
        format!("\n  ... and {} more mismatches", diffs.len() - 20)
    } else {
        String::new()
    };

    format!(
        "Signature mismatch ({} word(s) differ):\n{preview}{extra}",
        diffs.len()
    )
}
