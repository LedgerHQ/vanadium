#!/usr/bin/env python3
"""
Extract the RISC-V arch-test signature region from a Spike --log-commits log.

Usage:
    python3 extract_sig.py <elf> <commits_log> <sig_begin_hex> <sig_end_hex> <output_file>

The log is the stderr output of:
    spike --log-commits --isa=rv32imac_zicsr <elf>

Every store committed by Spike appears as a line of the form:
    core   0: 3 <pc> (<insn>) mem <addr> <value>

This script seeds the signature region with the ELF's initial data (so that
words the test never writes retain their true initial value), then overlays
every store that Spike committed inside [sig_begin, sig_end), and writes one
8-hex-digit word per 4-byte slot to <output_file>.

Stores are handled at byte granularity: byte stores (SB) write one byte into
the word, halfword stores (SH) write two bytes, and word stores (SW) replace
the entire word.  The store width is inferred from the instruction encoding
captured in the commit log.
"""
import re
import struct
import sys


def store_width_from_insn(insn: int) -> int:
    """Return the store width in bytes (1, 2, or 4) from a RISC-V instruction.

    Handles both 32-bit (SB/SH/SW, opcode 0x23) and 16-bit compressed
    (C.SW, opcode 0xE2) encodings.  Falls back to 4 for unrecognised forms.
    """
    if (insn & 0xFFFF) == insn:
        # 16-bit compressed instruction
        # C.SW: funct3=110 (0b110), op=10 → bits [15:13]=110, bits[1:0]=10
        if (insn & 0b1110_0000_0000_0011) == 0b1100_0000_0000_0010:
            return 4  # C.SW
        return 4  # default
    # 32-bit instruction
    opcode = insn & 0x7F
    if opcode == 0x23:  # S-type store
        funct3 = (insn >> 12) & 0x7
        if funct3 == 0:
            return 1  # SB
        elif funct3 == 1:
            return 2  # SH
        else:
            return 4  # SW
    return 4  # default


def read_elf_initial_words(elf_path: str, sig_begin: int, sig_end: int) -> dict:
    """Return {addr: word} for every 4-byte slot in [sig_begin, sig_end)
    using the ELF's PT_LOAD file data (BSS bytes default to 0)."""
    data = open(elf_path, "rb").read()

    e_phoff     = struct.unpack_from("<I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    e_phnum     = struct.unpack_from("<H", data, 0x2C)[0]

    initial: dict = {}
    for i in range(e_phnum):
        off      = e_phoff + i * e_phentsize
        p_type   = struct.unpack_from("<I", data, off + 0x00)[0]
        p_offset = struct.unpack_from("<I", data, off + 0x04)[0]
        p_vaddr  = struct.unpack_from("<I", data, off + 0x08)[0]
        p_filesz = struct.unpack_from("<I", data, off + 0x10)[0]
        p_memsz  = struct.unpack_from("<I", data, off + 0x14)[0]

        if p_type != 1:  # PT_LOAD
            continue
        seg_end = p_vaddr + p_memsz
        if seg_end <= sig_begin or p_vaddr >= sig_end:
            continue

        addr = sig_begin
        while addr < sig_end:
            rel      = addr - p_vaddr
            in_file  = rel < p_filesz
            file_off = p_offset + rel
            if in_file and file_off + 4 <= len(data):
                val = struct.unpack_from("<I", data, file_off)[0]
            else:
                val = 0  # BSS
            initial[addr] = val
            addr += 4

    return initial


def main() -> None:
    if len(sys.argv) != 6:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    elf_path, log_path, sig_begin_s, sig_end_s, out_path = sys.argv[1:]
    sig_begin = int(sig_begin_s, 16)
    sig_end   = int(sig_end_s, 16)

    # Seed with ELF initial values so unwritten words keep their true value.
    mem = read_elf_initial_words(elf_path, sig_begin, sig_end)

    # Pattern captures optional instruction encoding and the mem store.
    store_pat = re.compile(
        r"(?:\(0x([0-9a-f]+)\))?\s*mem (0x[0-9a-f]+) (0x[0-9a-f]+)"
    )

    # Overlay with what Spike actually stored during execution.
    with open(log_path) as f:
        for line in f:
            m = store_pat.search(line)
            if not m:
                continue
            insn_str, addr_str, val_str = m.group(1), m.group(2), m.group(3)
            addr = int(addr_str, 16)
            val  = int(val_str, 16)
            if not (sig_begin <= addr < sig_end):
                continue
            insn  = int(insn_str, 16) if insn_str else 0
            width = store_width_from_insn(insn)
            word_addr = addr & ~3
            byte_off  = addr & 3
            cur_word  = mem.get(word_addr, 0)
            if width == 1:
                # Clear the target byte, OR in the new value.
                cur_word = (cur_word & ~(0xFF << (byte_off * 8))) | ((val & 0xFF) << (byte_off * 8))
                mem[word_addr] = cur_word
            elif width == 2:
                # Clear the two target bytes, OR in the halfword value.
                cur_word = (cur_word & ~(0xFFFF << (byte_off * 8))) | ((val & 0xFFFF) << (byte_off * 8))
                mem[word_addr] = cur_word
            else:
                # Full-word store: replace.
                mem[word_addr] = val & 0xFFFFFFFF

    lines = []
    addr = sig_begin
    while addr < sig_end:
        lines.append(f"{mem.get(addr, 0):08x}")
        addr += 4

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
