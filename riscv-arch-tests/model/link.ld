/*
 * link.ld — Bare-metal linker script for riscv-arch-test binaries
 *
 * Produces exactly two PT_LOAD segments:
 *   - CODE  (RX)  at 0x80000000  — text, rodata
 *   - DATA  (RWX) at 0x80100000  — data, bss, signature region
 *
 * The entry point is rvtest_entry_point (a global symbol emitted by
 * RVTEST_CODE_BEGIN in arch_test.h).
 */

ENTRY(rvtest_entry_point)

MEMORY {
    CODE (rx)  : ORIGIN = 0x80000000, LENGTH = 1M
    DATA (rwx) : ORIGIN = 0x80100000, LENGTH = 512K
}

PHDRS {
    seg_text PT_LOAD FLAGS(5);   /* PF_R | PF_X */
    seg_data PT_LOAD FLAGS(6);   /* PF_R | PF_W */
}

SECTIONS {
    /* ---- Code segment ---- */
    . = ORIGIN(CODE);

    .text.init ALIGN(4) :
    {
        *(.text.init)
    } > CODE : seg_text

    .text ALIGN(4) :
    {
        *(.text*)
    } > CODE : seg_text

    .rodata ALIGN(4) :
    {
        *(.rodata*)
    } > CODE : seg_text

    /* ---- Data segment ---- */
    . = ORIGIN(DATA);

    .data ALIGN(16) :
    {
        *(.data*)
    } > DATA : seg_data

    .bss ALIGN(16) :
    {
        *(.bss*)
        *(COMMON)
    } > DATA : seg_data

    /*
     * Spike HTIF communication region.
     * tohost/fromhost must be 8-byte aligned and in a writable segment.
     * Writing 1 to tohost signals a clean exit to Spike.
     * Plain assignments (not PROVIDE) are used so both symbols always
     * appear in the ELF symbol table regardless of whether they are
     * referenced by code.
     */
    .htif ALIGN(8) :
    {
        tohost   = .;
        LONG(0); LONG(0);
        fromhost = .;
        LONG(0); LONG(0);
    } > DATA : seg_data

    /DISCARD/ :
    {
        *(.riscv.attributes)
        *(.comment)
    }
}
