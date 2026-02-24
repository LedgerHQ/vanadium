/*
 * model_test.h — Vanadium target macros for riscv-arch-test
 *
 * This file defines the model-specific macros required by arch_test.h.
 * We deliberately do NOT define rvtest_mtrap_routine so that arch_test.h
 * omits all CSR/trap-handler scaffolding (Vanadium has no CSR support).
 *
 * Halt protocol: RVMODEL_HALT emits "li t0, 93; ecall".
 * The Vanadium ECALL convention places the call code in t0 (x6).
 * The test runner detects t0==93 as the halt sentinel.
 */

#ifndef _COMPLIANCE_MODEL_H
#define _COMPLIANCE_MODEL_H

/* Required alignment for mtvec (unused but must be defined). */
#define RVMODEL_MTVEC_ALIGN 6

/* Boot code: empty — Vanadium has no special boot sequence. */
#define RVMODEL_BOOT

/*
 * Halt the simulation.
 *
 * For Spike:    writes 1 (HTIF exit-0 command) to `tohost` first, causing
 *               Spike to exit cleanly before reaching the ecall.
 * For Vanadium: the tohost write is a harmless store to a data address;
 *               ECALL with t0 = 93 signals the test runner to stop.
 */
#define RVMODEL_HALT                                             \
    la t0, tohost;                                               \
    li t1, 1;                                                    \
    sw t1, 0(t0);   /* HTIF low  word = 1 → Spike exits here */  \
    sw zero, 4(t0); /* HTIF high word = 0                     */ \
    li t0, 93;                                                   \
    ecall; /* Vanadium stops here                     */         \
    1 : j 1b

/*
 * Signature region delimiters.
 *
 * RVTEST_SIG_BEGIN (defined in arch_test.h) calls RVMODEL_DATA_BEGIN
 * then defines rvtest_sig_begin.  We just ensure 4-byte alignment.
 *
 * RVTEST_SIG_END (defined in arch_test.h) calls RVMODEL_DATA_END and
 * defines rvtest_sig_end.  Nothing special needed on our side.
 */
#define RVMODEL_DATA_BEGIN .align 4;
#define RVMODEL_DATA_END

/*
 * Optional I/O assertion hooks used by TEST_CASE macros inside test_macros.h.
 * Vanadium does not have an I/O subsystem, so these are no-ops.
 */
#define RVMODEL_IO_ASSERT_GPR_EQ(ScrReg, Reg, Value)
#define RVMODEL_IO_ASSERT_SFPR_EQ(ScrReg, Reg, Value)
#define RVMODEL_IO_ASSERT_DFPR_EQ(ScrReg, Reg, Value)
#define RVMODEL_IO_WRITE_STR(ScrReg, String)

#endif /* _COMPLIANCE_MODEL_H */
