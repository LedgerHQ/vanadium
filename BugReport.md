# Vanadium Security Bugs

## Bug 1: Integer Underflow
File: vm/src/handlers/lib/ecall.rs:472
Issue: Unchecked subtraction on remaining_length allows underflow if response exceeds declared size.
Fix: Use checked_sub with error handling.

## Bug 2: Panic on Corrupted Memory
File: vm/src/handlers/lib/outsourced_mem.rs:351
Issue: unwrap() on decrypted data size causes panic if decryption fails.
Fix: Return error instead of panicking.

## Bug 3: Unaligned Pointer Cast (CRITICAL)
File: vm/src/handlers/lib/ecall.rs:850
Issue: Cast byte array pointer to u32 slice without alignment guarantee. Undefined behavior on ARM.
Fix: Read bytes and combine manually, or use #[repr(align(4))].

## Bug 4: Buffer Bounds Not Rechecked
File: vm/src/handlers/lib/ecall.rs:362-384
Issue: Initial bounds check insufficient; loop increments unvalidated.
Fix: Validate each write operation.

## Bug 5: Signature Length Unchecked
File: vm/src/handlers/lib/ecall.rs:1165, 1306
Issue: signature_len cast to usize without bounds check.
Fix: Add length validation before slicing.

## Bug 6: Page Index Calculation Unvalidated
File: common/src/vm.rs:141-145
Issue: page_index calculated without explicit bounds check.
Fix: Validate page_index against max pages.
