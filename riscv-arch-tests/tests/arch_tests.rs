// This file is the integration-test entry-point for the RISC-V architectural
// tests.  Its sole job is to pull in the generated test functions produced by
// build.rs (one `#[test]` per arch-test .S source file).
//
// If the RISC-V cross-compiler was not found at build time, or the
// riscv-arch-test clone failed, `arch_tests.rs` will be an empty comment and
// this module will simply contain no tests.
//
// Run with:
//   cargo test -p vanadium-riscv-arch-tests [-- --nocapture]

include!(concat!(env!("OUT_DIR"), "/arch_tests.rs"));
