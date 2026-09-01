ECALLs allow Risc-V code to call system services, that are provided by the environment. The Vanadium VM defines ECALLs for low level primitives (communication, screen management, etc.) and access to the implementation cryptographic accelerator, or other functionalities the VM provides for performance reasons.

# Risc-V calling conventions for ECALLs

ECALLs use the following calling convention:

- ECALL code in `t0`
- Up to 8 ECALL arguments in `a0`, `a1`, ..., `a7`, in this order.
- Return value (if any) is in `a0`.

No ECALLs with more than 8 argments (using the stack) are currently defined.

# Currently defined ECALLs

See [ecalls.rs](../app-sdk/src/ecalls.rs) for the interface and documentation of the currently defined ECALLs.

# Implementation of ECALLs

Each new ECALL requires:
- adding the appropriate constants in [`common/src/ecall_constants.rs`](../common/src/ecall_constants.rs);
- add the ECALL to [`app-sdk/src/ecalls.rs`](../app-sdk/src/ecalls.rs);
- implementing the ECALL for native compilation in [`app-sdk/src/ecalls_native.rs`](../app-sdk/src/ecalls_native.rs);
- implementing the ECALL code generation via the macros in [`app-sdk/src/ecalls_riscv.rs`](../app-sdk/src/ecalls_riscv.rs) and [`ecalls/src/lib.rs`](../ecalls/src/lib.rs);
- implementing the ECALL handler in the Vanadium VM in [`vm/src/handlers/lib/ecall.rs`](../vm/src/handlers/lib/ecall.rs);
- expose the functionality of the ECALL via the appropriate abstraction in the app-sdk;
- add code to the [sadik V-App](../apps/sadik/) in order to test the new ECALLs.

ECALLs are not exported directly in the `vanadium-app-sdk`. Rather, clean Rust abstractions are implemented. Apart from providing a cleaner interface, the goal of the abstraction is to avoid that the application code depends on the low-level details of ECALLs. This allows breaking changes in the ECALLs, or even target-specific ECALLs, without impacting the users of the crate.

Eventually, the goal is to stabilize a set of ECALLs that constitutes the core of Vanadium, in order to simplify adding new targets.

# Big-number arithmetic and RSA

The big-number ECALLs (`bn_modm`, `bn_addm`, `bn_subm`, `bn_multm`, `bn_powm`, `bn_modinv_prime`) provide modular arithmetic on operands up to `MAX_BIGNUMBER_SIZE` (512 bytes, i.e. 4096 bits). They are exposed to V-Apps through the [`bignum`](../app-sdk/src/bignum.rs) module of the app SDK.
