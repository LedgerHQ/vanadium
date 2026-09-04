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

# Elliptic curves

`CurveKind` in [`ecall_constants.rs`](../common/src/ecall_constants.rs) is the single source of truth for which curves exist and what sizes follow from them (`scalar_len`, `point_len`, `max_der_signature_len`). Its discriminants are the Ledger SDK's `CX_CURVE_*` values, so the VM passes a `curve` ECALL argument straight through as the `curve` field of a `cx_ecfp_*_key_t`.

Not every curve is accepted by every curve ECALL:

| Curve | Point arithmetic, ECDSA verify | Signing, HD derivation, master fingerprint | Schnorr |
|---|---|---|---|
| `Secp256k1` (0x21) | yes | yes | yes (BIP-340) |
| `Secp256r1` (0x22) | yes | no | no |
| `Secp384r1` (0x23) | yes | no | no |

The asymmetry is deliberate and is recorded on the type as `CurveKind::supports_private_key_ops`. The private-key operations reach the device seed, which the VM only derives on secp256k1; BIP-340 Schnorr is defined for secp256k1 alone. P-256 and P-384 exist so a V-App can *verify* signatures produced elsewhere — DNSSEC algorithms 13 and 14, for instance — which needs no seed access.

Points cross the ECALL boundary in uncompressed SEC1 form (`0x04 || X || Y`), except the point at infinity, which is all-zero bytes. The length is `point_len()` for the curve, so it is implied by the `curve` argument rather than passed. ECDSA signatures are DER-encoded, because that is what `cx_ecdsa_verify_no_throw` takes; a V-App holding a raw `r || s` signature must encode it. The digest length, by contrast, *is* passed explicitly (`msg_hash_len`): ECDSA accepts a digest shorter than the curve order, so it does not follow from the curve.

Passing an unrecognised curve, an over-long signature or an over-long digest is treated as a V-App bug and terminates it, rather than being reported as an invalid signature. `ecdsa_verify` returns 0 only for a signature that is genuinely invalid.

Two things to know when adding a curve:

- **The VM's handlers are inlined into `handle_ecall`**, so a handler's stack locals are charged to the frame of *every* ECALL. Handlers whose buffer sizes depend on the curve width are therefore split into `#[inline(never)]` helpers, one per width. The native stack is the binding RAM constraint on this platform — see the comment in [`vm/.cargo/config.toml`](../vm/.cargo/config.toml) — so measure before and after.
- **The app must declare the curve** in `[package.metadata.ledger] curve` in [`vm/Cargo.toml`](../vm/Cargo.toml). Beware that the name differs between the two Ledger tools: the C SDK's `install_params.py`, which the build goes through, spells P-256 `secp256r1` and raises on anything else, while `ledgerwallet`'s `manifest.py` spells it `prime256r1` and silently ignores names it does not recognise. There is no P-384 bit at all, which is harmless here because the permission gates seed derivation rather than verification.
