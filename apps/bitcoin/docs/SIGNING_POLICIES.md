This document specifies **signing policies** for the Vanadium Bitcoin app: programs that a key
commits to, and that the device evaluates before signing with that key.

The transport and key-binding layers are specified in [PSBT.md](PSBT.md#signing-policies). This
document specifies the *engine*: the program format, its memory model, how it is invoked, and the
interface through which it observes the transaction.

Status: **draft specification. Not implemented.** The resource limits in
[Limits](#limits) are provisional and must be calibrated against a measurement of the nested
interpreter (see [Open problems](#open-problems)).

# Rationale

A signing policy needs to express conditions over a whole transaction. Earlier iterations of this
feature defined a small bespoke language for the purpose; every step toward generality (byte
strings, per-input access, loops, state) meant growing a lexer, a parser and an evaluator, and the
result was still unable to express anything about an individual input or output.

This engine instead executes **riscv32imac** machine code:

- policies are written in Rust (or any language with a RISC-V backend) and use an existing,
  well-tested compiler toolchain;
- the interpreter already exists. `common/src/vm.rs` provides `Cpu`, `MemorySegment`, the
  `PagedMemory` and `EcallHandler` traits and an in-RAM `VecMemory` backend, with the decoder in
  `common/src/riscv/`. It is `no_std` and generic over its memory backend, and the `common` crate
  is already a transitive dependency of this app through `vanadium-app-sdk`;
- expensive primitives — taproot tweaks, hash functions, elliptic-curve operations — are exposed as
  *accelerated calls* serviced by the app, so a policy never implements cryptography in RISC-V;
- with loops, memory and per-input invocation, a policy can simulate proposed consensus features.
  The design target is [BIP-443](https://github.com/bitcoin/bips/blob/master/bip-0443.mediawiki)
  `OP_CHECKCONTRACTVERIFY`, whose deferred amount logic requires state that survives across the
  evaluation of individual inputs.

Note that the app itself runs as RISC-V code interpreted by the Vanadium VM, so a policy program is
interpreted by an interpreter that is itself being interpreted. This is the dominant cost of the
design and the reason for the accelerated calls and the tight limits.

# Model

A signing policy is a **riscv32imac program image** (a `.vpol` file). The SHA-256 of its
`SigningPolicy` value encoding is committed in the BIP-32 derivation path of the key it encumbers,
exactly as specified in [PSBT.md](PSBT.md#binding-a-program-to-a-key). The engine identifier for
this engine is `ENGINE_ID_RISCV = 0x02` with `engine_version = 0`.

At account registration the device validates the image header of every program bound to a key it
controls; it does not execute it. At signing time, the device runs the program **once per signing
attempt** by the bound key, plus one final call, and uses the results to decide which signatures to
produce and whether the transaction may be signed without user confirmation.

The program is a pure function of the PSBT. It has no access to randomness, the clock, the block
height, persistent storage, the network, private keys, or the display. The same image over the same
PSBT always yields the same decisions.

## Decisions

Each invocation yields one `Decision`:

| Value | Name | Meaning |
|-------|------|---------|
| `0` | `Deny` | do not produce this signature |
| `1` | `Confirm` | produce it, using the normal user-confirmation flow |
| `2` | `ApproveSilently` | produce it without user confirmation |

The three values form an ordered lattice `Deny < Confirm < ApproveSilently`, and verdicts combine by
`min` — twice:

```
policy_verdict      = min over every invocation of that policy, the final call included
transaction_verdict = min over every policy the transaction invokes
```

So **a single refusal anywhere suppresses every signature the transaction would produce**, not just
the refusing key's, and `ApproveSilently` requires every invocation of every policy to have asked
for it. Silent signing additionally requires that all input amounts could be verified; otherwise the
normal confirmation flow applies.

Signing policies therefore compose conjunctively: each one is a restriction, and restrictions add
up. This is deliberate and stronger than suppressing one signature at a time. A policy-bound key is
typically one of several keys in a descriptor, so a refusal that only removed *that* signature could
be routed around through an alternative spending path — a key denied in a `2-of-3` changes nothing
if the device still signs with the other two. Under `min`, refusing is enforcement rather than
advice.

A verdict of `Deny` is **not an error**: the device produces no signatures and reports success with
an empty signature list, and contributes neither a nonce nor a partial signature to any
`musig(...)` session. By contrast, any *engine* failure — a malformed image, an unsupported engine
or version, a missing program, a trap, an exhausted budget — aborts `sign_psbt` with an error. The
device fails closed in both cases; the distinction is only whether the client is told that something
malfunctioned.

# Program image format

A `.vpol` file is a flat image with a fixed-size header. It is produced from an ELF by the packer;
the device validates the header and never scans instructions, since the interpreter traps on
anything invalid at runtime.

All multi-byte fields are little-endian.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | `"VPOL"` (`0x56 0x50 0x4F 0x4C`) |
| 4 | 1 | `abi_version` | must equal the engine's `engine_version` |
| 5 | 1 | `flags` | reserved; must be 0 |
| 6 | 1 | `label_len` | length of `label`, 0..=32 |
| 7 | 1 | `reserved` | must be 0 |
| 8 | 4 | `entrypoint` | byte offset into the code segment; even; `< code_len` |
| 12 | 4 | `code_len` | size of the code segment |
| 16 | 4 | `data_len` | size of the data segment: `.data` + `.bss` + shared state |
| 20 | 4 | `state_len` | size of the shared state, at the **end** of the data segment |
| 24 | 4 | `data_init_len` | bytes of initialized data carried in the image |
| 28 | 4 | `stack_len` | size of the stack segment |
| 32 | 4 | `step_budget_base` | see [Limits](#limits) |
| 36 | 4 | `step_budget_per_input` | see [Limits](#limits) |
| 40 | `label_len` | `label` | self-declared name, printable ASCII, zero-padded to a multiple of 4 |

`header_len = 40 + round_up_to_4(label_len)`, followed by `code_len` bytes of code, followed by
`data_init_len` bytes of initialized data. The file length is exactly
`header_len + code_len + data_init_len`.

Since the whole `SigningPolicy` value — `engine_id`, `engine_version` and the image — is hashed, and
the hash is what the key's derivation path commits to, every field above is committed. In
particular a program cannot be granted a larger budget, more memory or a different label after
registration without changing the key.

## Validation at registration

The device performs the following checks, in this order, and rejects the program otherwise. No code
is executed.

1. `magic == "VPOL"`;
2. `abi_version` equals the engine's `engine_version`;
3. `flags == 0` and `reserved == 0`;
4. `label_len <= 32` and every label byte is printable ASCII (`0x20..=0x7E`);
5. `code_len >= 2` and `code_len <= MAX_CODE_LEN`;
6. `entrypoint` is even and `entrypoint < code_len`;
7. `data_len <= MAX_DATA_LEN`, `state_len <= MAX_STATE_LEN`, `state_len <= data_len`,
   `data_init_len <= data_len - state_len`;
8. `data_len >= 4` and `stack_len >= 4`, and `stack_len <= MAX_STACK_LEN`;
9. the page-rounded total `pages(code_len) + pages(data_len) + pages(stack_len)` is at most
   `MAX_SANDBOX_MEMORY`;
10. `step_budget_base <= MAX_STEP_BUDGET_BASE` and
    `step_budget_per_input <= MAX_STEP_BUDGET_PER_INPUT`;
11. the file length is exactly `header_len + code_len + data_init_len`.

Registration displays the program's 32-byte hash in full, and the `label` next to it, explicitly
marked as self-declared. See [Auditability](#auditability).

# Memory model

The sandbox has the three segments that `common::vm::Cpu` provides. There is no MMU, no paging
visible to the program and no heap: all memory is reserved when the sandbox is created.

| Segment | Base address | Size | Access |
|---------|--------------|------|--------|
| code | `CODE_START = 0x0001_0000` | `code_len` | read + execute |
| data | `DATA_START = 0x0002_0000` | `data_len` | read + write |
| stack | `STACK_START = 0xF000_0000` | `stack_len` | read + write |

Addresses are fixed by this specification, not carried in the image, so the packer's linker script
is the only place they appear on the producing side. `STACK_START` matches the V-App convention
(`common::constants::DEFAULT_STACK_START`). All three bases are multiples of `PAGE_SIZE` (256
bytes), so a segment's page indices map exactly onto its backing store. Sizes are rounded up to
`PAGE_SIZE` when the backing stores are allocated; addresses beyond the declared size but inside the
final page are still addressable, and programs must not rely on their contents.

Every segment is non-empty: a program with no data and no shared state still declares
`data_len >= 4`, and the packer emits a minimum-size data segment for it.

Writes to the code segment fault. The code segment is backed directly by the image bytes, so it is
never copied into the app's heap.

## The data segment and the shared state

The data segment has three regions:

```
DATA_START                                 .data          (data_init_len bytes)  ─┐ restored from the
                                           .bss           (zeroed)               ─┘ image every call
DATA_START + data_len - state_len           shared state   (state_len bytes)      ── zeroed once
DATA_START + data_len
```

Before **every** invocation the engine:

1. restores `[DATA_START, DATA_START + data_init_len)` from the image;
2. zeroes `[DATA_START + data_init_len, DATA_START + data_len - state_len)`;
3. zeroes the whole stack segment;
4. zeroes all 32 registers, then sets `sp` (`x2`) to `(STACK_START + stack_len - 4) & !3`;
5. sets `pc` to `CODE_START + entrypoint`.

Before the **first** invocation only, it also zeroes the shared state.

This gives the engine's central invariant:

> The shared state is the only channel between invocations of a policy program.

Consequently the shared state's type must be valid when all-zeros, and a program must not expect
anything else to survive a call — not statics outside the shared state, not stack residue, not
register contents. An implementation may skip zeroing work it can prove unobservable (for instance
by tracking the stack high-water mark) but must not otherwise weaken the invariant.

The packer places the shared state in a dedicated `.policy_state` output section, emitted last in
the data segment, and derives `state_len` from its size. The policy SDK exposes it through a linker
symbol, so no address is hardcoded in a program.

# Invocation

One sandbox is created per **distinct policy hash** per transaction. If the same policy is bound to
two different keys of the same account, both keys' attempts share one sandbox and therefore one
shared state; the `SELF_PUBKEY` call distinguishes them.

A *signing attempt* is one opportunity for a policy-bound key to produce one signature: a plain key
in a descriptor placeholder, or one `musig(...)` participant. The engine enumerates the attempts
for a policy in a deterministic order — input index ascending, then placeholder index ascending,
then musig participant order — and invokes the entrypoint `attempt_count + 1` times: once per
attempt, then once for the **final call**.

Arguments are passed in registers:

| Register | Per-attempt call | Final call |
|----------|------------------|------------|
| `a0` | `input_index` | `0xFFFF_FFFF` |
| `a1` | `attempt_index` (`0..attempt_count`) | `attempt_count` |
| `a2` | `attempt_count` | `attempt_count` |
| `a3` | flags: bit 0 = musig participant | 0 |

Each invocation must terminate by calling `EXIT(decision)`. Every verdict is folded into the
policy's verdict with `min`, as described under [Decisions](#decisions), so no invocation can
undo another's refusal and `ApproveSilently` is the value that expresses "no objection".

The final call exists for **deferred checks** — conditions that can only be evaluated once every
attempt has been seen. BIP-443's amount aggregation is the motivating case. All invocations complete
before any signature is produced, which is what makes a late refusal effective.

## Which inputs a policy sees invocations for

This determines whether a policy can reason soundly about the transaction as a whole, so it is
specified rather than left to follow from the implementation.

A policy-bound key is a key expression in its account's BIP-388 descriptor template, and an account
has exactly one template. Every input belonging to that account is spent under it, and the device
attempts every placeholder of the template for every input of the account. Therefore:

> A policy is invoked for **every input of its account**, whichever spending path each input uses.

Two consequences worth relying on:

- A policy's own invocations already cover every input of its account, so aggregating over them is
  complete rather than a heuristic. If two different programs are bound to two different keys of the
  same account, each is invoked for every input and each aggregates completely and independently.
- The device rejects inputs that do not belong to a recognized account, so a transaction cannot
  contain an input that no account claims.

The one case a policy is *not* invoked for is an input belonging to a **different** account, in a
PSBT that spends from several. Such an input is signed by that account's keys under that account's
policies. A policy that aggregates amounts and wants certainty should require that every input
belongs to its own account, which is one loop over `INPUT_ACCOUNT`; see
[the vault example](#example-a-bip-443-vault-covenant).

## Failure

Any of the following aborts the whole signing operation with an error; no signature is produced for
any input:

- an unknown or unsupported instruction, or `EBREAK`;
- a memory access outside all three segments, an unaligned access, or a write to the code segment;
- `pc` leaving the code segment, or an invocation returning without calling `EXIT`;
- a decision value other than 0, 1 or 2;
- the step budget being exhausted;
- an invalid ecall number, or invalid arguments to an ecall;
- the program calling `PANIC`.

The engine reports these as a single error to the client; it deliberately does not distinguish them,
to avoid making the device an oracle for debugging a program against a live PSBT. Policy authors
test against the host-side engine instead.

# The program interface

The program observes the transaction only through ecalls. The calling convention is Vanadium's own,
as specified in [../../../docs/ecalls.md](../../../docs/ecalls.md):

- the call number is in `t0`;
- arguments are in `a0`..`a7`, in order;
- the return value, if any, is in `a0`.

Buffer arguments are copied across the sandbox boundary; the engine bounds-checks every buffer
against the segment that contains it, and rejects any buffer that is not wholly inside one segment.
Every output buffer argument is accompanied by an explicit capacity, and a call that would exceed it
fails rather than truncating. Unbounded copies are chunked through a bounce buffer of at most
`MAX_ECALL_BUFFER` bytes.

Unless stated otherwise, a call returns `0` on success and a nonzero error code on failure, and
calls that look up something absent return `NOT_FOUND` rather than failing. Amounts are unsigned
satoshis. Indices are 0-based; an out-of-range index is an error, not `NOT_FOUND`.

## Control

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0001` | `EXIT(decision: u32) -> !` | End this invocation with `decision`. |
| `0x0002` | `PANIC(msg: *const u8, len: u32) -> !` | Abort signing. `msg` is for host-side diagnostics and is ignored on device. |
| `0x0003` | `LOG(msg: *const u8, len: u32)` | Diagnostics. A no-op on device; printed by the host-side engine. |

`LOG` is specified as a no-op rather than omitted so that one image runs unmodified in tests and on
device.

## Transaction shape

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0010` | `TX_VERSION() -> u32` | The transaction version, as the raw 32-bit value. |
| `0x0011` | `LOCKTIME() -> u32` | The **resolved** locktime of the unsigned transaction: the maximum of the per-input height and time locktime requirements, falling back to `PSBT_GLOBAL_FALLBACK_LOCKTIME`. |
| `0x0012` | `INPUT_COUNT() -> u32` | |
| `0x0013` | `OUTPUT_COUNT() -> u32` | |
| `0x0014` | `FEE(out: *mut u64) -> u32` | `inputs_total - outputs_total`. |
| `0x0015` | `TOTALS(out: *mut [u64; 2]) -> u32` | Total input amount, then total output amount. |

## The signing key

These describe the key whose policy is running. `SELF_PUBKEY` depends on the current attempt and is
an error on the final call; the others are constant for the sandbox.

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0016` | `SELF_PUBKEY(out: *mut [u8; 33]) -> u32` | The compressed public key that would produce the current attempt's signature, i.e. the policy-bound key derived to this input's coordinates. |
| `0x0017` | `SELF_POLICY_HASH(out: *mut [u8; 32]) -> u32` | The running policy's own hash, so a program can reconstruct its own key path. |

Only public data is exposed. There is no call that signs, derives a private key, or reveals one.

## Inputs

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0018` | `INPUT_AMOUNT(i: u32, out: *mut u64) -> u32` | Amount of the input's prevout. |
| `0x0019` | `INPUT_PREVOUT(i: u32, out: *mut [u8; 36]) -> u32` | 32-byte txid in internal byte order, then the 4-byte little-endian output index. |
| `0x001A` | `INPUT_SEQUENCE(i: u32) -> u32` | The sequence number, or `0xFFFF_FFFF` if absent. |
| `0x001B` | `INPUT_SCRIPT_PUBKEY(i: u32, dst: *mut u8, dst_max: u32) -> u32` | Length written, or an error if it exceeds `dst_max`. |
| `0x001C` | `INPUT_FLAGS(i: u32) -> u32` | See below. |
| `0x001D` | `INPUT_ACCOUNT(i: u32, out: *mut Coords) -> u32` | The account coordinates claimed for this input, or `NOT_FOUND`. |
| `0x001E` | `INPUT_TAPTREE_HASH(i: u32, out: *mut [u8; 32]) -> u32` | The taproot merkle root of the account's descriptor for this input, or `NOT_FOUND` if the input is not taproot or the tree is empty. |
| `0x001F` | `ATTEMPT_INPUT(k: u32) -> u32` | The input index of the `k`-th attempt, for `k < attempt_count`. Lets a policy materialize the whole set of inputs it will be asked to sign on its first invocation, rather than discovering it one call at a time. |

`INPUT_FLAGS` bits:

| Bit | Meaning |
|-----|---------|
| 0 | the prevout amount is **verified**: a non-witness UTXO was supplied and its txid matches the input's `previous_txid` |
| 1 | a witness UTXO is present |
| 2 | the input belongs to a recognized account |
| 8..11 | segwit version + 1, or 0 if not segwit |

Bit 0 deserves attention when writing a policy that reasons about amounts. For legacy and
segwit-v0 inputs the device verifies the amount against the full previous transaction; for taproot
inputs it does not, because BIP-341 commits the amount in the sighash instead. See
[Trusting data about other inputs](#trusting-data-about-other-inputs).

`Coords` is a 12-byte little-endian structure describing wallet-policy coordinates:

```
0   4   account_index    index into the transaction's list of recognized accounts
4   4   is_change        0 or 1
8   4   address_index    0..=0x7FFF_FFFF
```

`INPUT_ACCOUNT` and `OUTPUT_ACCOUNT` return an error for account types that are not wallet
policies, so that adding an account type cannot silently change what a policy sees.

## Outputs

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0020` | `OUTPUT_AMOUNT(i: u32, out: *mut u64) -> u32` | |
| `0x0021` | `OUTPUT_SCRIPT_PUBKEY(i: u32, dst: *mut u8, dst_max: u32) -> u32` | Length written. |
| `0x0022` | `OUTPUT_FLAGS(i: u32) -> u32` | Bit 0: belongs to a recognized account (change or internal). Bit 1: authenticated by a registered identity key. |
| `0x0023` | `OUTPUT_ACCOUNT(i: u32, out: *mut Coords) -> u32` | As `INPUT_ACCOUNT`. |

## Raw PSBT access

The calls above expose what the device has already parsed and, where applicable, validated. These
calls expose everything else, so that a policy is never limited by what this specification
anticipated.

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0040` | `PSBT_LEN() -> u32` | Size of the PSBT as received. |
| `0x0041` | `PSBT_READ(offset: u32, dst: *mut u8, len: u32) -> u32` | Copy an arbitrary byte range of the raw PSBT. Bytes written, which is less than `len` at end of input. |
| `0x0042` | `PSBT_FIELD(scope: u32, index: u32, keytype: u32, keydata: *const u8, keydata_len: u32, dst: *mut u8, dst_max: u32) -> u32` | Look up one field by its full key. Value length, or `NOT_FOUND`. |
| `0x0043` | `PSBT_FIELD_COUNT(scope: u32, index: u32, keytype: u32) -> u32` | Number of fields with this key type. |
| `0x0044` | `PSBT_FIELD_NTH(scope: u32, index: u32, keytype: u32, n: u32, key_dst: *mut u8, key_max: u32, val_dst: *mut u8, val_max: u32) -> u32` | The `n`-th such field, in key order. Returns `key_len | (val_len << 16)`. |

`scope` is `0` for the global map, `1` for the input map at `index`, `2` for the output map at
`index`; `index` must be 0 for the global map. `keytype` is the BIP-174 key type as a compact-size
integer value, and `keydata` is the remainder of the key. Fields are enumerated in the map's
canonical (sorted) order, which is the order the device requires of a well-formed PSBT.

`PSBT_READ` returns the bytes as received, before any interpretation. It is the escape hatch for
structures this interface has no accessor for; a policy using it takes on the parsing itself, and
gets no validation from the device.

## Accelerated calls

These exist so that a policy does not implement cryptography in interpreted RISC-V. Each is
serviced by the app using the hardware-backed primitives it already uses itself.

| `t0` | Signature | Description |
|------|-----------|-------------|
| `0x0050` | `SHA256(ptr: *const u8, len: u32, out: *mut [u8; 32]) -> u32` | One-shot. |
| `0x0051` | `HASH_INIT(alg: u32, ctx: *mut u8) -> u32` | `alg`: 0 = SHA-256, 1 = SHA-512, 2 = RIPEMD-160. |
| `0x0052` | `HASH_UPDATE(ctx: *mut u8, ptr: *const u8, len: u32) -> u32` | |
| `0x0053` | `HASH_FINAL(ctx: *mut u8, out: *mut u8) -> u32` | Writes the algorithm's digest size. |
| `0x0054` | `RIPEMD160(ptr: *const u8, len: u32, out: *mut [u8; 20]) -> u32` | One-shot. |
| `0x0056` | `TAGGED_HASH(tag: *const u8, tag_len: u32, msg: *const u8, msg_len: u32, out: *mut [u8; 32]) -> u32` | BIP-340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`. |
| `0x0060` | `TAPLEAF_HASH(leaf_version: u32, script: *const u8, len: u32, out: *mut [u8; 32]) -> u32` | BIP-341 tapleaf hash. |
| `0x0061` | `TAPBRANCH_HASH(a: *const [u8; 32], b: *const [u8; 32], out: *mut [u8; 32]) -> u32` | BIP-341 branch hash; sorts its arguments as the BIP requires. |
| `0x0062` | `TAPTWEAK_PUBKEY(xonly: *const [u8; 32], merkle_root: *const [u8; 32], out: *mut [u8; 32]) -> u32` | BIP-341 `taproot_tweak_pubkey`. A null `merkle_root` means an empty tree. Returns the output key's parity (0 or 1), or an error. |
| `0x0063` | `XONLY_ADD_TWEAK(xonly: *const [u8; 32], tweak: *const [u8; 32], out: *mut [u8; 32]) -> u32` | Adds `tweak * G` to the lifted point. Returns the parity. |
| `0x0068` | `EC_POINT_ADD(p: *const [u8; 65], q: *const [u8; 65], out: *mut [u8; 65]) -> u32` | Uncompressed SEC1 points. |
| `0x0069` | `EC_SCALAR_MUL(p: *const [u8; 65], scalar: *const [u8; 32], out: *mut [u8; 65]) -> u32` | |
| `0x0070` | `SCHNORR_VERIFY(xonly: *const [u8; 32], msg: *const u8, msg_len: u32, sig: *const [u8; 64]) -> u32` | BIP-340. Returns 1 if valid, 0 if not. |
| `0x0071` | `ECDSA_VERIFY(pubkey: *const [u8; 33], msg: *const [u8; 32], sig: *const u8, sig_len: u32) -> u32` | DER signature over a 32-byte hash. |

`TAPTWEAK_PUBKEY` is the call that makes covenant simulation practical: it turns the
`taproot_tweak_pubkey` that BIP-443 performs per input into one accelerated call instead of a
scalar multiplication in interpreted code.

## Calls that do not exist

The following are deliberately absent, and adding any of them is a change to the engine version:

- randomness, the current time, and the block height — a policy must be a pure function of the PSBT;
- persistent storage, so a policy cannot carry state between transactions
  (see [Open problems](#open-problems));
- anything involving private keys, including signing;
- any display or user interaction. A policy decides; it does not ask;
- any allocation from the app's heap. The sandbox's memory is fixed at creation.

# Limits

All limits are enforced by the device. The two budget values are declared in the image header and
capped here; the rest are fixed by the engine version.

| Constant | Value |
|----------|-------|
| `MAX_CODE_LEN` | 8192 |
| `MAX_DATA_LEN` | 4096 |
| `MAX_STATE_LEN` | 1024 |
| `MAX_STACK_LEN` | 4096 |
| `MAX_SANDBOX_MEMORY` | 12 KiB, page-rounded |
| `MAX_STEP_BUDGET_BASE` | 2²⁰ |
| `MAX_STEP_BUDGET_PER_INPUT` | 2¹⁸ |
| `MAX_TOTAL_STEPS` | 2²² |
| `MAX_ECALL_BUFFER` | 256 |

The step budget for one policy over one transaction is

```
total_budget = min(step_budget_base + step_budget_per_input * attempt_count, MAX_TOTAL_STEPS)
```

decremented once per interpreted instruction and **shared across all invocations**, the final call
included. A budget that scales with the number of attempts is what lets a policy sized for a
two-input transaction still work on a twenty-input one; the absolute ceiling bounds the worst case
regardless of what the header declares.

Sharing one budget across invocations also rewards caching in the shared state: work done on the
first invocation and reused on later ones is paid for once.

An ecall costs one step plus the cost of what it does; the engine does not meter accelerated calls
separately. Since the expensive ones are bounded in number by the budget itself, and each is
comparable in cost to a few hundred interpreted instructions, this is adequate — but it is the part
of the limit design most likely to need revisiting after measurement.

**These numbers are provisional.** The memory limits are bounded by what the app can reserve from
its 64 KiB heap while a PSBT is resident; the step limits need a measurement of nested
interpretation throughput that does not exist yet.

# Writing a policy

Policies are written against a small SDK crate that wraps the ecalls, provides the entrypoint and
the shared state, and can be compiled for the host so that a policy is testable without a device.

```rust
#![no_std]
#![no_main]

use vnd_policy_sdk as policy;
use policy::{Attempt, Decision};

/// Declares the shared state. Zeroed before the first invocation, preserved
/// afterwards, so the type must be valid when all-zeros.
policy::state!(State);

#[derive(Default)]
struct State {
    /* ... */
}

#[policy::main]
fn main(attempt: Option<Attempt>, state: &mut State) -> Decision {
    match attempt {
        Some(a) => on_input(a, state),
        None => on_finalize(state), // the final call
    }
}
```

`Option<Attempt>` reflects the two invocation kinds, so a program cannot forget to handle the final
call. `Attempt` carries `input_index`, `attempt_index`, `attempt_count` and `is_musig`.

Calls that can fail — anything taking an index, anything writing into a buffer, anything that can
report `NOT_FOUND` — return `Result<_, policy::Error>`. `INPUT_COUNT`, `OUTPUT_COUNT`, `TX_VERSION`,
`LOCKTIME`, `FEE` and `TOTALS` cannot fail and return their value directly. Since every example
below maps an error to `Decision::Deny`, the fail-closed idiom is worth writing once:

```rust
#[policy::main]
fn main(attempt: Option<Attempt>, state: &mut State) -> Decision {
    check(attempt, state).unwrap_or(Decision::Deny)
}
```

## Example: fee cap

Refuse to sign if the fee exceeds 10% of the total input amount, and otherwise defer to the normal
confirmation flow. The equivalent policy in the bespoke language this engine replaces was three
lines; the RISC-V version is not much longer, but it is also not the interesting case.

```rust
fn check(attempt: Option<Attempt>, _state: &mut State) -> Result<Decision, policy::Error> {
    if attempt.is_none() {
        return Ok(Decision::ApproveSilently); // nothing deferred to check
    }
    let [inputs_total, _outputs_total] = policy::totals();
    if policy::fee().saturating_mul(10) > inputs_total {
        Ok(Decision::Deny)
    } else {
        Ok(Decision::Confirm)
    }
}
```

## Example: consolidation only

Sign silently, but only for transactions that send nothing outside the account and reduce the number
of UTXOs. A wallet service holding this key can tidy up the account on its own and cannot move a
satoshi out of it.

```rust
fn check(attempt: Option<Attempt>, _state: &mut State) -> Result<Decision, policy::Error> {
    if attempt.is_none() {
        return Ok(Decision::ApproveSilently);
    }
    for i in 0..policy::output_count() {
        if policy::output_flags(i)? & policy::OUTPUT_IS_INTERNAL == 0 {
            return Ok(Decision::Deny); // an output leaves the account
        }
    }
    if policy::input_count() <= policy::output_count() {
        return Ok(Decision::Deny); // does not consolidate
    }
    let [inputs_total, _] = policy::totals();
    if policy::fee().saturating_mul(100) > inputs_total {
        return Ok(Decision::Deny); // fee above 1%
    }
    Ok(Decision::ApproveSilently)
}
```

## Example: a BIP-443 vault covenant

This is the example that justifies the design. The policy enforces the amount-preserving half of
`OP_CHECKCONTRACTVERIFY` in `CCV_MODE_CHECK_OUTPUT`: everything the vault contributes to the
transaction must land in the vault's **next contract state**, up to a fee allowance.

The next state is not a registered account — it is a script the wallet has never seen, derived from
the vault key and the next state's taptree — so the device cannot recognize it and the policy
computes the expected `scriptPubKey` itself. That is what the accelerated taproot tweak is for.

It needs everything the previous examples did not: per-input invocation, the shared state, an
accelerated taproot tweak, and a deferred check in the final call.

```rust
/// The vault's internal key and its next state's taptree, both committed by the
/// policy hash. `VAULT_PK` plays the role of CCV's `pk` argument.
const VAULT_PK: [u8; 32] = [/* x-only vault key */];
const TAPTREE_NEXT: [u8; 32] = [/* taptree root of the next contract state */];
const MAX_FEE: u64 = 10_000;

policy::state!(State);

#[derive(Default)]
struct State {
    scanned: bool,
    vault_in: u64,
}

/// The next contract state's scriptPubKey: OP_1 <32-byte tweaked output key>.
fn next_state_spk() -> Result<[u8; 34], policy::Error> {
    let mut spk = [0u8; 34];
    spk[0] = 0x51; // OP_1
    spk[1] = 0x20; // push 32 bytes
    policy::taptweak_pubkey(&VAULT_PK, Some(&TAPTREE_NEXT), &mut spk[2..34])?;
    Ok(spk)
}

/// Total what the vault contributes. Run once, then cached in the shared state.
///
/// Siblings are recognized by **account membership**, not by script equality: a
/// BIP-388 key expression derives a different key per address index, so the
/// account's inputs have different scriptPubKeys. Account membership is also
/// what the device validates, by re-deriving each input's script from the
/// descriptor at its claimed coordinates.
fn scan(state: &mut State, my_input: u32) -> Result<bool, policy::Error> {
    let mine = policy::input_account(my_input)?.account_index;
    for i in 0..policy::input_count() {
        // A policy is not invoked for another account's inputs, so a foreign
        // input would leave the total incomplete. Refuse instead of guessing.
        if policy::input_account(i)?.account_index != mine {
            return Ok(false);
        }
        state.vault_in = state
            .vault_in
            .checked_add(policy::input_amount(i)?)
            .ok_or(policy::Error::Overflow)?;
    }
    state.scanned = true;
    Ok(true)
}

fn check(attempt: Option<Attempt>, state: &mut State) -> Result<Decision, policy::Error> {
    if let Some(a) = attempt {
        if !state.scanned && !scan(state, a.input_index)? {
            return Ok(Decision::Deny);
        }
        // Nothing about this input on its own is objectionable. Returning
        // `ApproveSilently` is what lets the transaction be signed silently at
        // all: verdicts combine with `min`, so one `Confirm` here would force
        // the confirmation flow for the whole transaction.
        return Ok(Decision::ApproveSilently);
    }

    // Deferred: everything the vault contributed must land in its next state.
    let expected = next_state_spk()?;
    let mut preserved = 0u64;
    let mut spk = [0u8; 34];
    for j in 0..policy::output_count() {
        if policy::output_script_pubkey(j, &mut spk) == Ok(34) && spk == expected {
            preserved = preserved
                .checked_add(policy::output_amount(j)?)
                .ok_or(policy::Error::Overflow)?;
        }
    }
    if preserved.saturating_add(MAX_FEE) < state.vault_in {
        return Ok(Decision::Deny);
    }
    Ok(Decision::ApproveSilently)
}
```

Three things about this example generalize.

**Aggregate as a conservation law, not as per-input residuals.** BIP-443 threads
`output_min_amount[]` through the transaction because a script has no view beyond its own input, and
defers the comparison to the validator. A policy *has* the whole transaction, so the same intent is
one equation over what the account contributes and what comes back. It is less code, and it cannot
exhibit the under-counting that per-input residual bookkeeping invites.

**Recognize siblings by what the device validates.** Account membership is checked by re-deriving
the script from the descriptor; script equality is a guess that happens to be wrong here, because
each address index yields a different key. Preferring the validated predicate is the general rule.

**The shared state is a cache as much as a channel.** `scan` is `O(n_inputs)`; doing it once instead
of once per invocation is the difference between `O(n)` and `O(n²)` against a budget that all
invocations share.

Full BIP-443 support would add the other three modes, a non-empty `data` tweak
(`data_tweak = SHA256(pk ‖ data)`), `CCV_MODE_CHECK_INPUT`, the residual-amount bookkeeping of
`CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT`, and the rule that an output may not be checked with both the
default and the deduct logic, or twice with the deduct logic. None of that needs anything beyond the
interface above — but a policy author should first ask whether the conservation form expresses the
same intent, since it usually does and is harder to get wrong.

# Security considerations

## Auditability

This is the design's weakest point, and it is worse here than for a source-level policy language.

A key commits to a program by its hash, and the device shows that hash — 64 hexadecimal characters
— at registration. It cannot show what the program *means*, and with a compiled binary the user
cannot audit the artifact even in principle. Everything therefore rests on the user obtaining the
hash from a source they trust and comparing it.

The header's `label` helps a little and must not be trusted too much. It is committed by the hash,
so it cannot be changed after the fact, and it gives the registration screen something more
memorable than 64 hex characters. But it is written by whoever wrote the program: a malicious
policy can label itself "Consolidation only". The device displays it explicitly marked as
self-declared, and it is a mnemonic for a hash the user has already verified, never evidence about
behaviour.

Consequently:

- policy images should be built reproducibly, with their hashes published alongside their source, so
  that "this hash is `consolidation-only` v1" is a claim someone other than the program's author can
  check;
- users should verify the hash on a second trusted machine before registering an account, exactly as
  for the source-level language;
- an unreviewed policy that returns `ApproveSilently` disables every on-device check for the
  transactions it approves. That is the point of the feature and the reason the hash matters.

Reproducible builds of the policy images are a prerequisite for this story and are not solved by
this specification.

## What the device vouches for

A policy sees a mixture of data the device has verified and data the client merely asserts, and the
distinction matters:

- **Verified**: that a legacy or segwit-v0 input's amount matches the previous transaction
  (`INPUT_FLAGS` bit 0); that an output's identity authentication signature is valid
  (`OUTPUT_FLAGS` bit 1); that each account named in the PSBT carries a valid proof of registration;
  that every input and internal output's script matches the account's descriptor at the claimed
  coordinates.
- **Asserted by the client**: the account coordinates themselves, until that last check runs.

The script re-derivation is the expensive part of signing and runs concurrently with the review, so
policies are evaluated before it completes. The signing flow must therefore keep the ordering it
already has: **evaluate the policies, then wait for verification to succeed, and only then produce
any signature**. Without it, a client could get a silent approval out of a policy by lying about
which outputs are change. This is a requirement on the flow, not an incidental property of it.

## Trusting data about other inputs

A policy that aggregates over inputs it does not itself sign is trusting the client's claims about
them. Whether that is safe depends on what the signature it is authorizing commits to.

With BIP-341 and `SIGHASH_DEFAULT`, the sighash covers `sha_amounts` and `sha_scriptpubkeys` over
**all** of the transaction's inputs, plus all of its outputs. A client that misreports another
input's amount or script therefore obtains a signature that is invalid on the real transaction:
lying is self-defeating, and a policy on a taproot key may rely on `INPUT_AMOUNT` and
`INPUT_SCRIPT_PUBKEY` for every input.

That reasoning does not extend to the other input types. A segwit-v0 sighash commits to
`hashPrevouts` — the set of outpoints, so the *set* of inputs is fixed — and to the signing input's
own amount, but not to any other input's amount or script. A legacy sighash commits to less again. A
policy on such a key that aggregates amounts must require `INPUT_FLAGS` bit 0 on every input it
counts, which is the device's own verification against the previous transaction.

**This depends on the app signing only with `SIGHASH_ALL` / `SIGHASH_DEFAULT`**, which is currently
the case (both sighash types are hardcoded, and the code paths that would derive them from the PSBT
are marked as unimplemented). Two future changes would invalidate it: `SIGHASH_ANYONECANPAY` drops
the commitment to other inputs, and `SIGHASH_NONE` / `SIGHASH_SINGLE` drop the commitment to the
outputs a policy checks. If support for either is added, this interface must expose the input's
sighash type and policies that reason about other inputs must check it.

## Memory access patterns

Vanadium does not hide where an app reads and writes; see
[../../../docs/security.md](../../../docs/security.md). The sandbox's memory lives inside the app's
data section, so a policy's accesses are observable to the host at 256-byte page granularity, and
its instruction fetches reveal the shape of its control flow. Policies handle no secrets, so this
leaks only which parts of a public PSBT a public program looked at — but a policy must not be
written as though its execution were private.

## Fail-closed behaviour

Every failure mode refuses to sign: an absent program for a policy-bound key, a malformed header, an
unsupported engine or version, a trap, an exhausted budget, an invalid decision value. A policy that
cannot be evaluated is never treated as absent, and a key whose path carries a policy binding cannot
be used without its program.

## Sandbox boundaries

The program cannot address anything outside its three segments; the code segment is not writable;
every buffer crossing the boundary is copied and bounds-checked; there is no call that allocates,
signs, or reaches the display. A malicious policy image can therefore waste its budget, return
`Deny`, or return `ApproveSilently` — which is exactly the authority its user granted it by
registering the account — and nothing else.

# Open problems

- **Nested interpretation cost is unmeasured, and it is the one thing that could invalidate this
  design.** A policy instruction costs on the order of hundreds of interpreted instructions in the
  app that hosts it. No throughput measurement for the Vanadium interpreter is published; the
  repository contains the harness (`tools/bench`, `common/src/metrics.rs`) but no results. Every
  limit in [Limits](#limits) is provisional until a benchmark of `Cpu` over `VecMemory` running
  inside a V-App reports instructions per second. If the number is too low, the same program ABI
  can be kept and the execution backend moved into the VM, which would interpret the sandbox
  natively and hand inner ecalls back to the app to service.
- **No state across transactions.** A policy's state is zeroed for each transaction, so per-period
  limits ("at most 0.01 BTC per day") remain out of reach. Implementing them needs the app's 32-byte
  persistent storage slots, a rule for which policies may claim one, and an anti-replay design,
  since a client that can roll back the state can reset the limit. This is the most requested
  capability the engine does not have.
- **Reproducible builds** of policy images, as described under [Auditability](#auditability).
- **Metering of accelerated calls.** Charging one step for a call whose cost is comparable to
  hundreds of instructions is a simplification that measurement may not support.
- **Shared state across keys.** Two keys of one account bound to the same policy currently share a
  sandbox and its state. This is the more expressive choice and lets a policy reason about the
  account as a whole, but a policy author who does not expect it could be surprised.
- **Aggregation across accounts is the policy author's responsibility.** A policy is invoked for
  every input of its own account, so aggregating over its own invocations is complete for that
  account — but a PSBT may spend from several accounts, and a policy is not invoked for another
  account's inputs. The guard is one loop over `INPUT_ACCOUNT`, and the vault example shows it, but
  the engine does not enforce it. The alternative would be an engine-maintained accumulator that
  every policy reserves against, checked once for the whole transaction; that would make the
  guarantee structural, at the cost of state shared between policies. Worth revisiting if
  multi-account covenants turn out to matter.
- **PSBT key types.** `PSBT_FIELD` specifies `keytype` as a compact-size value, which is what
  BIP-174 defines. The app's current PSBT parser treats a key type as a single byte; that must be
  widened before this interface is honest about arbitrary field access.
