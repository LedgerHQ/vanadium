use core::{
    cell::{RefCell, RefMut},
    cmp::min,
    fmt,
};

use alloc::{format, rc::Rc, string::String, vec, vec::Vec};
use common::{
    client_commands::{
        Message, MessageDeserializationError, ReceiveBufferMessage, ReceiveBufferResponse,
        SendBufferContinuedMessage, SendBufferMessage,
    },
    constants::{MAX_STORAGE_SLOTS, STORAGE_SLOT_SIZE},
    ecall_constants::{self, *},
    ecall_validation::{
        classify_secp256k1_point, is_bignum_len, is_modulus, is_reduced, is_secp256k1_scalar,
        is_zero, parse_hash_identifier, parse_slip21_labels, PointEncoding, MAX_BIP32_PATH_LEN,
        MAX_RANDOM_BYTES, MAX_SLIP21_LABELS_LEN, SECP256K1_P,
    },
    ux::Deserializable,
    vm::{Cpu, CpuError, EcallHandler, MemoryError},
    BufferType,
};
use ledger_device_sdk::sys::{
    self, cx_ripemd160_t, cx_sha256_t, cx_sha3_t, cx_sha512_t, CX_OK, CX_RIPEMD160, CX_SHA256,
    CX_SHA384, CX_SHA512,
};
use ledger_device_sdk::{hash::HashInit, io::DecodedEventType};

use crate::io::{interrupt, InterruptError, SerializeToComm};

use super::outsourced_mem::OutsourcedMemory;

use zeroize::Zeroizing;

mod ux_handler;

mod bitmaps;

mod slip21;

use ux_handler::*;

const VENDOR_ID: u16 = 0x2C97; // Ledger vendor ID

#[cfg(target_os = "nanox")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x40;
    pub const SCREEN_WIDTH: u16 = 128;
    pub const SCREEN_HEIGHT: u16 = 64;
}

#[cfg(target_os = "nanosplus")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x50;
    pub const SCREEN_WIDTH: u16 = 128;
    pub const SCREEN_HEIGHT: u16 = 64;
}

#[cfg(target_os = "stax")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x60;
    pub const SCREEN_WIDTH: u16 = 400;
    pub const SCREEN_HEIGHT: u16 = 672;
}

#[cfg(target_os = "flex")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x70;
    pub const SCREEN_WIDTH: u16 = 480;
    pub const SCREEN_HEIGHT: u16 = 600;
}

#[cfg(target_os = "apex_p")]
mod device_props {
    pub const PRODUCT_ID: u16 = 0x80;
    pub const SCREEN_WIDTH: u16 = 300;
    pub const SCREEN_HEIGHT: u16 = 400;
}

#[cfg(not(any(
    target_os = "nanox",
    target_os = "nanosplus",
    target_os = "stax",
    target_os = "flex",
    target_os = "apex_p"
)))]
compile_error!("Unsupported target OS. Only nanox, nanosplus, stax, and flex are supported.");

use device_props::*;

const MAX_UX_STEP_LEN: usize = 512;
const MAX_UX_PAGE_LEN: usize = 512;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum Register {
    Zero, // x0, constant zero
    Ra,   // x1, return address
    Sp,   // x2, stack pointer
    Gp,   // x3, global pointer
    Tp,   // x4, thread pointer
    T0,   // x5, temporary register
    T1,   // x6, temporary register
    T2,   // x7, temporary register
    S0,   // x8, saved register (frame pointer)
    S1,   // x9, saved register
    A0,   // x10, function argument/return value
    A1,   // x11, function argument/return value
    A2,   // x12, function argument
    A3,   // x13, function argument
    A4,   // x14, function argument
    A5,   // x15, function argument
    A6,   // x16, function argument
    A7,   // x17, function argument
    S2,   // x18, saved register
    S3,   // x19, saved register
    S4,   // x20, saved register
    S5,   // x21, saved register
    S6,   // x22, saved register
    S7,   // x23, saved register
    S8,   // x24, saved register
    S9,   // x25, saved register
    S10,  // x26, saved register
    S11,  // x27, saved register
    T3,   // x28, temporary register
    T4,   // x29, temporary register
    T5,   // x30, temporary register
    T6,   // x31, temporary register
}

impl Register {
    // To get the register's index as a number (x0 to x31)
    pub fn as_index(&self) -> u8 {
        match self {
            Register::Zero => 0,
            Register::Ra => 1,
            Register::Sp => 2,
            Register::Gp => 3,
            Register::Tp => 4,
            Register::T0 => 5,
            Register::T1 => 6,
            Register::T2 => 7,
            Register::S0 => 8,
            Register::S1 => 9,
            Register::A0 => 10,
            Register::A1 => 11,
            Register::A2 => 12,
            Register::A3 => 13,
            Register::A4 => 14,
            Register::A5 => 15,
            Register::A6 => 16,
            Register::A7 => 17,
            Register::S2 => 18,
            Register::S3 => 19,
            Register::S4 => 20,
            Register::S5 => 21,
            Register::S6 => 22,
            Register::S7 => 23,
            Register::S8 => 24,
            Register::S9 => 25,
            Register::S10 => 26,
            Register::S11 => 27,
            Register::T3 => 28,
            Register::T4 => 29,
            Register::T5 => 30,
            Register::T6 => 31,
        }
    }
}

pub fn pack_u16(high: u16, low: u16) -> u32 {
    ((high as u32) << 16) | (low as u32)
}

// A pointer in the V-app's address space
#[derive(Debug, Clone, Copy)]
struct GuestPointer(pub u32);

impl GuestPointer {
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LedgerHashContextError {
    InvalidHashId,
    /// The context handed back by the V-App is not one these ECALLs could have produced.
    CorruptedContext,
}

impl fmt::Display for LedgerHashContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerHashContextError::InvalidHashId => write!(f, "Invalid hash id"),
            LedgerHashContextError::CorruptedContext => write!(f, "Corrupted hash context"),
        }
    }
}

impl core::error::Error for LedgerHashContextError {}

// Compile-time size validation for EventData union
// Ensures that EventData is exactly 16 bytes with no unexpected padding
const _: () = assert!(
    core::mem::size_of::<common::ux::EventData>() == 16,
    "EventData must be exactly 16 bytes for safe transmutation to [u8; 16]"
);

// A union of all the supported hash contexts, in the same memory layout used in the Ledger SDK
#[repr(C)]
union LedgerHashContext {
    ripemd160: cx_ripemd160_t,
    sha256: cx_sha256_t,
    sha512: cx_sha512_t,
    // cx_sha3_t is shared by both CX_SHA3 and CX_KECCAK on the Ledger SDK
    sha3: cx_sha3_t,
}

/// Largest digest of any supported hash function.
const MAX_HASH_DIGEST_SIZE: usize = 64;

/// A hash context that the VM can safely hand to `cx_hash_update` / `cx_hash_final`.
///
/// The V-App keeps the context between ECALLs, so its bytes are untrusted. They cannot be passed
/// to `cx` as they are: `cx_hash_update` and `cx_hash_final` dispatch through the `info` function
/// pointer in the context's header, and the compression functions index the block buffer with the
/// `blen` field without checking it. A V-App could therefore make the VM jump to an arbitrary
/// address or write outside its buffers.
///
/// Instead, every ECALL starts from a context freshly initialized by `cx_hash_init_ex` for the
/// requested algorithm and output size, so the header and the size fields are the VM's own. Only
/// the running state (block counter, buffered bytes and accumulator) is restored from the V-App's
/// copy, after checking that `blen` is within the block buffer. The `info` pointer is cleared in
/// the copy handed back to the V-App, which never needs it.
struct VerifiedHashContext {
    ctx: LedgerHashContext,
    algorithm: u8,
    digest_size: usize,
}

impl VerifiedHashContext {
    /// Splits a hash identifier into its algorithm and output size, rejecting the identifiers that
    /// the hash ECALLs do not support. The algorithm identifiers match the cx ones.
    fn parse_id(hash_identifier: u32) -> Result<(u8, usize), LedgerHashContextError> {
        parse_hash_identifier(hash_identifier)
            .map(|(algorithm, output_size)| (algorithm as u8, output_size))
            .ok_or(LedgerHashContextError::InvalidHashId)
    }

    /// Size of the context struct that the V-App stores for `hash_identifier`.
    fn guest_size(hash_identifier: u32) -> Result<usize, LedgerHashContextError> {
        let (algorithm, _) = Self::parse_id(hash_identifier)?;
        Ok(match algorithm {
            CX_RIPEMD160 => core::mem::size_of::<cx_ripemd160_t>(),
            CX_SHA256 => core::mem::size_of::<cx_sha256_t>(),
            CX_SHA384 | CX_SHA512 => core::mem::size_of::<cx_sha512_t>(),
            _ => core::mem::size_of::<cx_sha3_t>(),
        })
    }

    /// A freshly initialized context. `cx_hash_init_ex` rejects an output size that the algorithm
    /// does not support, so `digest_size` is valid once this succeeds.
    fn new(hash_identifier: u32) -> Result<Self, LedgerHashContextError> {
        let (algorithm, digest_size) = Self::parse_id(hash_identifier)?;
        if digest_size > MAX_HASH_DIGEST_SIZE {
            return Err(LedgerHashContextError::InvalidHashId);
        }

        // SAFETY: every member of the union is a plain C struct, for which all-zero bytes are a
        // valid value; cx_hash_init_ex then initializes the member selected by `algorithm`.
        let mut ctx: LedgerHashContext = unsafe { core::mem::zeroed() };
        let err = unsafe {
            sys::cx_hash_init_ex(
                &mut ctx as *mut LedgerHashContext as *mut sys::cx_hash_t,
                algorithm,
                digest_size,
            )
        };
        if err != CX_OK {
            return Err(LedgerHashContextError::InvalidHashId);
        }

        Ok(Self {
            ctx,
            algorithm,
            digest_size,
        })
    }

    /// A fresh context for `hash_identifier`, with the running state restored from the V-App's
    /// copy `guest` (exactly `guest_size(hash_identifier)` bytes).
    fn restore(hash_identifier: u32, guest: &[u8]) -> Result<Self, LedgerHashContextError> {
        let mut res = Self::new(hash_identifier)?;

        // Copies the running state out of the guest's struct of type `$ty` into the union member
        // `$field`, after checking that the buffered length fits in the block, whose size is
        // `$block_size` computed on our own, trusted, context `$ours`.
        macro_rules! restore_state {
            ($field:ident, $ty:ty, |$ours:ident| $block_size:expr) => {{
                if guest.len() != core::mem::size_of::<$ty>() {
                    return Err(LedgerHashContextError::CorruptedContext);
                }
                // SAFETY: `guest` has exactly the size of `$ty`, a plain C struct for which any
                // bytes are a valid value; read_unaligned does not require alignment.
                let theirs: $ty = unsafe { core::ptr::read_unaligned(guest.as_ptr() as *const $ty) };
                // SAFETY: `new` initialized this member of the union.
                let $ours = unsafe { &mut res.ctx.$field };
                if theirs.blen >= $block_size {
                    return Err(LedgerHashContextError::CorruptedContext);
                }
                $ours.header.counter = theirs.header.counter;
                $ours.blen = theirs.blen;
                $ours.block = theirs.block;
                $ours.acc = theirs.acc;
            }};
        }

        match res.algorithm {
            CX_RIPEMD160 => restore_state!(ripemd160, cx_ripemd160_t, |c| c.block.len()),
            CX_SHA256 => restore_state!(sha256, cx_sha256_t, |c| c.block.len()),
            CX_SHA384 | CX_SHA512 => restore_state!(sha512, cx_sha512_t, |c| c.block.len()),
            // the rate depends on the output size, and was set by cx_hash_init_ex
            _ => restore_state!(sha3, cx_sha3_t, |c| c.block_size),
        }

        Ok(res)
    }

    /// Writes the context into `out` (exactly `guest_size` bytes) for the V-App to keep until the
    /// next ECALL, without the `info` pointer.
    fn export(&mut self, out: &mut [u8]) {
        // the header is the first field of every member of the union
        self.ctx.sha256.header.info = core::ptr::null();
        // SAFETY: the union is at least `out.len()` bytes long, since `out` is sized by
        // `guest_size` for the member that `new` initialized.
        let bytes = unsafe {
            core::slice::from_raw_parts(&self.ctx as *const LedgerHashContext as *const u8, out.len())
        };
        out.copy_from_slice(bytes);
    }

    fn as_cx_hash(&mut self) -> *mut sys::cx_hash_header_s {
        &mut self.ctx as *mut LedgerHashContext as *mut sys::cx_hash_header_s
    }
}

impl LedgerHashContext {
    const MAX_HASH_CONTEXT_SIZE: usize = core::mem::size_of::<LedgerHashContext>();
}

// Wraps the cx_ecfp_private_key_t struct to make sure that it is zeroed on drop
struct ZeroizingPrivateKey(sys::cx_ecfp_private_key_t);

impl Drop for ZeroizingPrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.d.zeroize();
        self.0.d_len.zeroize();
        self.0.curve.zeroize();
    }
}

impl core::ops::Deref for ZeroizingPrivateKey {
    type Target = sys::cx_ecfp_private_key_t;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for ZeroizingPrivateKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The modular operations of `bn_addm`, `bn_subm` and `bn_multm`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BnBinop {
    Add,
    Sub,
    Mul,
}

/// The cx big number functions require lengths that are a multiple of 16 bytes (`cx_bn_lock`), so
/// operands are left-padded with zeros to this length. `MAX_BIGNUMBER_SIZE` is a multiple of 16.
const fn bn_padded_len(len: usize) -> usize {
    len.div_ceil(16) * 16
}

/// Whether the big-endian integer `a` is 1.
fn is_one(a: &[u8]) -> bool {
    a.last() == Some(&1) && is_zero(&a[..a.len() - 1])
}

/// Copies `buf.len()` bytes of the V-App's memory at `ptr` into `buf`. An empty read does not
/// touch memory, since the pointer of an empty slice is dangling.
fn read_guest<E: fmt::Debug, const N: usize>(
    cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
    ptr: GuestPointer,
    buf: &mut [u8],
) -> Result<(), CommEcallError> {
    if buf.is_empty() {
        return Ok(());
    }
    cpu.get_segment::<E>(ptr.0)?.read_buffer(ptr.0, buf)?;
    Ok(())
}

/// Copies `buf` into the V-App's memory at `ptr`. An empty write does not touch memory.
fn write_guest<E: fmt::Debug, const N: usize>(
    cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
    ptr: GuestPointer,
    buf: &[u8],
) -> Result<(), CommEcallError> {
    if buf.is_empty() {
        return Ok(());
    }
    cpu.get_segment::<E>(ptr.0)?.write_buffer(ptr.0, buf)?;
    Ok(())
}

/// Derives the secp256k1 BIP-32 node at `path` from the device's seed, returning its private key
/// and chain code.
///
/// The derivation syscall reports errors by throwing, which would kill the V-App, and its
/// non-throwing replacement (`sys_hdkey_derive`) does not implement plain BIP-32 everywhere. So the
/// callers only pass inputs that it accepts: the secp256k1 curve, which the VM's manifest
/// authorizes for every path, and at most `MAX_BIP32_PATH_LEN` steps.
///
/// Not inlined, so that its buffers stay out of the frame of `handle_ecall`, which every ECALL pays.
#[inline(never)]
fn derive_bip32_node(path: &[u32]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    debug_assert!(path.len() <= MAX_BIP32_PATH_LEN);
    // The OS can write up to 64 bytes of private key, depending on the curve.
    let mut private_key = Zeroizing::new([0u8; 64]);
    let mut chain_code = [0u8; 32];
    // An empty path's pointer must still be valid on the device, so it always points to a local
    // array.
    let mut path_local = [0u32; MAX_BIP32_PATH_LEN];
    path_local[..path.len()].copy_from_slice(path);
    // SAFETY: path_local holds at least `path.len()` steps; the output buffers have the lengths
    // that the syscall requires.
    unsafe {
        sys::os_perso_derive_node_bip32(
            CurveKind::Secp256k1 as u8,
            path_local.as_ptr(),
            path.len() as u32,
            private_key.as_mut_ptr(),
            chain_code.as_mut_ptr(),
        );
    }

    let mut res = Zeroizing::new([0u8; 32]);
    res.copy_from_slice(&private_key[..32]);
    (res, chain_code)
}

/// The fingerprint of the secp256k1 master public key, or `None` if the OS fails to compute the
/// public key.
///
/// Not inlined, so that its buffers are released before the result is written to the V-App's
/// memory, which can page in.
#[inline(never)]
fn secp256k1_master_fingerprint() -> Option<u32> {
    let (private_key, _) = derive_bip32_node(&[]);

    let mut pubkey: sys::cx_ecfp_public_key_t = Default::default();
    let mut privkey = ZeroizingPrivateKey(sys::cx_ecfp_private_key_t::default());
    let curve = CurveKind::Secp256k1 as u8;
    // SAFETY: the private key buffer holds 32 bytes; privkey and pubkey are valid structs.
    let ok = unsafe {
        sys::cx_ecfp_init_private_key_no_throw(
            curve,
            private_key.as_ptr(),
            private_key.len(),
            &mut *privkey,
        ) == CX_OK
            && sys::cx_ecfp_generate_pair_no_throw(curve, &mut pubkey, &mut *privkey, true)
                == CX_OK
    };
    if !ok || pubkey.W_len != 65 {
        return None;
    }

    let mut sha_hasher = ledger_device_sdk::hash::sha2::Sha2_256::new();
    sha_hasher.update(&[02u8 + (pubkey.W[64] % 2)]).unwrap();
    sha_hasher.update(&pubkey.W[1..33]).unwrap();
    let mut sha256hash = [0u8; 32];
    sha_hasher.finalize(&mut sha256hash).unwrap();
    let mut ripemd160_hasher = ledger_device_sdk::hash::ripemd::Ripemd160::new();
    ripemd160_hasher.update(&sha256hash).unwrap();
    let mut rip = [0u8; 20];
    ripemd160_hasher.finalize(&mut rip).unwrap();
    Some(u32::from_be_bytes([rip[0], rip[1], rip[2], rip[3]]))
}

/// Computes `k * P` with cx, for a point `P` on the curve other than infinity, and a scalar
/// `0 < k < n`; the result is then never infinity. Returns `None` if cx fails.
fn secp256k1_scalar_mult(p: &[u8; 65], k: &[u8; 32]) -> Option<[u8; 65]> {
    let mut res = *p;
    // SAFETY: res holds a 65-byte uncompressed point, and k 32 bytes.
    let err = unsafe {
        sys::cx_ecfp_scalar_mult_no_throw(
            CurveKind::Secp256k1 as u8,
            res.as_mut_ptr(),
            k.as_ptr(),
            k.len(),
        )
    };
    (err == CX_OK).then_some(res)
}

/// Whether the canonical coordinates `x, y < p` satisfy the secp256k1 equation y^2 = x^3 + 7.
///
/// The check is done here, rather than left to cx, because cx's behaviour on points that are not
/// on the curve is not documented.
fn is_on_secp256k1(x: &[u8], y: &[u8]) -> bool {
    let mut seven = [0u8; 32];
    seven[31] = 7;
    let (mut y2, mut x2, mut x3, mut rhs) = ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
    let p = SECP256K1_P.as_ptr();
    // SAFETY: all operands are 32 bytes (a multiple of 16) and smaller than the odd modulus p.
    let ok = unsafe {
        sys::cx_math_multm_no_throw(y2.as_mut_ptr(), y.as_ptr(), y.as_ptr(), p, 32) == CX_OK
            && sys::cx_math_multm_no_throw(x2.as_mut_ptr(), x.as_ptr(), x.as_ptr(), p, 32) == CX_OK
            && sys::cx_math_multm_no_throw(x3.as_mut_ptr(), x2.as_ptr(), x.as_ptr(), p, 32) == CX_OK
            && sys::cx_math_addm_no_throw(rhs.as_mut_ptr(), x3.as_ptr(), seven.as_ptr(), p, 32)
                == CX_OK
    };
    ok && y2 == rhs
}

/// Whether a 65-byte point is valid: either infinity, encoded as 65 zero bytes, or
/// `0x04 || x || y` with canonical coordinates of a point on the curve.
fn is_valid_secp256k1_point(p: &[u8; 65]) -> bool {
    match classify_secp256k1_point(p) {
        Some(PointEncoding::Infinity) => true,
        Some(PointEncoding::Affine) => is_on_secp256k1(&p[1..33], &p[33..]),
        None => false,
    }
}

/// `P + Q`, or `None` if a point is invalid.
///
/// Like the other curve helpers, it is not inlined, so that its buffers are not on the stack while
/// the handlers read or write the V-App's memory, which can page in.
#[inline(never)]
fn secp256k1_add(p: &[u8; 65], q: &[u8; 65]) -> Option<[u8; 65]> {
    if !is_valid_secp256k1_point(p) || !is_valid_secp256k1_point(q) {
        return None;
    }

    if is_zero(p) {
        Some(*q)
    } else if is_zero(q) {
        Some(*p)
    } else if p[1..33] != q[1..33] {
        // distinct x-coordinates: the only case that cx_ecfp_add_point needs to handle
        let mut res = [0u8; 65];
        // SAFETY: all buffers are 65 bytes; both points are valid and neither is the negation of
        // the other.
        let err = unsafe {
            sys::cx_ecfp_add_point_no_throw(
                CurveKind::Secp256k1 as u8,
                res.as_mut_ptr(),
                p.as_ptr(),
                q.as_ptr(),
            )
        };
        (err == CX_OK).then_some(res)
    } else if p[33..] == q[33..] {
        // P + P = 2P
        let mut two = [0u8; 32];
        two[31] = 2;
        secp256k1_scalar_mult(p, &two)
    } else {
        // same x-coordinate and different y-coordinate: Q = -P, and P + Q is infinity
        Some([0u8; 65])
    }
}

/// `k * P`, or `None` if the point is invalid or `k >= n`.
#[inline(never)]
fn secp256k1_mul(p: &[u8; 65], k: &[u8; 32]) -> Option<[u8; 65]> {
    if !is_valid_secp256k1_point(p) || !is_secp256k1_scalar(k) {
        return None;
    }
    if is_zero(p) || is_zero(k) {
        Some([0u8; 65])
    } else {
        secp256k1_scalar_mult(p, k)
    }
}

pub enum CommEcallError {
    Exit(i32),
    Panic,
    InvalidParameters(&'static str),
    GenericError(&'static str),
    Overflow,
    MessageDeserializationError(MessageDeserializationError),
    InvalidResponse(&'static str),
    CpuError(String),
    MemoryError(MemoryError),
    InterruptError(InterruptError),
    UnhandledEcall,
}

impl core::fmt::Display for CommEcallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CommEcallError::Exit(code) => write!(f, "Exit with code {}", code),
            CommEcallError::Panic => write!(f, "Panic occurred"),
            CommEcallError::InvalidParameters(msg) => {
                write!(f, "Invalid parameters: {}", msg)
            }
            CommEcallError::GenericError(msg) => write!(f, "Error: {}", msg),
            CommEcallError::Overflow => write!(f, "Buffer overflow"),
            CommEcallError::MessageDeserializationError(e) => {
                write!(f, "Message deserialization error: {:?}", e)
            }
            CommEcallError::InvalidResponse(msg) => {
                write!(f, "Invalid response from host: {}", msg)
            }
            CommEcallError::CpuError(e) => write!(f, "Cpu error: {:?}", e),
            CommEcallError::MemoryError(e) => write!(f, "Memory error: {:?}", e),
            CommEcallError::InterruptError(e) => write!(f, "Interrupt error: {}", e),
            CommEcallError::UnhandledEcall => write!(f, "Unhandled ecall"),
        }
    }
}

impl core::fmt::Debug for CommEcallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl<E: fmt::Debug> From<CpuError<E>> for CommEcallError {
    fn from(error: CpuError<E>) -> Self {
        CommEcallError::CpuError(format!("{:?}", error))
    }
}

impl From<MemoryError> for CommEcallError {
    fn from(error: MemoryError) -> Self {
        CommEcallError::MemoryError(error)
    }
}

impl From<InterruptError> for CommEcallError {
    fn from(error: InterruptError) -> Self {
        CommEcallError::InterruptError(error)
    }
}

impl From<MessageDeserializationError> for CommEcallError {
    fn from(error: MessageDeserializationError) -> Self {
        CommEcallError::MessageDeserializationError(error)
    }
}

impl From<alloc::ffi::NulError> for CommEcallError {
    fn from(_: alloc::ffi::NulError) -> Self {
        CommEcallError::InvalidParameters("CString contains a null byte")
    }
}

impl core::error::Error for CommEcallError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            CommEcallError::MemoryError(e) => Some(e),
            CommEcallError::MessageDeserializationError(e) => Some(e),
            // since we convert CpuError to a string, we don't keep the original error
            _ => None,
        }
    }
}

pub struct CommEcallHandler<'a, const N: usize> {
    comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm<N>>>,
    ux_handler: &'static mut UxHandler,
    vapp_hash: [u8; 32],
    n_storage_slots: u32,
}

impl<'a, const N: usize> CommEcallHandler<'a, N> {
    pub fn new(
        comm: Rc<RefCell<&'a mut ledger_device_sdk::io::Comm<N>>>,
        vapp_hash: [u8; 32],
        n_storage_slots: u32,
    ) -> Self {
        assert!(n_storage_slots <= MAX_STORAGE_SLOTS);

        Self {
            comm,
            ux_handler: init_ux_handler(),
            vapp_hash,
            n_storage_slots,
        }
    }

    fn handle_send_buffer<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        mut size: usize,
        buffer_type: BufferType,
    ) -> Result<(), CommEcallError> {
        if size == 0 {
            // We must not read the pointer for an empty buffer; Rust always uses address 0x01 for
            // an empty buffer

            let mut comm = self.comm.borrow_mut();
            let mut resp = comm.begin_response();
            SendBufferMessage::new(size as u32, buffer_type, &[]).serialize_to_comm(&mut resp);
            interrupt(resp)?;
            return Ok(());
        }

        if buffer.0.checked_add(size as u32).is_none() {
            return Err(CommEcallError::Overflow);
        }

        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        let mut buffer = [0u8; 256];
        let mut first_chunk = true;
        // loop while size > 0
        while size > 0 {
            if first_chunk {
                let copy_size = min(size, 255 - 6); // send maximum 249 bytes in the first chunk
                segment.read_buffer(g_ptr, &mut buffer[0..copy_size])?;

                let mut comm = self.comm.borrow_mut();
                let mut resp = comm.begin_response();
                SendBufferMessage::new(size as u32, buffer_type, &buffer[0..copy_size])
                    .serialize_to_comm(&mut resp);
                interrupt(resp)?;
                size -= copy_size;
                g_ptr += copy_size as u32;
                first_chunk = false;
            } else {
                let copy_size = min(size, 255 - 1); // send maximum 255 bytes in each subsequent chunk
                segment.read_buffer(g_ptr, &mut buffer[0..copy_size])?;
                let mut comm = self.comm.borrow_mut();
                let mut resp = comm.begin_response();
                SendBufferContinuedMessage::new(&buffer[0..copy_size]).serialize_to_comm(&mut resp);
                interrupt(resp)?;
                size -= copy_size;
                g_ptr += copy_size as u32;
            }
        }

        Ok(())
    }

    // Sends a panic message
    fn handle_panic<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<(), CommEcallError> {
        self.handle_send_buffer::<E>(cpu, buffer, size, BufferType::Panic)
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    fn handle_xsend<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<(), CommEcallError> {
        self.handle_send_buffer::<E>(cpu, buffer, size, BufferType::VAppMessage)
    }

    // Receives up to max_size bytes from the host into the buffer in the V-app memory
    // Returns the catual of bytes received.
    fn handle_xrecv<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        max_size: usize,
    ) -> Result<usize, CommEcallError> {
        let mut g_ptr = buffer.0;

        let segment = cpu.get_segment::<E>(g_ptr)?;

        let mut remaining_length = None;
        let mut total_received: usize = 0;
        while remaining_length != Some(0) {
            let response_content = {
                let mut comm = self.comm.borrow_mut();
                let mut resp = comm.begin_response();
                ReceiveBufferMessage::new().serialize_to_comm(&mut resp);

                let command = interrupt(resp)?;

                let raw_data = command.get_data();
                let response = ReceiveBufferResponse::deserialize(raw_data)?;

                match remaining_length {
                    None => {
                        // first chunk, check if the total length is acceptable
                        if response.remaining_length > max_size as u32 {
                            return Err(CommEcallError::InvalidResponse(
                                "Received data is too large",
                            ));
                        }
                        remaining_length = Some(response.remaining_length);
                    }
                    Some(remaining) => {
                        if remaining != response.remaining_length {
                            return Err(CommEcallError::InvalidResponse(
                                "Mismatching remaining length",
                            ));
                        }
                    }
                }

                // We need to clone the content, since it is tied to the `comm` borrow.
                response.content.to_vec()
            };

            segment.write_buffer(g_ptr, &response_content)?;

            // make sure chunk doesn't exceed remaining length
            let chunk_len = response_content.len() as u32;
            let curr_remaining = remaining_length.unwrap();
            if chunk_len > curr_remaining {
                return Err(CommEcallError::InvalidResponse(
                    "Chunk exceeds declared remaining length",
                ));
            }
            remaining_length = Some(curr_remaining - chunk_len);
            g_ptr += chunk_len;
            total_received += response_content.len();
        }
        Ok(total_received)
    }

    // Sends exactly size bytes from the buffer in the V-app memory to the host
    fn handle_print<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<(), CommEcallError> {
        self.handle_send_buffer::<E>(cpu, buffer, size, BufferType::Print)
    }

    fn handle_storage_read<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        slot_index: u32,
        buffer: GuestPointer,
        buffer_size: usize,
    ) -> Result<u32, CommEcallError> {
        // Validate buffer size
        if buffer_size != STORAGE_SLOT_SIZE {
            return Ok(0); // Invalid buffer size
        }

        // Validate slot index
        if slot_index >= self.n_storage_slots || slot_index >= MAX_STORAGE_SLOTS {
            return Ok(0); // Invalid slot index
        }

        // Find the VApp in storage
        let vapp_index = match crate::vapp::VAppStore::find_by_hash(&self.vapp_hash) {
            Some(index) => index,
            None => return Ok(0), // VApp not found
        };

        // Get the storage slot data
        let entry = crate::vapp::VAppStore::get_entry(vapp_index)
            .ok_or(CommEcallError::GenericError("VApp entry not found"))?;
        let slot_data = &entry.storage_slots[slot_index as usize];

        // Write slot data to guest memory
        cpu.get_segment::<E>(buffer.0)?
            .write_buffer(buffer.0, slot_data)?;

        Ok(1) // Success
    }

    fn handle_storage_write<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        slot_index: u32,
        buffer: GuestPointer,
        buffer_size: usize,
    ) -> Result<u32, CommEcallError> {
        // Validate buffer size
        if buffer_size != STORAGE_SLOT_SIZE {
            return Ok(0); // Invalid buffer size
        }

        // Validate slot index
        if slot_index >= self.n_storage_slots || slot_index >= MAX_STORAGE_SLOTS {
            return Ok(0); // Invalid slot index
        }

        // Find the VApp in storage
        let vapp_index = match crate::vapp::VAppStore::find_by_hash(&self.vapp_hash) {
            Some(index) => index,
            None => return Ok(0), // VApp not found
        };

        // Read data from guest memory
        let mut slot_data: [u8; STORAGE_SLOT_SIZE] = [0; STORAGE_SLOT_SIZE];
        cpu.get_segment::<E>(buffer.0)?
            .read_buffer(buffer.0, &mut slot_data)?;

        // Get current entry and update it
        let mut entry = *crate::vapp::VAppStore::get_entry(vapp_index)
            .ok_or(CommEcallError::GenericError("VApp entry not found"))?;
        entry.storage_slots[slot_index as usize] = slot_data;

        // Write back to NVRAM atomically
        let storage = crate::vapp::VAppStore::get_storage_mut();
        storage[vapp_index].update(&entry);

        Ok(1) // Success
    }

    /// Computes `n mod m` into `r` (`len` bytes).
    ///
    /// Returns 1 on success, 0 if `len > MAX_BIGNUMBER_SIZE`, `len_m > len`, or `m` is zero.
    fn handle_bn_modm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        n: GuestPointer,
        len: usize,
        m: GuestPointer,
        len_m: usize,
    ) -> Result<u32, CommEcallError> {
        if !is_bignum_len(len) || len_m > len {
            return Ok(0);
        }
        let (padded_len, padded_len_m) = (bn_padded_len(len), bn_padded_len(len_m));

        // n is reduced in place, so v_local holds the result too
        let mut v_local = [0u8; MAX_BIGNUMBER_SIZE];
        let mut m_local = [0u8; MAX_BIGNUMBER_SIZE];
        read_guest::<E, N>(cpu, n, &mut v_local[padded_len - len..padded_len])?;
        read_guest::<E, N>(cpu, m, &mut m_local[padded_len_m - len_m..padded_len_m])?;
        if !is_modulus(&m_local[..padded_len_m], false) {
            return Ok(0);
        }

        // SAFETY: both buffers hold their padded lengths, as cx_bn_lock requires.
        let res = unsafe {
            sys::cx_math_modm_no_throw(
                v_local.as_mut_ptr(),
                padded_len,
                m_local.as_ptr(),
                padded_len_m,
            )
        };
        if res != CX_OK {
            return Ok(0);
        }

        write_guest::<E, N>(cpu, r, &v_local[padded_len - len..padded_len])?;
        Ok(1)
    }

    /// Computes `a op b mod m` into `r`, for `op` one of `bn_addm`, `bn_subm` or `bn_multm`. All
    /// the operands are `len` bytes long.
    ///
    /// Returns 1 on success, 0 if `len > MAX_BIGNUMBER_SIZE`, `m` is zero (or even for `bn_multm`),
    /// or `a` or `b` is not smaller than `m`.
    fn handle_bn_binop<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        op: BnBinop,
        r: GuestPointer,
        a: GuestPointer,
        b: GuestPointer,
        m: GuestPointer,
        len: usize,
    ) -> Result<u32, CommEcallError> {
        if !is_bignum_len(len) {
            return Ok(0);
        }
        let padded_len = bn_padded_len(len);
        let range = padded_len - len..padded_len;

        let mut a_local = [0u8; MAX_BIGNUMBER_SIZE];
        let mut b_local = [0u8; MAX_BIGNUMBER_SIZE];
        let mut m_local = [0u8; MAX_BIGNUMBER_SIZE];
        read_guest::<E, N>(cpu, a, &mut a_local[range.clone()])?;
        read_guest::<E, N>(cpu, b, &mut b_local[range.clone()])?;
        read_guest::<E, N>(cpu, m, &mut m_local[range.clone()])?;
        let (a_local, b_local, m_local) = (
            &a_local[..padded_len],
            &b_local[..padded_len],
            &m_local[..padded_len],
        );
        if !is_modulus(m_local, op == BnBinop::Mul)
            || !is_reduced(a_local, m_local)
            || !is_reduced(b_local, m_local)
        {
            return Ok(0);
        }

        let mut r_local = [0u8; MAX_BIGNUMBER_SIZE];
        // a, b < m = 1 means that a = b = 0; the result is 0, whatever cx would do with m = 1
        if !is_one(m_local) {
            let f = match op {
                BnBinop::Add => sys::cx_math_addm_no_throw,
                BnBinop::Sub => sys::cx_math_subm_no_throw,
                BnBinop::Mul => sys::cx_math_multm_no_throw,
            };
            // SAFETY: all buffers hold `padded_len` bytes, as cx_bn_lock requires; the operands
            // are smaller than the modulus, which is odd for the multiplication.
            let res = unsafe {
                f(
                    r_local.as_mut_ptr(),
                    a_local.as_ptr(),
                    b_local.as_ptr(),
                    m_local.as_ptr(),
                    padded_len,
                )
            };
            if res != CX_OK {
                return Ok(0);
            }
        }

        write_guest::<E, N>(cpu, r, &r_local[range])?;
        Ok(1)
    }

    /// Computes the inverse of `a` modulo the odd prime `p` into `r`; all are `len` bytes long.
    ///
    /// Returns 1 on success, 0 if `len > MAX_BIGNUMBER_SIZE`, `p` is zero or even, or `a` is zero
    /// or not smaller than `p`. The result is unspecified if `p` is not prime.
    fn handle_bn_modinv_prime<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        a: GuestPointer,
        p: GuestPointer,
        len: usize,
    ) -> Result<u32, CommEcallError> {
        if !is_bignum_len(len) {
            return Ok(0);
        }
        let padded_len = bn_padded_len(len);
        let range = padded_len - len..padded_len;

        let mut a_local = [0u8; MAX_BIGNUMBER_SIZE];
        let mut p_local = [0u8; MAX_BIGNUMBER_SIZE];
        read_guest::<E, N>(cpu, a, &mut a_local[range.clone()])?;
        read_guest::<E, N>(cpu, p, &mut p_local[range.clone()])?;
        let (a_local, p_local) = (&a_local[..padded_len], &p_local[..padded_len]);
        if !is_modulus(p_local, true) || is_zero(a_local) || !is_reduced(a_local, p_local) {
            return Ok(0);
        }

        let mut r_local = [0u8; MAX_BIGNUMBER_SIZE];
        // SAFETY: all buffers hold `padded_len` bytes; 0 < a < p, with p odd.
        let res = unsafe {
            sys::cx_math_invprimem_no_throw(
                r_local.as_mut_ptr(),
                a_local.as_ptr(),
                p_local.as_ptr(),
                padded_len,
            )
        };
        if res != CX_OK {
            return Ok(0);
        }

        write_guest::<E, N>(cpu, r, &r_local[range])?;
        Ok(1)
    }

    /// Computes `a^e mod m` into `r`; `a`, `m` and `r` are `len` bytes long, `e` is `len_e`.
    ///
    /// Returns 1 on success, 0 if `len` or `len_e` exceeds `MAX_BIGNUMBER_SIZE`, `m` is zero or
    /// even, or `a` is not smaller than `m`.
    fn handle_bn_powm<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        r: GuestPointer,
        a: GuestPointer,
        e: GuestPointer,
        len_e: usize,
        m: GuestPointer,
        len: usize,
    ) -> Result<u32, CommEcallError> {
        if !is_bignum_len(len) || !is_bignum_len(len_e) {
            return Ok(0);
        }
        let padded_len = bn_padded_len(len);
        let range = padded_len - len..padded_len;

        let mut a_local = [0u8; MAX_BIGNUMBER_SIZE];
        let mut e_local = [0u8; MAX_BIGNUMBER_SIZE];
        let mut m_local = [0u8; MAX_BIGNUMBER_SIZE];
        read_guest::<E, N>(cpu, a, &mut a_local[range.clone()])?;
        read_guest::<E, N>(cpu, e, &mut e_local[..len_e])?;
        read_guest::<E, N>(cpu, m, &mut m_local[range.clone()])?;
        let (a_local, e_local, m_local) = (
            &a_local[..padded_len],
            &e_local[..len_e],
            &m_local[..padded_len],
        );
        if !is_modulus(m_local, true) || !is_reduced(a_local, m_local) {
            return Ok(0);
        }

        let mut r_local = [0u8; MAX_BIGNUMBER_SIZE];
        if is_one(m_local) {
            // everything is 0 modulo 1
        } else if is_zero(e_local) {
            // a^0 = 1, whatever cx would do with an empty or zero exponent
            r_local[padded_len - 1] = 1;
        } else {
            // SAFETY: a, m and r hold `padded_len` bytes, as cx_bn_lock requires; e is passed as
            // a byte string; a < m, with m odd.
            let res = unsafe {
                sys::cx_math_powm_no_throw(
                    r_local.as_mut_ptr(),
                    a_local.as_ptr(),
                    e_local.as_ptr(),
                    len_e,
                    m_local.as_ptr(),
                    padded_len,
                )
            };
            if res != CX_OK {
                return Ok(0);
            }
        }

        write_guest::<E, N>(cpu, r, &r_local[range])?;
        Ok(1)
    }

    /// Initializes the hash context `ctx` for `hash_identifier`.
    ///
    /// Returns 1 on success, 0 if `hash_identifier` is not a supported algorithm and output size.
    fn handle_hash_init<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        hash_identifier: u32,
        ctx: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        let Ok(ctx_size) = VerifiedHashContext::guest_size(hash_identifier) else {
            return Ok(0);
        };
        let Ok(mut hash_ctx) = VerifiedHashContext::new(hash_identifier) else {
            return Ok(0);
        };

        let mut ctx_local = [0u8; LedgerHashContext::MAX_HASH_CONTEXT_SIZE];
        hash_ctx.export(&mut ctx_local[..ctx_size]);
        cpu.get_segment::<E>(ctx.0)?
            .write_buffer(ctx.0, &ctx_local[..ctx_size])?;

        Ok(1)
    }

    /// Absorbs `data_len` bytes at `data` into the hash context `ctx`.
    ///
    /// Returns 1 on success, 0 if `hash_identifier` is invalid or `ctx` is not a context that the
    /// hash ECALLs produced for it.
    fn handle_hash_update<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        hash_identifier: u32,
        ctx: GuestPointer,
        data: GuestPointer,
        data_len: usize,
    ) -> Result<u32, CommEcallError> {
        let Ok(ctx_size) = VerifiedHashContext::guest_size(hash_identifier) else {
            return Ok(0);
        };

        let mut ctx_local = [0u8; LedgerHashContext::MAX_HASH_CONTEXT_SIZE];
        cpu.get_segment::<E>(ctx.0)?
            .read_buffer(ctx.0, &mut ctx_local[..ctx_size])?;
        let Ok(mut hash_ctx) = VerifiedHashContext::restore(hash_identifier, &ctx_local[..ctx_size])
        else {
            return Ok(0);
        };

        if data_len == 0 {
            // nothing to absorb; an empty slice's pointer is dangling, so it must not be read
            return Ok(1);
        }
        if data.0.checked_add(data_len as u32).is_none() {
            return Err(CommEcallError::Overflow);
        }

        // copy data to local memory in chunks of at most 256 bytes
        let mut data_local: [u8; 256] = [0; 256];
        let mut data_remaining = data_len;
        let mut data_ptr = data.0;
        let data_seg = cpu.get_segment::<E>(data_ptr)?;
        while data_remaining > 0 {
            let copy_size = min(data_remaining, 256);
            data_seg.read_buffer(data_ptr, &mut data_local[0..copy_size])?;

            // SAFETY: the context's header and sizes were set by cx_hash_init_ex, and its
            // buffered length was checked by `restore`.
            let err = unsafe {
                sys::cx_hash_update(hash_ctx.as_cx_hash(), data_local.as_ptr(), copy_size)
            };
            if err != CX_OK {
                return Ok(0);
            }

            data_remaining -= copy_size;
            data_ptr += copy_size as u32;
        }

        hash_ctx.export(&mut ctx_local[..ctx_size]);
        cpu.get_segment::<E>(ctx.0)?
            .write_buffer(ctx.0, &ctx_local[..ctx_size])?;

        Ok(1)
    }

    /// Writes the digest of the hash context `ctx` to `digest`. The context is left unchanged.
    ///
    /// Returns 1 on success, 0 if `hash_identifier` is invalid or `ctx` is not a context that the
    /// hash ECALLs produced for it.
    fn handle_hash_digest<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        hash_identifier: u32,
        ctx: GuestPointer,
        digest: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        let Ok(ctx_size) = VerifiedHashContext::guest_size(hash_identifier) else {
            return Ok(0);
        };

        let mut ctx_local = [0u8; LedgerHashContext::MAX_HASH_CONTEXT_SIZE];
        cpu.get_segment::<E>(ctx.0)?
            .read_buffer(ctx.0, &mut ctx_local[..ctx_size])?;
        let Ok(mut hash_ctx) = VerifiedHashContext::restore(hash_identifier, &ctx_local[..ctx_size])
        else {
            return Ok(0);
        };

        let mut digest_local = [0u8; MAX_HASH_DIGEST_SIZE];
        // SAFETY: as in handle_hash_update; `digest_local` holds the largest supported digest.
        let err = unsafe { sys::cx_hash_final(hash_ctx.as_cx_hash(), digest_local.as_mut_ptr()) };
        if err != CX_OK {
            return Ok(0);
        }

        cpu.get_segment::<E>(digest.0)?
            .write_buffer(digest.0, &digest_local[..hash_ctx.digest_size])?;

        Ok(1)
    }

    /// Derives the BIP-32 node at `path` from the device's seed, writing its private key and chain
    /// code to `private_key` and `chain_code` (32 bytes each).
    ///
    /// Returns 1 on success, 0 if the curve is not supported or `path_len > MAX_BIP32_PATH_LEN`.
    fn handle_derive_hd_node<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        path: GuestPointer,
        path_len: usize,
        private_key: GuestPointer,
        chain_code: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 || path_len > MAX_BIP32_PATH_LEN {
            return Ok(0);
        }

        let mut path_local_raw = [0u8; MAX_BIP32_PATH_LEN * 4];
        read_guest::<E, N>(cpu, path, &mut path_local_raw[..path_len * 4])?;
        // read bytes and combine into u32 values safely (avoid unaligned access)
        let mut path_local = [0u32; MAX_BIP32_PATH_LEN];
        for (step, bytes) in path_local.iter_mut().zip(path_local_raw.chunks_exact(4)) {
            *step = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }

        let (private_key_local, chain_code_local) = derive_bip32_node(&path_local[..path_len]);

        write_guest::<E, N>(cpu, private_key, &private_key_local[..])?;
        write_guest::<E, N>(cpu, chain_code, &chain_code_local)?;
        Ok(1)
    }

    /// Writes to `fingerprint` the fingerprint of the master public key: the first 4 bytes of
    /// `ripemd160(sha256(pk))`, where `pk` is the compressed public key, as a `u32`.
    ///
    /// Returns 1 on success, 0 if the curve is not supported.
    fn handle_get_master_fingerprint<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        fingerprint: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Ok(0);
        }
        let Some(value) = secp256k1_master_fingerprint() else {
            return Ok(0);
        };
        write_guest::<E, N>(cpu, fingerprint, &value.to_le_bytes())?;
        Ok(1)
    }

    /// Derives the SLIP-21 node for the length-prefixed `labels`, writing its 64 bytes to `out`.
    ///
    /// Returns 1 on success, 0 if the labels buffer is longer than `MAX_SLIP21_LABELS_LEN`, a label
    /// is longer than `MAX_SLIP21_LABEL_LEN`, or the last label is truncated. An empty buffer
    /// gives the master node.
    fn handle_derive_slip21_node<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        labels: GuestPointer,
        labels_len: usize,
        out: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if labels_len > MAX_SLIP21_LABELS_LEN {
            return Ok(0);
        }
        let mut labels_local = [0u8; MAX_SLIP21_LABELS_LEN];
        read_guest::<E, N>(cpu, labels, &mut labels_local[..labels_len])?;

        let Some(labels) = parse_slip21_labels(&labels_local[..labels_len]) else {
            return Ok(0);
        };
        let slices: Vec<&[u8]> = labels.collect();
        let out_node = Zeroizing::new(slip21::get_custom_slip21_node(&slices));

        write_guest::<E, N>(cpu, out, &out_node[..])?;
        Ok(1)
    }

    /// Adds the points `p` and `q`, writing the result to `r`.
    ///
    /// Returns 1 on success, 0 if the curve is not supported or a point is invalid (see
    /// `is_valid_secp256k1_point`).
    #[inline(never)]
    fn handle_ecfp_add_point<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        r: GuestPointer,
        p: GuestPointer,
        q: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Ok(0);
        }
        let (mut p_local, mut q_local) = ([0u8; 65], [0u8; 65]);
        read_guest::<E, N>(cpu, p, &mut p_local)?;
        read_guest::<E, N>(cpu, q, &mut q_local)?;

        let Some(r_local) = secp256k1_add(&p_local, &q_local) else {
            return Ok(0);
        };
        write_guest::<E, N>(cpu, r, &r_local)?;
        Ok(1)
    }

    /// Multiplies the point `p` by the scalar `k` (`k_len` bytes, big-endian), writing the result
    /// to `r`.
    ///
    /// Returns 1 on success, 0 if the curve is not supported, the point is invalid (see
    /// `is_valid_secp256k1_point`), `k_len > 32` or `k >= n`.
    #[inline(never)]
    fn handle_ecfp_scalar_mult<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        r: GuestPointer,
        p: GuestPointer,
        k: GuestPointer,
        k_len: usize,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 || k_len > 32 {
            return Ok(0);
        }
        let mut p_local = [0u8; 65];
        let mut k_local = Zeroizing::new([0u8; 32]);
        read_guest::<E, N>(cpu, p, &mut p_local)?;
        read_guest::<E, N>(cpu, k, &mut k_local[32 - k_len..])?;

        let Some(r_local) = secp256k1_mul(&p_local, &k_local) else {
            return Ok(0);
        };
        write_guest::<E, N>(cpu, r, &r_local)?;
        Ok(1)
    }

    /// Fills `size` bytes at `buffer` with random bytes.
    ///
    /// Returns 1 on success, 0 if `size > MAX_RANDOM_BYTES`.
    fn handle_get_random_bytes<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        buffer: GuestPointer,
        size: usize,
    ) -> Result<u32, CommEcallError> {
        if size > MAX_RANDOM_BYTES {
            return Ok(0);
        }

        let mut random_bytes = [0u8; MAX_RANDOM_BYTES];
        // SAFETY: random_bytes holds at least `size` bytes.
        unsafe { sys::cx_rng_no_throw(random_bytes.as_mut_ptr(), size) };

        write_guest::<E, N>(cpu, buffer, &random_bytes[..size])?;
        Ok(1)
    }

    fn handle_ecdsa_sign<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: GuestPointer,
        msg_hash: GuestPointer,
        signature: GuestPointer,
    ) -> Result<usize, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if mode != ecall_constants::EcdsaSignMode::RFC6979 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported ecdsa signing mode",
            ));
        }

        if hash_id != ecall_constants::HashId::Sha256 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported hash id",
            ));
        }

        // copy inputs to local memory
        let mut privkey_local = ZeroizingPrivateKey(sys::cx_ecfp_private_key_t::default());
        privkey_local.curve = curve as u8;
        privkey_local.d_len = 32;
        cpu.get_segment::<E>(privkey.0)?
            .read_buffer(privkey.0, &mut privkey_local.d)?;

        let mut msg_hash_local: [u8; 32] = [0; 32];
        cpu.get_segment::<E>(msg_hash.0)?
            .read_buffer(msg_hash.0, &mut msg_hash_local)?;

        // ECDSA signatures are at most 72 bytes long.
        let mut signature_local: [u8; 72] = [0; 72];
        let mut signature_len: usize = signature_local.len();
        let mut info: u32 = 0; // will get the parity bit

        unsafe {
            let res = sys::cx_ecdsa_sign_no_throw(
                &mut *privkey_local,
                ecall_constants::EcdsaSignMode::RFC6979 as u32,
                ecall_constants::HashId::Sha256 as u8,
                msg_hash_local.as_ptr(),
                msg_hash_local.len(),
                signature_local.as_mut_ptr(),
                &mut signature_len,
                &mut info,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError(
                    "cx_ecdsa_sign_no_throw failed",
                ));
            }
        }

        // validate signature length before writing
        if signature_len as usize > signature_local.len() {
            return Err(CommEcallError::GenericError(
                "Signature length exceeds buffer size",
            ));
        }

        // copy signature to V-App memory
        cpu.get_segment::<E>(signature.0)?
            .write_buffer(signature.0, &signature_local[0..signature_len as usize])?;

        Ok(signature_len)
    }

    fn handle_ecdsa_verify<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        pubkey: GuestPointer,
        msg_hash: GuestPointer,
        signature: GuestPointer,
        signature_len: usize,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if signature_len > 72 {
            return Err(CommEcallError::InvalidParameters(
                "signature_len is too large",
            ));
        }

        // copy inputs to local memory
        let mut pubkey_local: sys::cx_ecfp_public_key_t = Default::default();
        pubkey_local.curve = curve as u8;
        pubkey_local.W_len = 65;
        cpu.get_segment::<E>(pubkey.0)?
            .read_buffer(pubkey.0, &mut pubkey_local.W)?;

        let mut msg_hash_local: [u8; 32] = [0; 32];
        cpu.get_segment::<E>(msg_hash.0)?
            .read_buffer(msg_hash.0, &mut msg_hash_local)?;

        let mut signature_local: [u8; 72] = [0; 72];
        cpu.get_segment::<E>(signature.0)?
            .read_buffer(signature.0, &mut signature_local[0..signature_len])?;

        // verify the signature
        let res = unsafe {
            sys::cx_ecdsa_verify_no_throw(
                &pubkey_local,
                msg_hash_local.as_ptr(),
                msg_hash_local.len(),
                signature_local.as_ptr(),
                signature_len,
            )
        };

        Ok(res as u32)
    }

    fn handle_schnorr_sign<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: GuestPointer,
        msg: GuestPointer,
        msg_len: usize,
        signature: GuestPointer,
        entropy: GuestPointer,
    ) -> Result<usize, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if mode != ecall_constants::SchnorrSignMode::BIP340 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported schnorr signing mode",
            ));
        }

        if msg_len > 128 {
            return Err(CommEcallError::InvalidParameters("msg_len is too large"));
        }

        if hash_id != ecall_constants::HashId::Sha256 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported hash id",
            ));
        }

        // copy inputs to local memory
        let mut privkey_local = ZeroizingPrivateKey(sys::cx_ecfp_private_key_t::default());
        privkey_local.curve = curve as u8;
        privkey_local.d_len = 32;
        cpu.get_segment::<E>(privkey.0)?
            .read_buffer(privkey.0, &mut privkey_local.d)?;

        let mut msg_local = vec![0; 128];
        cpu.get_segment::<E>(msg.0)?
            .read_buffer(msg.0, &mut msg_local[..msg_len])?;

        // Schnorr signatures are at most 64 bytes long.
        let mut signature_local: [u8; 64] = [0; 64];
        let mut signature_len: usize = signature_local.len();

        unsafe {
            // We don't expose this, but cx_ecschnorr_sign_no_throw requires one of
            // CX_RND_TRNG or CX_RND_PROVIDED to be provided. We use `entropy` if it's provided,
            // CX_RND_TRNG  otherwise.
            const CX_RND_TRNG: u32 = 2 << 9;
            const CX_RND_PROVIDED: u32 = 4 << 9;

            let mode = if entropy.is_null() {
                mode | CX_RND_TRNG
            } else {
                cpu.get_segment::<E>(entropy.0)?
                    .read_buffer(entropy.0, &mut signature_local[..32])?;
                mode | CX_RND_PROVIDED
            };

            let res = sys::cx_ecschnorr_sign_no_throw(
                &mut *privkey_local,
                mode,
                ecall_constants::HashId::Sha256 as u8,
                msg_local.as_ptr(),
                msg_len,
                signature_local.as_mut_ptr(),
                &mut signature_len,
            );
            if res != CX_OK {
                return Err(CommEcallError::GenericError(
                    "cx_schnorr_sign_no_throw failed",
                ));
            }
        }

        // signatures returned per BIP340 are always exactly 64 bytes
        if signature_len != 64 {
            return Err(CommEcallError::GenericError(
                "cx_schnorr_sign_no_throw returned a signature of unexpected length",
            ));
        }

        // validate signature length before writing
        if signature_len as usize > signature_local.len() {
            return Err(CommEcallError::GenericError(
                "Signature length exceeds buffer size",
            ));
        }

        // copy signature to V-App memory
        cpu.get_segment::<E>(signature.0)?
            .write_buffer(signature.0, &signature_local[0..signature_len as usize])?;

        Ok(signature_len)
    }

    fn handle_schnorr_verify<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        curve: u32,
        mode: u32,
        hash_id: u32,
        pubkey: GuestPointer,
        msg: GuestPointer,
        msg_len: usize,
        signature: GuestPointer,
        signature_len: usize,
    ) -> Result<u32, CommEcallError> {
        if curve != CurveKind::Secp256k1 as u32 {
            return Err(CommEcallError::InvalidParameters("Unsupported curve"));
        }

        if mode != ecall_constants::SchnorrSignMode::BIP340 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported schnorr signing mode",
            ));
        }

        if msg_len > 128 {
            return Err(CommEcallError::InvalidParameters("msg_len is too large"));
        }

        if hash_id != ecall_constants::HashId::Sha256 as u32 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid or unsupported hash id",
            ));
        }

        if signature_len != 64 {
            return Err(CommEcallError::InvalidParameters(
                "Invalid signature length",
            ));
        }

        // copy inputs to local memory
        let mut pubkey_local: sys::cx_ecfp_public_key_t = Default::default();
        pubkey_local.curve = curve as u8;
        pubkey_local.W_len = 65;
        cpu.get_segment::<E>(pubkey.0)?
            .read_buffer(pubkey.0, &mut pubkey_local.W)?;

        let mut msg_local = vec![0; msg_len];
        cpu.get_segment::<E>(msg.0)?
            .read_buffer(msg.0, &mut msg_local)?;

        let mut signature_local: [u8; 64] = [0; 64];
        cpu.get_segment::<E>(signature.0)?
            .read_buffer(signature.0, &mut signature_local)?;

        // verify the signature
        let res = unsafe {
            sys::cx_ecschnorr_verify(
                &pubkey_local,
                mode,
                ecall_constants::HashId::Sha256 as u8,
                msg_local.as_ptr(),
                msg_len,
                signature_local.as_ptr(),
                signature_len,
            )
        };

        Ok(res as u32)
    }

    fn handle_get_event<E: fmt::Debug>(
        &self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        event_data_ptr: GuestPointer,
    ) -> Result<u32, CommEcallError> {
        if let Some((event_code, event_data)) = get_last_event() {
            // transmute the EventData as a [u8]
            // SAFETY: EventData is #[repr(C)] with size 16 bytes. All event data is initialized
            // via EventData::default() which zeros all 16 bytes before setting specific fields.
            // This ensures no uninitialized padding bytes exist when transmuting to &[u8].
            let event_data_raw = unsafe {
                core::slice::from_raw_parts(
                    &event_data as *const _ as *const u8,
                    core::mem::size_of::<common::ux::EventData>(),
                )
            };

            // copy event data to guest pointer
            cpu.get_segment::<E>(event_data_ptr.0)?
                .write_buffer(event_data_ptr.0, &event_data_raw)?;

            Ok(event_code as u32)
        } else {
            // if there's no stored event, wait for the next ticker and return it
            let mut comm = self.comm.borrow_mut();

            wait_for_ticker(&mut comm);

            Ok(common::ux::EventCode::Ticker as u32)
        }
    }

    fn handle_show_page<E: fmt::Debug>(
        &mut self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        page_ptr: GuestPointer,
        page_len: usize,
    ) -> Result<u32, CommEcallError> {
        if page_len > MAX_UX_PAGE_LEN {
            return Err(CommEcallError::InvalidParameters("page_len is too large"));
        }

        let mut page_local: [u8; MAX_UX_PAGE_LEN] = [0; MAX_UX_PAGE_LEN];

        cpu.get_segment::<E>(page_ptr.0)?
            .read_buffer(page_ptr.0, &mut page_local[0..page_len])?;

        let page = common::ux::Page::deserialize_full(&page_local[0..page_len])
            .map_err(|_| CommEcallError::InvalidParameters("Failed to deserialize page"))?;

        self.ux_handler.show_page(&page)?;
        Ok(1)
    }

    fn handle_show_step<E: fmt::Debug>(
        &mut self,
        cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        step_ptr: GuestPointer,
        step_len: usize,
    ) -> Result<u32, CommEcallError> {
        if step_len > MAX_UX_STEP_LEN {
            return Err(CommEcallError::InvalidParameters("step_len is too large"));
        }

        let mut step_local: [u8; MAX_UX_STEP_LEN] = [0; MAX_UX_STEP_LEN];

        cpu.get_segment::<E>(step_ptr.0)?
            .read_buffer(step_ptr.0, &mut step_local[0..step_len])?;

        let step = common::ux::Step::deserialize_full(&step_local[0..step_len])
            .map_err(|_| CommEcallError::InvalidParameters("Failed to deserialize step"))?;

        self.ux_handler.show_step(&step)?;
        Ok(1)
    }

    fn handle_get_device_property<E: fmt::Debug>(
        &mut self,
        _cpu: &mut Cpu<OutsourcedMemory<'_, N>>,
        property: u32,
    ) -> Result<u32, CommEcallError> {
        match property {
            DEVICE_PROPERTY_ID => Ok(pack_u16(VENDOR_ID, PRODUCT_ID)),
            DEVICE_PROPERTY_SCREEN_SIZE => Ok(pack_u16(SCREEN_WIDTH, SCREEN_HEIGHT)),
            DEVICE_PROPERTY_FEATURES => Ok(0),
            _ => Err(CommEcallError::InvalidParameters("Unknown device property")),
        }
    }
}

// Processes all events until a ticker is received, then returns
fn wait_for_ticker<const N: usize>(comm: &mut RefMut<'_, &mut ledger_device_sdk::io::Comm<N>>) {
    loop {
        let ety = comm.try_next_event().into_type();
        if matches!(ety, DecodedEventType::Ticker) {
            return;
        }
    }
}

#[cfg(feature = "trace_ecalls")]
fn get_ecall_name(ecall_code: u32) -> String {
    match ecall_code {
        ECALL_EXIT => "exit".into(),
        ECALL_FATAL => "fatal".into(),
        ECALL_XSEND => "xsend".into(),
        ECALL_XRECV => "xrecv".into(),
        ECALL_PRINT => "print".into(),
        ECALL_GET_EVENT => "get_event".into(),
        ECALL_SHOW_PAGE => "show_page".into(),
        ECALL_SHOW_STEP => "show_step".into(),
        ECALL_GET_DEVICE_PROPERTY => "get_device_property".into(),
        ECALL_MODM => "modm".into(),
        ECALL_ADDM => "addm".into(),
        ECALL_SUBM => "subm".into(),
        ECALL_MULTM => "multm".into(),
        ECALL_POWM => "powm".into(),
        ECALL_MODINV_PRIME => "modinv_prime".into(),
        ECALL_HASH_INIT => "hash_init".into(),
        ECALL_HASH_UPDATE => "hash_update".into(),
        ECALL_HASH_DIGEST => "hash_digest".into(),
        ECALL_DERIVE_HD_NODE => "derive_hd_node".into(),
        ECALL_GET_MASTER_FINGERPRINT => "get_master_fingerprint".into(),
        ECALL_DERIVE_SLIP21_KEY => "derive_slip21_key".into(),
        ECALL_ECFP_ADD_POINT => "ecfp_add_point".into(),
        ECALL_ECFP_SCALAR_MULT => "ecfp_scalar_mult".into(),
        ECALL_GET_RANDOM_BYTES => "get_random_bytes".into(),
        ECALL_STORAGE_READ => "storage_read".into(),
        ECALL_STORAGE_WRITE => "storage_write".into(),
        ECALL_ECDSA_SIGN => "ecdsa_sign".into(),
        ECALL_ECDSA_VERIFY => "ecdsa_verify".into(),
        ECALL_SCHNORR_SIGN => "schnorr_sign".into(),
        ECALL_SCHNORR_VERIFY => "schnorr_verify".into(),
        _ => alloc::format!("unknown: {}", ecall_code),
    }
}

impl<'a, const N: usize> EcallHandler for CommEcallHandler<'a, N> {
    type Memory = OutsourcedMemory<'a, N>;
    type Error = CommEcallError;

    fn handle_ecall(
        &mut self,
        cpu: &mut Cpu<OutsourcedMemory<'a, N>>,
    ) -> Result<(), CommEcallError> {
        macro_rules! reg {
            ($reg:ident) => {
                cpu.regs[Register::$reg.as_index() as usize]
            };
        }

        macro_rules! GPreg {
            ($reg:ident) => {
                GuestPointer(cpu.regs[Register::$reg.as_index() as usize] as u32)
            };
        }

        let ecall_code = reg!(T0);

        #[cfg(feature = "trace_ecalls")]
        crate::trace!(
            "ecall",
            "light_blue",
            "code: {}",
            get_ecall_name(ecall_code)
        );

        match ecall_code {
            ECALL_EXIT => return Err(CommEcallError::Exit(reg!(A0) as i32)),
            ECALL_FATAL => {
                self.handle_panic::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("xsend failed"))?;
                return Err(CommEcallError::Panic);
            }
            ECALL_XSEND => self
                .handle_xsend::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                .map_err(|_| CommEcallError::GenericError("xsend failed"))?,
            ECALL_XRECV => {
                let ret = self
                    .handle_xrecv::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("xrecv failed"))?;
                reg!(A0) = ret as u32;
            }
            ECALL_PRINT => {
                self.handle_print::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("print failed"))?;
                reg!(A0) = 1;
            }
            ECALL_GET_EVENT => {
                reg!(A0) = self.handle_get_event::<CommEcallError>(cpu, GPreg!(A0))?;
            }

            ECALL_STORAGE_READ => {
                reg!(A0) = self.handle_storage_read::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                )?;
            }
            ECALL_STORAGE_WRITE => {
                reg!(A0) = self.handle_storage_write::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                )?;
            }

            ECALL_SHOW_PAGE => {
                self.handle_show_page::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)?;

                reg!(A0) = 1;
            }
            ECALL_SHOW_STEP => {
                self.handle_show_step::<CommEcallError>(cpu, GPreg!(A0), reg!(A1) as usize)
                    .map_err(|_| CommEcallError::GenericError("show_step failed"))?;
                reg!(A0) = 1;
            }
            ECALL_GET_DEVICE_PROPERTY => {
                reg!(A0) = self
                    .handle_get_device_property::<CommEcallError>(cpu, reg!(A0))
                    .map_err(|_| CommEcallError::GenericError("get_device_property failed"))?;
            }
            ECALL_MODM => {
                reg!(A0) = self.handle_bn_modm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;
            }
            ECALL_ADDM | ECALL_SUBM | ECALL_MULTM => {
                let op = match ecall_code {
                    ECALL_ADDM => BnBinop::Add,
                    ECALL_SUBM => BnBinop::Sub,
                    _ => BnBinop::Mul,
                };
                reg!(A0) = self.handle_bn_binop::<CommEcallError>(
                    cpu,
                    op,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;
            }
            ECALL_MODINV_PRIME => {
                reg!(A0) = self.handle_bn_modinv_prime::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    reg!(A3) as usize,
                )?;
            }
            ECALL_POWM => {
                reg!(A0) = self.handle_bn_powm::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    reg!(A3) as usize,
                    GPreg!(A4),
                    reg!(A5) as usize,
                )?;
            }
            ECALL_HASH_INIT => {
                reg!(A0) = self.handle_hash_init::<CommEcallError>(cpu, reg!(A0), GPreg!(A1))?;
            }
            ECALL_HASH_UPDATE => {
                reg!(A0) = self.handle_hash_update::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    reg!(A3) as usize,
                )?;
            }
            ECALL_HASH_DIGEST => {
                reg!(A0) = self.handle_hash_digest::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                )?;
            }

            ECALL_DERIVE_HD_NODE => {
                reg!(A0) = self.handle_derive_hd_node::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    reg!(A2) as usize,
                    GPreg!(A3),
                    GPreg!(A4),
                )?;
            }
            ECALL_GET_MASTER_FINGERPRINT => {
                reg!(A0) = self.handle_get_master_fingerprint::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                )?;
            }
            ECALL_DERIVE_SLIP21_KEY => {
                reg!(A0) = self.handle_derive_slip21_node::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    reg!(A1) as usize,
                    GPreg!(A2),
                )?;
            }

            ECALL_ECFP_ADD_POINT => {
                reg!(A0) = self.handle_ecfp_add_point::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                )?;
            }
            ECALL_ECFP_SCALAR_MULT => {
                reg!(A0) = self.handle_ecfp_scalar_mult::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;
            }

            ECALL_GET_RANDOM_BYTES => {
                reg!(A0) = self.handle_get_random_bytes::<CommEcallError>(
                    cpu,
                    GPreg!(A0),
                    reg!(A1) as usize,
                )? as u32;
            }

            ECALL_ECDSA_SIGN => {
                reg!(A0) = self.handle_ecdsa_sign::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    reg!(A1),
                    reg!(A2),
                    GPreg!(A3),
                    GPreg!(A4),
                    GPreg!(A5),
                )? as u32;
            }
            ECALL_ECDSA_VERIFY => {
                reg!(A0) = self.handle_ecdsa_verify::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    GPreg!(A1),
                    GPreg!(A2),
                    GPreg!(A3),
                    reg!(A4) as usize,
                )?;
            }
            ECALL_SCHNORR_SIGN => {
                reg!(A0) = self.handle_schnorr_sign::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    reg!(A1),
                    reg!(A2),
                    GPreg!(A3),
                    GPreg!(A4),
                    reg!(A5) as usize,
                    GPreg!(A6),
                    GPreg!(A7),
                )? as u32;
            }
            ECALL_SCHNORR_VERIFY => {
                reg!(A0) = self.handle_schnorr_verify::<CommEcallError>(
                    cpu,
                    reg!(A0),
                    reg!(A1),
                    reg!(A2),
                    GPreg!(A3),
                    GPreg!(A4),
                    reg!(A5) as usize,
                    GPreg!(A6),
                    reg!(A7) as usize,
                )?;
            }

            // Any other ecall is unhandled and will case the CPU to abort
            _ => {
                return Err(CommEcallError::UnhandledEcall);
            }
        }

        Ok(())
    }
}

impl<'a, const N: usize> Drop for CommEcallHandler<'a, N> {
    fn drop(&mut self) {
        drop_ux_handler();
    }
}
