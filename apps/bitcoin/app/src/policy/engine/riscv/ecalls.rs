//! The ecall handler: how a policy program reads the transaction.
//!
//! Every buffer crossing the sandbox boundary is copied through
//! `MemorySegment::{read,write}_buffer`, which bounds-checks it against the segment
//! that contains it and rejects anything straddling two segments. Output buffers
//! always carry an explicit capacity, and a call that would exceed it fails rather
//! than truncating.

use alloc::vec::Vec;
use core::fmt;

use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::{TapLeafHash, TapNodeHash, XOnlyPublicKey};
use vanadium_common::vm::{Cpu, CpuError, EcallHandler, MemoryError, PagedMemory};

use crate::policy::{host::PolicyHost, SigningDecision};

use super::abi;

/// Register indices used by the ABI.
mod reg {
    pub const T0: usize = 5;
    pub const A0: usize = 10;
    pub const A1: usize = 11;
    pub const A2: usize = 12;
    pub const A3: usize = 13;
    pub const A4: usize = 14;
}

/// Signals that leave the interpreter loop.
pub enum PolicyEcallError {
    /// The program called `EXIT`.
    Exit(SigningDecision),
    /// Anything else: `PANIC`, an unknown ecall, bad arguments, a bad buffer, or an
    /// out-of-range decision value.
    Failed,
}

impl fmt::Debug for PolicyEcallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately terse: `Cpu`'s own Debug impl pulls in `alloc::format!`, and
        // this type is only ever formatted in tests.
        match self {
            PolicyEcallError::Exit(_) => f.write_str("Exit"),
            PolicyEcallError::Failed => f.write_str("Failed"),
        }
    }
}

impl From<MemoryError> for PolicyEcallError {
    fn from(_: MemoryError) -> Self {
        PolicyEcallError::Failed
    }
}

impl From<CpuError<PolicyEcallError>> for PolicyEcallError {
    fn from(err: CpuError<PolicyEcallError>) -> Self {
        match err {
            // `Exit` must survive being funnelled through a memory-access helper,
            // or a program exiting from inside one would look like a trap.
            CpuError::EcallError(e) => e,
            _ => PolicyEcallError::Failed,
        }
    }
}

type EcallResult = Result<(), PolicyEcallError>;

pub struct PolicyEcallHandler<'h, M: PagedMemory> {
    host: &'h mut dyn PolicyHost,
    /// Index of the attempt this invocation is for; `None` on the final call.
    attempt_index: Option<u32>,
    _memory: core::marker::PhantomData<M>,
}

impl<'h, M: PagedMemory> PolicyEcallHandler<'h, M> {
    pub fn new(host: &'h mut dyn PolicyHost, attempt_index: Option<u32>) -> Self {
        Self {
            host,
            attempt_index,
            _memory: core::marker::PhantomData,
        }
    }
}

/// Copy `data` into sandbox memory at `ptr`, refusing if it does not fit `capacity`.
fn write_out<M: PagedMemory>(
    cpu: &mut Cpu<'_, M>,
    ptr: u32,
    capacity: usize,
    data: &[u8],
) -> Result<(), PolicyEcallError> {
    if data.len() > capacity {
        return Err(PolicyEcallError::Failed);
    }
    cpu.get_segment::<PolicyEcallError>(ptr)?
        .write_buffer(ptr, data)?;
    Ok(())
}

/// Read exactly `len` bytes from sandbox memory, capped so that a policy cannot make
/// the app allocate without bound.
fn read_in<M: PagedMemory>(
    cpu: &mut Cpu<'_, M>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, PolicyEcallError> {
    // The cap applies to a single call; a program that needs more must use the
    // streaming hash calls (not in ABI v0) or hash in chunks itself.
    if len as usize > abi::MAX_ECALL_BUFFER {
        return Err(PolicyEcallError::Failed);
    }
    let mut buf = alloc::vec![0u8; len as usize];
    if len > 0 {
        cpu.get_segment::<PolicyEcallError>(ptr)?
            .read_buffer(ptr, &mut buf)?;
    }
    Ok(buf)
}

fn read_array<const N: usize, M: PagedMemory>(
    cpu: &mut Cpu<'_, M>,
    ptr: u32,
) -> Result<[u8; N], PolicyEcallError> {
    let mut buf = [0u8; N];
    cpu.get_segment::<PolicyEcallError>(ptr)?
        .read_buffer(ptr, &mut buf)?;
    Ok(buf)
}

impl<'h, M: PagedMemory> EcallHandler for PolicyEcallHandler<'h, M> {
    type Memory = M;
    type Error = PolicyEcallError;

    fn handle_ecall(&mut self, cpu: &mut Cpu<'_, M>) -> EcallResult {
        let code = cpu.regs[reg::T0];
        let a0 = cpu.regs[reg::A0];
        let a1 = cpu.regs[reg::A1];
        let a2 = cpu.regs[reg::A2];
        let a3 = cpu.regs[reg::A3];
        let a4 = cpu.regs[reg::A4];

        // Set the return value. Nothing after this may fail, or a partially
        // completed call could report success.
        macro_rules! ret {
            ($v:expr) => {{
                cpu.regs[reg::A0] = $v;
                return Ok(());
            }};
        }

        /// Resolve an `Option` from the host: `None` means the index was out of
        /// range, which is fatal.
        macro_rules! in_range {
            ($e:expr) => {
                match $e {
                    Some(v) => v,
                    None => return Err(PolicyEcallError::Failed),
                }
            };
        }

        match code {
            abi::EXIT => {
                let decision =
                    SigningDecision::from_u32(a0).ok_or(PolicyEcallError::Failed)?;
                Err(PolicyEcallError::Exit(decision))
            }
            abi::PANIC => Err(PolicyEcallError::Failed),
            abi::LOG => {
                // A no-op on device, so that one image runs unmodified in tests and
                // on hardware. The pointer is not even dereferenced.
                let _ = (a0, a1);
                ret!(abi::OK)
            }

            abi::TX_VERSION => ret!(self.host.tx_version()),
            abi::LOCKTIME => ret!(self.host.locktime()),
            abi::INPUT_COUNT => ret!(self.host.input_count()),
            abi::OUTPUT_COUNT => ret!(self.host.output_count()),
            abi::FEE => {
                let fee = self.host.fee();
                write_out(cpu, a0, 8, &fee.to_le_bytes())?;
                ret!(abi::OK)
            }
            abi::TOTALS => {
                let mut buf = [0u8; 16];
                buf[..8].copy_from_slice(&self.host.inputs_total().to_le_bytes());
                buf[8..].copy_from_slice(&self.host.outputs_total().to_le_bytes());
                write_out(cpu, a0, 16, &buf)?;
                ret!(abi::OK)
            }

            abi::SELF_PUBKEY => {
                // Attempt-dependent, so meaningless on the final call.
                let k = self.attempt_index.ok_or(PolicyEcallError::Failed)?;
                let pk = in_range!(self.host.self_pubkey(k));
                write_out(cpu, a0, 33, &pk)?;
                ret!(abi::OK)
            }
            abi::SELF_POLICY_HASH => {
                let hash = self.host.policy_hash();
                write_out(cpu, a0, 32, &hash)?;
                ret!(abi::OK)
            }

            abi::INPUT_AMOUNT => {
                let amount = in_range!(self.host.input_amount(a0));
                write_out(cpu, a1, 8, &amount.to_le_bytes())?;
                ret!(abi::OK)
            }
            abi::INPUT_PREVOUT => {
                let prevout = in_range!(self.host.input_prevout(a0));
                write_out(cpu, a1, 36, &prevout)?;
                ret!(abi::OK)
            }
            abi::INPUT_SEQUENCE => {
                let seq = in_range!(self.host.input_sequence(a0));
                ret!(seq)
            }
            abi::INPUT_SCRIPT_PUBKEY => {
                let spk = in_range!(self.host.input_script_pubkey(a0));
                let len = spk.len();
                if len > a2 as usize {
                    return Err(PolicyEcallError::Failed);
                }
                // Copy through a bounce buffer: `spk` borrows the host, and writing
                // needs the cpu, so the two borrows must not overlap.
                let mut buf = [0u8; abi::MAX_ECALL_BUFFER];
                if len > abi::MAX_ECALL_BUFFER {
                    return Err(PolicyEcallError::Failed);
                }
                buf[..len].copy_from_slice(spk);
                write_out(cpu, a1, a2 as usize, &buf[..len])?;
                ret!(len as u32)
            }
            abi::INPUT_FLAGS => {
                let flags = in_range!(self.host.input_flags(a0));
                ret!(flags)
            }
            abi::INPUT_ACCOUNT => {
                match in_range!(self.host.input_account(a0)) {
                    None => ret!(abi::NOT_FOUND),
                    Some(coords) => {
                        write_out(cpu, a1, 12, &encode_coords(&coords))?;
                        ret!(abi::OK)
                    }
                }
            }
            abi::INPUT_TAPTREE_HASH => {
                match in_range!(self.host.input_taptree_hash(a0)) {
                    None => ret!(abi::NOT_FOUND),
                    Some(hash) => {
                        write_out(cpu, a1, 32, &hash)?;
                        ret!(abi::OK)
                    }
                }
            }
            abi::ATTEMPT_INPUT => {
                let attempts = self.host.attempts();
                let attempt = attempts
                    .get(a0 as usize)
                    .ok_or(PolicyEcallError::Failed)?;
                ret!(attempt.input_index)
            }

            abi::OUTPUT_AMOUNT => {
                let amount = in_range!(self.host.output_amount(a0));
                write_out(cpu, a1, 8, &amount.to_le_bytes())?;
                ret!(abi::OK)
            }
            abi::OUTPUT_SCRIPT_PUBKEY => {
                let spk = in_range!(self.host.output_script_pubkey(a0));
                let len = spk.len();
                if len > a2 as usize || len > abi::MAX_ECALL_BUFFER {
                    return Err(PolicyEcallError::Failed);
                }
                let mut buf = [0u8; abi::MAX_ECALL_BUFFER];
                buf[..len].copy_from_slice(spk);
                write_out(cpu, a1, a2 as usize, &buf[..len])?;
                ret!(len as u32)
            }
            abi::OUTPUT_FLAGS => {
                let flags = in_range!(self.host.output_flags(a0));
                ret!(flags)
            }
            abi::OUTPUT_ACCOUNT => {
                match in_range!(self.host.output_account(a0)) {
                    None => ret!(abi::NOT_FOUND),
                    Some(coords) => {
                        write_out(cpu, a1, 12, &encode_coords(&coords))?;
                        ret!(abi::OK)
                    }
                }
            }

            abi::PSBT_LEN => ret!(self.host.raw_psbt().len() as u32),
            abi::PSBT_READ => {
                let raw = self.host.raw_psbt();
                let offset = a0 as usize;
                let len = (a2 as usize).min(abi::MAX_ECALL_BUFFER);
                let available = raw.len().saturating_sub(offset);
                let n = len.min(available);
                let mut buf = [0u8; abi::MAX_ECALL_BUFFER];
                buf[..n].copy_from_slice(&raw[offset..offset + n]);
                write_out(cpu, a1, len, &buf[..n])?;
                ret!(n as u32)
            }

            abi::SHA256 => {
                let data = read_in(cpu, a0, a1)?;
                let digest = bitcoin::hashes::sha256::Hash::hash(&data).to_byte_array();
                write_out(cpu, a2, 32, &digest)?;
                ret!(abi::OK)
            }
            abi::RIPEMD160 => {
                let data = read_in(cpu, a0, a1)?;
                let digest = bitcoin::hashes::ripemd160::Hash::hash(&data).to_byte_array();
                write_out(cpu, a2, 20, &digest)?;
                ret!(abi::OK)
            }
            abi::TAGGED_HASH => {
                use bitcoin::hashes::{sha256, HashEngine};
                let tag = read_in(cpu, a0, a1)?;
                let msg = read_in(cpu, a2, a3)?;
                let tag_hash = sha256::Hash::hash(&tag);
                let mut engine = sha256::Hash::engine();
                engine.input(tag_hash.as_byte_array());
                engine.input(tag_hash.as_byte_array());
                engine.input(&msg);
                let digest = sha256::Hash::from_engine(engine).to_byte_array();
                write_out(cpu, a4, 32, &digest)?;
                ret!(abi::OK)
            }
            abi::TAPLEAF_HASH => {
                let script = read_in(cpu, a1, a2)?;
                let version = bitcoin::taproot::LeafVersion::from_consensus(a0 as u8)
                    .map_err(|_| PolicyEcallError::Failed)?;
                let script = bitcoin::ScriptBuf::from_bytes(script);
                let hash = TapLeafHash::from_script(&script, version).to_byte_array();
                write_out(cpu, a3, 32, &hash)?;
                ret!(abi::OK)
            }
            abi::TAPBRANCH_HASH => {
                let a: [u8; 32] = read_array(cpu, a0)?;
                let b: [u8; 32] = read_array(cpu, a1)?;
                let a = TapNodeHash::from_byte_array(a);
                let b = TapNodeHash::from_byte_array(b);
                // from_node_hashes sorts its arguments, as BIP-341 requires.
                let hash = TapNodeHash::from_node_hashes(a, b).to_byte_array();
                write_out(cpu, a2, 32, &hash)?;
                ret!(abi::OK)
            }
            abi::TAPTWEAK_PUBKEY => {
                let xonly: [u8; 32] = read_array(cpu, a0)?;
                let internal: UntweakedPublicKey =
                    XOnlyPublicKey::from_slice(&xonly).map_err(|_| PolicyEcallError::Failed)?;
                let merkle_root = if a1 == 0 {
                    None
                } else {
                    let root: [u8; 32] = read_array(cpu, a1)?;
                    Some(TapNodeHash::from_byte_array(root))
                };
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let (tweaked, parity) = internal.tap_tweak(&secp, merkle_root);
                write_out(cpu, a2, 32, &tweaked.serialize())?;
                ret!(parity as u32)
            }
            abi::XONLY_ADD_TWEAK => {
                let xonly: [u8; 32] = read_array(cpu, a0)?;
                let tweak_bytes: [u8; 32] = read_array(cpu, a1)?;
                let key =
                    XOnlyPublicKey::from_slice(&xonly).map_err(|_| PolicyEcallError::Failed)?;
                let tweak = bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes)
                    .map_err(|_| PolicyEcallError::Failed)?;
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let (tweaked, parity) = key
                    .add_tweak(&secp, &tweak)
                    .map_err(|_| PolicyEcallError::Failed)?;
                write_out(cpu, a2, 32, &tweaked.serialize())?;
                ret!(parity as u32)
            }
            abi::SCHNORR_VERIFY => {
                let xonly: [u8; 32] = read_array(cpu, a0)?;
                let msg = read_in(cpu, a1, a2)?;
                let sig: [u8; 64] = read_array(cpu, a3)?;
                // BIP-340 x-only keys denote the even-Y lift, so prepend 0x02.
                let mut compressed = [0u8; 33];
                compressed[0] = 0x02;
                compressed[1..].copy_from_slice(&xonly);
                let ok = sdk::curve::EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(
                    &compressed,
                )
                .map(|pk| pk.schnorr_verify(&msg, &sig).is_ok())
                .unwrap_or(false);
                ret!(ok as u32)
            }

            _ => Err(PolicyEcallError::Failed),
        }
    }
}

fn encode_coords(coords: &crate::policy::PolicyCoords) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&coords.account_index.to_le_bytes());
    buf[4..8].copy_from_slice(&(coords.is_change as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&coords.address_index.to_le_bytes());
    buf
}
