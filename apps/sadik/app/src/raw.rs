//! Raw ECALLs, made with exactly the arguments the client chose, to test the ECALLs' own contract
//! on every target.

use alloc::{vec, vec::Vec};

use common::{RawEcall, RawEcallResult};
use sdk::ecalls;

/// Size of the largest hash context (`CTX_SHA3_SIZE`), used for every algorithm.
const MAX_HASH_CTX_SIZE: usize = 448;

fn result(status: u32, output: Vec<u8>) -> RawEcallResult {
    RawEcallResult { status, output }
}

pub fn raw_ecall(call: RawEcall) -> RawEcallResult {
    // SAFETY (for every ECALL below): each pointer is to a live buffer of at least the length that
    // the ECALL reads or writes for the given length arguments, as asserted where the client
    // provides the buffer.
    unsafe {
        match call {
            RawEcall::BnModm { n, m } => {
                let mut r = vec![0u8; n.len()];
                let status =
                    ecalls::bn_modm(r.as_mut_ptr(), n.as_ptr(), n.len(), m.as_ptr(), m.len());
                result(status, r)
            }
            RawEcall::BnAddm { a, b, m } => {
                assert!(a.len() == b.len() && a.len() == m.len());
                let mut r = vec![0u8; a.len()];
                let status =
                    ecalls::bn_addm(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), a.len());
                result(status, r)
            }
            RawEcall::BnSubm { a, b, m } => {
                assert!(a.len() == b.len() && a.len() == m.len());
                let mut r = vec![0u8; a.len()];
                let status =
                    ecalls::bn_subm(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), a.len());
                result(status, r)
            }
            RawEcall::BnMultm { a, b, m } => {
                assert!(a.len() == b.len() && a.len() == m.len());
                let mut r = vec![0u8; a.len()];
                let status =
                    ecalls::bn_multm(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), a.len());
                result(status, r)
            }
            RawEcall::BnPowm { a, e, m } => {
                assert!(a.len() == m.len());
                let mut r = vec![0u8; a.len()];
                let status = ecalls::bn_powm(
                    r.as_mut_ptr(),
                    a.as_ptr(),
                    e.as_ptr(),
                    e.len(),
                    m.as_ptr(),
                    a.len(),
                );
                result(status, r)
            }
            RawEcall::BnModinvPrime { a, p } => {
                assert!(a.len() == p.len());
                let mut r = vec![0u8; a.len()];
                let status =
                    ecalls::bn_modinv_prime(r.as_mut_ptr(), a.as_ptr(), p.as_ptr(), a.len());
                result(status, r)
            }
            RawEcall::Hash {
                hash_id,
                chunks,
                tamper,
            } => {
                let mut ctx = [0u8; MAX_HASH_CTX_SIZE];
                let status = ecalls::hash_init(hash_id, ctx.as_mut_ptr());
                if status != 1 {
                    return result(status, Vec::new());
                }
                if let Some((offset, value)) = tamper {
                    ctx[offset as usize] = value;
                }
                for chunk in chunks {
                    let status =
                        ecalls::hash_update(hash_id, ctx.as_mut_ptr(), chunk.as_ptr(), chunk.len());
                    if status != 1 {
                        return result(status, Vec::new());
                    }
                }
                let mut digest = [0u8; 64];
                let status = ecalls::hash_final(hash_id, ctx.as_mut_ptr(), digest.as_mut_ptr());
                result(status, digest.to_vec())
            }
            RawEcall::GetRandomBytes { size } => {
                let mut buffer = vec![0u8; size as usize];
                let status = ecalls::get_random_bytes(buffer.as_mut_ptr(), buffer.len());
                result(status, buffer)
            }
            RawEcall::DeriveHdNode { curve, path } => {
                let mut node = [0u8; 64];
                let (privkey, chain_code) = node.split_at_mut(32);
                let status = ecalls::derive_hd_node(
                    curve,
                    path.as_ptr(),
                    path.len(),
                    privkey.as_mut_ptr(),
                    chain_code.as_mut_ptr(),
                );
                result(status, node.to_vec())
            }
            RawEcall::GetMasterFingerprint { curve } => {
                let mut fingerprint = 0u32;
                let status = ecalls::get_master_fingerprint(curve, &mut fingerprint);
                result(status, fingerprint.to_be_bytes().to_vec())
            }
            RawEcall::DeriveSlip21Node { labels } => {
                let mut out = [0u8; 64];
                let status =
                    ecalls::derive_slip21_node(labels.as_ptr(), labels.len(), out.as_mut_ptr());
                result(status, out.to_vec())
            }
            RawEcall::EcfpAddPoint { curve, p, q } => {
                assert!(p.len() == 65 && q.len() == 65);
                let mut r = [0u8; 65];
                let status = ecalls::ecfp_add_point(curve, r.as_mut_ptr(), p.as_ptr(), q.as_ptr());
                result(status, r.to_vec())
            }
            RawEcall::EcfpScalarMult { curve, p, k } => {
                assert!(p.len() == 65);
                let mut r = [0u8; 65];
                let status = ecalls::ecfp_scalar_mult(
                    curve,
                    r.as_mut_ptr(),
                    p.as_ptr(),
                    k.as_ptr(),
                    k.len(),
                );
                result(status, r.to_vec())
            }
            RawEcall::EcdsaSign {
                curve,
                mode,
                hash_id,
                privkey,
                msg_hash,
            } => {
                assert!(privkey.len() == 32 && msg_hash.len() == 32);
                let mut signature = [0u8; 72];
                let len = ecalls::ecdsa_sign(
                    curve,
                    mode,
                    hash_id,
                    privkey.as_ptr(),
                    msg_hash.as_ptr(),
                    signature.as_mut_ptr(),
                );
                result(len as u32, signature[..len.min(72)].to_vec())
            }
            RawEcall::EcdsaVerify {
                curve,
                pubkey,
                msg_hash,
                signature,
            } => {
                assert!(pubkey.len() == 65 && msg_hash.len() == 32);
                let status = ecalls::ecdsa_verify(
                    curve,
                    pubkey.as_ptr(),
                    msg_hash.as_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                );
                result(status, Vec::new())
            }
            RawEcall::SchnorrSign {
                curve,
                mode,
                hash_id,
                privkey,
                msg,
                entropy,
            } => {
                assert!(privkey.len() == 32);
                let mut signature = [0u8; 64];
                let entropy_ptr = match &entropy {
                    Some(e) => e as *const [u8; 32],
                    None => core::ptr::null(),
                };
                let len = ecalls::schnorr_sign(
                    curve,
                    mode,
                    hash_id,
                    privkey.as_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    signature.as_mut_ptr(),
                    entropy_ptr,
                );
                result(len as u32, signature[..len.min(64)].to_vec())
            }
            RawEcall::SchnorrVerify {
                curve,
                mode,
                hash_id,
                pubkey,
                msg,
                signature,
            } => {
                assert!(pubkey.len() == 32);
                let status = ecalls::schnorr_verify(
                    curve,
                    mode,
                    hash_id,
                    pubkey.as_ptr(),
                    msg.as_ptr(),
                    msg.len(),
                    signature.as_ptr(),
                    signature.len(),
                );
                result(status, Vec::new())
            }
        }
    }
}
