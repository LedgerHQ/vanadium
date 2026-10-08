#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum BigIntOperator {
    Add,
    Sub,
    Mul,
    Pow,
    Inv,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ECPointOperation {
    Add(Vec<u8>, Vec<u8>),
    ScalarMult(Vec<u8>, Vec<u8>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Curve {
    Secp256k1,
}

/// A single ECALL, made with exactly the given arguments and bypassing the SDK's wrappers, to test
/// the ECALL's own contract. The V-App allocates the output buffers, sized as each ECALL requires.
///
/// Lengths that the ECALL takes as a parameter are the lengths of the vectors, so a test can pass
/// any length while every pointer stays valid.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum RawEcall {
    /// `bn_modm(r, n, n.len(), m, m.len())`
    BnModm { n: Vec<u8>, m: Vec<u8> },
    /// `bn_addm(r, a, b, m, len)`; `a`, `b` and `m` must have the same length
    BnAddm { a: Vec<u8>, b: Vec<u8>, m: Vec<u8> },
    /// `bn_subm(r, a, b, m, len)`; `a`, `b` and `m` must have the same length
    BnSubm { a: Vec<u8>, b: Vec<u8>, m: Vec<u8> },
    /// `bn_multm(r, a, b, m, len)`; `a`, `b` and `m` must have the same length
    BnMultm { a: Vec<u8>, b: Vec<u8>, m: Vec<u8> },
    /// `bn_powm(r, a, e, e.len(), m, len)`; `a` and `m` must have the same length
    BnPowm { a: Vec<u8>, e: Vec<u8>, m: Vec<u8> },
    /// `bn_modinv_prime(r, a, p, len)`; `a` and `p` must have the same length
    BnModinvPrime { a: Vec<u8>, p: Vec<u8> },
    /// `hash_init`, then `hash_update` with each chunk, then `hash_final` into a 64-byte buffer.
    /// If `tamper` is `Some((offset, value))`, the context byte at `offset` is overwritten after
    /// `hash_init`. Stops at the first call that does not return 1.
    Hash {
        hash_id: u32,
        chunks: Vec<Vec<u8>>,
        tamper: Option<(u32, u8)>,
    },
    /// `get_random_bytes(buffer, size)`
    GetRandomBytes { size: u32 },
    /// `derive_hd_node(curve, path, path.len(), privkey, chain_code)`; output `privkey || chain_code`
    DeriveHdNode { curve: u32, path: Vec<u32> },
    /// `get_master_fingerprint(curve, fingerprint)`; output the fingerprint, big-endian
    GetMasterFingerprint { curve: u32 },
    /// `derive_slip21_node(labels, labels.len(), out)` with the raw length-prefixed labels buffer
    DeriveSlip21Node { labels: Vec<u8> },
    /// `ecfp_add_point(curve, r, p, q)`; `p` and `q` must be 65 bytes
    EcfpAddPoint { curve: u32, p: Vec<u8>, q: Vec<u8> },
    /// `ecfp_scalar_mult(curve, r, p, k, k.len())`; `p` must be 65 bytes
    EcfpScalarMult { curve: u32, p: Vec<u8>, k: Vec<u8> },
    /// `ecdsa_sign(curve, mode, hash_id, privkey, msg_hash, signature)`; `privkey` and `msg_hash`
    /// must be 32 bytes; output the signature, whose length is the status
    EcdsaSign {
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: Vec<u8>,
        msg_hash: Vec<u8>,
    },
    /// `ecdsa_verify(curve, pubkey, msg_hash, signature, signature.len())`; `pubkey` must be 65
    /// bytes and `msg_hash` 32
    EcdsaVerify {
        curve: u32,
        pubkey: Vec<u8>,
        msg_hash: Vec<u8>,
        signature: Vec<u8>,
    },
    /// `schnorr_sign(curve, mode, hash_id, privkey, msg, msg.len(), signature, entropy)`;
    /// `privkey` must be 32 bytes; output the signature, whose length is the status
    SchnorrSign {
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: Vec<u8>,
        msg: Vec<u8>,
        entropy: Option<[u8; 32]>,
    },
    /// `schnorr_verify(curve, mode, hash_id, pubkey, msg, msg.len(), signature, signature.len())`;
    /// `pubkey` must be 32 bytes
    SchnorrVerify {
        curve: u32,
        mode: u32,
        hash_id: u32,
        pubkey: Vec<u8>,
        msg: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// What a [`RawEcall`] returned: the ECALL's return value, and the content of its output buffer.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct RawEcallResult {
    pub status: u32,
    pub output: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    BigIntOperation {
        operator: BigIntOperator,
        a: Vec<u8>,
        b: Vec<u8>,
        modular: bool, // if false, not modular; otherwise, modulo the curve order of Secp256k1
    },
    Hash {
        hash_id: u32,
        msg: Vec<u8>,
    },
    GetMasterFingerprint {
        curve: Curve,
    },
    DeriveHdNode {
        curve: Curve,
        path: Vec<u32>,
    },
    DeriveSlip21Key {
        labels: Vec<Vec<u8>>,
    },
    ECPointOperation {
        curve: Curve,
        operation: ECPointOperation,
    },
    EcdsaSign {
        curve: Curve,
        privkey: Vec<u8>,
        msg_hash: Vec<u8>,
    },
    EcdsaVerify {
        curve: Curve,
        msg_hash: Vec<u8>,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    },
    SchnorrSign {
        curve: Curve,
        privkey: Vec<u8>,
        msg: Vec<u8>,
    },
    SchnorrVerify {
        curve: Curve,
        pubkey: Vec<u8>,
        msg: Vec<u8>,
        signature: Vec<u8>,
    },
    Sleep {
        n_ticks: u32,
    },
    WriteStorage {
        slot: u32,
        data: Vec<u8>,
    },
    ReadStorage {
        slot: u32,
    },
    RawEcall(RawEcall),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashId {
    Ripemd160 = 1,
    Sha256 = 3,
    Sha512 = 5,
}

impl TryFrom<u32> for HashId {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HashId::Ripemd160),
            3 => Ok(HashId::Sha256),
            5 => Ok(HashId::Sha512),
            _ => Err(()),
        }
    }
}
impl From<HashId> for u32 {
    fn from(hash_id: HashId) -> Self {
        hash_id as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_command_serde() {
        let cmd = Command::Hash {
            hash_id: 1,
            msg: vec![1, 2, 3],
        };

        let serialized = postcard::to_allocvec(&cmd).expect("Serialization failed");
        let deserialized: Command =
            postcard::from_bytes(&serialized).expect("Deserialization failed");

        assert_eq!(cmd, deserialized);
    }
}
