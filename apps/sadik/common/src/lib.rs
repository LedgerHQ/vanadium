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
