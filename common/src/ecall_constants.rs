pub const ECALL_FATAL: u32 = 1;
pub const ECALL_XSEND: u32 = 2;
pub const ECALL_XRECV: u32 = 3;
pub const ECALL_EXIT: u32 = 4;
pub const ECALL_UX_IDLE: u32 = 12;

// Big numbers
pub const ECALL_MODM: u32 = 110;
pub const ECALL_ADDM: u32 = 111;
pub const ECALL_SUBM: u32 = 112;
pub const ECALL_MULTM: u32 = 113;
pub const ECALL_POWM: u32 = 114;

pub const MAX_BIGNUMBER_SIZE: usize = 64;

// HD derivations
pub enum CurveKind {
    Secp256k1 = 0x21,
}

// TODO: IDs for now are matching the ones in the ledger SDK
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum HashId {
    Ripemd160 = 1,
    Sha256 = 3,
    Sha512 = 5,
}

// TODO: signing modes for now are matching the ones in the ledger SDK
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum EcdsaSignMode {
    RFC6979 = (3 << 9),
}

// TODO: signing modes for now are matching the ones in the ledger SDK
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum SchnorrSignMode {
    BIP340 = 0,
}

pub const ECALL_DERIVE_HD_NODE: u32 = 130;
pub const ECALL_GET_MASTER_FINGERPRINT: u32 = 131;

// Hash functions
pub const ECALL_HASH_INIT: u32 = 150;
pub const ECALL_HASH_UPDATE: u32 = 151;
pub const ECALL_HASH_DIGEST: u32 = 152;

// Operations for public keys over elliptic curves
pub const ECALL_ECFP_ADD_POINT: u32 = 160;
pub const ECALL_ECFP_SCALAR_MULT: u32 = 161;

pub const ECALL_ECDSA_SIGN: u32 = 180;
pub const ECALL_ECDSA_VERIFY: u32 = 181;
pub const ECALL_SCHNORR_SIGN: u32 = 182;
pub const ECALL_SCHNORR_VERIFY: u32 = 183;
