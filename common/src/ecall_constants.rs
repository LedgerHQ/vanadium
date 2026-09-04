pub const ECALL_FATAL: u32 = 1;
pub const ECALL_XSEND: u32 = 2;
pub const ECALL_XRECV: u32 = 3;
pub const ECALL_EXIT: u32 = 4;
pub const ECALL_PRINT: u32 = 5;

// device handling, events, and UX

pub const ECALL_GET_EVENT: u32 = 10;
pub const ECALL_GET_DEVICE_PROPERTY: u32 = 15;

// Constants used for GET_DEVICE_PROPERTY

// device id (vendor_id: u16, product_id: u16)
pub const DEVICE_PROPERTY_ID: u32 = 0x01;
// (screen_width: u16, screen_height: u16)
pub const DEVICE_PROPERTY_SCREEN_SIZE: u32 = 0x02;
// bitmask of device features (to be defined)
pub const DEVICE_PROPERTY_FEATURES: u32 = 0x03;

// Persistent storage
pub const ECALL_STORAGE_READ: u32 = 20;
pub const ECALL_STORAGE_WRITE: u32 = 21;

// Big numbers
pub const ECALL_MODM: u32 = 110;
pub const ECALL_ADDM: u32 = 111;
pub const ECALL_SUBM: u32 = 112;
pub const ECALL_MULTM: u32 = 113;
pub const ECALL_POWM: u32 = 114;
pub const ECALL_MODINV_PRIME: u32 = 115;

/// Maximum size, in bytes, of a big number operand accepted by the modular arithmetic ECALLs
/// (`bn_modm`, `bn_addm`, `bn_subm`, `bn_multm`, `bn_powm`, `bn_modinv_prime`).
pub const MAX_BIGNUMBER_SIZE: usize = 512;

/// The elliptic curves the ECALL interface knows about.
///
/// The discriminants match the Ledger SDK's `cx_curve_e` constants, so that a `curve` ECALL
/// argument can be passed straight through as the `curve` field of a `cx_ecfp_*_key_t`.
///
/// Not every curve is accepted by every curve ECALL: secp256k1 is the only one with private-key
/// operations (see [`CurveKind::supports_private_key_ops`]), since it is the only one the VM
/// derives from the seed. The others are verification-only.
// TODO: IDs for now are matching the ones in the ledger SDK
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum CurveKind {
    Secp256k1 = 0x21,
    Secp256r1 = 0x22,
    Secp384r1 = 0x23,
}

impl CurveKind {
    /// Parses the `curve` argument of an ECALL, returning `None` if it names no known curve.
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x21 => Some(CurveKind::Secp256k1),
            0x22 => Some(CurveKind::Secp256r1),
            0x23 => Some(CurveKind::Secp384r1),
            _ => None,
        }
    }

    /// Length in bytes of a scalar (a private key, or one point coordinate) on this curve.
    pub const fn scalar_len(self) -> usize {
        match self {
            CurveKind::Secp256k1 | CurveKind::Secp256r1 => 32,
            CurveKind::Secp384r1 => 48,
        }
    }

    /// Length in bytes of a point in uncompressed SEC1 form (`0x04 || X || Y`), which is how
    /// points are passed to and from the curve ECALLs.
    pub const fn point_len(self) -> usize {
        1 + 2 * self.scalar_len()
    }

    /// Maximum length in bytes of a DER-encoded ECDSA signature on this curve.
    ///
    /// A `SEQUENCE` of two `INTEGER`s, each at worst `scalar_len + 1` bytes of content (a leading
    /// zero byte when the high bit is set) plus a 2-byte tag-and-length, inside a 2-byte
    /// tag-and-length: `2 + 2 * (2 + scalar_len + 1)`.
    pub const fn max_der_signature_len(self) -> usize {
        2 + 2 * (3 + self.scalar_len())
    }

    /// Whether the VM will perform private-key operations on this curve: signing, HD derivation
    /// from the seed, and the master key fingerprint.
    ///
    /// Only secp256k1 qualifies. The other curves exist so that a V-App can *verify* signatures
    /// made elsewhere, which needs no access to the device's seed.
    pub const fn supports_private_key_ops(self) -> bool {
        matches!(self, CurveKind::Secp256k1)
    }
}

/// Largest [`CurveKind::point_len`] over all supported curves, for sizing buffers that must hold
/// a point on any of them.
pub const MAX_CURVE_POINT_SIZE: usize = CurveKind::Secp384r1.point_len();

/// Largest [`CurveKind::max_der_signature_len`] over all supported curves.
pub const MAX_DER_SIGNATURE_SIZE: usize = CurveKind::Secp384r1.max_der_signature_len();

// TODO: IDs for now are matching the ones in the ledger SDK
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum HashId {
    Ripemd160 = 1,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Keccak = 6,
    Sha3 = 7,
}

impl HashId {
    /// Returns the composite ECALL hash_id passed to hash_init / hash_update / hash_final.
    ///
    /// Layout (32 bits):
    ///   - bits 31-24: always 0 (reserved for future extensibility)
    ///   - bits 23-16: algorithm identifier (u8, matches the Ledger SDK hash type constants)
    ///   - bits 15-0:  output size in bytes, supplied by the caller
    ///
    /// Casting through `u8` enforces that the algorithm identifier always fits in a single byte,
    /// keeping the high 8 bits of the hash_id parameter free for future use.
    /// The output size is passed explicitly rather than being derived from `self` so that
    /// one algorithm identifier can support multiple output lengths.
    /// Note that only certain output sizes might be valid for each algorithm.
    pub const fn ecall_id(self, output_size: u16) -> u32 {
        ((self as u8 as u32) << 16) | (output_size as u32)
    }
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
pub const ECALL_DERIVE_SLIP21_KEY: u32 = 132;

// Hash functions
pub const ECALL_HASH_INIT: u32 = 150;
pub const ECALL_HASH_UPDATE: u32 = 151;
pub const ECALL_HASH_DIGEST: u32 = 152;

/// Size in bytes of the hash context structs used by the hash ecalls.
///
/// These are the sizes of the opaque context buffers passed to `hash_init`,
/// `hash_update`, and `hash_final`. Each context must be at least this large.
/// The sizes are at least 16 bytes larger than what the Ledger OS uses, in
/// order to have some leeway for different targets where the struct might
/// be larger.
pub const CTX_SHA256_SIZE: usize = 128;
pub const CTX_SHA512_SIZE: usize = 224;
// SHA-384 shares the same context structure as SHA-512 in the Ledger C SDK.
pub const CTX_SHA384_SIZE: usize = CTX_SHA512_SIZE;
pub const CTX_RIPEMD160_SIZE: usize = 120;
// Keccak and SHA-3 share the same internal Keccak-f[1600] state (cx_sha3_t on Ledger, ~200 bytes
// of rate buffer + 25×u64 state). 448 bytes gives comfortable headroom above the 424-byte
// cx_sha3_t and the RustCrypto sha3 context structs.
pub const CTX_SHA3_SIZE: usize = 448;

// Operations for public keys over elliptic curves
pub const ECALL_ECFP_ADD_POINT: u32 = 160;
pub const ECALL_ECFP_SCALAR_MULT: u32 = 161;

// Random number generation
pub const ECALL_GET_RANDOM_BYTES: u32 = 170;

// Signatures
pub const ECALL_ECDSA_SIGN: u32 = 180;
pub const ECALL_ECDSA_VERIFY: u32 = 181;
pub const ECALL_SCHNORR_SIGN: u32 = 182;
pub const ECALL_SCHNORR_VERIFY: u32 = 183;

/// =======================================
/// Device-specific ECALLs
/// =======================================
/// The range 192..255 is reserved for vendor-specific ECALLs
/// Different implementation of Vanadium can assign different meaning to these ECALLs.
/// The following ECALLs are defined for Ledger devices.

pub const ECALL_SHOW_PAGE: u32 = 192; // Flex / Stax / Apex_P
pub const ECALL_SHOW_STEP: u32 = 193; // Nano X / Nano S+

#[cfg(test)]
mod tests {
    use super::*;

    /// The buffer sizes these helpers compute used to be hardcoded in the ECALL handlers, so
    /// secp256k1 must keep producing exactly the values that were written there by hand.
    #[test]
    fn secp256k1_sizes_match_the_previously_hardcoded_ones() {
        assert_eq!(CurveKind::Secp256k1.scalar_len(), 32);
        assert_eq!(CurveKind::Secp256k1.point_len(), 65);
        assert_eq!(CurveKind::Secp256k1.max_der_signature_len(), 72);
    }

    #[test]
    fn secp384r1_sizes() {
        assert_eq!(CurveKind::Secp384r1.scalar_len(), 48);
        assert_eq!(CurveKind::Secp384r1.point_len(), 97);
        assert_eq!(CurveKind::Secp384r1.max_der_signature_len(), 104);
    }

    #[test]
    fn maxima_cover_every_curve() {
        for curve in [
            CurveKind::Secp256k1,
            CurveKind::Secp256r1,
            CurveKind::Secp384r1,
        ] {
            assert!(curve.point_len() <= MAX_CURVE_POINT_SIZE);
            assert!(curve.max_der_signature_len() <= MAX_DER_SIGNATURE_SIZE);
        }
        assert_eq!(MAX_CURVE_POINT_SIZE, 97);
        assert_eq!(MAX_DER_SIGNATURE_SIZE, 104);
    }

    /// The discriminants are the Ledger SDK's `CX_CURVE_*` values; the VM relies on that by
    /// passing the ECALL argument through as `curve as u8`.
    #[test]
    fn discriminants_match_the_ledger_sdk() {
        assert_eq!(CurveKind::Secp256k1 as u32, 0x21);
        assert_eq!(CurveKind::Secp256r1 as u32, 0x22);
        assert_eq!(CurveKind::Secp384r1 as u32, 0x23);
    }

    #[test]
    fn from_u32_round_trips_and_rejects_unknown_curves() {
        for curve in [
            CurveKind::Secp256k1,
            CurveKind::Secp256r1,
            CurveKind::Secp384r1,
        ] {
            assert_eq!(CurveKind::from_u32(curve as u32), Some(curve));
        }
        // 0x24 is CX_CURVE_BLS12_381_G1 in the SDK, which the VM does not implement.
        for unknown in [0u32, 0x20, 0x24, 0x30, u32::MAX] {
            assert_eq!(CurveKind::from_u32(unknown), None);
        }
    }

    #[test]
    fn only_secp256k1_has_private_key_ops() {
        assert!(CurveKind::Secp256k1.supports_private_key_ops());
        assert!(!CurveKind::Secp256r1.supports_private_key_ops());
        assert!(!CurveKind::Secp384r1.supports_private_key_ops());
    }
}
