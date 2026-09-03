//! RSA signatures (RSASSA-PKCS1-v1_5), implemented in the SDK on top of the big-number
//! modular-arithmetic ECALLs and the hash ECALLs.
//!
//! This module implements the `RSASSA-PKCS1-v1_5` signature scheme from
//! [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) (PKCS #1 v2.2), for moduli up to
//! [`MAX_BIGNUMBER_SIZE`] bytes (4096 bits). Both signing (private-key) and verification
//! (public-key) are provided.
//!
//! The core RSA primitive `x^k mod n` is delegated to the `bn_powm` ECALL, so it runs at
//! native speed; only the PKCS#1 v1.5 padding is performed in Rust.
//!
//! # Padding scheme
//!
//! Only `EMSA-PKCS1-v1_5` encoding is implemented. RSASSA-PSS is intentionally not provided:
//! it is not needed by the main motivating use case (verifying DNSSEC signatures, which use
//! `RSASSA-PKCS1-v1_5` exclusively — see RFC 3110 and RFC 5702), and can be added later if
//! required.
//!
//! # Keys
//!
//! Private keys are represented in their plain `(n, d)` form (modulus and private exponent);
//! CRT parameters are not used. Since the modular exponentiation is done by the native
//! `bn_powm`, a single full-width exponentiation is already fast.
//!
//! Moduli and exponents are raw, unsigned, big-endian byte strings with no extra leading
//! zero bytes. The modulus length (in bytes) defines the RSA modulus size `k`; produced and
//! accepted signatures are exactly `k` bytes long.

use alloc::vec;
use alloc::vec::Vec;

use crate::ecalls;
use common::ecall_constants::MAX_BIGNUMBER_SIZE;

/// Hash algorithms that can be used with `RSASSA-PKCS1-v1_5`.
///
/// The variant selects both the expected digest length and the DER-encoded `DigestInfo`
/// prefix used by the EMSA-PKCS1-v1_5 encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaHash {
    /// SHA-1 (160-bit). Provided for legacy interoperability (e.g. DNSSEC algorithms 5 and 7);
    /// SHA-1 is deprecated and the SDK does not expose a SHA-1 hasher, so the digest must be
    /// supplied by the caller.
    Sha1,
    /// SHA-256 (e.g. DNSSEC algorithm 8).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512 (e.g. DNSSEC algorithm 10).
    Sha512,
}

impl RsaHash {
    /// Length in bytes of the digest produced by this hash algorithm.
    pub const fn digest_len(self) -> usize {
        match self {
            RsaHash::Sha1 => 20,
            RsaHash::Sha256 => 32,
            RsaHash::Sha384 => 48,
            RsaHash::Sha512 => 64,
        }
    }

    /// The DER-encoded `DigestInfo` prefix (the algorithm identifier that precedes the raw
    /// digest in the EMSA-PKCS1-v1_5 encoding), as specified in RFC 8017 §9.2 note 1.
    const fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            RsaHash::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            RsaHash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            RsaHash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            RsaHash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    /// Computes the digest of `message` using the SDK hash ECALLs.
    ///
    /// Returns `None` for [`RsaHash::Sha1`], which the SDK hash module does not provide; in
    /// that case the caller must compute the digest itself and use the digest-based API.
    fn hash_message(self, message: &[u8]) -> Option<Vec<u8>> {
        use crate::hash::{Hasher, Sha256, Sha384, Sha512};
        match self {
            RsaHash::Sha256 => Some(Sha256::hash(message).to_vec()),
            RsaHash::Sha384 => Some(Sha384::hash(message).to_vec()),
            RsaHash::Sha512 => Some(Sha512::hash(message).to_vec()),
            RsaHash::Sha1 => None,
        }
    }
}

/// Computes `base^exponent mod modulus`, returning the result as a big-endian byte vector of
/// the same length as `modulus`, or `None` if the inputs are out of range or the ECALL fails.
///
/// `base` must be no longer than `modulus`, and strictly smaller than it: `bn_powm` requires
/// a reduced base, and an out-of-range one is rejected.
/// Note that a signature received for verification is untrusted and may well be `>= modulus`.
fn mod_exp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Option<Vec<u8>> {
    let k = modulus.len();
    if k == 0 || k > MAX_BIGNUMBER_SIZE {
        return None;
    }
    if exponent.is_empty() || exponent.len() > MAX_BIGNUMBER_SIZE {
        return None;
    }
    if base.len() > k {
        return None;
    }

    // Left-pad the base to the modulus length, as required by bn_powm.
    let mut a = vec![0u8; k];
    a[k - base.len()..].copy_from_slice(base);

    // Both operands are now `k` bytes long and big-endian, so the lexicographic comparison of
    // the byte strings is the numeric comparison.
    if a[..] >= modulus[..] {
        return None;
    }

    let mut r = vec![0u8; k];
    // SAFETY: `r` and `a` are writable/readable for `k` bytes, `exponent` for `exponent.len()`
    // bytes, and `modulus` for `k` bytes; all are distinct allocations.
    let ok = unsafe {
        ecalls::bn_powm(
            r.as_mut_ptr(),
            a.as_ptr(),
            exponent.as_ptr(),
            exponent.len(),
            modulus.as_ptr(),
            k,
        )
    };
    if ok != 1 {
        return None;
    }
    Some(r)
}

/// Builds the `EMSA-PKCS1-v1_5` encoded message of length `em_len` for the given digest:
/// `0x00 || 0x01 || PS || 0x00 || DigestInfo || digest`, where `PS` is at least eight `0xff`
/// bytes. Returns `None` if `digest` has the wrong length, or if the modulus is too small to
/// hold the padding or larger than `MAX_BIGNUMBER_SIZE`.
fn emsa_pkcs1_v15_encode(hash: RsaHash, digest: &[u8], em_len: usize) -> Option<Vec<u8>> {
    if em_len > MAX_BIGNUMBER_SIZE {
        return None;
    }
    if digest.len() != hash.digest_len() {
        return None;
    }
    let prefix = hash.digest_info_prefix();
    let t_len = prefix.len() + digest.len();

    // RFC 8017 §9.2: the encoding requires at least 8 bytes of 0xff padding, plus the leading
    // `00 01` and the `00` separator.
    if em_len < t_len + 11 {
        return None;
    }

    let mut em = vec![0xffu8; em_len];
    em[0] = 0x00;
    em[1] = 0x01;
    // Index of the 0x00 separator between the padding and the DigestInfo.
    let sep = em_len - t_len - 1;
    em[sep] = 0x00;
    em[sep + 1..sep + 1 + prefix.len()].copy_from_slice(prefix);
    em[sep + 1 + prefix.len()..].copy_from_slice(digest);
    Some(em)
}

/// An RSA public key `(n, e)`.
#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RsaPublicKey {
    /// Creates a public key from the big-endian modulus and public exponent.
    ///
    /// Both must be raw unsigned big-endian byte strings with no extra leading zero bytes.
    pub fn new(modulus: &[u8], exponent: &[u8]) -> Self {
        Self {
            n: modulus.to_vec(),
            e: exponent.to_vec(),
        }
    }

    /// The modulus, in big-endian.
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// The public exponent, in big-endian.
    pub fn exponent(&self) -> &[u8] {
        &self.e
    }

    /// The modulus size in bytes (i.e. the length of a signature for this key).
    pub fn size(&self) -> usize {
        self.n.len()
    }

    /// Verifies an `RSASSA-PKCS1-v1_5` signature over a message digest.
    ///
    /// `digest` must be the output of `hash` applied to the signed message, and `signature`
    /// must be exactly [`RsaPublicKey::size`] bytes. Returns `true` if and only if the
    /// signature is valid.
    ///
    /// All inputs are public, so this comparison is not constant-time.
    pub fn verify_pkcs1_v1_5(&self, hash: RsaHash, digest: &[u8], signature: &[u8]) -> bool {
        let k = self.n.len();
        if signature.len() != k {
            return false;
        }
        let expected = match emsa_pkcs1_v15_encode(hash, digest, k) {
            Some(em) => em,
            None => return false,
        };
        let recovered = match mod_exp(signature, &self.e, &self.n) {
            Some(m) => m,
            None => return false,
        };
        recovered == expected
    }

    /// Convenience wrapper around [`RsaPublicKey::verify_pkcs1_v1_5`] that hashes `message`
    /// with the SDK hash ECALLs before verifying.
    ///
    /// Returns `false` for [`RsaHash::Sha1`], which the SDK cannot hash; use
    /// [`RsaPublicKey::verify_pkcs1_v1_5`] with a caller-computed digest instead.
    pub fn verify_pkcs1_v1_5_message(
        &self,
        hash: RsaHash,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match hash.hash_message(message) {
            Some(digest) => self.verify_pkcs1_v1_5(hash, &digest, signature),
            None => false,
        }
    }
}

/// An RSA private key in plain `(n, d)` form (modulus and private exponent).
#[derive(Clone)]
pub struct RsaPrivateKey {
    n: Vec<u8>,
    d: Vec<u8>,
}

impl RsaPrivateKey {
    /// Creates a private key from the big-endian modulus and private exponent.
    ///
    /// Both must be raw unsigned big-endian byte strings with no extra leading zero bytes.
    pub fn new(modulus: &[u8], private_exponent: &[u8]) -> Self {
        Self {
            n: modulus.to_vec(),
            d: private_exponent.to_vec(),
        }
    }

    /// The modulus, in big-endian.
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// The modulus size in bytes (i.e. the length of a produced signature).
    pub fn size(&self) -> usize {
        self.n.len()
    }

    /// Produces an `RSASSA-PKCS1-v1_5` signature over a message digest.
    ///
    /// `digest` must be the output of `hash` applied to the message to sign. On success the
    /// signature is exactly [`RsaPrivateKey::size`] bytes long. Returns `None` if the digest
    /// length is wrong, the modulus is too small for the padding or larger than
    /// [`MAX_BIGNUMBER_SIZE`], or the ECALL fails.
    pub fn sign_pkcs1_v1_5(&self, hash: RsaHash, digest: &[u8]) -> Option<Vec<u8>> {
        let k = self.n.len();
        let em = emsa_pkcs1_v15_encode(hash, digest, k)?;
        mod_exp(&em, &self.d, &self.n)
    }

    /// Convenience wrapper around [`RsaPrivateKey::sign_pkcs1_v1_5`] that hashes `message`
    /// with the SDK hash ECALLs before signing.
    ///
    /// Returns `None` for [`RsaHash::Sha1`], which the SDK cannot hash; use
    /// [`RsaPrivateKey::sign_pkcs1_v1_5`] with a caller-computed digest instead.
    pub fn sign_pkcs1_v1_5_message(&self, hash: RsaHash, message: &[u8]) -> Option<Vec<u8>> {
        let digest = hash.hash_message(message)?;
        self.sign_pkcs1_v1_5(hash, &digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rustfmt::skip]
    mod vectors {
        use hex_literal::hex;
// ---- RSA-2048 (e=65537) ----
    pub const RSA2048_N: &[u8] = &hex!(
        "90a7ab03f7877a18d757e5c3e2e1dd45880008339006f3669919c357bbe6b4fc"
        "f20586b52cbd37d49da485e689702bd2f06966b64c5ba110e5f3c46ed37d1b21"
        "73745d8edc1f3a339f8668eba99bc653aa1a71e448cd35b2300a1fc690fc21f3"
        "66cb4d566d17bb4115576cf4c243e608234c6e10ea000fcdb93cdd8c2ad4b4c3"
        "fcd2b4f02c6a4c9cf7e2bd79052bea5c36550e9b3f55ea842ef7c260cc490cd4"
        "fa6be4f03555b80fb5375837513c62941ca011b76f1de56f3536451d7fdcf90b"
        "0781d35c45acb9e2f11e0cd0becd3aea83bdc651c8a8bbd9afb4c082ce5fc62d"
        "281bed5ca31270cca0ab5c640d2396be54f04511d10bf500017acc890d999557"
    );
    pub const RSA2048_E: &[u8] = &hex!(
        "010001"
    );
    pub const RSA2048_D: &[u8] = &hex!(
        "0453c7b5642bbcd6ce66563cc0664250c8ab3b93934ce9ee1949608318df636d"
        "a7adcba452d4cc3d4383feef71101677867298bc7e57455fb48950c881f21da4"
        "2808849df7eec5367320b9b5c70a9e69b54e7a36ba88cd00ea17fb705cb8f629"
        "0a5bad9216cc5d712a7ac58b22de961c8b35c79b20ece48c226cf431b3bc4e35"
        "fd2e670ba043446879c016425908a05d4ea22051548bc38e7a33d442ae78c93d"
        "dcefb6a4b5896911cb0f00fb20c27b384de5bb87c651766e9262eaab38a06c6a"
        "5d9927d574ad1c189ce43eba9985e7d7eae06ca132067f2e368a3c0cce3cfd14"
        "dd3d558067b12f3d9966972ba133b6b8b8776fff23936eda8fde1fe73af65b2d"
    );
    pub const RSA2048_MSG: &[u8] = &hex!(
        "56616e616469756d2052534120504b435323312076312e35206b6e6f776e2d61"
        "6e73776572207465737420766563746f72"
    );
    pub const RSA2048_DIGEST_SHA256: &[u8] = &hex!(
        "2bf552c3cfd5a5b99039b477f2a2a6603f11ec9b58165d04f372def9ab39c8fe"
    );
    pub const RSA2048_SIG_SHA256: &[u8] = &hex!(
        "7f2a2faf8fc2a54ae7125857d6ac107acf1b0842212149de25bfbacc67774172"
        "fabc534697c255840e9624e095802a61d0f6bc91094ae0de5512bb4f6b85ab95"
        "4ec91dd0e041cad0bc9d167e502f12e85facb0719a3c706551ae94f14cbff0da"
        "442025fe96891540891f67442690e6360a9d60fc899fdb69ebedbe0c76171f0b"
        "a86abc00d683553853960125b17ef07d68879f31a52e9117d5e96460304adb52"
        "06c615af108b58a6609f8918800bdab8e0443a3be5ed0360ac9aa4f004c7e5dc"
        "97c28f4e78a62da117dbf8a79dc2636f6b6794f3c6cb2c8e7c53206ecd8cecff"
        "6b9291c4f0322eacb0b89e12c3f6960bd63dbfdb8ca0f22701493250eb755c14"
    );

// ---- RSA-4096 (e=65537) ----
    pub const RSA4096_N: &[u8] = &hex!(
        "cf8e4d063f383c2a0f351779075bc88cd548aa2991e168937a7ad8b10b7ae78f"
        "109f38dab8aa2cc37613aac27310e60583f36f8a693e92276490fd084ec6f270"
        "34747f3ee0e4776fc70cddfbde58830c03735375dee24f0f0f962b1236583e5d"
        "38fc30dec2c45dcd5d25e3232858c45a96960ed391ef4d95853c5aa3bf6b145a"
        "f1723db716bcbb48aade735ac244c46b3cd72b38a30162734ad851753a31058a"
        "008ba5a5784110cc2c83839993548af0c89556e8a71b06690d84d31af8eb684c"
        "853fe4307b6b552fc448e15b69b40fea72da6f1ca52bbf405a5cea858719c299"
        "6f24b0070e906c46449b713d1f402ca7fa294e2a57b50e8bf89c664ca01093b2"
        "92b8cf15138f015bfb25c02d5a33da6f8d2c0c386917616a19d8b53dbdbdfc50"
        "bbf4a81e503e8f613923fa46c6d2a1fdeba89c1e1cd1286175c19ac51624933d"
        "3030e5c6b36dfb6321ba717041c353fc9cde47025ee5044b84860b0b1254dfdf"
        "529a4dcdae781ed843aab230a957df631b057c479a7c59c1b324aaac65249b7e"
        "edb33bd7d2d995b19d8277edd6c0867d913fa72e58304753b3dd5e4e78f01a65"
        "6c61e1f22e3a089b693fb6c3e6c74f498484736886740be90d13c20ee4f0ea66"
        "777357f37777dbd060471865cd2eb91ea49f5a77c022a00d30007a33f591b88e"
        "9da5abe29aa35897cd60ebc4291af9878199e7975e435589132fae5724db9e6f"
    );
    pub const RSA4096_E: &[u8] = &hex!(
        "010001"
    );
    pub const RSA4096_D: &[u8] = &hex!(
        "19760be5d9c884bce61badb2f79f9f45037f03fcd07bf5cfada53742d4b53185"
        "bfd4c06d385d0bdbb876e62a2f6261cd48680b05502ed0500bcaab77a2ee4ddc"
        "4cdb03a70b808b544777411dfe231e8451420af9792b8ae63e93bdd9e097c7a2"
        "b8f45aec60b92506a5c8198a7d0f129b4840c535d7ffa2a55670567022f1b850"
        "05b16d77b1ceda2caa655a8246359860cd5859e17b4196b9acf3475ed9921ceb"
        "5670cb13b6e24874bb7b30a01cce30b323f009f6c5550fdec03d4c865105d3c8"
        "1b4a80ac1fdfc555f43eba8273bf967a3cb7a60cbe085550482580d17b86c1f3"
        "ff89e11c2481bbfe8cb902d5ac293bb129837aa6c016a25fb252414c62105685"
        "c750e8475e3b187089eaff22ddd2af7561df37e53dfaf4011cd557411ef5af6c"
        "8cbdf97e2a26ebac03a2f712df84121e096b576f7e4fd354f1451600b4ec5118"
        "25dd47a238e3f9517496b9df1d994da38fe38237934979e858b513c31c015437"
        "6d769804b768c9d257234a6b138756f21e9658e7b086bb095f55214a7737649f"
        "70931a9cbd8281cdff8b165716182c0f519d20502000d2d76887102c10459534"
        "1c3c3ed85eefd3bb939e546d52902b9d354f95ab5ebb98f24e054ecc2f69860a"
        "36533e503a9676697b7d9758c45aa57e1fb1b7798a6c1cad4e690aff6e61787e"
        "68a17e2e5199b62a3a35288a4fa440566aa0c975112a8a374684256edef27a01"
    );
    pub const RSA4096_MSG: &[u8] = &hex!(
        "56616e616469756d2052534120504b435323312076312e35206b6e6f776e2d61"
        "6e73776572207465737420766563746f72"
    );
    pub const RSA4096_DIGEST_SHA256: &[u8] = &hex!(
        "2bf552c3cfd5a5b99039b477f2a2a6603f11ec9b58165d04f372def9ab39c8fe"
    );
    pub const RSA4096_SIG_SHA256: &[u8] = &hex!(
        "2c87e8c1f483297d7054ee8d27dd097481fbf1cfce21c481e7e788f108254cca"
        "20859d0a9e8c764d127c31d04c82e7b12f82e1c56ee04ca4b7842a3ea5d22680"
        "ccb1c85ffca72e26df0582bd3e1761e31f1964bb9088c8820883c5936015c30b"
        "aa8c89b76773ea0b357514ebad70f1a137656af73c645f669bf2947a14a603bd"
        "6b538429c0373ebc2e1b1d4e748899c6a5a32285c0c0c2dd495b1402f54e530a"
        "e0005fad8c8ecc9953419e106dc5dae6a596be6b8cf75caeff5ca471e804eef4"
        "3eb86e7c2e42512ffd199332ff965c417cc5c8993730547870479d3769fabf30"
        "1c471bb2ff86f23bc4bc344c4b8c93583c4b8593d04033180ce55dd649807a26"
        "610732dfc1ec071bb2b6564ae9fd0358e2c46eebf2a3860df53549d516fc68b3"
        "800a701d93dcd82c8c03a3460d7f98e93f81b391e06da4c719e967f872149e39"
        "a44a3289db8cb78c532251a839e6b2d93515d8384818d7c134857d75dbc6a9d2"
        "6c0ec7ebd7fb3a70d9738f7065149089cad3528af50ca666fd8b24ead3d5d3c4"
        "60725f07cfff5936a08e3720cbfa309af9609f9def805c9370e60b1be28ab09a"
        "10af41c412439c69cc5e986e4c129825493bee102112de524141068299b221a6"
        "8e98fe7c6e3380780ff43c9a669e51b2eb526b1d34fd88cc87afbf93b2f2c165"
        "6bae385fed6caa003013e630fd3368885f2f12138eb053dd75b90151e81489b5"
    );
    pub const RSA4096_DIGEST_SHA384: &[u8] = &hex!(
        "1f6c0f72c24112e99082e1c9648bb83b452c5414dd97910be097d1a65f1acee5"
        "1137eda7cdea3c4b6f323c328ab7cd0d"
    );
    pub const RSA4096_SIG_SHA384: &[u8] = &hex!(
        "c4c8ae8a35a25a8fd5528b2153447c22cfc1429e0dceed0870ce120ab9a90d65"
        "2cdde731645f47ecf5352b59ab9718ae3595594d8a5b7cf0811d1162b80ade03"
        "4db6a488d502f7134124d8d108301ee68b9c9b3453c3e12aec5e6355504388f9"
        "0f9ca1f0b80f285539d87aba2f9b7c51f0dab6f4df01edb0268206886d7f34df"
        "a7b5a10e42173bca825fdf34ccda982cc83310d93b26978af0eae8b8eab083e5"
        "6c698a41a6cdaef7be1b32e742749e65cd67248abba8ef4b04ebf864bb827496"
        "89a4ebdfdd7d07e674a33a321127e3a0f4cef0da7e40833fe44987d1eeb7781c"
        "532b97070ec6494f6f5089d3ce4db8b25ce1c62e87e1c426ea7169c6dc7065ae"
        "abd168a7cc88430484218be548d5cca6edb5c1eda304d6d87c19e753821edb56"
        "bc807643afc7b42a7968aee851abc0ac156c4ef9aae3b59a634494410e2f53b7"
        "7981df6bccc02880de9eebc8758ed7044cced1b4f8d269207436c34cfbabc9df"
        "65870bd5c17083416335378d94b3d116dd78f32be63b583a7f3cd0bead31cc51"
        "3dd7c05284ffb8607e9f5ddf2e5ad526b3a11a207ad85a7000ec9cb03fc979d0"
        "730f3a0599b403a99fe0d7e2ecbae3b60977c1610493b309cb465d3d7b7cf1ea"
        "cda480770cde28ed6b0d69cf6249e624f6c6e0439b3c77002e982c4bb0155b9b"
        "77acc7462db1814293ac9c749bf35cbf47d9c699f9b51666594956d210532ae3"
    );
    pub const RSA4096_DIGEST_SHA512: &[u8] = &hex!(
        "c9c8e9e37bf45a7b51d090aa1879d6419d3d5eda7b9d592ead72d1b001a2ec7b"
        "e44cbc609705fb956b735773bfd72aca4066df223586f763562d1822aed9d6b8"
    );
    pub const RSA4096_SIG_SHA512: &[u8] = &hex!(
        "8485d583e56ada2f57980b374e8407e6c2f38c598f743c8d82d02133ed7380d8"
        "c206c394e2c763abd9b7b241f0e72d760948b2fd98f2a2f6b3dc80767bde0621"
        "8c557c9810eb30003bf7dc4da4c21f692b2fb3879fb97f18b03bcc3e15ba2024"
        "450c23a169426e6c447a84b799af4b1dd358b53a67dbcf1ce6070fcaac5432b8"
        "d5b6cf024e58a7bf3859a56430ec3023cd0fcc945b5c234a2f5f32e25f48eea9"
        "f4c2ca80f974117ad41b61899d0b3b4482839a1223f643279209fffe630b9584"
        "7c79d3a330729a27c2a151824d1d3b1701c1923c75595f80b3bb7f88e49b93dd"
        "b720d59fcc988616bd823daa37493943a6be42190650ef17a84cb613a9817ed8"
        "c6a274203831c1c2a040972c719b04071b9941a10c5b01fff286605ab1a06055"
        "72bb83e8c8b72c8d893098219c049144209e357c9ceb7515346d146ded4d7916"
        "26998bb80b802e0184e80c13109baa9fc217bd7f2d783eed8acc467b28b8c653"
        "4069564ad70ddc062501f24c8fa7fe6ec8ac15555209a3080f1ea225dff4240e"
        "3c4ba9034d5544519bca37ed4aa857f516aed161cc5e8983e01cea15cfba8369"
        "a62b17aca0fe5c09a83e8c86df8f3296ece3ec2450d06cbe7287fd345a4d29d4"
        "dc7cb71e433e08cc41eee7d1f36981fb584970f71b643180551f8ae3e28fb2ec"
        "f3f8c8c4fe8e9ac1a0d67a7d6765da10ac83256f068491b5a79aeaebd40c18db"
    );

    }
    use vectors::*;

    #[test]
    fn test_verify_rsa2048_sha256() {
        let pk = RsaPublicKey::new(RSA2048_N, RSA2048_E);
        assert!(pk.verify_pkcs1_v1_5(RsaHash::Sha256, RSA2048_DIGEST_SHA256, RSA2048_SIG_SHA256));
        // the message-based API hashes with the SDK before verifying
        assert!(pk.verify_pkcs1_v1_5_message(RsaHash::Sha256, RSA2048_MSG, RSA2048_SIG_SHA256));
    }

    #[test]
    fn test_verify_rsa4096_all_hashes() {
        let pk = RsaPublicKey::new(RSA4096_N, RSA4096_E);
        assert_eq!(pk.size(), 512);
        assert!(pk.verify_pkcs1_v1_5(RsaHash::Sha256, RSA4096_DIGEST_SHA256, RSA4096_SIG_SHA256));
        assert!(pk.verify_pkcs1_v1_5(RsaHash::Sha384, RSA4096_DIGEST_SHA384, RSA4096_SIG_SHA384));
        assert!(pk.verify_pkcs1_v1_5(RsaHash::Sha512, RSA4096_DIGEST_SHA512, RSA4096_SIG_SHA512));
        assert!(pk.verify_pkcs1_v1_5_message(RsaHash::Sha512, RSA4096_MSG, RSA4096_SIG_SHA512));
    }

    #[test]
    fn test_verify_rejects_tampered() {
        let pk = RsaPublicKey::new(RSA2048_N, RSA2048_E);

        // wrong hash algorithm (digest length no longer matches)
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha512, RSA2048_DIGEST_SHA256, RSA2048_SIG_SHA256));

        // a single flipped signature byte must be rejected
        let mut sig = RSA2048_SIG_SHA256.to_vec();
        sig[100] ^= 0x01;
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha256, RSA2048_DIGEST_SHA256, &sig));

        // a single flipped digest byte must be rejected
        let mut digest = RSA2048_DIGEST_SHA256.to_vec();
        digest[0] ^= 0x01;
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha256, &digest, RSA2048_SIG_SHA256));

        // a signature of the wrong length must be rejected
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha256, RSA2048_DIGEST_SHA256, &RSA2048_SIG_SHA256[..255]));
    }

    #[test]
    fn test_verify_rejects_signature_out_of_range() {
        // A signature is untrusted input and may be >= n even when it has the right length;
        // such a value must be rejected cleanly rather than reaching `bn_powm`, which
        // requires a reduced base.
        let pk = RsaPublicKey::new(RSA2048_N, RSA2048_E);
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha256, RSA2048_DIGEST_SHA256, RSA2048_N));
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha256, RSA2048_DIGEST_SHA256, &[0xffu8; 256]));

        // The largest in-range value is still accepted as a (wrong) signature, i.e. the check
        // is `>= n`, not `>= n - 1`.
        let mut n_minus_1 = RSA2048_N.to_vec();
        n_minus_1[255] -= 1;
        assert!(mod_exp(&n_minus_1, RSA2048_E, RSA2048_N).is_some());
    }

    #[test]
    fn test_sign_matches_known_vectors() {
        // RSASSA-PKCS1-v1_5 is deterministic, so signing must reproduce the reference
        // signatures produced independently by OpenSSL.
        let sk2048 = RsaPrivateKey::new(RSA2048_N, RSA2048_D);
        assert_eq!(
            sk2048.sign_pkcs1_v1_5(RsaHash::Sha256, RSA2048_DIGEST_SHA256).unwrap().as_slice(),
            RSA2048_SIG_SHA256
        );

        let sk4096 = RsaPrivateKey::new(RSA4096_N, RSA4096_D);
        assert_eq!(
            sk4096.sign_pkcs1_v1_5(RsaHash::Sha256, RSA4096_DIGEST_SHA256).unwrap().as_slice(),
            RSA4096_SIG_SHA256
        );
        assert_eq!(
            sk4096.sign_pkcs1_v1_5(RsaHash::Sha384, RSA4096_DIGEST_SHA384).unwrap().as_slice(),
            RSA4096_SIG_SHA384
        );
        assert_eq!(
            sk4096.sign_pkcs1_v1_5(RsaHash::Sha512, RSA4096_DIGEST_SHA512).unwrap().as_slice(),
            RSA4096_SIG_SHA512
        );
    }

    #[test]
    fn test_sign_verify_roundtrip_message() {
        let sk = RsaPrivateKey::new(RSA4096_N, RSA4096_D);
        let pk = RsaPublicKey::new(RSA4096_N, RSA4096_E);
        let sig = sk.sign_pkcs1_v1_5_message(RsaHash::Sha256, RSA4096_MSG).unwrap();
        assert!(pk.verify_pkcs1_v1_5_message(RsaHash::Sha256, RSA4096_MSG, &sig));
    }

    #[test]
    fn test_sha1_hashing_unsupported() {
        // The SDK does not expose a SHA-1 hasher, so the message-based helpers must fail
        // gracefully rather than produce a wrong result. (The digest-based API still works
        // with a caller-supplied SHA-1 digest.)
        let pk = RsaPublicKey::new(RSA2048_N, RSA2048_E);
        assert!(!pk.verify_pkcs1_v1_5_message(RsaHash::Sha1, RSA2048_MSG, RSA2048_SIG_SHA256));
        let sk = RsaPrivateKey::new(RSA2048_N, RSA2048_D);
        assert!(sk.sign_pkcs1_v1_5_message(RsaHash::Sha1, RSA2048_MSG).is_none());
    }

    #[test]
    fn test_emsa_encoding_shape() {
        // Structure of EMSA-PKCS1-v1_5 for a SHA-256 digest at a 2048-bit (256-byte) modulus.
        let digest = [0xabu8; 32];
        let em = emsa_pkcs1_v15_encode(RsaHash::Sha256, &digest, 256).unwrap();
        assert_eq!(em.len(), 256);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        // DigestInfo (19 bytes) + digest (32) = 51; the 0x00 separator sits at 256-51-1 = 204.
        assert_eq!(em[204], 0x00);
        assert!(em[2..204].iter().all(|&b| b == 0xff));
        assert_eq!(&em[205..224], RsaHash::Sha256.digest_info_prefix());
        assert_eq!(&em[224..], &digest[..]);

        // A modulus too small to hold at least 8 bytes of padding is rejected.
        assert!(emsa_pkcs1_v15_encode(RsaHash::Sha256, &digest, 40).is_none());
        // A digest of the wrong length for the algorithm is rejected.
        assert!(emsa_pkcs1_v15_encode(RsaHash::Sha256, &[0u8; 20], 256).is_none());
        // The largest supported modulus is fine, one byte more is not: the buffer is
        // allocated from `em_len`, so the bound must be checked before allocating.
        assert!(emsa_pkcs1_v15_encode(RsaHash::Sha256, &digest, MAX_BIGNUMBER_SIZE).is_some());
        assert!(emsa_pkcs1_v15_encode(RsaHash::Sha256, &digest, MAX_BIGNUMBER_SIZE + 1).is_none());
    }

    #[test]
    fn test_oversized_modulus_rejected() {
        let n = [0xffu8; MAX_BIGNUMBER_SIZE + 1];
        let digest = [0xabu8; 32];

        let pk = RsaPublicKey::new(&n, RSA2048_E);
        assert!(!pk.verify_pkcs1_v1_5(RsaHash::Sha256, &digest, &[0x01u8; MAX_BIGNUMBER_SIZE + 1]));

        let sk = RsaPrivateKey::new(&n, RSA2048_D);
        assert!(sk.sign_pkcs1_v1_5(RsaHash::Sha256, &digest).is_none());
    }
}
