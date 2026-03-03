use common::errors::Error;
use sdk::curve::{EcfpPrivateKey, EcfpPublicKey, Secp256k1, ToPublicKey};

#[cfg(not(any(test, feature = "fixed_resident_key")))]
use sdk::storage::{is_slot_empty, read_slot};

#[cfg(not(feature = "fixed_resident_key"))]
use sdk::storage::write_slot;

#[cfg(not(feature = "fixed_resident_key"))]
const RESIDENT_KEY_SLOT: u32 = 0;

#[cfg(any(test, feature = "fixed_resident_key"))]
pub const FIXED_RESIDENT_KEY: [u8; 32] =
    hex_literal::hex!("5245534944454e544b45595245534944454e544b45595245534944454e544b45");
#[cfg(test)]
pub const FIXED_RESIDENT_PUBKEY: [u8; 33] =
    hex_literal::hex!("032349d1abe6d9e0c174f011a1c4bd09fe5b6e88b2a162e61ddec5d07554fa275a");

/// Returns the resident private key from storage slot 0, generating and storing
/// a fresh random key on first use (detected by the slot being all-zeros).
///
/// If the `fixed_resident_key` feature is enabled, always returns the fixed
/// compile-time key FIXED_RESIDENT_KEY.
/// This is only useful for testing.
pub fn get_or_init_resident_private_key() -> Result<EcfpPrivateKey<Secp256k1, 32>, Error> {
    #[cfg(any(test, feature = "fixed_resident_key"))]
    return Ok(EcfpPrivateKey::new(FIXED_RESIDENT_KEY));

    #[cfg(not(any(test, feature = "fixed_resident_key")))]
    if is_slot_empty(RESIDENT_KEY_SLOT).map_err(|_| Error::StorageError)? {
        // First run: generate a random 32-byte private key and persist it.
        let random_key = sdk::rand::random_bytes(32).try_into().unwrap();
        write_slot(RESIDENT_KEY_SLOT, &random_key).map_err(|_| Error::StorageError)?;
        Ok(EcfpPrivateKey::new(random_key))
    } else {
        let slot = read_slot(RESIDENT_KEY_SLOT).map_err(|_| Error::StorageError)?;
        Ok(EcfpPrivateKey::new(slot))
    }
}

/// Returns the resident public key derived from the resident private key in storage slot 0,
/// generating and storing a fresh random private key on first use.
pub fn get_or_init_resident_public_key() -> Result<EcfpPublicKey<Secp256k1, 32>, Error> {
    Ok(get_or_init_resident_private_key()?.to_public_key())
}

/// Returns the compressed resident public key.
pub fn get_resident_compressed_pubkey() -> Result<[u8; 33], Error> {
    let pubkey = get_or_init_resident_public_key()?;
    let uncompressed = pubkey.as_ref().to_bytes();
    let mut compressed = [0u8; 33];
    compressed[0] = 2 + uncompressed[64] % 2;
    compressed[1..33].copy_from_slice(&uncompressed[1..33]);
    Ok(compressed)
}

/// Sets the resident key to the given 32-byte value. Only available in tests.
#[cfg(test)]
pub fn set_resident_key(key: [u8; 32]) -> Result<(), Error> {
    write_slot(RESIDENT_KEY_SLOT, &key).map_err(|_| Error::StorageError)
}
