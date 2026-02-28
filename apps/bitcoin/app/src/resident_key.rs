use common::bip388::KeyInformation;
use common::errors::Error;
use sdk::curve::{EcfpPrivateKey, EcfpPublicKey, HDPrivNode, Secp256k1, ToPublicKey};
use sdk::storage::{is_slot_empty, read_slot, write_slot};

const RESIDENT_KEY_SLOT: u32 = 0;

/// Returns the resident private key from storage slot 0, generating and storing
/// a fresh random key on first use (detected by the slot being all-zeros).
pub fn get_or_init_resident_private_key() -> Result<EcfpPrivateKey<Secp256k1, 32>, Error> {
    if is_slot_empty(RESIDENT_KEY_SLOT).map_err(|_| Error::StorageError)? {
        // First run: generate a random 32-byte private key and persist it.
        let random = sdk::rand::random_bytes(32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&random);
        write_slot(RESIDENT_KEY_SLOT, &key).map_err(|_| Error::StorageError)?;
        Ok(EcfpPrivateKey::new(key))
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
