use ledger_device_sdk::hmac::{self, HMACInit};
use ledger_device_sdk::nvm::*;
use ledger_device_sdk::NVMData;

use common::manifest::Manifest;

use crate::hash::Sha256Hasher;

/// Encapsulates the key used for the V-App registration.
/// It is generated on first use, and stored in the NVM.
#[derive(Default)]
struct VappRegistrationKey;

// We use the initial value (all zeros) to mark the key as uninitialized.
// We generate a new random key at first use.

#[link_section = ".nvm_data"]
static mut VAPP_REGISTRATION_KEY: NVMData<AtomicStorage<[u8; 32]>> =
    NVMData::new(AtomicStorage::new(&[0u8; 32]));

/// Checks whether all bytes in the slice are zero using constant-time comparison.
///
/// This function is intentionally written to avoid early returns or branching
/// based on the data, preventing timing side-channels that could leak information
/// about the key's state.
#[inline(never)]
fn is_all_zeros_ct(data: &[u8]) -> bool {
    let mut data_or = 0u8;
    for &byte in data.iter() {
        data_or |= byte;
    }
    data_or == 0
}

impl VappRegistrationKey {
    /// Generates a new random key and stores it in NVM.
    unsafe fn generate_new_key(storage: &mut AtomicStorage<[u8; 32]>) {
        let mut new_key = [0u8; 32];
        ledger_device_sdk::random::rand_bytes(&mut new_key);
        storage.update(&new_key);
    }

    fn ensure_initialized() {
        // if the key is all zeros, initialize it with 32 random bytes
        let nvm_key = &raw mut VAPP_REGISTRATION_KEY;
        unsafe {
            let storage = (*nvm_key).get_mut();

            // check whether the key is all zeros with a constant time comparison
            if is_all_zeros_ct(storage.get_ref().as_slice()) {
                Self::generate_new_key(storage);
            }
        }
    }

    /// Generates a new random key, replacing the existing one.
    /// This invalidates all previously generated HMACs.
    fn regenerate() {
        let nvm_key = &raw mut VAPP_REGISTRATION_KEY;
        unsafe {
            let storage = (*nvm_key).get_mut();
            Self::generate_new_key(storage);
        }
    }

    #[inline(never)]
    pub fn get_ref(&self) -> &AtomicStorage<[u8; 32]> {
        Self::ensure_initialized();

        let data = &raw const VAPP_REGISTRATION_KEY;
        unsafe { (*data).get_ref() }
    }

    pub fn get_key(&self) -> &[u8; 32] {
        self.get_ref().get_ref()
    }
}

/// Returns a deterministic Vanadium ID derived from the VappRegistrationKey.
///
/// The ID is computed as SHA256("\x0bVanadium ID" || VappRegistrationKey).
#[must_use]
pub fn get_vanadium_id() -> [u8; 32] {
    let key = VappRegistrationKey.get_key();
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"\x0bVanadium ID");
    hasher.update(key);
    hasher.finalize()
}

/// Regenerates the V-App registration key with new random bytes.
///
/// This invalidates all previously generated HMACs and changes the Vanadium ID.
pub fn reinitialize_vanadium_id() {
    VappRegistrationKey::regenerate();
}

/// Computes the HMAC for the V-App.
///
/// SECURITY: The caller is responsible for ensuring that comparisons involving the
/// result of this function run in constant time, in order to prevent timing attacks.
#[must_use]
pub fn get_vapp_hmac(manifest: &Manifest) -> [u8; 32] {
    let vapp_hash: [u8; 32] = manifest.get_vapp_hash::<Sha256Hasher, 32>();

    let mut sha2 = hmac::sha2::Sha2_256::new(VappRegistrationKey.get_key());
    sha2.update(&vapp_hash).expect("Should never fail");
    let mut vapp_hmac = [0u8; 32];
    sha2.finalize(&mut vapp_hmac).expect("Should never fail");

    vapp_hmac
}
