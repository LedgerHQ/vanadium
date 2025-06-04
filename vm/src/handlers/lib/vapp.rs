use common::manifest::Manifest;
use ledger_device_sdk::hmac::{self, HMACInit};

use crate::hash::Sha256Hasher;

use ledger_device_sdk::nvm::*;
use ledger_device_sdk::NVMData;

/// Encapsulates the key used for the V-App registration.
/// It is generated on first use, and stored in the NVM.
pub struct VappRegistrationKey;

impl Default for VappRegistrationKey {
    fn default() -> Self {
        VappRegistrationKey
    }
}

// We use the initial value (all zeros) to mark the key as uninitialized.
// We generate a new random key at first use.

#[link_section = ".nvm_data"]
static mut VAPP_REGISTRATION_KEY: NVMData<AtomicStorage<[u8; 32]>> =
    NVMData::new(AtomicStorage::new(&[0u8; 32]));

// check whether the key is all zeros with a constant time comparison
fn is_all_zeros_ct(data: &[u8]) -> bool {
    let mut data_or = 0u8;
    for &byte in data.iter() {
        data_or |= byte;
    }
    data_or == 0
}

impl VappRegistrationKey {
    fn ensure_initialized() {
        // if the key is all zeros, initialize it with 32 random bytes
        let nvm_key = &raw mut VAPP_REGISTRATION_KEY;
        unsafe {
            let storage = (*nvm_key).get_mut();

            // check whether the key is all zeros with a constant time comparison
            if is_all_zeros_ct(storage.get_ref().as_slice()) {
                let mut new_key = [0u8; 32];
                ledger_device_sdk::random::rand_bytes(&mut new_key);
                storage.update(&new_key);
            }
        }
    }

    #[inline(never)]
    pub fn get_ref(&mut self) -> &AtomicStorage<[u8; 32]> {
        Self::ensure_initialized();

        let data = &raw const VAPP_REGISTRATION_KEY;
        unsafe { (*data).get_ref() }
    }

    pub fn get_key(&mut self) -> &[u8; 32] {
        self.get_ref().get_ref()
    }
}

/// Computes the HMAC for the V-App.
///
/// SECURITY: The caller is responsible for ensuring that comparisons involving the
/// result of this function run in constant time, in order to prevent timing attacks.
pub fn get_vapp_hmac(manifest: &Manifest) -> [u8; 32] {
    let vapp_hash: [u8; 32] = manifest.get_vapp_hash::<Sha256Hasher, 32>();

    let mut vapp_key = VappRegistrationKey;

    let mut sha2 = hmac::sha2::Sha2_256::new(vapp_key.get_key());
    sha2.update(&vapp_hash).expect("Should never fail");
    let mut vapp_hmac = [0u8; 32];
    sha2.finalize(&mut vapp_hmac).expect("Should never fail");

    vapp_hmac
}
