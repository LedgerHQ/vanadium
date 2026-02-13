/// This module manages Vanadium's auth_key. This is a 32-byte secret that is generated when the app is first launched,
/// and is used for anything that needs a permanent bind to the identity of the instance of the app. Therefore, it
/// doesn't persist if the Vanadium app is reinstalled or upgraded.
use common::accumulator::Hasher;
use ledger_device_sdk::NVMData;

use crate::hash::Sha256Hasher;
use crate::nvm::LazyStorage;

// This key is initialized the first time the Vanadium app is launched.
#[link_section = ".nvm_data"]
static mut VM_AUTH_KEY: NVMData<LazyStorage<[u8; 32]>> = NVMData::new(LazyStorage::new());

pub struct VMAuthKey;

impl VMAuthKey {
    /// Gets a mutable reference to the auth key storage.
    #[inline(never)]
    fn get_storage_mut() -> &'static mut LazyStorage<[u8; 32]> {
        let data = &raw mut VM_AUTH_KEY;
        unsafe { (*data).get_mut() }
    }

    /// Gets a reference to the auth key storage.
    #[inline(never)]
    fn get_storage_ref() -> &'static LazyStorage<[u8; 32]> {
        let data = &raw const VM_AUTH_KEY;
        unsafe { (*data).get_ref() }
    }

    /// Ensures the auth key is initialized. If uninitialized, generates a new secure 32-byte random key.
    fn ensure_initialized() {
        let storage = Self::get_storage_mut();
        if !storage.is_initialized() {
            let mut key = [0u8; 32];
            unsafe {
                let result = ledger_device_sdk::sys::cx_get_random_bytes(
                    key.as_mut_ptr() as *mut core::ffi::c_void,
                    key.len(),
                );
                assert!(
                    result == ledger_device_sdk::sys::CX_OK,
                    "Failed to generate random bytes"
                );
            }
            storage.initialize(&key);
        }
    }

    /// Creates a new `VMAuthKey` instance, ensuring the auth key is initialized.
    ///
    /// On first call, generates a secure 32-byte random key if not already initialized.
    pub fn get() -> Self {
        Self::ensure_initialized();
        VMAuthKey
    }

    /// Computes a tagged hash: `SHA256(SHA256(tag) || auth_key || buffer)`.
    ///
    /// This produces a deterministic, domain-separated hash that commits to auth_key.
    /// It can also be used as a subkey.
    pub fn tagged_hash(&self, tag: &[u8], buffer: &[u8]) -> [u8; 32] {
        let storage = Self::get_storage_ref();
        let auth_key = storage.get_ref(); // panics if not initialized, but initialization is ensured in get()

        // Compute SHA256(tag)
        let mut tag_hash = [0u8; 32];
        let mut hasher = Sha256Hasher::new();
        hasher.update(tag);
        hasher.digest(&mut tag_hash);

        // Compute SHA256(SHA256(tag) || auth_key || buffer)
        let mut result = [0u8; 32];
        let mut hasher = Sha256Hasher::new();
        hasher.update(&tag_hash);
        hasher.update(auth_key);
        hasher.update(buffer);
        hasher.digest(&mut result);

        result
    }
}
