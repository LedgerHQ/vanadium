/// This module manages Vanadium's auth_key. This is a 32-byte secret that is generated when the app is first launched,
/// and is used for anything that needs a permanent bind to the identity of the instance of the app. Therefore, it
/// doesn't persist if the Vanadium app is reinstalled or upgraded.
use common::accumulator::Hasher;
use ledger_device_sdk::hmac::{sha2::Sha2_256 as HmacSha256, HMACInit};
use ledger_device_sdk::NVMData;

use crate::hash::Sha256Hasher;
use crate::nvm::LazyStorage;

// This key is initialized the first time the Vanadium app is launched.
#[link_section = ".nvm_data"]
static mut VM_AUTH_KEY: NVMData<LazyStorage<[u8; 32]>> = NVMData::new(LazyStorage::new());

pub struct VMAuthKey;

const TAG_APP_ID: &[u8] = b"VND_APP_ID";
const TAG_APP_AUTH_KEY: &[u8] = b"VND_APP_AUTH_KEY";
const TAG_PAGE_HMAC: &[u8] = b"VND_PAGE_TAG";
const TAG_PAGE_HMAC_MASK: &[u8] = b"VND_HMAC_MASK";

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

/// Computes the app auth key bound to a specific V-App.
#[inline]
pub fn get_vapp_auth_key(vapp_hash: &[u8; 32]) -> [u8; 32] {
    let auth_key = VMAuthKey::get();
    auth_key.tagged_hash(TAG_APP_AUTH_KEY, vapp_hash)
}

/// Computes the page HMAC for one code page.
pub fn compute_code_page_hmac(
    app_auth_key: &[u8; 32],
    vapp_hash: &[u8; 32],
    page_index: u32,
    page_hash: &[u8; 32],
) -> Result<[u8; 32], ()> {
    let mut mac = HmacSha256::new(app_auth_key);
    mac.update(TAG_PAGE_HMAC).map_err(|_| ())?;
    mac.update(vapp_hash).map_err(|_| ())?;
    mac.update(&page_index.to_be_bytes()).map_err(|_| ())?;
    mac.update(page_hash).map_err(|_| ())?;

    let mut out = [0u8; 32];
    mac.finalize(&mut out).map_err(|_| ())?;
    Ok(out)
}

/// Computes SHA256("VND_HMAC_MASK" || ephemeral_sk || be32(page_index)).
pub fn compute_page_hmac_mask(ephemeral_sk: &[u8; 32], page_index: u32) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(TAG_PAGE_HMAC_MASK);
    hasher.update(ephemeral_sk);
    hasher.update(&page_index.to_be_bytes());

    let mut out = [0u8; 32];
    hasher.digest(&mut out);
    out
}

/// Returns a public identifier that uniquely identifies this instance of the Vanadium app.
/// This is derived from the auth key, so it is stable across app restarts but changes if the app is reinstalled or upgraded.
pub fn get_vanadium_app_id() -> [u8; 32] {
    let auth_key = VMAuthKey::get();
    auth_key.tagged_hash(TAG_APP_ID, b"")
}
