use common::manifest::{Manifest, APP_NAME_MAX_LEN, APP_VERSION_MAX_LEN};
use ledger_device_sdk::NVMData;

use crate::nvm::LazyStorage;

use crate::hash::Sha256Hasher;

/// Maximum number of V-Apps that can be registered.
pub const MAX_REGISTERED_VAPPS: usize = 32;

/// A registered V-App entry stored in NVRAM.
/// Uses fixed-size arrays for deterministic storage layout.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct VAppEntry {
    /// SHA-256 hash of the V-App manifest. All zeros indicates an empty slot.
    pub vapp_hash: [u8; 32],
    /// V-App name, null-padded to 32 bytes.
    pub vapp_name: [u8; APP_NAME_MAX_LEN],
    /// V-App version, null-padded to 32 bytes.
    pub vapp_version: [u8; APP_VERSION_MAX_LEN],
}

impl VAppEntry {
    /// Creates an empty entry (sentinel value).
    pub const fn empty() -> Self {
        Self {
            vapp_hash: [0u8; 32],
            vapp_name: [0u8; APP_NAME_MAX_LEN],
            vapp_version: [0u8; APP_VERSION_MAX_LEN],
        }
    }

    /// Gets the app name as a string slice (up to first null byte, or the maximum length
    /// of APP_NAME_MAX_LEN).
    pub fn get_app_name(&self) -> &str {
        let len = self
            .vapp_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(APP_NAME_MAX_LEN);
        core::str::from_utf8(&self.vapp_name[..len]).unwrap_or("")
    }

    /// Gets the app version as a string slice (up to first null byte, or the maximum length
    /// of APP_VERSION_MAX_LEN).
    #[allow(dead_code)] // Will be used by device UI for app management
    pub fn get_app_version(&self) -> &str {
        let len = self
            .vapp_version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(APP_VERSION_MAX_LEN);
        core::str::from_utf8(&self.vapp_version[..len]).unwrap_or("")
    }
}

/// Error type for V-App store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VAppStoreError {
    /// The store is full and cannot accept new registrations.
    StoreFull,
    /// The app name is too long.
    NameTooLong,
    /// The app version is too long.
    VersionTooLong,
}

// Use a fixed-length array of LazyStorage for zero-initialized NVM storage.
// Each slot can be independently initialized or cleared.
#[link_section = ".nvm_data"]
static mut VAPP_STORE: NVMData<[LazyStorage<VAppEntry>; MAX_REGISTERED_VAPPS]> =
    NVMData::new([LazyStorage::new(); MAX_REGISTERED_VAPPS]);

/// The V-App store manages registered V-Apps in NVRAM.
pub struct VAppStore;

impl VAppStore {
    /// Gets a mutable reference to the storage array.
    #[inline(never)]
    fn get_storage_mut() -> &'static mut [LazyStorage<VAppEntry>; MAX_REGISTERED_VAPPS] {
        let data = &raw mut VAPP_STORE;
        unsafe { (*data).get_mut() }
    }

    /// Gets a reference to the storage array.
    #[inline(never)]
    fn get_storage_ref() -> &'static [LazyStorage<VAppEntry>; MAX_REGISTERED_VAPPS] {
        let data = &raw const VAPP_STORE;
        unsafe { (*data).get_ref() }
    }

    /// Checks if a V-App with the given hash is registered.
    pub fn is_registered(vapp_hash: &[u8; 32]) -> bool {
        Self::find_by_hash(vapp_hash).is_some()
    }

    /// Finds an entry by its vapp_hash. Returns the index if found.
    /// We don't use a constant time comparison, as knowledge about which apps are registered is not
    /// considered sensitive information.
    pub fn find_by_hash(vapp_hash: &[u8; 32]) -> Option<usize> {
        let storage = Self::get_storage_ref();
        for i in 0..MAX_REGISTERED_VAPPS {
            if storage[i].is_initialized() {
                let entry = storage[i].get_ref();
                if &entry.vapp_hash == vapp_hash {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Finds an entry by app name. Returns the index if found.
    /// We don't use a constant time comparison, as knowledge about which apps are registered is not
    /// considered sensitive information.
    pub fn find_by_name(vapp_name: &str) -> Option<usize> {
        let storage = Self::get_storage_ref();
        for i in 0..MAX_REGISTERED_VAPPS {
            if storage[i].is_initialized() {
                let entry = storage[i].get_ref();
                if entry.get_app_name() == vapp_name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Registers a V-App. If an app with the same name exists, it will be overwritten.
    /// Returns Ok(()) on success, or an error if the store is full or parameters are invalid.
    pub fn register(manifest: &Manifest) -> Result<(), VAppStoreError> {
        let vapp_name = manifest.get_app_name();
        let vapp_version = manifest.get_app_version();

        if vapp_name.len() > APP_NAME_MAX_LEN {
            return Err(VAppStoreError::NameTooLong);
        }
        if vapp_version.len() > APP_VERSION_MAX_LEN {
            return Err(VAppStoreError::VersionTooLong);
        }

        // Compute the V-App hash from the manifest
        let vapp_hash = manifest.get_vapp_hash::<Sha256Hasher, 32>();

        // Create the new entry
        let mut entry = VAppEntry::empty();
        entry.vapp_hash.copy_from_slice(&vapp_hash);
        entry.vapp_name[..vapp_name.len()].copy_from_slice(vapp_name.as_bytes());
        entry.vapp_version[..vapp_version.len()].copy_from_slice(vapp_version.as_bytes());

        let storage = Self::get_storage_mut();

        // Check if an app with the same name already exists (for update/overwrite)
        if let Some(existing_index) = Self::find_by_name(vapp_name) {
            // Update the existing entry
            storage[existing_index].update(&entry);
            Ok(())
        } else {
            // Find first uninitialized slot and add new entry
            for i in 0..MAX_REGISTERED_VAPPS {
                if !storage[i].is_initialized() {
                    storage[i].initialize(&entry);
                    return Ok(());
                }
            }
            // No free slots
            Err(VAppStoreError::StoreFull)
        }
    }

    /// Unregisters a V-App at the given index by clearing the entry.
    #[allow(dead_code)] // Will be used by device UI for app management
    pub fn unregister(index: usize) -> bool {
        if index >= MAX_REGISTERED_VAPPS {
            return false;
        }
        let storage = Self::get_storage_mut();
        if !storage[index].is_initialized() {
            return false;
        }
        storage[index].clear();
        true
    }

    /// Returns the number of registered V-Apps.
    #[allow(dead_code)] // Will be used by device UI for app management
    pub fn count() -> usize {
        let storage = Self::get_storage_ref();
        let mut count = 0;
        for i in 0..MAX_REGISTERED_VAPPS {
            if storage[i].is_initialized() {
                count += 1;
            }
        }
        count
    }

    /// Gets an entry at the given index.
    #[allow(dead_code)] // Will be used by device UI for app management
    pub fn get_entry(index: usize) -> Option<&'static VAppEntry> {
        if index >= MAX_REGISTERED_VAPPS {
            return None;
        }
        let storage = Self::get_storage_ref();
        if storage[index].is_initialized() {
            Some(storage[index].get_ref())
        } else {
            None
        }
    }

    /// Returns an iterator over all registered V-Apps.
    #[allow(dead_code)] // Will be used by device UI for app management
    pub fn iter() -> VAppStoreIter {
        VAppStoreIter { current_index: 0 }
    }

    /// Uninstalls all V-Apps by clearing all entries in storage.
    pub fn uninstall_all() {
        let storage = Self::get_storage_mut();
        for i in 0..MAX_REGISTERED_VAPPS {
            if storage[i].is_initialized() {
                storage[i].clear();
            }
        }
    }
}

/// Iterator over registered V-Apps.
#[allow(dead_code)] // Will be used by device UI for app management
pub struct VAppStoreIter {
    current_index: usize,
}

impl Iterator for VAppStoreIter {
    type Item = (usize, VAppEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let storage = VAppStore::get_storage_ref();
        // Find next initialized slot
        while self.current_index < MAX_REGISTERED_VAPPS {
            let index = self.current_index;
            self.current_index += 1;
            if storage[index].is_initialized() {
                return Some((index, *storage[index].get_ref()));
            }
        }
        None
    }
}
