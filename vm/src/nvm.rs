use ledger_device_sdk::nvm::{AlignedStorage, NvmValue, SingleStorage};

const STORAGE_VALID: u8 = 0xa5;

/// Non-Volatile data storage similar to SafeStorage but with lazy initialization.
///
/// This storage type is designed to have an all-zero representation in the binary
/// when uninitialized. The flag starts at 0 (uninitialized) and transitions to
/// STORAGE_VALID (0xa5) after initialization.
///
/// This ensures that all entries in the `.nvm_data` section are zero-initialized when
/// uninitialized, working around the imperfect emulation of speculos until
/// https://github.com/LedgerHQ/speculos/issues/562 is addressed.
///
/// # States
///
/// - **Uninitialized**: flag = 0, value = undefined (binary contains all zeros)
/// - **Initialized**: flag = STORAGE_VALID (0xa5), value = T (behaves like SafeStorage)
///
/// # Examples
///
/// ```
/// use ledger_device_sdk::NVMData;
/// use crate::nvm::LazyStorage;
///
/// // `nvm_data!` only accepts the SDK's own storages, so the static is placed
/// // in `.nvm_data` by hand.
/// #[link_section=".nvm_data"]
/// static mut DATA: NVMData<LazyStorage<[u8; 32]>> =
///     unsafe { NVMData::new_unchecked(LazyStorage::new()) };
///
/// // Later in code:
/// let mut data = unsafe { DATA.get_mut() };
/// if !data.is_initialized() {
///     data.initialize(&[0u8; 32]);
/// }
/// let value = data.get_ref();
/// ```
///
/// `T` must be [`NvmValue`]: every bit pattern is a valid `T`, so the zeroed value of an
/// uninitialized storage, and a value torn by an interrupted update, can be read back.
#[derive(Copy, Clone)]
pub struct LazyStorage<T: NvmValue> {
    flag: AlignedStorage<u8>,
    value: AlignedStorage<T>,
}

impl<T: NvmValue> LazyStorage<T> {
    /// Create an uninitialized `LazyStorage<T>` with all-zero binary representation.
    ///
    /// This is a const fn that can be used in static initializers. The flag
    /// starts at 0 (uninitialized) and the value is zero-initialized.
    pub const fn new() -> LazyStorage<T> {
        // SAFETY: every bit pattern, all zeroes included, is a valid `T: NvmValue`.
        unsafe {
            LazyStorage {
                flag: AlignedStorage::new(0),
                value: AlignedStorage::new(core::mem::zeroed()),
            }
        }
    }

    /// Returns true if the storage has been initialized.
    pub fn is_initialized(&self) -> bool {
        *self.flag.get_ref() == STORAGE_VALID
    }

    /// Initialize the storage with a value.
    ///
    /// # Panics
    ///
    /// Panics if the storage is already initialized.
    pub fn initialize(&mut self, value: &T) {
        assert!(!self.is_initialized(), "LazyStorage already initialized");
        self.value.update(value);
        self.flag.update(&STORAGE_VALID);
    }

    /// Returns a reference to the stored value.
    ///
    /// # Panics
    ///
    /// Panics if the storage is not initialized.
    pub fn get_ref(&self) -> &T {
        assert!(self.is_initialized(), "LazyStorage not initialized");
        self.value.get_ref()
    }

    /// Updates the stored value.
    ///
    /// This performs an atomic three-step write like SafeStorage:
    /// 1. Flag is set to 0 (invalidate)
    /// 2. Value is updated
    /// 3. Flag is restored to STORAGE_VALID
    ///
    /// # Panics
    ///
    /// Panics if the storage is not initialized.
    pub fn update(&mut self, value: &T) {
        assert!(self.is_initialized(), "LazyStorage not initialized");
        self.flag.update(&0);
        self.value.update(value);
        self.flag.update(&STORAGE_VALID);
    }

    /// Clears the storage by overwriting with zeros, returning it to uninitialized state.
    ///
    /// This performs an atomic two-step write:
    /// 1. Flag is set to 0 (mark as uninitialized)
    /// 2. Value is zeroed
    ///
    /// After calling this method, `is_initialized()` will return false.
    pub fn clear(&mut self) {
        // First invalidate the flag
        self.flag.update(&0);
        // Then zero the value
        // SAFETY: every bit pattern, all zeroes included, is a valid `T: NvmValue`.
        unsafe {
            self.value.update(&core::mem::zeroed());
        }
    }
}
