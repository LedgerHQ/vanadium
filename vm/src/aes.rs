use alloc::vec::Vec;
use core::fmt;
use ledger_device_sdk::sys::{cx_aes_enc_block, cx_aes_init_key_no_throw, cx_aes_key_t, CX_OK};

/// AES errors that can occur during cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// Key initialization failed
    KeyInitFailed,
    /// Invalid input length (must be a multiple of 16 bytes for block operations)
    InvalidInputLength,
    /// Encryption operation failed
    EncryptionFailed,
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AesError::KeyInitFailed => write!(f, "AES key initialization failed"),
            AesError::InvalidInputLength => write!(
                f,
                "Invalid input length (must be a multiple of 16 bytes for block operations)"
            ),
            AesError::EncryptionFailed => write!(f, "AES encryption operation failed"),
        }
    }
}

/// Wrapper for the AES key from ledger_device_sdk::sys
pub struct AesKey {
    key: cx_aes_key_t,
}

impl AesKey {
    /// Create a new random 128-bit AES key.
    ///
    /// # Returns
    ///
    /// A new AesKey instance or an error if initialization fails
    pub fn new_random() -> Result<Self, AesError> {
        let mut key_data = [0u8; 16];
        unsafe {
            if CX_OK
                != ledger_device_sdk::sys::cx_get_random_bytes(
                    key_data.as_mut_ptr() as *mut core::ffi::c_void,
                    key_data.len(),
                )
            {
                return Err(AesError::KeyInitFailed);
            }
        }

        let mut key = unsafe { core::mem::zeroed::<cx_aes_key_t>() };
        let result = unsafe {
            cx_aes_init_key_no_throw(key_data.as_ptr(), key_data.len() as usize, &mut key)
        };

        if result != 0 {
            return Err(AesError::KeyInitFailed);
        }

        Ok(Self { key })
    }

    /// Create a new AES-128 key from the provided key data.
    ///
    /// # Arguments
    ///
    /// * `key_data` - The key material to use (must be 16 bytes)
    ///
    /// # Returns
    ///
    /// A new AesKey instance or an error if initialization fails
    #[cfg(feature = "run_tests")]
    pub fn from_slice(key_data: &[u8]) -> Result<Self, AesError> {
        // Only accept valid AES key sizes: 16 bytes (128 bits)
        if key_data.len() != 16 {
            return Err(AesError::InvalidInputLength);
        }

        let mut key = unsafe { core::mem::zeroed::<cx_aes_key_t>() };
        let result = unsafe {
            cx_aes_init_key_no_throw(key_data.as_ptr(), key_data.len() as usize, &mut key)
        };

        if result != 0 {
            return Err(AesError::KeyInitFailed);
        }

        Ok(Self { key })
    }

    /// Encrypt a single 16-byte block
    ///
    /// # Arguments
    ///
    /// * `input` - The 16-byte plaintext block to encrypt
    ///
    /// # Returns
    ///
    /// A 16-byte ciphertext block or an error
    pub fn encrypt_block(&self, input: &[u8]) -> Result<[u8; 16], AesError> {
        if input.len() != 16 {
            return Err(AesError::InvalidInputLength);
        }

        let mut output = [0u8; 16];

        let result = unsafe { cx_aes_enc_block(&self.key, input.as_ptr(), output.as_mut_ptr()) };

        if result != 0 {
            return Err(AesError::EncryptionFailed);
        }

        Ok(output)
    }
}

/// AES-CTR mode implementation that encapsulates the state for Counter mode operations
pub struct AesCtr {
    /// The AES key
    key: AesKey,
    /// A 12-byte nonce, incremented for each new message
    nonce: [u8; 12],
}

impl AesCtr {
    /// Create a new AES-CTR instance with the given key, and initialize the nonce to 0.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use
    ///
    /// # Returns
    ///
    /// A new AesCtr instance
    pub fn new(key: AesKey) -> Self {
        Self {
            key,
            nonce: [0u8; 12],
        }
    }

    /// Create a new AES-CTR instance with the given key, and initialize the nonce to the given value
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use
    /// * `nonce` - The nonce to use
    ///
    /// # Returns
    ///
    /// A new AesCtr instance
    #[cfg(feature = "run_tests")]
    pub fn new_with_nonce(key: AesKey, nonce: [u8; 12]) -> Self {
        Self { key, nonce }
    }

    /// Increment a counter block by 1
    #[inline]
    fn increment_be_slice(counter: &mut [u8]) {
        for i in (0..counter.len()).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }

    /// Process data with AES-CTR using the provided counter block
    ///
    /// # Arguments
    ///
    /// * `input` - The input data to process
    /// * `counter` - The initial counter block to use
    ///
    /// # Returns
    ///
    /// The processed data or an error
    fn process_with_counter(
        &self,
        input: &[u8],
        counter: &mut [u8; 16],
    ) -> Result<Vec<u8>, AesError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut output = Vec::with_capacity(input.len());

        // Process input in blocks (or partial blocks)
        for chunk in input.chunks(16) {
            // Encrypt the counter to create keystream
            let keystream = self.key.encrypt_block(counter)?;

            // XOR input with keystream to produce output
            for i in 0..chunk.len() {
                output.push(chunk[i] ^ keystream[i]);
            }

            // Increment counter for next block
            Self::increment_be_slice(counter);
        }

        Ok(output)
    }

    #[inline(always)]
    fn create_counter_block(nonce: &[u8; 12], initial_counter: u32) -> [u8; 16] {
        let mut counter_block = [0u8; 16];
        counter_block[0..12].copy_from_slice(nonce);
        counter_block[12..16].copy_from_slice(&initial_counter.to_be_bytes());
        counter_block
    }

    #[inline(always)]
    fn _encrypt_with_initial_counter(
        &mut self,
        plaintext: &[u8],
        initial_counter: u32,
    ) -> Result<([u8; 12], Vec<u8>), AesError> {
        // Copy the nonce to return it with the cyphertext
        let nonce = self.nonce.clone();

        // Increment the nonce for the next message
        Self::increment_be_slice(&mut self.nonce);

        let mut counter_block = Self::create_counter_block(&nonce, initial_counter);

        Ok((
            nonce,
            self.process_with_counter(plaintext, &mut counter_block)?,
        ))
    }

    /// Encrypt data using AES in Counter (CTR) mode
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext data to encrypt
    ///
    /// # Returns
    ///
    /// A pair of the initial value of the counter block and the ciphertext, or an error
    #[inline]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), AesError> {
        self._encrypt_with_initial_counter(plaintext, 0)
    }

    #[inline]
    fn _decrypt_with_initial_counter(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        initial_counter: u32,
    ) -> Result<Vec<u8>, AesError> {
        let mut counter_block = Self::create_counter_block(&nonce, initial_counter);
        self.process_with_counter(ciphertext, &mut counter_block)
    }

    /// Decrypt data using AES in Counter (CTR) mode
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce the ciphertext was generated with
    /// * `ciphertext` - The ciphertext data to decrypt
    ///
    /// # Returns
    ///
    /// The decrypted plaintext or an error
    #[inline]
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
        self._decrypt_with_initial_counter(nonce, ciphertext, 0)
    }

    /// We make these function public only for tests, so we can use test vectors with an arbitrary counter block
    #[cfg(feature = "run_tests")]
    pub fn encrypt_with_initial_counter(
        &mut self,
        plaintext: &[u8],
        initial_counter: u32,
    ) -> Result<([u8; 12], Vec<u8>), AesError> {
        self._encrypt_with_initial_counter(plaintext, initial_counter)
    }

    #[cfg(feature = "run_tests")]
    pub fn decrypt_with_initial_counter(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        initial_counter: u32,
    ) -> Result<Vec<u8>, AesError> {
        let mut counter_block = Self::create_counter_block(&nonce, initial_counter);
        self.process_with_counter(ciphertext, &mut counter_block)
    }
}
