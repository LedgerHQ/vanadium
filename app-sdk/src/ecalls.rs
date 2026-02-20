#[cfg(feature = "target_vanadium_ledger")]
use crate::ecalls_riscv as ecalls_module;

#[cfg(feature = "target_native")]
use crate::ecalls_native as ecalls_module;

use common::ux::EventData;

/// Macro to forward unsafe function calls to the `ecalls_module`.
/// This approach ensures that the actual implementations are consistent across native and riscv targets.
/// Functions forwarded by this macro involve raw pointers. See the `# Safety` section on each
/// function for the exact caller requirements.
macro_rules! forward_to_ecall {
    (
        $(
            $(#[$meta:meta])*
            pub unsafe fn $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) $(-> $ret:ty)? ;
        )*
    ) => {
        $(
            $(#[$meta])*
            #[inline(always)]
            pub unsafe fn $name($($arg : $ty),*) $(-> $ret)? {
                ecalls_module::$name($($arg),*)
            }
        )*
    }
}

// The few functions that do not require `unsafe` are defined here without the macro.

/// Exits the V-App with the specified status code.
///
/// # Parameters
/// - `status`: The exit status code.
///
/// # Returns
/// This function does not return.
#[inline(always)]
pub fn exit(status: i32) -> ! {
    ecalls_module::exit(status)
}

/// Retrieves device information based on the requested property type.
///
/// # Parameters
/// - `property_id`: The property identifier
///
/// # Returns
/// The requested property value. It will panic if the property is not supported.
#[inline(always)]
pub fn get_device_property(property_id: u32) -> u32 {
    ecalls_module::get_device_property(property_id)
}

/// Retrieves the fingerprint for the master public key for the specified curve.
///
/// # Parameters
/// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
///
/// # Returns
/// The master fingerprint as a 32-bit unsigned integer, computed as the first 32 bits of
/// `ripemd160(sha256(pk))`, where `pk` is the compressed public key.
///
/// # Panics
/// This function panics if the curve is not supported.
#[inline(always)]
pub fn get_master_fingerprint(curve: u32) -> u32 {
    ecalls_module::get_master_fingerprint(curve)
}

forward_to_ecall! {
    /// Prints a fatal error message and exits the V-App.
    ///
    /// # Parameters
    /// - `msg`: Pointer to the error message, that must be a valid UTF-8 string.
    /// - `size`: Size of the error message.
    ///
    /// # Returns
    /// This function does not return.
    ///
    /// # Safety
    /// - `msg` must be a valid pointer to at least `size` bytes of readable memory.
    /// - The bytes at `[msg, msg+size)` must be valid UTF-8.
    pub unsafe fn fatal(msg: *const u8, size: usize) -> !;

    /// Sends a buffer to the host.
    ///
    /// # Parameters
    /// - `buffer`: Pointer to the buffer to send.
    /// - `size`: Size of the buffer.
    ///
    /// # Safety
    /// - `buffer` must be a valid pointer to at least `size` bytes of readable memory.
    pub unsafe fn xsend(buffer: *const u8, size: usize);

    /// Receives a buffer from the host.
    ///
    /// # Parameters
    /// - `buffer`: Pointer to the buffer to store received data.
    /// - `max_size`: Maximum size of the buffer.
    ///
    /// # Returns
    /// The number of bytes received.
    ///
    /// # Safety
    /// - `buffer` must be a valid pointer to at least `max_size` bytes of writable memory.
    pub unsafe fn xrecv(buffer: *mut u8, max_size: usize) -> usize;

    /// Sends a buffer to print to the host.
    ///
    /// # Parameters
    /// - `buffer`: Pointer to the buffer to print, that must be a valid UTF-8 string.
    /// - `size`: Size of the buffer.
    ///
    /// # Safety
    /// - `buffer` must be a valid pointer to at least `size` bytes of readable memory.
    /// - The bytes at `[buffer, buffer+size)` must be valid UTF-8.
    pub unsafe fn print(buffer: *const u8, size: usize);

    /// Waits for the next event.
    ///
    /// # Parameters
    /// - `data`: Pointer to a 16-byte buffer to receive the event data (if any).
    /// # Returns
    /// The event code.
    ///
    /// # Safety
    /// - `data` must be a valid pointer to a writable buffer of at least
    ///   `size_of::<EventData>()` (16) bytes.
    pub unsafe fn get_event(data: *mut EventData) -> u32;

    /// Reads a 32-byte value from the specified storage slot.
    ///
    /// # Parameters
    /// - `slot_index`: The index of the storage slot to read (0 to n_storage_slots-1).
    /// - `buffer`: Pointer to a 32-byte buffer to store the read value.
    /// - `buffer_size`: Size of the buffer (must be 32).
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `buffer` must be a valid pointer to at least `buffer_size` bytes of writable memory.
    pub unsafe fn storage_read(slot_index: u32, buffer: *mut u8, buffer_size: usize) -> u32;

    /// Writes a 32-byte value to the specified storage slot.
    ///
    /// # Parameters
    /// - `slot_index`: The index of the storage slot to write (0 to n_storage_slots-1).
    /// - `buffer`: Pointer to the 32-byte buffer containing the value to write.
    /// - `buffer_size`: Size of the buffer (must be 32).
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `buffer` must be a valid pointer to at least `buffer_size` bytes of readable memory.
    pub unsafe fn storage_write(slot_index: u32, buffer: *const u8, buffer_size: usize) -> u32;

    /// Shows a page.
    ///
    /// # Parameters
    /// - `page_desc`: Pointer to the serialized description of a page.
    /// - `page_desc_len`: Length of the serialized description of a page.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `page_desc` must be a valid pointer to at least `page_desc_len` bytes of readable memory.
    pub unsafe fn show_page(page_desc: *const u8, page_desc_len: usize) -> u32;

    /// Shows a step.
    ///
    /// # Parameters
    /// - `step_desc`: Pointer to the serialized description of a step.
    /// - `step_desc_len`: Length of the serialized description of a step.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `step_desc` must be a valid pointer to at least `step_desc_len` bytes of readable memory.
    pub unsafe fn show_step(step_desc: *const u8, step_desc_len: usize) -> u32;

    /// Computes the remainder of dividing `n` by `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `n`: Pointer to the dividend buffer.
    /// - `len`: Length of `r` and `n`.
    /// - `m`: Pointer to the divisor buffer.
    /// - `len_m`: Length of `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least `len` bytes of writable memory.
    /// - `n` must be a valid pointer to at least `len` bytes of readable memory.
    /// - `m` must be a valid pointer to at least `len_m` bytes of readable memory.
    pub unsafe fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> u32;

    /// Adds two big numbers `a` and `b` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the first addend buffer.
    /// - `b`: Pointer to the second addend buffer.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, `b`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least `len` bytes of writable memory.
    /// - `a`, `b`, and `m` must each be a valid pointer to at least `len` bytes of readable memory.
    pub unsafe fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;

    /// Subtracts two big numbers `a` and `b` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the minuend buffer.
    /// - `b`: Pointer to the subtrahend buffer.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, `b`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least `len` bytes of writable memory.
    /// - `a`, `b`, and `m` must each be a valid pointer to at least `len` bytes of readable memory.
    pub unsafe fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;

    /// Multiplies two big numbers `a` and `b` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the first factor buffer.
    /// - `b`: Pointer to the second factor buffer.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, `b`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least `len` bytes of writable memory.
    /// - `a`, `b`, and `m` must each be a valid pointer to at least `len` bytes of readable memory.
    pub unsafe fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;

    /// Computes `a` to the power of `e` modulo `m`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the base buffer.
    /// - `e`: Pointer to the exponent buffer.
    /// - `len_e`: Length of `e`.
    /// - `m`: Pointer to the modulus buffer.
    /// - `len`: Length of `r`, `a`, and `m`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least `len` bytes of writable memory.
    /// - `a` must be a valid pointer to at least `len` bytes of readable memory.
    /// - `e` must be a valid pointer to at least `len_e` bytes of readable memory.
    /// - `m` must be a valid pointer to at least `len` bytes of readable memory.
    pub unsafe fn bn_powm(
        r: *mut u8,
        a: *const u8,
        e: *const u8,
        len_e: usize,
        m: *const u8,
        len: usize,
    ) -> u32;

    /// Computes the modular inverse of `a` modulo `p`, storing the result in `r`.
    /// The modulus `p` must be a prime number. The result is undefined if `p` is not prime.
    ///
    /// # Parameters
    /// - `r`: Pointer to the result buffer.
    /// - `a`: Pointer to the value to invert.
    /// - `p`: Pointer to the prime modulus buffer.
    /// - `len`: Length of `r`, `a`, and `p`.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least `len` bytes of writable memory.
    /// - `a` and `p` must each be a valid pointer to at least `len` bytes of readable memory.
    pub unsafe fn bn_modinv_prime(r: *mut u8, a: *const u8, p: *const u8, len: usize) -> u32;

    /// Derives a hierarchical deterministic (HD) node, made of the private key and the corresponding chain code.
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `path`: Pointer to the derivation path array.
    /// - `path_len`: Length of the derivation path array.
    /// - `privkey`: Pointer to the buffer to store the derived private key.
    /// - `chain_code`: Pointer to the buffer to store the derived chain code.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Panics
    /// This function panics if the curve is not supported.
    ///
    /// # Safety
    /// - `path` must be a valid pointer to at least `path_len` `u32` values of readable memory.
    /// - `privkey` must be a valid pointer to at least 32 bytes of writable memory.
    /// - `chain_code` must be a valid pointer to at least 32 bytes of writable memory.
    pub unsafe fn derive_hd_node(
        curve: u32,
        path: *const u32,
        path_len: usize,
        privkey: *mut u8,
        chain_code: *mut u8,
    ) -> u32;

    /// Derives the root SLIP-21 node m/<label1>/<label2>/.../<labelN>, saving it to the provided 64-byte buffer.
    /// The last 32 bytes of the node are the SLIP-21 key, while the first 32 bytes are the chain code.
    ///
    /// The `labels` buffer (with length `labels_len`) must contain the concatenated labels, each prefixed by its length.
    /// `labels_len` must be at most 256 bytes. Each of the labels must not be longer than 252 bytes.
    ///
    /// Ledger-specific limitations:
    /// - The `labels` buffer must not be empty (no master key derivation).
    /// - Each label must not contain a '/' character.
    ///
    /// # Parameters
    /// - `labels`: Pointer to the concatenated, length-prefixed labels used for SLIP-21 derivation.
    /// - `labels_len`: Length of the labels buffer.
    /// - `out`: Pointer to the buffer where the result will be written. It must be at least 64 bytes long.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `labels` must be a valid pointer to at least `labels_len` bytes of readable memory.
    /// - `out` must be a valid pointer to at least 64 bytes of writable memory.
    pub unsafe fn derive_slip21_node(labels: *const u8, labels_len: usize, out: *mut u8) -> u32;

    /// Adds two elliptic curve points `p` and `q`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `r`: Pointer to the result buffer.
    /// - `p`: Pointer to the first point buffer.
    /// - `q`: Pointer to the second point buffer.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least 65 bytes of writable memory.
    /// - `p` and `q` must each be a valid pointer to at least 65 bytes of readable memory.
    pub unsafe fn ecfp_add_point(curve: u32, r: *mut u8, p: *const u8, q: *const u8) -> u32;

    /// Multiplies an elliptic curve point `p` by a scalar `k`, storing the result in `r`.
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `r`: Pointer to the result buffer.
    /// - `p`: Pointer to the point buffer.
    /// - `k`: Pointer to the scalar buffer.
    /// - `k_len`: Length of the scalar buffer.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `r` must be a valid pointer to at least 65 bytes of writable memory.
    /// - `p` must be a valid pointer to at least 65 bytes of readable memory.
    /// - `k` must be a valid pointer to at least `k_len` bytes of readable memory.
    pub unsafe fn ecfp_scalar_mult(curve: u32, r: *mut u8, p: *const u8, k: *const u8, k_len: usize) -> u32;

    /// Generates `size` random bytes using a cryptographically secure random number generator,
    /// and writes them to the provided buffer.
    ///
    /// # Parameters
    /// - `buffer`: Pointer to the buffer where the random bytes will be written.
    /// - `size`: The number of random bytes to generate.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `buffer` must be a valid pointer to at least `size` bytes of writable memory.
    pub unsafe fn get_random_bytes(buffer: *mut u8, size: usize) -> u32;

    /// Signs a message hash using ECDSA.
    ///
    /// # Warning
    /// **This ecall is unstable and subject to change in future versions.**
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `mode`: The signing mode. Only `RFC6979` is supported.
    /// - `hash_id`: The hash identifier. Only `Sha256` is supported.
    /// - `privkey`: Pointer to the private key buffer.
    /// - `msg_hash`: Pointer to the message hash buffer.
    /// - `signature`: Pointer to the buffer to store the signature.
    ///
    /// # Returns
    /// The length of the signature on success, 0 on error.
    ///
    /// # Safety
    /// - `privkey` must be a valid pointer to at least 32 bytes of readable memory.
    /// - `msg_hash` must be a valid pointer to at least 32 bytes of readable memory.
    /// - `signature` must be a valid pointer to at least 72 bytes of writable memory
    ///   (maximum length of a DER-encoded ECDSA signature for secp256k1).
    pub unsafe fn ecdsa_sign(
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: *const u8,
        msg_hash: *const u8,
        signature: *mut u8,
    ) -> usize;

    /// Verifies an ECDSA signature for a message hash.
    ///
    /// # Warning
    /// **This ecall is unstable and subject to change in future versions.**
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `pubkey`: Pointer to the public key buffer.
    /// - `msg_hash`: Pointer to the message hash buffer.
    /// - `signature`: Pointer to the signature buffer.
    /// - `signature_len`: Length of the signature buffer.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `pubkey` must be a valid pointer to at least 65 bytes of readable memory.
    /// - `msg_hash` must be a valid pointer to at least 32 bytes of readable memory.
    /// - `signature` must be a valid pointer to at least `signature_len` bytes of readable memory.
    pub unsafe fn ecdsa_verify(
        curve: u32,
        pubkey: *const u8,
        msg_hash: *const u8,
        signature: *const u8,
        signature_len: usize,
    ) -> u32;

    /// Signs a message using Schnorr signature.
    ///
    /// # Warning
    /// **This ecall is unstable and subject to change in future versions.**
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `mode`: The signing mode. Only `BIP340` is supported.
    /// - `hash_id`: The hash identifier.
    /// - `privkey`: Pointer to the private key buffer.
    /// - `msg`: Pointer to the message buffer.
    /// - `msg_len`: Length of the message buffer.
    /// - `signature`: Pointer to the buffer to store the signature.
    /// - `entropy`: Additional entropy to use during signing or null if not needed
    ///
    /// # Returns
    /// The length of the signature (always 64) on success, 0 on error.
    ///
    /// # Safety
    /// - `privkey` must be a valid pointer to at least 32 bytes of readable memory.
    /// - `msg` must be a valid pointer to at least `msg_len` bytes of readable memory.
    /// - `signature` must be a valid pointer to at least 64 bytes of writable memory.
    /// - `entropy` must either be null, or a valid pointer to exactly 32 bytes of readable memory.
    pub unsafe fn schnorr_sign(
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: *const u8,
        msg: *const u8,
        msg_len: usize,
        signature: *mut u8,
        entropy: *const [u8; 32],
    ) -> usize;

    /// Verifies a Schnorr signature for a message.
    ///
    /// # Warning
    /// **This ecall is unstable and subject to change in future versions.**
    ///
    /// # Parameters
    /// - `curve`: The elliptic curve identifier. Currently only `Secp256k1` is supported.
    /// - `mode`: The verification mode. It must match the mode used for signing.
    /// - `hash_id`: The hash identifier. Only `Sha256` is supported.
    /// - `pubkey`: Pointer to the public key buffer.
    /// - `msg`: Pointer to the message buffer.
    /// - `msg_len`: Length of the message buffer.
    /// - `signature`: Pointer to the signature buffer.
    /// - `signature_len`: Length of the signature buffer.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `pubkey` must be a valid pointer to at least 32 bytes of readable memory
    ///   (x-only BIP-340 public key).
    /// - `msg` must be a valid pointer to at least `msg_len` bytes of readable memory.
    /// - `signature` must be a valid pointer to at least `signature_len` bytes of readable memory.
    pub unsafe fn schnorr_verify(
        curve: u32,
        mode: u32,
        hash_id: u32,
        pubkey: *const u8,
        msg: *const u8,
        msg_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> u32;

    /// Initializes a hash context for the specified hash algorithm.
    ///
    /// # Parameters
    /// - `hash_id`: The hash algorithm identifier (see [`common::ecall_constants::HashId`]).
    /// - `ctx`: Pointer to the opaque context buffer to initialize. The buffer must be at
    ///   least as large as the corresponding `CTX_*_SIZE` constant defined in
    ///   [`common::ecall_constants`] for the given `hash_id`.
    ///
    /// # Safety
    /// - `ctx` must be a valid pointer to a writable buffer of at least the required size for
    ///   the given `hash_id` (see `CTX_*_SIZE` constants in [`common::ecall_constants`]).
    /// - `hash_id` must be a supported hash algorithm identifier; passing an unsupported value
    ///   results in undefined behaviour.
    pub unsafe fn hash_init(hash_id: u32, ctx: *mut u8);

    /// Updates a hash context with additional input data.
    ///
    /// # Parameters
    /// - `hash_id`: The hash algorithm identifier (see [`common::ecall_constants::HashId`]).
    /// - `ctx`: Pointer to the opaque context buffer previously initialized by [`hash_init`].
    ///   The buffer must be at least as large as the corresponding `CTX_*_SIZE` constant
    ///   defined in [`common::ecall_constants`] for the given `hash_id`.
    /// - `data`: Pointer to the input data buffer.
    /// - `len`: Length of the input data.
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `ctx` must be a valid pointer to a writable buffer that was previously initialized via
    ///   [`hash_init`] with the same `hash_id`. Passing an uninitialized context or a
    ///   `hash_id` that differs from the one used during initialization is undefined behaviour.
    /// - `data` must be a valid pointer to at least `len` bytes of readable memory.
    pub unsafe fn hash_update(hash_id: u32, ctx: *mut u8, data: *const u8, len: usize) -> u32;

    /// Finalizes a hash computation and writes the digest to the output buffer.
    ///
    /// After calling this function the context is consumed and must not be reused
    /// without a new call to [`hash_init`].
    ///
    /// # Parameters
    /// - `hash_id`: The hash algorithm identifier (see [`common::ecall_constants::HashId`]).
    /// - `ctx`: Pointer to the opaque context buffer previously initialized by [`hash_init`].
    ///   The buffer must be at least as large as the corresponding `CTX_*_SIZE` constant
    ///   defined in [`common::ecall_constants`] for the given `hash_id`.
    /// - `digest`: Pointer to the output buffer where the digest will be written. The buffer
    ///   must be large enough to hold the digest for the given `hash_id` (e.g. 32 bytes for
    ///   SHA-256, 64 bytes for SHA-512, 20 bytes for RIPEMD-160).
    ///
    /// # Returns
    /// 1 on success, 0 on error.
    ///
    /// # Safety
    /// - `ctx` must be a valid pointer to a writable buffer that was previously initialized via
    ///   [`hash_init`] with the same `hash_id`. Passing an uninitialized context or a
    ///   `hash_id` that differs from the one used during initialization is undefined behaviour.
    /// - `digest` must be a valid pointer to a writable buffer large enough to hold the digest
    ///   for the given `hash_id`.
    pub unsafe fn hash_final(hash_id: u32, ctx: *mut u8, digest: *mut u8) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_data_size() {
        // make sure that the size of the EventData union is exactly 16 bytes
        assert_eq!(core::mem::size_of::<EventData>(), 16);
    }
}
