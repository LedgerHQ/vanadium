use crate::ecalls;
pub use common::constants::STORAGE_SLOT_SIZE;

/// Reads a 32-byte value from the specified storage slot.
///
/// # Parameters
/// - `slot_index`: The index of the storage slot to read (0 to n_storage_slots-1).
///
/// # Returns
/// A `Result` containing the 32-byte array on success, or an error message on failure.
///
/// # Examples
/// ```no_run
/// use vanadium_app_sdk::storage::read_slot;
///
/// match read_slot(0) {
///     Ok(data) => println!("Read data: {:?}", data),
///     Err(e) => eprintln!("Error reading storage: {}", e),
/// }
/// ```
pub fn read_slot(slot_index: u32) -> Result<[u8; STORAGE_SLOT_SIZE], &'static str> {
    let mut buffer = [0u8; STORAGE_SLOT_SIZE];
    // SAFETY: buffer is a valid [u8; STORAGE_SLOT_SIZE] on the stack.
    let result = unsafe { ecalls::storage_read(slot_index, buffer.as_mut_ptr(), STORAGE_SLOT_SIZE) };

    if result == 1 {
        Ok(buffer)
    } else {
        Err("Failed to read from storage slot")
    }
}

/// Writes a 32-byte value to the specified storage slot.
///
/// # Parameters
/// - `slot_index`: The index of the storage slot to write (0 to n_storage_slots-1).
/// - `data`: A reference to the 32-byte array to write.
///
/// # Returns
/// A `Result` indicating success or an error message on failure.
///
/// # Examples
/// ```no_run
/// use vanadium_app_sdk::storage::write_slot;
///
/// let data = [0u8; 32];
/// match write_slot(0, &data) {
///     Ok(()) => println!("Data written successfully"),
///     Err(e) => eprintln!("Error writing storage: {}", e),
/// }
/// ```
pub fn write_slot(slot_index: u32, data: &[u8; STORAGE_SLOT_SIZE]) -> Result<(), &'static str> {
    // SAFETY: data is a valid reference to a [u8; STORAGE_SLOT_SIZE] array.
    let result = unsafe { ecalls::storage_write(slot_index, data.as_ptr(), STORAGE_SLOT_SIZE) };

    if result == 1 {
        Ok(())
    } else {
        Err("Failed to write to storage slot")
    }
}
