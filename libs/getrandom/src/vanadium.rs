use core::mem::MaybeUninit;
use crate::Error;

/// The most bytes that a single `get_random_bytes` ECALL returns.
const MAX_CHUNK_SIZE: usize = 256;

pub fn getrandom_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    for chunk in dest.chunks_mut(MAX_CHUNK_SIZE) {
        // Avoid pointer invalidation
        let len = chunk.len();
        // SOUNDNESS: the pointer and length are valid and live during the call
        let ret = unsafe { vanadium_ecalls::get_random_bytes(chunk.as_mut_ptr().cast(), len) };
        if ret == 0 {
            return Err(Error::UNEXPECTED);
        }
    }
    Ok(())
}
