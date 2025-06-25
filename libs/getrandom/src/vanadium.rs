use core::mem::MaybeUninit;
use crate::Error;

pub fn getrandom_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    // Avoid pointer invalidation
    let len = dest.len();
    // SOUNDNESS: the pointer and length are valid and live during the call
    let ret = unsafe { vanadium_ecalls::get_random_bytes(dest.as_mut_ptr().cast(), len) };
    if ret != 0 {
        Ok(())
    } else {
        Err(Error::UNEXPECTED)
    }
}
