use alloc::{vec, vec::Vec};

use crate::ecalls;

/// Generates cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    // generate randomness in chunks of at most 256 bytes
    let max_chunk_size = 256;
    let mut offset = 0;
    while offset < len {
        let size = usize::min(max_chunk_size, len - offset);
        // SAFETY: bytes[offset..] is a valid slice of at least `size` writable bytes.
        let res = unsafe { ecalls::get_random_bytes(bytes[offset..].as_mut_ptr(), size) };
        if res == 0 {
            panic!("Failed to generate random bytes");
        }
        offset += size
    }
    bytes
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let len = 64;
        let random_bytes = random_bytes(len);
        assert_eq!(random_bytes.len(), len);
        // Check that every chunk of 8 bytes is not all zeroes
        // (which would be unlikely in a reasonable random generator)
        for chunk in random_bytes.chunks(8) {
            assert!(!chunk.iter().all(|&b| b == 0), "Found all zeroes in chunk");
        }
    }
}
