use common::accumulator::{Hasher, ResettableHasher};
use ledger_device_sdk::hash::HashInit;

pub struct Sha256Hasher(ledger_device_sdk::hash::sha2::Sha2_256);

impl Hasher<32> for Sha256Hasher {
    #[inline]
    fn new() -> Self {
        Self(ledger_device_sdk::hash::sha2::Sha2_256::new())
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data).unwrap();
        self
    }

    #[inline]
    fn digest(mut self, out: &mut [u8; 32]) {
        self.0.finalize(out).unwrap();
    }
}

impl ResettableHasher<32> for Sha256Hasher {
    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    fn digest_inplace<'a, 'b>(&'a mut self, out: &'b mut [u8; 32]) {
        self.0.finalize(out).unwrap();
    }
}
