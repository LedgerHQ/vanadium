pub use common::accumulator::Hasher;

#[cfg(feature = "target_native")]
mod hashers {
    use super::*;
    use ripemd::Ripemd160 as Ripemd160Real;
    use sha2::{Digest, Sha256 as Sha256Real, Sha512 as Sha512Real};

    macro_rules! impl_hash {
        ($name:ident, $real:ty, $digest_size:expr) => {
            #[derive(Clone, Debug)]
            pub struct $name {
                hasher: $real,
            }

            impl Hasher<$digest_size> for $name {
                fn new() -> Self {
                    Self {
                        hasher: <$real>::new(),
                    }
                }

                fn update(&mut self, data: &[u8]) -> &mut Self {
                    self.hasher.update(data);
                    self
                }

                fn digest(self, digest: &mut [u8; $digest_size]) {
                    digest.copy_from_slice(&self.hasher.finalize());
                }
            }
        };
    }

    impl_hash!(Sha256, Sha256Real, 32);
    impl_hash!(Sha512, Sha512Real, 64);
    impl_hash!(Ripemd160, Ripemd160Real, 20);
}

#[cfg(feature = "target_vanadium_ledger")]
mod hashers {
    use super::*;
    use crate::ecalls;
    use common::ecall_constants::HashId;

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[repr(C)]
    struct CtxSha256 {
        hash_id: HashId,
        counter: u32,
        blen: usize,
        block: [u8; 64],
        acc: [u8; 8 * 4],
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[repr(C)]
    struct CtxSha512 {
        hash_id: HashId,
        counter: u32,
        blen: usize,
        block: [u8; 128],
        acc: [u8; 8 * 8],
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[repr(C)]
    struct CtxRipemd160 {
        hash_id: HashId,
        counter: u32,
        blen: usize,
        block: [u8; 64],
        acc: [u8; 5 * 4],
    }

    macro_rules! impl_hash {
        ($name:ident, $ctx:ident, $digest_size:expr) => {
            #[derive(Clone, PartialEq, Eq, Debug)]
            #[repr(transparent)]
            pub struct $name($ctx);

            impl Hasher<$digest_size> for $name {
                fn new() -> Self {
                    let mut res = core::mem::MaybeUninit::<Self>::uninit();

                    unsafe {
                        ecalls::hash_init(HashId::$name as u32, res.as_mut_ptr() as *mut u8);
                        res.assume_init()
                    }
                }

                fn update(&mut self, data: &[u8]) -> &mut Self {
                    if 0 == ecalls::hash_update(
                        HashId::$name as u32,
                        &mut self.0 as *mut _ as *mut u8,
                        data.as_ptr(),
                        data.len(),
                    ) {
                        panic!("Failed to update hash");
                    }

                    self
                }

                fn digest(mut self, digest: &mut [u8; $digest_size]) {
                    if digest.len() != $digest_size {
                        panic!("Invalid digest size");
                    }
                    if 0 == ecalls::hash_final(
                        HashId::$name as u32,
                        &mut self.0 as *mut _ as *mut u8,
                        digest.as_mut_ptr(),
                    ) {
                        panic!("Failed to finalize hash");
                    }
                }
            }
        };
    }

    impl_hash!(Sha256, CtxSha256, 32);
    impl_hash!(Sha512, CtxSha512, 64);
    impl_hash!(Ripemd160, CtxRipemd160, 20);
}

pub use hashers::{Ripemd160, Sha256, Sha512};
