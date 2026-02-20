pub use common::accumulator::Hasher;

mod hashers {
    use super::*;
    use crate::ecalls;
    use common::ecall_constants::{HashId, CTX_RIPEMD160_SIZE, CTX_SHA256_SIZE, CTX_SHA512_SIZE};

    /// Generates a hash wrapper backed by an opaque byte buffer of `$ctx_size`
    /// bytes. The buffer is passed to the `hash_init`, `hash_update`, and
    /// `hash_final` ecalls, which fill it with implementation-specific state,
    /// which can be different for each target.
    macro_rules! impl_hash {
        ($name:ident, $ctx_size:expr, $digest_size:expr) => {
            #[derive(Clone, Debug)]
            #[repr(C)]
            pub struct $name {
                ctx: [u8; $ctx_size],
            }

            impl Hasher<$digest_size> for $name {
                fn new() -> Self {
                    let mut res = core::mem::MaybeUninit::<Self>::zeroed();

                    unsafe {
                        ecalls::hash_init(HashId::$name as u32, res.as_mut_ptr() as *mut u8);
                        res.assume_init()
                    }
                }

                fn update(&mut self, data: &[u8]) -> &mut Self {
                    // SAFETY: ctx was initialized by hash_init in new() with the same HashId;
                    // data is a valid slice provided by the caller.
                    if 0 == unsafe {
                        ecalls::hash_update(
                            HashId::$name as u32,
                            self.ctx.as_mut_ptr(),
                            data.as_ptr(),
                            data.len(),
                        )
                    } {
                        panic!("Failed to update hash");
                    }

                    self
                }

                fn digest(mut self, digest: &mut [u8; $digest_size]) {
                    // SAFETY: ctx was initialized by hash_init in new() with the same HashId;
                    // digest is a valid mutable reference of the correct size.
                    if 0 == unsafe {
                        ecalls::hash_final(
                            HashId::$name as u32,
                            self.ctx.as_mut_ptr(),
                            digest.as_mut_ptr(),
                        )
                    } {
                        panic!("Failed to finalize hash");
                    }
                }
            }
        };
    }

    impl_hash!(Sha256, CTX_SHA256_SIZE, 32);
    impl_hash!(Sha512, CTX_SHA512_SIZE, 64);
    impl_hash!(Ripemd160, CTX_RIPEMD160_SIZE, 20);
}

pub use hashers::{Ripemd160, Sha256, Sha512};
