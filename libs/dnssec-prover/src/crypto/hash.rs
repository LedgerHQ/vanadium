//! Simple wrapper around various hash options to provide a single enum which can calculate
//! different hashes.

#[cfg(not(dnssec_prover_c_hashers))]
mod imp {
	use bitcoin_hashes::Hash;
	use bitcoin_hashes::HashEngine as _;
	use bitcoin_hashes::sha1::Hash as Sha1;
	use bitcoin_hashes::sha256::Hash as Sha256;
	use bitcoin_hashes::sha384::Hash as Sha384;
	use bitcoin_hashes::sha512::Hash as Sha512;

	pub(crate) enum Hasher {
		Sha1(<Sha1 as Hash>::Engine),
		Sha256(<Sha256 as Hash>::Engine),
		Sha384(<Sha384 as Hash>::Engine),
		Sha512(<Sha512 as Hash>::Engine),
	}

	pub(crate) enum HashResult {
		Sha1(Sha1),
		Sha256(Sha256),
		Sha384(Sha384),
		Sha512(Sha512),
	}

	impl AsRef<[u8]> for HashResult {
		fn as_ref(&self) -> &[u8] {
			match self {
				HashResult::Sha1(hash) => hash.as_ref(),
				HashResult::Sha256(hash) => hash.as_ref(),
				HashResult::Sha384(hash) => hash.as_ref(),
				HashResult::Sha512(hash) => hash.as_ref(),
			}
		}
	}

	impl Hasher {
		pub(crate) fn sha1() -> Hasher { Hasher::Sha1(Sha1::engine()) }
		pub(crate) fn sha256() -> Hasher { Hasher::Sha256(Sha256::engine()) }
		pub(crate) fn sha384() -> Hasher { Hasher::Sha384(Sha384::engine()) }
		pub(crate) fn sha512() -> Hasher { Hasher::Sha512(Sha512::engine()) }

		pub(crate) fn update(&mut self, buf: &[u8]) {
			match self {
				Hasher::Sha1(hasher) => hasher.input(buf),
				Hasher::Sha256(hasher) => hasher.input(buf),
				Hasher::Sha384(hasher) => hasher.input(buf),
				Hasher::Sha512(hasher) => hasher.input(buf),
			}
		}

		pub(crate) fn finish(self) -> HashResult {
			match self {
				Hasher::Sha1(hasher) => HashResult::Sha1(Sha1::from_engine(hasher)),
				Hasher::Sha256(hasher) => HashResult::Sha256(Sha256::from_engine(hasher)),
				Hasher::Sha384(hasher) => HashResult::Sha384(Sha384::from_engine(hasher)),
				Hasher::Sha512(hasher) => HashResult::Sha512(Sha512::from_engine(hasher)),
			}
		}
	}
}

#[cfg(dnssec_prover_c_hashers)]
mod imp {
	extern "C" {
		fn dnssec_prover_sha1_init() -> *mut u8;
		fn dnssec_prover_sha1_update(ctx: *mut u8, bytes: *const u8, len: usize);
		fn dnssec_prover_sha1_finish(ctx: *mut u8, out: *mut [u8; 160 / 8]);

		fn dnssec_prover_sha256_init() -> *mut u8;
		fn dnssec_prover_sha256_update(ctx: *mut u8, bytes: *const u8, len: usize);
		fn dnssec_prover_sha256_finish(ctx: *mut u8, out: *mut [u8; 256 / 8]);

		fn dnssec_prover_sha384_init() -> *mut u8;
		fn dnssec_prover_sha384_update(ctx: *mut u8, bytes: *const u8, len: usize);
		fn dnssec_prover_sha384_finish(ctx: *mut u8, out: *mut [u8; 384 / 8]);

		fn dnssec_prover_sha512_init() -> *mut u8;
		fn dnssec_prover_sha512_update(ctx: *mut u8, bytes: *const u8, len: usize);
		fn dnssec_prover_sha512_finish(ctx: *mut u8, out: *mut [u8; 512 / 8]);
	}
	pub(crate) enum Hasher {
		Sha1((*mut u8, bool)),
		Sha256((*mut u8, bool)),
		Sha384((*mut u8, bool)),
		Sha512((*mut u8, bool)),
	}

	pub(crate) enum HashResult {
		Sha1([u8; 160 / 8]),
		Sha256([u8; 256 / 8]),
		Sha384([u8; 384 / 8]),
		Sha512([u8; 512 / 8]),
	}

	impl AsRef<[u8]> for HashResult {
		fn as_ref(&self) -> &[u8] {
			match self {
				HashResult::Sha1(hash) => hash.as_ref(),
				HashResult::Sha256(hash) => hash.as_ref(),
				HashResult::Sha384(hash) => hash.as_ref(),
				HashResult::Sha512(hash) => hash.as_ref(),
			}
		}
	}

	impl Hasher {
		pub(crate) fn sha1() -> Hasher { Hasher::Sha1((unsafe { dnssec_prover_sha1_init() }, false)) }
		pub(crate) fn sha256() -> Hasher { Hasher::Sha256((unsafe { dnssec_prover_sha256_init() }, false)) }
		pub(crate) fn sha384() -> Hasher { Hasher::Sha384((unsafe { dnssec_prover_sha384_init() }, false)) }
		pub(crate) fn sha512() -> Hasher { Hasher::Sha512((unsafe { dnssec_prover_sha512_init() }, false)) }

		pub(crate) fn update(&mut self, buf: &[u8]) {
			unsafe {
				match self {
					Hasher::Sha1((hasher, _)) => dnssec_prover_sha1_update(*hasher, buf.as_ptr(), buf.len()),
					Hasher::Sha256((hasher, _)) => dnssec_prover_sha256_update(*hasher, buf.as_ptr(), buf.len()),
					Hasher::Sha384((hasher, _)) => dnssec_prover_sha384_update(*hasher, buf.as_ptr(), buf.len()),
					Hasher::Sha512((hasher, _)) => dnssec_prover_sha512_update(*hasher, buf.as_ptr(), buf.len()),
				}
			}
		}

		pub(crate) fn finish(mut self) -> HashResult {
			unsafe {
				match &mut self {
					Hasher::Sha1((hasher, finished)) => {
						let mut res = [0; 160 / 8];
						dnssec_prover_sha1_finish(*hasher, &mut res);
						*finished = true;
						HashResult::Sha1(res)
					},
					Hasher::Sha256((hasher, finished)) => {
						let mut res = [0; 256 / 8];
						dnssec_prover_sha256_finish(*hasher, &mut res);
						*finished = true;
						HashResult::Sha256(res)
					},
					Hasher::Sha384((hasher, finished)) => {
						let mut res = [0; 384 / 8];
						dnssec_prover_sha384_finish(*hasher, &mut res);
						*finished = true;
						HashResult::Sha384(res)
					},
					Hasher::Sha512((hasher, finished)) => {
						let mut res = [0; 512 / 8];
						dnssec_prover_sha512_finish(*hasher, &mut res);
						*finished = true;
						HashResult::Sha512(res)
					},
				}
			}
		}
	}

	impl Drop for Hasher {
		fn drop(&mut self) {
			unsafe {
				match self {
					Hasher::Sha1((hasher, finished)) => {
						if !*finished {
							let mut res = [0; 160 / 8];
							dnssec_prover_sha1_finish(*hasher, &mut res);
						}
					},
					Hasher::Sha256((hasher, finished)) => {
						if !*finished {
							let mut res = [0; 256 / 8];
							dnssec_prover_sha256_finish(*hasher, &mut res);
						}
					},
					Hasher::Sha384((hasher, finished)) => {
						if !*finished {
							let mut res = [0; 384 / 8];
							dnssec_prover_sha384_finish(*hasher, &mut res);
						}
					},
					Hasher::Sha512((hasher, finished)) => {
						if !*finished {
							let mut res = [0; 512 / 8];
							dnssec_prover_sha512_finish(*hasher, &mut res);
						}
					},
				}
			}
		}
	}

	#[cfg(dnssec_prover_c_hashers_test)]
	mod c_impls {
		use std::ffi::c_void;
		use alloc::boxed::Box;
		use bitcoin_hashes::Hash;
		use bitcoin_hashes::HashEngine as _;
		use bitcoin_hashes::sha1::Hash as Sha1;
		use bitcoin_hashes::sha256::Hash as Sha256;
		use bitcoin_hashes::sha384::Hash as Sha384;
		use bitcoin_hashes::sha512::Hash as Sha512;

		#[no_mangle]
		extern "C" fn dnssec_prover_sha1_init() -> *mut c_void {
			let engine = Box::new(Sha1::engine());
			(Box::leak(engine) as *mut <Sha1 as Hash>::Engine) as *mut c_void
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha1_update(ctx: *mut c_void, bytes: *const u8, len: usize) {
			let ptr: *mut <Sha1 as Hash>::Engine = ctx as *mut <Sha1 as Hash>::Engine;
			let slice = unsafe { core::slice::from_raw_parts(bytes, len as usize) };
			unsafe { &mut *ptr }.input(slice);
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha1_finish(ctx: *mut c_void, out: *mut [u8; 160 / 8]) {
			let ptr: *mut <Sha1 as Hash>::Engine = ctx as *mut <Sha1 as Hash>::Engine;
			let engine = unsafe { Box::from_raw(ptr) };
			let res = Sha1::from_engine(*engine).to_byte_array();
			unsafe { *out = res; }
		}

		#[no_mangle]
		extern "C" fn dnssec_prover_sha256_init() -> *mut c_void {
			let engine = Box::new(Sha256::engine());
			(Box::leak(engine) as *mut <Sha256 as Hash>::Engine) as *mut c_void
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha256_update(ctx: *mut c_void, bytes: *const u8, len: usize) {
			let ptr: *mut <Sha256 as Hash>::Engine = ctx as *mut <Sha256 as Hash>::Engine;
			let slice = unsafe { core::slice::from_raw_parts(bytes, len as usize) };
			unsafe { &mut *ptr }.input(slice);
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha256_finish(ctx: *mut c_void, out: *mut [u8; 256 / 8]) {
			let ptr: *mut <Sha256 as Hash>::Engine = ctx as *mut <Sha256 as Hash>::Engine;
			let engine = unsafe { Box::from_raw(ptr) };
			let res = Sha256::from_engine(*engine).to_byte_array();
			unsafe { *out = res; }
		}

		#[no_mangle]
		extern "C" fn dnssec_prover_sha384_init() -> *mut c_void {
			let engine = Box::new(Sha384::engine());
			(Box::leak(engine) as *mut <Sha384 as Hash>::Engine) as *mut c_void
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha384_update(ctx: *mut c_void, bytes: *const u8, len: usize) {
			let ptr: *mut <Sha384 as Hash>::Engine = ctx as *mut <Sha384 as Hash>::Engine;
			let slice = unsafe { core::slice::from_raw_parts(bytes, len as usize) };
			unsafe { &mut *ptr }.input(slice);
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha384_finish(ctx: *mut c_void, out: *mut [u8; 384 / 8]) {
			let ptr: *mut <Sha384 as Hash>::Engine = ctx as *mut <Sha384 as Hash>::Engine;
			let engine = unsafe { Box::from_raw(ptr) };
			let res = Sha384::from_engine(*engine).to_byte_array();
			unsafe { *out = res; }
		}

		#[no_mangle]
		extern "C" fn dnssec_prover_sha512_init() -> *mut c_void {
			let engine = Box::new(Sha512::engine());
			(Box::leak(engine) as *mut <Sha512 as Hash>::Engine) as *mut c_void
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha512_update(ctx: *mut c_void, bytes: *const u8, len: usize) {
			let ptr: *mut <Sha512 as Hash>::Engine = ctx as *mut <Sha512 as Hash>::Engine;
			let slice = unsafe { core::slice::from_raw_parts(bytes, len as usize) };
			unsafe { &mut *ptr }.input(slice);
		}
		#[no_mangle]
		extern "C" fn dnssec_prover_sha512_finish(ctx: *mut c_void, out: *mut [u8; 512 / 8]) {
			let ptr: *mut <Sha512 as Hash>::Engine = ctx as *mut <Sha512 as Hash>::Engine;
			let engine = unsafe { Box::from_raw(ptr) };
			let res = Sha512::from_engine(*engine).to_byte_array();
			unsafe { *out = res; }
		}
	}
}

pub(crate) use imp::*;
