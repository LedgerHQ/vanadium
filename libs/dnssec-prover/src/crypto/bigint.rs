//! Simple variable-time big integer implementation

use alloc::vec::Vec;
use core::marker::PhantomData;

#[allow(clippy::needless_lifetimes)] // lifetimes improve readability
#[allow(clippy::needless_borrow)] // borrows indicate read-only/non-move
#[allow(clippy::too_many_arguments)] // sometimes we don't have an option
#[allow(clippy::identity_op)] // sometimes identities improve readability for repeated actions

// **************************************
// * Implementations of math primitives *
// **************************************

macro_rules! debug_unwrap { ($v: expr) => { {
	let v = $v;
	debug_assert!(v.is_ok());
	match v {
		Ok(r) => r,
		Err(e) => return Err(e),
	}
} } }

// Various const versions of existing slice utilities
/// Const version of `&a[start..end]`
const fn const_subslice<'a, T>(a: &'a [T], start: usize, end: usize) -> &'a [T] {
	assert!(start <= a.len());
	assert!(end <= a.len());
	assert!(end >= start);
	let mut startptr = a.as_ptr();
	startptr = unsafe { startptr.add(start) };
	let len: usize = end - start;
	// We should use alloc::slice::from_raw_parts here, but sadly it was only stabilized as const
	// in 1.64, whereas we need an MSRV of 1.63. Instead we rely on that which "you should not rely
	// on" - that slices are laid out as a simple tuple of pointer + length.
	//
	// The Rust language reference doesn't specify the layout of slices at all, but does give us a
	// hint, saying
	//   Note: Though you should not rely on this, all pointers to DSTs are currently twice the
	//   size of the size of usize and have the same alignment.
	// This leaves only two possibilities (for today's rust) - `(length, pointer)` and
	// `(pointer, length)`. Today, in practice, this seems to always be `(pointer, length)`, so we
	// just assume it and hope to move to a later MSRV soon.
	unsafe { core::mem::transmute((startptr, len)) }
	/*// The docs for from_raw_parts do not mention any requirements that the pointer be valid if the
	// length is zero, aside from requiring proper alignment (which is met here). Thus,
	// one-past-the-end should be an acceptable pointer for a 0-length slice.
	unsafe { alloc::slice::from_raw_parts(startptr, len) }*/
}

/// Const version of `...: &[a; N] = &a[start..start + N].try_into().unwrap()`
const fn const_subarr<'a, const N: usize, T>(a: &'a [T], start: usize) -> &'a [T; N] {
	debug_assert!(N > 0);

	let end = start + N;
	assert!(start <= a.len());
	assert!(end <= a.len());
	let mut startptr = a.as_ptr();
	startptr = unsafe { startptr.add(start) };
	// transmute will fail to compile if the source and target sizes don't match, so we know the
	// target type is just the length of a pointer. This leaves only a few possible encodings for
	// a pointer to an array, basically just a pointer to the start or end. While its possible Rust
	// could use a pointer to the end, this would be very surprising (and probably less efficient
	// in most cases), so we just assume array references are always just pointers to the start.
	unsafe { core::mem::transmute(startptr) }
}

/// Const version of `dest[dest_start..dest_end].copy_from_slice(source)`
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! copy_from_slice {
	($dest: ident, $dest_start: expr, $dest_end: expr, $source: ident) => { {
		let dest_start = $dest_start;
		let dest_end = $dest_end;
		assert!(dest_start <= $dest.len());
		assert!(dest_end <= $dest.len());
		assert!(dest_end >= dest_start);
		assert!(dest_end - dest_start == $source.len());
		let mut i = 0;
		while i < $source.len() {
			$dest[i + dest_start] = $source[i];
			i += 1;
		}
	} }
}

/// Const version of a > b
const fn slice_greater_than(a: &[u64], b: &[u64]) -> bool {
	debug_assert!(a.len() == b.len());
	let len = if a.len() <= b.len() { a.len() } else { b.len() };
	let mut i = 0;
	while i < len {
		if a[i] > b[i] { return true; }
		else if a[i] < b[i] { return false; }
		i += 1;
	}
	false // Equal
}

/// Const version of a == b
const fn slice_equal(a: &[u64], b: &[u64]) -> bool {
	debug_assert!(a.len() == b.len());
	let len = if a.len() <= b.len() { a.len() } else { b.len() };
	let mut i = 0;
	while i < len {
		if a[i] != b[i] { return false; }
		i += 1;
	}
	true
}

/// Adds a single u64 valuein-place, returning an overflow flag, in which case one out-of-bounds
/// high bit is implicitly included in the result.
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! add_u64 { ($a: ident, $b: expr) => { {
	let len = $a.len();
	let mut i = len - 1;
	let mut add = $b;
	loop {
		let (v, carry) = $a[i].overflowing_add(add);
		$a[i] = v;
		add = carry as u64;
		if add == 0 { break; }

		if i == 0 { break; }
		i -= 1;
	}
	add != 0
} } }

/// Negates the given u64 slice.
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! negate { ($v: ident) => { {
	let mut i = 0;
	while i < $v.len() {
		$v[i] ^= 0xffff_ffff_ffff_ffff;
		i += 1;
	}
	let _ = add_u64!($v, 1);
} } }

/// Doubles in-place, returning an overflow flag, in which case one out-of-bounds high bit is
/// implicitly included in the result.
///
/// Once `const_mut_refs` is stable we can convert this to a function
macro_rules! double { ($a: ident) => { {
	{ let _: &[u64] = &$a; } // Force type resolution
	let len = $a.len();
	let mut carry = false;
	let mut i = len - 1;
	loop {
		let next_carry = ($a[i] & (1 << 63)) != 0;
		let (v, _next_carry_2) = ($a[i] << 1).overflowing_add(carry as u64);
		if !next_carry {
			debug_assert!(!_next_carry_2, "Adding one to 0x7ffff..*2 is only 0xffff..");
		}
		// Note that we can ignore _next_carry_2 here as we never need it - it cannot be set if
		// next_carry is not set and at max 0xffff..*2 + 1 is only 0x1ffff.. (i.e. we can not need
		// a double-carry).
		$a[i] = v;
		carry = next_carry;

		if i == 0 { break; }
		i -= 1;
	}
	carry
} } }

const fn add<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], bool) {
	let mut r = [0; N];
	let mut carry = false;
	let mut i = N - 1;
	loop {
		let (v, mut new_carry) = a[i].overflowing_add(b[i]);
		let (v2, new_new_carry) = v.overflowing_add(carry as u64);
		new_carry |= new_new_carry;
		r[i] = v2;
		carry = new_carry;

		if i == 0 { break; }
		i -= 1;
	}
	(r, carry)
}

/// Subtracts the `b` N-64-bit integer from the `a` N-64-bit integer, returning a new
/// N-64-bit integer and an overflow bit, with the same semantics as the std
/// [`u64::overflowing_sub`] method.
const fn sub<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], bool) {
	let mut r = [0; N];
	let mut carry = false;
	let mut i = N - 1;
	loop {
		let (v, mut new_carry) = a[i].overflowing_sub(b[i]);
		let (v2, new_new_carry) = v.overflowing_sub(carry as u64);
		new_carry |= new_new_carry;
		r[i] = v2;
		carry = new_carry;

		if i == 0 { break; }
		i -= 1;
	}
	(r, carry)
}

/// Subtracts the `b` N-64-bit integer from the `a` N-64-bit integer, returning a new
/// N-64-bit integer representing the absolute value of the result, as well as a sign bit.
const fn sub_abs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], bool) {
	let (mut res, neg) = sub(a, b);
	if neg {
		negate!(res);
	}
	(res, neg)
}

/// Multiplies two 128-bit integers together, returning a new 256-bit integer.
///
/// This is the base case for our multiplication, taking advantage of Rust's native 128-bit int
/// types to do multiplication (potentially) natively.
const fn mul_2(a: &[u64; 2], b: &[u64; 2]) -> [u64; 4] {
	// Gradeschool multiplication is way faster here.
	let (a0, a1) = (a[0] as u128, a[1] as u128);
	let (b0, b1) = (b[0] as u128, b[1] as u128);
	let z2 = a0 * b0;
	let z1i = a0 * b1;
	let z1j = b0 * a1;
	let (z1, i_carry_a) = z1i.overflowing_add(z1j);
	let z0 = a1 * b1;

	add_mul_2_parts(z2, z1, z0, i_carry_a)
}

/// Adds the gradeschool multiplication intermediate parts to a final 256-bit result
const fn add_mul_2_parts(z2: u128, z1: u128, z0: u128, i_carry_a: bool) -> [u64; 4] {
	let z2a = ((z2 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z1a = ((z1 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z0a = ((z0 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let z2b = (z2 & 0xffff_ffff_ffff_ffff) as u64;
	let z1b = (z1 & 0xffff_ffff_ffff_ffff) as u64;
	let z0b = (z0 & 0xffff_ffff_ffff_ffff) as u64;

	let l = z0b;

	let (k, j_carry) = z0a.overflowing_add(z1b);

	let (mut j, i_carry_b) = z1a.overflowing_add(z2b);
	let i_carry_c;
	(j, i_carry_c) = j.overflowing_add(j_carry as u64);

	let i_carry = i_carry_a as u64 + i_carry_b as u64 + i_carry_c as u64;
	let (i, must_not_overflow) = z2a.overflowing_add(i_carry);
	debug_assert!(!must_not_overflow, "Two 2*64 bit numbers, multiplied, will not use more than 4*64 bits");

	[i, j, k, l]
}

#[cfg(not(feature = "slower_smaller_binary"))]
const fn mul_3(a: &[u64; 3], b: &[u64; 3]) -> [u64; 6] {
	let (a0, a1, a2) = (a[0] as u128, a[1] as u128, a[2] as u128);
	let (b0, b1, b2) = (b[0] as u128, b[1] as u128, b[2] as u128);

	let m4 = a2 * b2;
	let m3a = a2 * b1;
	let m3b = a1 * b2;
	let m2a = a2 * b0;
	let m2b = a1 * b1;
	let m2c = a0 * b2;
	let m1a = a1 * b0;
	let m1b = a0 * b1;
	let m0 = a0 * b0;

	let r5 = ((m4 >> 0) & 0xffff_ffff_ffff_ffff) as u64;

	let r4a = ((m4 >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r4b = ((m3a >> 0) & 0xffff_ffff_ffff_ffff) as u64;
	let r4c = ((m3b >> 0) & 0xffff_ffff_ffff_ffff) as u64;

	let r3a = ((m3a >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r3b = ((m3b >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r3c = ((m2a >> 0 ) & 0xffff_ffff_ffff_ffff) as u64;
	let r3d = ((m2b >> 0 ) & 0xffff_ffff_ffff_ffff) as u64;
	let r3e = ((m2c >> 0 ) & 0xffff_ffff_ffff_ffff) as u64;

	let r2a = ((m2a >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r2b = ((m2b >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r2c = ((m2c >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r2d = ((m1a >> 0 ) & 0xffff_ffff_ffff_ffff) as u64;
	let r2e = ((m1b >> 0 ) & 0xffff_ffff_ffff_ffff) as u64;

	let r1a = ((m1a >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r1b = ((m1b >> 64) & 0xffff_ffff_ffff_ffff) as u64;
	let r1c = ((m0  >> 0 ) & 0xffff_ffff_ffff_ffff) as u64;

	let r0a = ((m0  >> 64) & 0xffff_ffff_ffff_ffff) as u64;

	let (r4, r3_ca) = r4a.overflowing_add(r4b);
	let (r4, r3_cb) = r4.overflowing_add(r4c);
	let r3_c = r3_ca as u64 + r3_cb as u64;

	let (r3, r2_ca) = r3a.overflowing_add(r3b);
	let (r3, r2_cb) = r3.overflowing_add(r3c);
	let (r3, r2_cc) = r3.overflowing_add(r3d);
	let (r3, r2_cd) = r3.overflowing_add(r3e);
	let (r3, r2_ce) = r3.overflowing_add(r3_c);
	let r2_c = r2_ca as u64 + r2_cb as u64 + r2_cc as u64 + r2_cd as u64 + r2_ce as u64;

	let (r2, r1_ca) = r2a.overflowing_add(r2b);
	let (r2, r1_cb) = r2.overflowing_add(r2c);
	let (r2, r1_cc) = r2.overflowing_add(r2d);
	let (r2, r1_cd) = r2.overflowing_add(r2e);
	let (r2, r1_ce) = r2.overflowing_add(r2_c);
	let r1_c = r1_ca as u64 + r1_cb as u64 + r1_cc as u64 + r1_cd as u64 + r1_ce as u64;

	let (r1, r0_ca) = r1a.overflowing_add(r1b);
	let (r1, r0_cb) = r1.overflowing_add(r1c);
	let (r1, r0_cc) = r1.overflowing_add(r1_c);
	let r0_c = r0_ca as u64 + r0_cb as u64 + r0_cc as u64;

	let (r0, must_not_overflow) = r0a.overflowing_add(r0_c);
	debug_assert!(!must_not_overflow, "Two 3*64 bit numbers, multiplied, will not use more than 6*64 bits");

	[r0, r1, r2, r3, r4, r5]
}

macro_rules! define_gradeschool_mul { ($name: ident, $len: expr, $submul: ident) => {
	/// Multiplies two $len-64-bit integers together, returning a new $len*2-64-bit integer.
	const fn $name(a: &[u64; $len], b: &[u64; $len]) -> [u64; $len * 2] {
		let a0: &[u64; $len / 2] = const_subarr(a, 0);
		let a1: &[u64; $len / 2] = const_subarr(a, $len / 2);
		let b0: &[u64; $len / 2] = const_subarr(b, 0);
		let b1: &[u64; $len / 2] = const_subarr(b, $len / 2);

		let z2 = $submul(&a0, &b0);
		let z1i = $submul(&a0, &b1);
		let z1j = $submul(&b0, &a1);
		let z0 = $submul(&a1, &b1);

		let (z1, i_carry_a) = add(&z1i, &z1j);

		let z2a: &[u64; $len / 2] = const_subarr(&z2, 0);
		let z1a: &[u64; $len / 2] = const_subarr(&z1, 0);
		let z0a: &[u64; $len / 2] = const_subarr(&z0, 0);
		let z2b: &[u64; $len / 2] = const_subarr(&z2, $len / 2);
		let z1b: &[u64; $len / 2] = const_subarr(&z1, $len / 2);
		let z0b: &[u64; $len / 2] = const_subarr(&z0, $len / 2);

		let l = z0b;

		let (k, j_carry) = add(&z0a, &z1b);

		let (mut j, i_carry_b) = add(&z1a, &z2b);
		let i_carry_c = add_u64!(j, j_carry as u64);

		let mut i = *z2a;
		let i_carry = i_carry_a as u64 + i_carry_b as u64 + i_carry_c as u64;
		let must_not_overflow = add_u64!(i, i_carry);
		debug_assert!(!must_not_overflow, "Two N*64 bit numbers, multiplied, will not use more than 2*N*64 bits");

		let mut res = [0; $len * 2];
		copy_from_slice!(res, 0, $len / 2, i);
		copy_from_slice!(res, $len / 2, $len, j);
		copy_from_slice!(res, $len, $len * 3 / 2, k);
		copy_from_slice!(res, $len * 3 / 2, $len * 2, l);
		res
	}
} }

macro_rules! define_mul { ($name: ident, $len: expr, $submul: ident) => {
	/// Multiplies two $len-64-bit integers together, returning a new $len*2-64-bit integer.
	const fn $name(a: &[u64; $len], b: &[u64; $len]) -> [u64; $len * 2] {
		let a0: &[u64; $len / 2] = const_subarr(a, 0);
		let a1: &[u64; $len / 2] = const_subarr(a, $len / 2);
		let b0: &[u64; $len / 2] = const_subarr(b, 0);
		let b1: &[u64; $len / 2] = const_subarr(b, $len / 2);

		let z2 = $submul(a0, b0);
		let z0 = $submul(a1, b1);

		let (z1a_max, z1a_min, z1a_sign) =
			if slice_greater_than(a1, a0) { (a1, a0, true) } else { (a0, a1, false) };
		let (z1b_max, z1b_min, z1b_sign) =
			if slice_greater_than(b1, b0) { (b1, b0, true) } else { (b0, b1, false) };

		let z1a = sub(z1a_max, z1a_min);
		debug_assert!(!z1a.1, "z1a_max was selected to be greater than z1a_min");
		let z1b = sub(z1b_max, z1b_min);
		debug_assert!(!z1b.1, "z1b_max was selected to be greater than z1b_min");
		let z1m_sign = z1a_sign == z1b_sign;

		let z1m = $submul(&z1a.0, &z1b.0);
		let z1n = add(&z0, &z2);
		let mut z1_carry = z1n.1;
		let z1 = if z1m_sign {
			let r = sub(&z1n.0, &z1m);
			if r.1 { z1_carry ^= true; }
			r.0
		} else {
			let r = add(&z1n.0, &z1m);
			if r.1 { z1_carry = true; }
			r.0
		};

		let z0_start: &[u64; $len / 2] = const_subarr(&z0, 0);
		let z1_start: &[u64; $len / 2] = const_subarr(&z1, 0);
		let z1_end: &[u64; $len / 2] = const_subarr(&z1, $len / 2);
		let z2_end: &[u64; $len / 2] = const_subarr(&z2, $len / 2);

		let l = const_subslice(&z0, $len / 2, $len);
		let (k, j_carry) = add(z0_start, z1_end);
		let (mut j, i_carry_a) = add(z1_start, z2_end);
		let i_carry_b = add_u64!(j, j_carry as u64);

		let mut i = [0; $len / 2];
		let i_source = const_subslice(&z2, 0, $len / 2);
		copy_from_slice!(i, 0, $len / 2, i_source);
		let i_carry = i_carry_a as u64 + i_carry_b as u64 + z1_carry as u64;
		let must_not_overflow = add_u64!(i, i_carry);
		debug_assert!(!must_not_overflow, "Two N*64 bit numbers, multiplied, will not use more than 2*N*64 bits");

		let mut res = [0; $len * 2];
		copy_from_slice!(res, $len * 2 * 0 / 4, $len * 2 * 1 / 4, i);
		copy_from_slice!(res, $len * 2 * 1 / 4, $len * 2 * 2 / 4, j);
		copy_from_slice!(res, $len * 2 * 2 / 4, $len * 2 * 3 / 4, k);
		copy_from_slice!(res, $len * 2 * 3 / 4, $len * 2 * 4 / 4, l);
		res
	}
} }

define_gradeschool_mul!(mul_4, 4, mul_2);
#[cfg(not(feature = "slower_smaller_binary"))]
define_gradeschool_mul!(mul_6, 6, mul_3);

#[cfg(not(feature = "slower_smaller_binary"))]
define_mul!(mul_8, 8, mul_4);

#[cfg(feature = "slower_smaller_binary")]
define_gradeschool_mul!(mul_8, 8, mul_4);

define_mul!(mul_16, 16, mul_8);
define_mul!(mul_32, 32, mul_16);
define_mul!(mul_64, 64, mul_32);

#[cfg(feature = "slower_smaller_binary")]
const fn mul_6(a: &[u64; 6], b: &[u64; 6]) -> [u64; 12] {
	let mut ae = [0; 8];
	let mut be = [0; 8];
	copy_from_slice!(ae, 2, 8, a);
	copy_from_slice!(be, 2, 8, b);
	let bonus_res = mul_8(&ae, &be);
	let mut res = [0; 12];
	let mut i = 0;
	while i < 4 { debug_assert!(bonus_res[i] == 0); i += 1; }
	while i < 16 { res[i - 4] = bonus_res[i]; i += 1; }
	res
}

/// Squares a 128-bit integer, returning a new 256-bit integer.
///
/// This is the base case for our squaring, taking advantage of Rust's native 128-bit int
/// types to do multiplication (potentially) natively.
#[cfg(not(feature = "slower_smaller_binary"))]
const fn sqr_2(a: &[u64; 2]) -> [u64; 4] {
	let (a0, a1) = (a[0] as u128, a[1] as u128);
	let z2 = a0 * a0;
	let mut z1 = a0 * a1;
	let i_carry_a = z1 & (1u128 << 127) != 0;
	z1 <<= 1;
	let z0 = a1 * a1;

	add_mul_2_parts(z2, z1, z0, i_carry_a)
}

macro_rules! define_sqr { ($name: ident, $len: expr, $mul: ident, $submul: ident, $subsqr: ident) => {
	#[cfg(feature = "slower_smaller_binary")]
	/// Squares a $len-64-bit integers, returning a new $len*2-64-bit integer.
	const fn $name(a: &[u64; $len]) -> [u64; $len * 2] {
		$mul(a, a)
	}

	#[cfg(not(feature = "slower_smaller_binary"))]
	/// Squares a $len-64-bit integers, returning a new $len*2-64-bit integer.
	const fn $name(a: &[u64; $len]) -> [u64; $len * 2] {
		// Squaring is only 3 half-length multiplies/squares in gradeschool math, so use that.
		let hi: &[u64; $len / 2] = const_subarr(a, 0);
		let lo: &[u64; $len / 2] = const_subarr(a, $len / 2);

		let v0 = $subsqr(lo);
		let mut v1 = $submul(hi, lo);
		let i_carry_a  = double!(v1);
		let v2 = $subsqr(hi);

		let v0_start: &[u64; $len / 2] = const_subarr(&v0, 0);
		let v1_start: &[u64; $len / 2] = const_subarr(&v1, 0);
		let v1_end: &[u64; $len / 2] = const_subarr(&v1, $len / 2);
		let v2_end: &[u64; $len / 2] = const_subarr(&v2, $len / 2);

		let l = const_subslice(&v0, $len / 2, $len);
		let (k, j_carry) = add(v0_start, v1_end);
		let (mut j, i_carry_b) = add(v1_start, v2_end);

		let mut i = [0; $len / 2];
		let i_source = const_subslice(&v2, 0, $len / 2);
		copy_from_slice!(i, 0, $len / 2, i_source);

		let mut i_carry_c = false;
		if j_carry {
			i_carry_c = add_u64!(j, 1);
		}
		let i_carry = i_carry_a as u64 + i_carry_b as u64 + i_carry_c as u64;
		if i_carry != 0 {
			let must_not_overflow = add_u64!(i, i_carry);
			debug_assert!(!must_not_overflow, "Two N*64 bit numbers, multiplied, will not use more than 2*N*64 bits");
		}

		let mut res = [0; $len * 2];
		copy_from_slice!(res, $len * 2 * 0 / 4, $len * 2 * 1 / 4, i);
		copy_from_slice!(res, $len * 2 * 1 / 4, $len * 2 * 2 / 4, j);
		copy_from_slice!(res, $len * 2 * 2 / 4, $len * 2 * 3 / 4, k);
		copy_from_slice!(res, $len * 2 * 3 / 4, $len * 2 * 4 / 4, l);
		res
	}
} }

// TODO: Write an optimized sqr_3 (though secp384r1 is barely used)
#[cfg(not(feature = "slower_smaller_binary"))]
const fn sqr_3(a: &[u64; 3]) -> [u64; 6] { mul_3(a, a) }

define_sqr!(sqr_4, 4, mul_4, mul_2, sqr_2);
define_sqr!(sqr_6, 6, mul_6, mul_3, sqr_3);
#[cfg(not(feature = "slower_smaller_binary"))]
define_sqr!(sqr_8, 8, mul_8, mul_4, sqr_4);
define_sqr!(sqr_16, 16, mul_16, mul_8, sqr_8);
define_sqr!(sqr_32, 32, mul_32, mul_16, sqr_16);
define_sqr!(sqr_64, 64, mul_64, mul_32, sqr_32);

macro_rules! dummy_pre_push { ($name: ident, $len: expr) => {} }
macro_rules! vec_pre_push { ($name: ident, $len: expr) => { $name.push([0; $len]); } }

macro_rules! define_div_rem { ($name: ident, $len: expr, $heap_init: expr, $pre_push: ident $(, $const_opt: tt)?) => {
	/// Divides two $len-64-bit integers, `a` by `b`, returning the quotient and remainder
	///
	/// Fails iff `b` is zero.
	$($const_opt)? fn $name(a: &[u64; $len], b: &[u64; $len]) -> Result<([u64; $len], [u64; $len]), ()> {
		if slice_equal(b, &[0; $len]) { return Err(()); }

		// Very naively divide `a` by `b` by calculating all the powers of two times `b` up to `a`,
		// then subtracting the powers of two in decreasing order. What's left is the remainder.
		//
		// This requires storing all the multiples of `b` in `pow2s`, which may be a vec or an
		// array. `$pre_push!()` sets up the next element with zeros and then we can overwrite it.
		let mut b_pow = *b;
		let mut pow2s = $heap_init;
		let mut pow2s_count = 0;
		while slice_greater_than(a, &b_pow) {
			$pre_push!(pow2s, $len);
			pow2s[pow2s_count] = b_pow;
			pow2s_count += 1;
			let double_overflow = double!(b_pow);
			if double_overflow { break; }
		}
		let mut quot = [0; $len];
		let mut rem = *a;
		let mut pow2 = pow2s_count as isize - 1;
		while pow2 >= 0 {
			let b_pow = pow2s[pow2 as usize];
			let overflow = double!(quot);
			debug_assert!(!overflow, "quotient should be expressible in $len*64 bits");
			if slice_greater_than(&rem, &b_pow) {
				let (r, underflow) = sub(&rem, &b_pow);
				debug_assert!(!underflow, "rem was just checked to be > b_pow, so sub cannot underflow");
				rem = r;
				quot[$len - 1] |= 1;
			}
			pow2 -= 1;
		}
		if slice_equal(&rem, b) {
			let overflow = add_u64!(quot, 1);
			debug_assert!(!overflow, "quotient should be expressible in $len*64 bits");
			Ok((quot, [0; $len]))
		} else {
			Ok((quot, rem))
		}
	}
} }

#[cfg(dnssec_prover_fuzzing)]
define_div_rem!(div_rem_2, 2, [[0; 2]; 2 * 64], dummy_pre_push, const);
define_div_rem!(div_rem_4, 4, [[0; 4]; 4 * 64], dummy_pre_push, const); // Uses 8 KiB of stack
define_div_rem!(div_rem_6, 6, [[0; 6]; 6 * 64], dummy_pre_push, const); // Uses 18 KiB of stack!
#[cfg(debug_assertions)]
define_div_rem!(div_rem_8, 8, [[0; 8]; 8 * 64], dummy_pre_push, const); // Uses 32 KiB of stack!
#[cfg(debug_assertions)]
define_div_rem!(div_rem_12, 12, [[0; 12]; 12 * 64], dummy_pre_push, const); // Uses 72 KiB of stack!
define_div_rem!(div_rem_64, 64, Vec::new(), vec_pre_push); // Uses up to 2 MiB of heap
#[cfg(debug_assertions)]
define_div_rem!(div_rem_128, 128, Vec::new(), vec_pre_push); // Uses up to 8 MiB of heap

macro_rules! define_mod_inv { ($name: ident, $len: expr, $div: ident, $mul: ident) => {
	/// Calculates the modular inverse of a $len-64-bit number with respect to the given modulus,
	/// if one exists.
	const fn $name(a: &[u64; $len], m: &[u64; $len]) -> Result<[u64; $len], ()> {
		if slice_equal(a, &[0; $len]) || slice_equal(m, &[0; $len]) { return Err(()); }

		let (mut s, mut old_s) = ([0; $len], [0; $len]);
		old_s[$len - 1] = 1;
		let mut r = *m;
		let mut old_r = *a;

		let (mut old_s_neg, mut s_neg) = (false, false);

		while !slice_equal(&r, &[0; $len]) {
			let (quot, new_r) = debug_unwrap!($div(&old_r, &r));

			let new_sa = $mul(&quot, &s);
			debug_assert!(slice_equal(const_subslice(&new_sa, 0, $len), &[0; $len]), "S overflowed");
			let (new_s, new_s_neg) = match (old_s_neg, s_neg) {
				(true, true) => {
					let (new_s, overflow) = add(&old_s, const_subarr(&new_sa, $len));
					debug_assert!(!overflow);
					(new_s, true)
				}
				(false, true) => {
					let (new_s, overflow) = add(&old_s, const_subarr(&new_sa, $len));
					debug_assert!(!overflow);
					(new_s, false)
				},
				(true, false) => {
					let (new_s, overflow) = add(&old_s, const_subarr(&new_sa, $len));
					debug_assert!(!overflow);
					(new_s, true)
				},
				(false, false) => sub_abs(&old_s, const_subarr(&new_sa, $len)),
			};

			old_r = r;
			r = new_r;

			old_s = s;
			old_s_neg = s_neg;
			s = new_s;
			s_neg = new_s_neg;
		}

		// At this point old_r contains our GCD and old_s our first Bézout's identity coefficient.
		if !slice_equal(const_subslice(&old_r, 0, $len - 1), &[0; $len - 1]) || old_r[$len - 1] != 1 {
			Err(())
		} else {
			debug_assert!(slice_greater_than(m, &old_s));
			if old_s_neg {
				let (modinv, underflow) = sub_abs(m, &old_s);
				debug_assert!(!underflow);
				debug_assert!(slice_greater_than(m, &modinv));
				Ok(modinv)
			} else {
				Ok(old_s)
			}
		}
	}
} }
#[cfg(dnssec_prover_fuzzing)]
define_mod_inv!(mod_inv_2, 2, div_rem_2, mul_2);
define_mod_inv!(mod_inv_4, 4, div_rem_4, mul_4);
define_mod_inv!(mod_inv_6, 6, div_rem_6, mul_6);
#[cfg(dnssec_prover_fuzzing)]
define_mod_inv!(mod_inv_8, 8, div_rem_8, mul_8);

// ******************
// * The public API *
// ******************

const WORD_COUNT_4096: usize = 4096 / 64;
const WORD_COUNT_256: usize = 256 / 64;
const WORD_COUNT_384: usize = 384 / 64;

// RFC 5702 indicates RSA keys can be up to 4096 bits, so we always use 4096-bit integers
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct U4096([u64; WORD_COUNT_4096]);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct U256([u64; WORD_COUNT_256]);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct U384([u64; WORD_COUNT_384]);

pub(super) trait Int: Clone + Ord + Sized {
	const ZERO: Self;
	const BYTES: usize;
	fn from_be_bytes(b: &[u8]) -> Result<Self, ()>;
	fn limbs(&self) -> &[u64];
}
impl Int for U256 {
	const ZERO: U256 = U256([0; 4]);
	const BYTES: usize = 32;
	fn from_be_bytes(b: &[u8]) -> Result<Self, ()> { Self::from_be_bytes(b) }
	fn limbs(&self) -> &[u64] { &self.0 }
}
impl Int for U384 {
	const ZERO: U384 = U384([0; 6]);
	const BYTES: usize = 48;
	fn from_be_bytes(b: &[u8]) -> Result<Self, ()> { Self::from_be_bytes(b) }
	fn limbs(&self) -> &[u64] { &self.0 }
}

/// Defines a *PRIME* Modulus
pub(super) trait PrimeModulus<I: Int> {
	const PRIME: I;
	const R_SQUARED_MOD_PRIME: I;
	const NEGATIVE_PRIME_INV_MOD_R: I;
}

#[derive(Clone, Debug, PartialEq, Eq)] // Ord doesn't make sense cause we have an R factor
pub(super) struct U256Mod<M: PrimeModulus<U256>>(U256, PhantomData<M>);

#[derive(Clone, Debug, PartialEq, Eq)] // Ord doesn't make sense cause we have an R factor
pub(super) struct U384Mod<M: PrimeModulus<U384>>(U384, PhantomData<M>);

impl U4096 {
	/// Constructs a new [`U4096`] from a variable number of big-endian bytes.
	pub(super) fn from_be_bytes(bytes: &[u8]) -> Result<U4096, ()> {
		if bytes.len() > 4096/8 { return Err(()); }
		let u64s = (bytes.len() + 7) / 8;
		let mut res = [0; WORD_COUNT_4096];
		for i in 0..u64s {
			let mut b = [0; 8];
			let pos = (u64s - i) * 8;
			let start = bytes.len().saturating_sub(pos);
			let end = bytes.len() + 8 - pos;
			b[8 + start - end..].copy_from_slice(&bytes[start..end]);
			res[i + WORD_COUNT_4096 - u64s] = u64::from_be_bytes(b);
		}
		Ok(U4096(res))
	}

	/// Naively multiplies `self` * `b` mod `m`, returning a new [`U4096`].
	///
	/// Fails iff m is 0 or self or b are greater than m.
	#[cfg(debug_assertions)]
	fn mulmod_naive(&self, b: &U4096, m: &U4096) -> Result<U4096, ()> {
		if m.0 == [0; WORD_COUNT_4096] { return Err(()); }
		if self > m || b > m { return Err(()); }

		let mul = mul_64(&self.0, &b.0);

		let mut m_zeros = [0; 128];
		m_zeros[WORD_COUNT_4096..].copy_from_slice(&m.0);
		let (_, rem) = div_rem_128(&mul, &m_zeros)?;
		let mut res = [0; WORD_COUNT_4096];
		debug_assert_eq!(&rem[..WORD_COUNT_4096], &[0; WORD_COUNT_4096]);
		res.copy_from_slice(&rem[WORD_COUNT_4096..]);
		Ok(U4096(res))
	}

	/// Calculates `self` ^ `exp` mod `m`, returning a new [`U4096`].
	///
	/// Fails iff m is 0, even, or self or b are greater than m.
	pub(super) fn expmod_odd_mod(&self, mut exp: u32, m: &U4096) -> Result<U4096, ()> {
		#![allow(non_camel_case_types)]

		if m.0 == [0; WORD_COUNT_4096] { return Err(()); }
		if m.0[WORD_COUNT_4096 - 1] & 1 == 0 { return Err(()); }
		if self > m { return Err(()); }

		let mut t = [0; WORD_COUNT_4096];
		if m.0[..WORD_COUNT_4096 - 1] == [0; WORD_COUNT_4096 - 1] && m.0[WORD_COUNT_4096 - 1] == 1 {
			return Ok(U4096(t));
		}
		t[WORD_COUNT_4096 - 1] = 1;
		if exp == 0 { return Ok(U4096(t)); }

		// Because m is not even, using 2^4096 as the Montgomery R value is always safe - it is
		// guaranteed to be co-prime with any non-even integer.

		// We use a single 4096-bit integer type for all our RSA operations, though in most cases
		// we're actually dealing with 1024-bit or 2048-bit ints. Thus, we define sub-array math
		// here which debug_assert's the required bits are 0s and then uses faster math primitives.

		type mul_ty = fn(&[u64; WORD_COUNT_4096], &[u64; WORD_COUNT_4096]) -> [u64; WORD_COUNT_4096 * 2];
		type sqr_ty = fn(&[u64; WORD_COUNT_4096]) -> [u64; WORD_COUNT_4096 * 2];
		type add_double_ty = fn(&[u64; WORD_COUNT_4096 * 2], &[u64; WORD_COUNT_4096 * 2]) -> ([u64; WORD_COUNT_4096 * 2], bool);
		type sub_ty = fn(&[u64; WORD_COUNT_4096], &[u64; WORD_COUNT_4096]) -> ([u64; WORD_COUNT_4096], bool);
		let (word_count, log_bits, mul, sqr, add_double, sub) =
			if m.0[..WORD_COUNT_4096 / 2] == [0; WORD_COUNT_4096 / 2] {
				if m.0[..WORD_COUNT_4096 * 3 / 4] == [0; WORD_COUNT_4096 * 3 / 4] {
					fn mul_16_subarr(a: &[u64; WORD_COUNT_4096], b: &[u64; WORD_COUNT_4096]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						let a_arr = const_subarr(a, WORD_COUNT_4096 * 3 / 4);
						let b_arr = const_subarr(b, WORD_COUNT_4096 * 3 / 4);
						res[WORD_COUNT_4096 + WORD_COUNT_4096 / 2..]
							.copy_from_slice(&mul_16(a_arr, b_arr));
						res
					}
					fn sqr_16_subarr(a: &[u64; WORD_COUNT_4096]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						let a_arr = const_subarr(a, WORD_COUNT_4096 * 3 / 4);
						res[WORD_COUNT_4096 + WORD_COUNT_4096 / 2..]
							.copy_from_slice(&sqr_16(a_arr));
						res
					}
					fn add_32_subarr(a: &[u64; WORD_COUNT_4096 * 2], b: &[u64; WORD_COUNT_4096 * 2]) -> ([u64; WORD_COUNT_4096 * 2], bool) {
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 2], &[0; WORD_COUNT_4096 * 3 / 2]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 * 3 / 2], &[0; WORD_COUNT_4096 * 3 / 2]);
						let a_arr: &[u64; 32] = const_subarr(a, WORD_COUNT_4096 * 3 / 2);
						let b_arr: &[u64; 32] = const_subarr(b, WORD_COUNT_4096 * 3 / 2);
						let (add, overflow) = add(a_arr, b_arr);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096 * 3 / 2..].copy_from_slice(&add);
						(res, overflow)
					}
					fn sub_16_subarr(a: &[u64; WORD_COUNT_4096], b: &[u64; WORD_COUNT_4096]) -> ([u64; WORD_COUNT_4096], bool) {
						debug_assert_eq!(&a[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 * 3 / 4], &[0; WORD_COUNT_4096 * 3 / 4]);
						let a_arr: &[u64; 16] = const_subarr(a, WORD_COUNT_4096 * 3 / 4);
						let b_arr: &[u64; 16] = const_subarr(b, WORD_COUNT_4096 * 3 / 4);
						let (sub, underflow) = sub(a_arr, b_arr);
						let mut res = [0; WORD_COUNT_4096];
						res[WORD_COUNT_4096 * 3 / 4..].copy_from_slice(&sub);
						(res, underflow)
					}
					(16, 10, mul_16_subarr as mul_ty, sqr_16_subarr as sqr_ty, add_32_subarr as add_double_ty, sub_16_subarr as sub_ty)
				} else {
					fn mul_32_subarr(a: &[u64; WORD_COUNT_4096], b: &[u64; WORD_COUNT_4096]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(&a[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						let mut res = [0; WORD_COUNT_4096 * 2];
						let a_arr = const_subarr(a, WORD_COUNT_4096 / 2);
						let b_arr = const_subarr(b, WORD_COUNT_4096 / 2);
						res[WORD_COUNT_4096..].copy_from_slice(&mul_32(a_arr, b_arr));
						res
					}
					fn sqr_32_subarr(a: &[u64; WORD_COUNT_4096]) -> [u64; WORD_COUNT_4096 * 2] {
						debug_assert_eq!(a.len(), WORD_COUNT_4096);
						debug_assert_eq!(&a[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						let a_arr = const_subarr(a, WORD_COUNT_4096 / 2);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096..].copy_from_slice(&sqr_32(a_arr));
						res
					}
					fn add_64_subarr(a: &[u64; WORD_COUNT_4096 * 2], b: &[u64; WORD_COUNT_4096 * 2]) -> ([u64; WORD_COUNT_4096 * 2], bool) {
						debug_assert_eq!(&a[..WORD_COUNT_4096], &[0; WORD_COUNT_4096]);
						debug_assert_eq!(&b[..WORD_COUNT_4096], &[0; WORD_COUNT_4096]);
						let a_arr: &[u64; 64] = const_subarr(a, WORD_COUNT_4096);
						let b_arr: &[u64; 64] = const_subarr(b, WORD_COUNT_4096);
						let (add, overflow) = add(a_arr, b_arr);
						let mut res = [0; WORD_COUNT_4096 * 2];
						res[WORD_COUNT_4096..].copy_from_slice(&add);
						(res, overflow)
					}
					fn sub_32_subarr(a: &[u64; WORD_COUNT_4096], b: &[u64; WORD_COUNT_4096]) -> ([u64; WORD_COUNT_4096], bool) {
						debug_assert_eq!(&a[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						debug_assert_eq!(&b[..WORD_COUNT_4096 / 2], &[0; WORD_COUNT_4096 / 2]);
						let a_arr: &[u64; 32] = const_subarr(a, WORD_COUNT_4096 / 2);
						let b_arr: &[u64; 32] = const_subarr(b, WORD_COUNT_4096 / 2);
						let (sub, underflow) = sub(a_arr, b_arr);
						let mut res = [0; WORD_COUNT_4096];
						res[WORD_COUNT_4096 / 2..].copy_from_slice(&sub);
						(res, underflow)
					}
					(32, 11, mul_32_subarr as mul_ty, sqr_32_subarr as sqr_ty, add_64_subarr as add_double_ty, sub_32_subarr as sub_ty)
				}
			} else {
				(64, 12, mul_64 as mul_ty, sqr_64 as sqr_ty, add as add_double_ty, sub as sub_ty)
			};

		// r is always the even value with one bit set above the word count we're using.
		let mut r = [0; WORD_COUNT_4096 * 2];
		r[WORD_COUNT_4096 * 2 - word_count - 1] = 1;

		let mut m_inv_pos = [0; WORD_COUNT_4096];
		m_inv_pos[WORD_COUNT_4096 - 1] = 1;
		let mut two = [0; WORD_COUNT_4096];
		two[WORD_COUNT_4096 - 1] = 2;
		for _ in 0..log_bits {
			let mut m_m_inv = mul(&m_inv_pos, &m.0);
			m_m_inv[..WORD_COUNT_4096 * 2 - word_count].fill(0);
			let m_m_inv_low_bytes = const_subarr(&m_m_inv, WORD_COUNT_4096);
			let m_inv = mul(&sub(&two, m_m_inv_low_bytes).0, &m_inv_pos);
			m_inv_pos[WORD_COUNT_4096 - word_count..].copy_from_slice(&m_inv[WORD_COUNT_4096 * 2 - word_count..]);
		}
		m_inv_pos[..WORD_COUNT_4096 - word_count].fill(0);

		// `m_inv` is the negative modular inverse of m mod R, so subtract m_inv from R.
		let mut m_inv = m_inv_pos;
		negate!(m_inv);
		m_inv[..WORD_COUNT_4096 - word_count].fill(0);
		debug_assert_eq!(&mul(&m_inv, &m.0)[WORD_COUNT_4096 * 2 - word_count..],
			// R - 1 == -1 % R
			&[0xffff_ffff_ffff_ffff; WORD_COUNT_4096][WORD_COUNT_4096 - word_count..]);

		let mont_reduction = |mu: [u64; WORD_COUNT_4096 * 2]| -> [u64; WORD_COUNT_4096] {
			debug_assert_eq!(&mu[..WORD_COUNT_4096 * 2 - word_count * 2],
				&[0; WORD_COUNT_4096 * 2][..WORD_COUNT_4096 * 2 - word_count * 2]);
			// Do a montgomery reduction of `mu`

			// The definition of REDC (with some names changed):
			// v = ((mu % R) * N') mod R
			// t = (mu + v*N) / R
			// if t >= N { t - N } else { t }

			// mu % R is just the bottom word_count bytes of mu
			let mut mu_mod_r = [0; WORD_COUNT_4096];
			mu_mod_r[WORD_COUNT_4096 - word_count..].copy_from_slice(&mu[WORD_COUNT_4096 * 2 - word_count..]);

			// v = ((mu % R) * negative_modulus_inverse) % R
			let mut v = mul(&mu_mod_r, &m_inv);
			v[..WORD_COUNT_4096 * 2 - word_count].fill(0); // mod R

			// t_on_r = (mu + v*modulus) / R
			let t0 = mul(const_subarr(&v, WORD_COUNT_4096), &m.0);
			let (t1, t1_extra_bit) = add_double(&t0, &mu);

			// Note that dividing t1 by R is simply a matter of shifting right by word_count bytes
			// We only need to maintain word_count bytes (plus `t1_extra_bit` which is implicitly
			// an extra bit) because t_on_r is guarantee to be, at max, 2*m - 1.
			let mut t1_on_r = [0; WORD_COUNT_4096];
			debug_assert_eq!(&t1[WORD_COUNT_4096 * 2 - word_count..], &[0; WORD_COUNT_4096][WORD_COUNT_4096 - word_count..],
				"t1 should be divisible by r");
			t1_on_r[WORD_COUNT_4096 - word_count..].copy_from_slice(&t1[WORD_COUNT_4096 * 2 - word_count * 2..WORD_COUNT_4096 * 2 - word_count]);

			// The modulus has only word_count bytes, so if t1_extra_bit is set we are definitely
			// larger than the modulus.
			if t1_extra_bit || t1_on_r >= m.0 {
				let underflow;
				(t1_on_r, underflow) = sub(&t1_on_r, &m.0);
				debug_assert_eq!(t1_extra_bit, underflow,
					"The number (t1_extra_bit, t1_on_r) is at most 2m-1, so underflowing t1_on_r - m should happen iff t1_extra_bit is set.");
			}
			t1_on_r
		};

		// Calculate R^2 mod m as ((2^DOUBLES * R) mod m)^(log_bits - LOG2_DOUBLES) mod R
		let mut r_minus_one = [0xffff_ffff_ffff_ffffu64; WORD_COUNT_4096];
		r_minus_one[..WORD_COUNT_4096 - word_count].fill(0);
		// While we do a full div here, in general R should be less than 2x m (assuming the RSA
		// modulus used its full bit range and is 1024, 2048, or 4096 bits), so it should be cheap.
		// In cases with a nonstandard RSA modulus we may end up being pretty slow here, but we'll
		// survive.
		// If we ever find a problem with this we should reduce R to be tigher on m, as we're
		// wasting extra bits of calculation if R is too far from m.
		let (_, mut r_mod_m) = debug_unwrap!(div_rem_64(&r_minus_one, &m.0));
		let r_mod_m_overflow = add_u64!(r_mod_m, 1);
		if r_mod_m_overflow || r_mod_m >= m.0 {
			(r_mod_m, _) = crate::crypto::bigint::sub(&r_mod_m, &m.0);
		}

		let mut r2_mod_m: [u64; 64] = r_mod_m;
		const DOUBLES: usize = 32;
		const LOG2_DOUBLES: usize = 5;

		for _ in 0..DOUBLES {
			let overflow = double!(r2_mod_m);
			if overflow || r2_mod_m > m.0 {
				(r2_mod_m, _) = crate::crypto::bigint::sub(&r2_mod_m, &m.0);
			}
		}
		for _ in 0..log_bits - LOG2_DOUBLES {
			r2_mod_m = mont_reduction(sqr(&r2_mod_m));
		}
		// Clear excess high bits
		for (m_limb, r2_limb) in m.0.iter().zip(r2_mod_m.iter_mut()) {
			let clear_bits = m_limb.leading_zeros();
			if clear_bits == 0 { break; }
			*r2_limb &= !(0xffff_ffff_ffff_ffffu64 << (64 - clear_bits));
			if *m_limb != 0 { break; }
		}

		debug_assert!(r2_mod_m < m.0);
		#[cfg(debug_assertions)] {
			debug_assert_eq!(r2_mod_m, U4096(r_mod_m).mulmod_naive(&U4096(r_mod_m), &m).unwrap().0);
		}

		// Finally, actually do the exponentiation...

		// Calculate t * R and a * R as mont multiplications by R^2 mod m
		// (i.e. t * R^2 / R and 1 * R^2 / R)
		let mut tr = mont_reduction(mul(&r2_mod_m, &t));
		let mut ar = mont_reduction(mul(&r2_mod_m, &self.0));

		#[cfg(debug_assertions)] {
			// Check that tr/ar match naive multiplication
			debug_assert_eq!(&tr, &U4096(t).mulmod_naive(&U4096(r_mod_m), &m).unwrap().0);
			debug_assert_eq!(&ar, &self.mulmod_naive(&U4096(r_mod_m), &m).unwrap().0);
		}

		while exp != 1 {
			if exp % 2 == 1 {
				tr = mont_reduction(mul(&tr, &ar));
				exp -= 1;
			}
			ar = mont_reduction(sqr(&ar));
			exp /= 2;
		}
		ar = mont_reduction(mul(&ar, &tr));
		let mut resr = [0; WORD_COUNT_4096 * 2];
		resr[WORD_COUNT_4096..].copy_from_slice(&ar);
		Ok(U4096(mont_reduction(resr)))
	}
}

// In a const context we can't subslice a slice, so instead we pick the eight bytes we want and
// pass them here to build u64s from arrays.
const fn eight_bytes_to_u64_be(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> u64 {
	let b = [a, b, c, d, e, f, g, h];
	u64::from_be_bytes(b)
}

impl U256 {
	/// Constructs a new [`U256`] from a variable number of big-endian bytes.
	pub(super) fn from_be_bytes(bytes: &[u8]) -> Result<U256, ()> {
		if bytes.len() > 256/8 { return Err(()); }
		let u64s = (bytes.len() + 7) / 8;
		let mut res = [0; WORD_COUNT_256];
		for i in 0..u64s {
			let mut b = [0; 8];
			let pos = (u64s - i) * 8;
			let start = bytes.len().saturating_sub(pos);
			let end = bytes.len() + 8 - pos;
			b[8 + start - end..].copy_from_slice(&bytes[start..end]);
			res[i + WORD_COUNT_256 - u64s] = u64::from_be_bytes(b);
		}
		Ok(U256(res))
	}

	/// Constructs a new [`U256`] from a fixed number of big-endian bytes.
	pub(super) const fn from_32_be_bytes_panicking(bytes: &[u8; 32]) -> U256 {
		let res = [
			eight_bytes_to_u64_be(bytes[0*8 + 0], bytes[0*8 + 1], bytes[0*8 + 2], bytes[0*8 + 3],
			                      bytes[0*8 + 4], bytes[0*8 + 5], bytes[0*8 + 6], bytes[0*8 + 7]),
			eight_bytes_to_u64_be(bytes[1*8 + 0], bytes[1*8 + 1], bytes[1*8 + 2], bytes[1*8 + 3],
			                      bytes[1*8 + 4], bytes[1*8 + 5], bytes[1*8 + 6], bytes[1*8 + 7]),
			eight_bytes_to_u64_be(bytes[2*8 + 0], bytes[2*8 + 1], bytes[2*8 + 2], bytes[2*8 + 3],
			                      bytes[2*8 + 4], bytes[2*8 + 5], bytes[2*8 + 6], bytes[2*8 + 7]),
			eight_bytes_to_u64_be(bytes[3*8 + 0], bytes[3*8 + 1], bytes[3*8 + 2], bytes[3*8 + 3],
			                      bytes[3*8 + 4], bytes[3*8 + 5], bytes[3*8 + 6], bytes[3*8 + 7]),
		];
		U256(res)
	}

	pub(super) const fn zero() -> U256 { U256([0, 0, 0, 0]) }
	pub(super) const fn one() -> U256 { U256([0, 0, 0, 1]) }
}

/// Do mont reduction (but avoid putting it in the templated [`U256Mod`] to avoid having two copies
/// for different primes
const fn u256_mont_reduction_given_prime(mu: [u64; 8], prime: &[u64; 4], negative_prime_inv_mod_r: &[u64; 4]) -> U256 {
	// The definition of REDC (with some names changed):
	// v = ((mu % R) * N') mod R
	// t = (mu + v*N) / R
	// if t >= N { t - N } else { t }

	// mu % R is just the bottom 4 bytes of mu
	let mu_mod_r: &[u64; 4] = const_subarr(&mu, 4);
	// v = ((mu % R) * negative_modulus_inverse) % R
	let mut v = mul_4(mu_mod_r, negative_prime_inv_mod_r);
	const ZEROS: &[u64; 4] = &[0; 4];
	copy_from_slice!(v, 0, 4, ZEROS); // mod R

	// t_on_r = (mu + v*modulus) / R
	let t0 = mul_4(const_subarr(&v, 4), prime);
	let (t1, t1_extra_bit) = add(&t0, &mu);

	// Note that dividing t1 by R is simply a matter of shifting right by 4 bytes.
	// We only need to maintain 4 bytes (plus `t1_extra_bit` which is implicitly an extra bit)
	// because t_on_r is guarantee to be, at max, 2*m - 1.
	let t1_on_r: &[u64; 4] = const_subarr(&t1, 0);

	let mut res = [0; 4];
	// The modulus is only 4 bytes, so t1_extra_bit implies we're definitely larger than the
	// modulus.
	if t1_extra_bit || slice_greater_than(t1_on_r, prime) {
		let underflow;
		(res, underflow) = sub(t1_on_r, prime);
		debug_assert!(t1_extra_bit == underflow,
			"The number (t1_extra_bit, t1_on_r) is at most 2m-1, so underflowing t1_on_r - m should happen iff t1_extra_bit is set.");
	} else {
		copy_from_slice!(res, 0, 4, t1_on_r);
	}
	U256(res)
}

// Values modulus M::PRIME.0, stored in montgomery form.
impl<M: PrimeModulus<U256>> U256Mod<M> {
	const fn mont_reduction(mu: [u64; 8]) -> Self {
		#[cfg(debug_assertions)] {
			// Check NEGATIVE_PRIME_INV_MOD_R is correct. Since this is all const, the compiler
			// should be able to do it at compile time alone.
			let minus_one_mod_r = mul_4(&M::PRIME.0, &M::NEGATIVE_PRIME_INV_MOD_R.0);
			assert!(slice_equal(const_subslice(&minus_one_mod_r, 4, 8), &[0xffff_ffff_ffff_ffff; 4]));
		}

		#[cfg(debug_assertions)] {
			// Check R_SQUARED_MOD_PRIME is correct. Since this is all const, the compiler
			// should be able to do it at compile time alone.
			let r_minus_one = [0xffff_ffff_ffff_ffff; 4];
			let (mut r_mod_prime, _) = sub(&r_minus_one, &M::PRIME.0);
			let r_mod_prime_overflow = add_u64!(r_mod_prime, 1);
			assert!(!r_mod_prime_overflow);
			let r_squared = sqr_4(&r_mod_prime);
			let mut prime_extended = [0; 8];
			let prime = M::PRIME.0;
			copy_from_slice!(prime_extended, 4, 8, prime);
			let (_, r_squared_mod_prime) = if let Ok(v) = div_rem_8(&r_squared, &prime_extended) { v } else { panic!() };
			assert!(slice_greater_than(&prime_extended, &r_squared_mod_prime));
			assert!(slice_equal(const_subslice(&r_squared_mod_prime, 4, 8), &M::R_SQUARED_MOD_PRIME.0));
		}

		Self(u256_mont_reduction_given_prime(mu, &M::PRIME.0, &M::NEGATIVE_PRIME_INV_MOD_R.0), PhantomData)
	}

	pub(super) const fn from_u256_panicking(v: U256) -> Self {
		assert!(v.0[0] <= M::PRIME.0[0]);
		if v.0[0] == M::PRIME.0[0] {
			assert!(v.0[1] <= M::PRIME.0[1]);
			if v.0[1] == M::PRIME.0[1] {
				assert!(v.0[2] <= M::PRIME.0[2]);
				if v.0[2] == M::PRIME.0[2] {
					assert!(v.0[3] < M::PRIME.0[3]);
				}
			}
		}
		assert!(M::PRIME.0[0] != 0 || M::PRIME.0[1] != 0 || M::PRIME.0[2] != 0 || M::PRIME.0[3] != 0);
		Self::mont_reduction(mul_4(&M::R_SQUARED_MOD_PRIME.0, &v.0))
	}

	pub(super) fn from_u256(mut v: U256) -> Self {
		debug_assert!(M::PRIME.0 != [0; 4]);
		debug_assert!(M::PRIME.0[0] > (1 << 63), "PRIME should have the top bit set");
		while v >= M::PRIME {
			let (new_v, spurious_underflow) = sub(&v.0, &M::PRIME.0);
			debug_assert!(!spurious_underflow, "v was > M::PRIME.0");
			v = U256(new_v);
		}
		Self::mont_reduction(mul_4(&M::R_SQUARED_MOD_PRIME.0, &v.0))
	}

	pub(super) fn from_modinv_of(v: U256) -> Result<Self, ()> {
		Ok(Self::from_u256(U256(mod_inv_4(&v.0, &M::PRIME.0)?)))
	}

	/// Multiplies `self` * `b` mod `m`.
	///
	/// Panics if `self`'s modulus is not equal to `b`'s
	pub(super) fn mul(&self, b: &Self) -> Self {
		Self::mont_reduction(mul_4(&self.0.0, &b.0.0))
	}

	fn maybe_reduce_by_prime(mut res: [u64; 4], extra_high_bit: bool) -> Self {
		if extra_high_bit || !slice_greater_than(&M::PRIME.0, &res) {
			let underflow;
			(res, underflow) = sub(&res, &M::PRIME.0);
			debug_assert_eq!(extra_high_bit, underflow);
		}
		Self(U256(res), PhantomData)
	}

	/// Doubles `self` mod `m`.
	pub(super) fn double(&self) -> Self {
		let mut res = self.0.0;
		let overflow = double!(res);
		Self::maybe_reduce_by_prime(res, overflow)
	}

	/// Multiplies `self` by 3 mod `m`.
	pub(super) fn times_three(&self) -> Self {
		let mid = self.double();
		let (res, overflow) = add(&mid.0.0, &self.0.0);
		Self::maybe_reduce_by_prime(res, overflow)
	}

	/// Multiplies `self` by 4 mod `m`.
	pub(super) fn times_four(&self) -> Self {
		// TODO: Optimize this somewhat?
		self.double().double()
	}

	/// Multiplies `self` by 8 mod `m`.
	pub(super) fn times_eight(&self) -> Self {
		// TODO: Optimize this somewhat?
		self.double().double().double()
	}

	/// Multiplies `self` by 8 mod `m`.
	pub(super) fn square(&self) -> Self {
		Self::mont_reduction(sqr_4(&self.0.0))
	}

	/// Subtracts `b` from `self` % `m`.
	pub(super) fn sub(&self, b: &Self) -> Self {
		let (mut val, underflow) = sub(&self.0.0, &b.0.0);
		if underflow {
			let overflow;
			(val, overflow) = add(&val, &M::PRIME.0);
			debug_assert_eq!(overflow, underflow);
		}
		Self(U256(val), PhantomData)
	}

	/// Adds `b` to `self` % `m`.
	pub(super) fn add(&self, b: &Self) -> Self {
		let (mut val, overflow) = add(&self.0.0, &b.0.0);
		if overflow || !slice_greater_than(&M::PRIME.0, &val) {
			let underflow;
			(val, underflow) = sub(&val, &M::PRIME.0);
			debug_assert_eq!(overflow, underflow);
		}
		Self(U256(val), PhantomData)
	}

	/// Returns the underlying [`U256`].
	pub(super) fn into_u256(self) -> U256 {
		let mut expanded_self = [0; 8];
		expanded_self[4..].copy_from_slice(&self.0.0);
		Self::mont_reduction(expanded_self).0
	}
}

// Values modulus M::PRIME.0, stored in montgomery form.
impl U384 {
	/// Constructs a new [`U384`] from a variable number of big-endian bytes.
	pub(super) fn from_be_bytes(bytes: &[u8]) -> Result<U384, ()> {
		if bytes.len() > 384/8 { return Err(()); }
		let u64s = (bytes.len() + 7) / 8;
		let mut res = [0; WORD_COUNT_384];
		for i in 0..u64s {
			let mut b = [0; 8];
			let pos = (u64s - i) * 8;
			let start = bytes.len().saturating_sub(pos);
			let end = bytes.len() + 8 - pos;
			b[8 + start - end..].copy_from_slice(&bytes[start..end]);
			res[i + WORD_COUNT_384 - u64s] = u64::from_be_bytes(b);
		}
		Ok(U384(res))
	}

	/// Constructs a new [`U384`] from a fixed number of big-endian bytes.
	pub(super) const fn from_48_be_bytes_panicking(bytes: &[u8; 48]) -> U384 {
		let res = [
			eight_bytes_to_u64_be(bytes[0*8 + 0], bytes[0*8 + 1], bytes[0*8 + 2], bytes[0*8 + 3],
			                      bytes[0*8 + 4], bytes[0*8 + 5], bytes[0*8 + 6], bytes[0*8 + 7]),
			eight_bytes_to_u64_be(bytes[1*8 + 0], bytes[1*8 + 1], bytes[1*8 + 2], bytes[1*8 + 3],
			                      bytes[1*8 + 4], bytes[1*8 + 5], bytes[1*8 + 6], bytes[1*8 + 7]),
			eight_bytes_to_u64_be(bytes[2*8 + 0], bytes[2*8 + 1], bytes[2*8 + 2], bytes[2*8 + 3],
			                      bytes[2*8 + 4], bytes[2*8 + 5], bytes[2*8 + 6], bytes[2*8 + 7]),
			eight_bytes_to_u64_be(bytes[3*8 + 0], bytes[3*8 + 1], bytes[3*8 + 2], bytes[3*8 + 3],
			                      bytes[3*8 + 4], bytes[3*8 + 5], bytes[3*8 + 6], bytes[3*8 + 7]),
			eight_bytes_to_u64_be(bytes[4*8 + 0], bytes[4*8 + 1], bytes[4*8 + 2], bytes[4*8 + 3],
			                      bytes[4*8 + 4], bytes[4*8 + 5], bytes[4*8 + 6], bytes[4*8 + 7]),
			eight_bytes_to_u64_be(bytes[5*8 + 0], bytes[5*8 + 1], bytes[5*8 + 2], bytes[5*8 + 3],
			                      bytes[5*8 + 4], bytes[5*8 + 5], bytes[5*8 + 6], bytes[5*8 + 7]),
		];
		U384(res)
	}

	pub(super) const fn zero() -> U384 { U384([0, 0, 0, 0, 0, 0]) }
	pub(super) const fn one() -> U384 { U384([0, 0, 0, 0, 0, 1]) }
}

/// Do mont reduction (but avoid putting it in the templated [`U256Mod`] to avoid having two copies
/// for different primes
const fn u384_mont_reduction_given_prime(mu: [u64; 12], prime: &[u64; 6], negative_prime_inv_mod_r: &[u64; 6]) -> U384 {
	// The definition of REDC (with some names changed):
	// v = ((mu % R) * N') mod R
	// t = (mu + v*N) / R
	// if t >= N { t - N } else { t }

	// mu % R is just the bottom 4 bytes of mu
	let mu_mod_r: &[u64; 6] = const_subarr(&mu, 6);
	// v = ((mu % R) * negative_modulus_inverse) % R
	let mut v = mul_6(mu_mod_r, negative_prime_inv_mod_r);
	const ZEROS: &[u64; 6] = &[0; 6];
	copy_from_slice!(v, 0, 6, ZEROS); // mod R

	// t_on_r = (mu + v*modulus) / R
	let t0 = mul_6(const_subarr(&v, 6), prime);
	let (t1, t1_extra_bit) = add(&t0, &mu);

	// Note that dividing t1 by R is simply a matter of shifting right by 4 bytes.
	// We only need to maintain 4 bytes (plus `t1_extra_bit` which is implicitly an extra bit)
	// because t_on_r is guarantee to be, at max, 2*m - 1.
	let t1_on_r: &[u64; 6] = const_subarr(&t1, 0);

	let mut res = [0; 6];
	// The modulus is only 4 bytes, so t1_extra_bit implies we're definitely larger than the
	// modulus.
	if t1_extra_bit || slice_greater_than(t1_on_r, prime) {
		let underflow;
		(res, underflow) = sub(t1_on_r, prime);
		debug_assert!(t1_extra_bit == underflow);
	} else {
		copy_from_slice!(res, 0, 6, t1_on_r);
	}
	U384(res)
}

impl<M: PrimeModulus<U384>> U384Mod<M> {
	const fn mont_reduction(mu: [u64; 12]) -> Self {
		#[cfg(debug_assertions)] {
			// Check NEGATIVE_PRIME_INV_MOD_R is correct. Since this is all const, the compiler
			// should be able to do it at compile time alone.
			let minus_one_mod_r = mul_6(&M::PRIME.0, &M::NEGATIVE_PRIME_INV_MOD_R.0);
			assert!(slice_equal(const_subslice(&minus_one_mod_r, 6, 12), &[0xffff_ffff_ffff_ffff; 6]));
		}

		#[cfg(debug_assertions)] {
			// Check R_SQUARED_MOD_PRIME is correct. Since this is all const, the compiler
			// should be able to do it at compile time alone.
			let r_minus_one = [0xffff_ffff_ffff_ffff; 6];
			let (mut r_mod_prime, _) = sub(&r_minus_one, &M::PRIME.0);
			let r_mod_prime_overflow = add_u64!(r_mod_prime, 1);
			assert!(!r_mod_prime_overflow);
			let r_squared = sqr_6(&r_mod_prime);
			let mut prime_extended = [0; 12];
			let prime = M::PRIME.0;
			copy_from_slice!(prime_extended, 6, 12, prime);
			let (_, r_squared_mod_prime) = if let Ok(v) = div_rem_12(&r_squared, &prime_extended) { v } else { panic!() };
			assert!(slice_greater_than(&prime_extended, &r_squared_mod_prime));
			assert!(slice_equal(const_subslice(&r_squared_mod_prime, 6, 12), &M::R_SQUARED_MOD_PRIME.0));
		}

		Self(u384_mont_reduction_given_prime(mu, &M::PRIME.0, &M::NEGATIVE_PRIME_INV_MOD_R.0), PhantomData)
	}

	pub(super) const fn from_u384_panicking(v: U384) -> Self {
		assert!(v.0[0] <= M::PRIME.0[0]);
		if v.0[0] == M::PRIME.0[0] {
			assert!(v.0[1] <= M::PRIME.0[1]);
			if v.0[1] == M::PRIME.0[1] {
				assert!(v.0[2] <= M::PRIME.0[2]);
				if v.0[2] == M::PRIME.0[2] {
					assert!(v.0[3] <= M::PRIME.0[3]);
					if v.0[3] == M::PRIME.0[3] {
						assert!(v.0[4] <= M::PRIME.0[4]);
						if v.0[4] == M::PRIME.0[4] {
							assert!(v.0[5] < M::PRIME.0[5]);
						}
					}
				}
			}
		}
		assert!(M::PRIME.0[0] != 0 || M::PRIME.0[1] != 0 || M::PRIME.0[2] != 0
			|| M::PRIME.0[3] != 0|| M::PRIME.0[4] != 0|| M::PRIME.0[5] != 0);
		Self::mont_reduction(mul_6(&M::R_SQUARED_MOD_PRIME.0, &v.0))
	}

	pub(super) fn from_u384(mut v: U384) -> Self {
		debug_assert!(M::PRIME.0 != [0; 6]);
		debug_assert!(M::PRIME.0[0] > (1 << 63), "PRIME should have the top bit set");
		while v >= M::PRIME {
			let (new_v, spurious_underflow) = sub(&v.0, &M::PRIME.0);
			debug_assert!(!spurious_underflow);
			v = U384(new_v);
		}
		Self::mont_reduction(mul_6(&M::R_SQUARED_MOD_PRIME.0, &v.0))
	}

	pub(super) fn from_modinv_of(v: U384) -> Result<Self, ()> {
		Ok(Self::from_u384(U384(mod_inv_6(&v.0, &M::PRIME.0)?)))
	}

	/// Multiplies `self` * `b` mod `m`.
	///
	/// Panics if `self`'s modulus is not equal to `b`'s
	pub(super) fn mul(&self, b: &Self) -> Self {
		Self::mont_reduction(mul_6(&self.0.0, &b.0.0))
	}

	fn maybe_reduce_by_prime(mut res: [u64; 6], extra_high_bit: bool) -> Self {
		if extra_high_bit || !slice_greater_than(&M::PRIME.0, &res) {
			let underflow;
			(res, underflow) = sub(&res, &M::PRIME.0);
			debug_assert_eq!(extra_high_bit, underflow);
		}
		Self(U384(res), PhantomData)
	}

	/// Doubles `self` mod `m`.
	pub(super) fn double(&self) -> Self {
		let mut res = self.0.0;
		let overflow = double!(res);
		Self::maybe_reduce_by_prime(res, overflow)
	}

	/// Multiplies `self` by 3 mod `m`.
	pub(super) fn times_three(&self) -> Self {
		let mid = self.double();
		let (res, overflow) = add(&mid.0.0, &self.0.0);
		Self::maybe_reduce_by_prime(res, overflow)
	}

	/// Multiplies `self` by 4 mod `m`.
	pub(super) fn times_four(&self) -> Self {
		// TODO: Optimize this somewhat?
		self.double().double()
	}

	/// Multiplies `self` by 8 mod `m`.
	pub(super) fn times_eight(&self) -> Self {
		// TODO: Optimize this somewhat?
		self.double().double().double()
	}

	/// Multiplies `self` by 8 mod `m`.
	pub(super) fn square(&self) -> Self {
		Self::mont_reduction(sqr_6(&self.0.0))
	}

	/// Subtracts `b` from `self` % `m`.
	pub(super) fn sub(&self, b: &Self) -> Self {
		let (mut val, underflow) = sub(&self.0.0, &b.0.0);
		if underflow {
			let overflow;
			(val, overflow) = add(&val, &M::PRIME.0);
			debug_assert_eq!(overflow, underflow);
		}
		Self(U384(val), PhantomData)
	}

	/// Adds `b` to `self` % `m`.
	pub(super) fn add(&self, b: &Self) -> Self {
		let (mut val, overflow) = add(&self.0.0, &b.0.0);
		if overflow || !slice_greater_than(&M::PRIME.0, &val) {
			let underflow;
			(val, underflow) = sub(&val, &M::PRIME.0);
			debug_assert_eq!(overflow, underflow);
		}
		Self(U384(val), PhantomData)
	}

	/// Returns the underlying [`U384`].
	pub(super) fn into_u384(self) -> U384 {
		let mut expanded_self = [0; 12];
		expanded_self[6..].copy_from_slice(&self.0.0);
		Self::mont_reduction(expanded_self).0
	}
}

#[cfg(dnssec_prover_fuzzing)]
mod fuzz_moduli {
	use crate::unhex::unhex;
	use super::*;

	pub struct P256();
	impl PrimeModulus<U256> for P256 {
		const PRIME: U256 = U256::from_32_be_bytes_panicking(&unhex(
			"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
		const R_SQUARED_MOD_PRIME: U256 = U256::from_32_be_bytes_panicking(&unhex(
			"00000004fffffffdfffffffffffffffefffffffbffffffff0000000000000003"));
		const NEGATIVE_PRIME_INV_MOD_R: U256 = U256::from_32_be_bytes_panicking(&unhex(
			"ffffffff00000002000000000000000000000001000000000000000000000001"));
	}

	pub struct P384();
	impl PrimeModulus<U384> for P384 {
		const PRIME: U384 = U384::from_48_be_bytes_panicking(&unhex(
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"));
		const R_SQUARED_MOD_PRIME: U384 = U384::from_48_be_bytes_panicking(&unhex(
			"000000000000000000000000000000010000000200000000fffffffe000000000000000200000000fffffffe00000001"));
		const NEGATIVE_PRIME_INV_MOD_R: U384 = U384::from_48_be_bytes_panicking(&unhex(
			"00000014000000140000000c00000002fffffffcfffffffafffffffbfffffffe00000000000000010000000100000001"));
	}
}

#[cfg(dnssec_prover_fuzzing)]
extern crate ibig;
#[cfg(dnssec_prover_fuzzing)]
/// Read some bytes and use them to test bigint math by comparing results against the `ibig` crate.
pub fn fuzz_math(input: &[u8]) {
	if input.len() < 32 || input.len() % 16 != 0 { return; }
	let split = core::cmp::min(input.len() / 2, 512);
	let (a, b) = input.split_at(core::cmp::min(input.len() / 2, 512));
	let b = &b[..split];

	let ai = ibig::UBig::from_be_bytes(&a);
	let bi = ibig::UBig::from_be_bytes(&b);

	let mut a_u64s = Vec::with_capacity(split / 8);
	for chunk in a.chunks(8) {
		a_u64s.push(u64::from_be_bytes(chunk.try_into().unwrap()));
	}
	let mut b_u64s = Vec::with_capacity(split / 8);
	for chunk in b.chunks(8) {
		b_u64s.push(u64::from_be_bytes(chunk.try_into().unwrap()));
	}

	macro_rules! test { ($mul: ident, $sqr: ident, $div_rem: ident, $mod_inv: ident) => {
		let a_arg = (&a_u64s[..]).try_into().unwrap();
		let b_arg = (&b_u64s[..]).try_into().unwrap();

		let res = $mul(a_arg, b_arg);
		let mut res_bytes = Vec::with_capacity(input.len() / 2);
		for i in res {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), ai.clone() * bi.clone());

		debug_assert_eq!($mul(a_arg, a_arg), $sqr(a_arg));
		debug_assert_eq!($mul(b_arg, b_arg), $sqr(b_arg));

		let (res, carry) = add(a_arg, b_arg);
		let mut res_bytes = Vec::with_capacity(input.len() / 2 + 1);
		if carry { res_bytes.push(1); } else { res_bytes.push(0); }
		for i in res {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), ai.clone() + bi.clone());

		let mut add_u64s = a_u64s.clone();
		let carry = add_u64!(add_u64s, 1);
		let mut res_bytes = Vec::with_capacity(input.len() / 2 + 1);
		if carry { res_bytes.push(1); } else { res_bytes.push(0); }
		for i in &add_u64s {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), ai.clone() + 1);

		let mut double_u64s = b_u64s.clone();
		let carry = double!(double_u64s);
		let mut res_bytes = Vec::with_capacity(input.len() / 2 + 1);
		if carry { res_bytes.push(1); } else { res_bytes.push(0); }
		for i in &double_u64s {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}
		assert_eq!(ibig::UBig::from_be_bytes(&res_bytes), bi.clone() * 2);

		let (quot, rem) = if let Ok(res) =
			$div_rem(&a_u64s[..].try_into().unwrap(), &b_u64s[..].try_into().unwrap()) {
				res
			} else { return };
		let mut quot_bytes = Vec::with_capacity(input.len() / 2);
		for i in quot {
			quot_bytes.extend_from_slice(&i.to_be_bytes());
		}
		let mut rem_bytes = Vec::with_capacity(input.len() / 2);
		for i in rem {
			rem_bytes.extend_from_slice(&i.to_be_bytes());
		}
		let (quoti, remi) = ibig::ops::DivRem::div_rem(ai.clone(), &bi);
		assert_eq!(ibig::UBig::from_be_bytes(&quot_bytes), quoti);
		assert_eq!(ibig::UBig::from_be_bytes(&rem_bytes), remi);

		if ai != ibig::UBig::from(0u32) { // ibig provides a spurious modular inverse for 0
			let ring = ibig::modular::ModuloRing::new(&bi);
			let ar = ring.from(ai.clone());
			let invi = ar.inverse().map(|i| i.residue());

			if let Ok(modinv) = $mod_inv(&a_u64s[..].try_into().unwrap(), &b_u64s[..].try_into().unwrap()) {
				let mut modinv_bytes = Vec::with_capacity(input.len() / 2);
				for i in modinv {
					modinv_bytes.extend_from_slice(&i.to_be_bytes());
				}
				assert_eq!(invi.unwrap(), ibig::UBig::from_be_bytes(&modinv_bytes));
			} else {
				assert!(invi.is_none());
			}
		}
	} }

	macro_rules! test_mod { ($amodp: expr, $bmodp: expr, $PRIME: expr, $len: expr, $into: ident, $div_rem_double: ident, $div_rem: ident, $mul: ident) => {
		// Test the U256/U384Mod wrapper, which operates in Montgomery representation
		let mut p_extended = [0; $len * 2];
		p_extended[$len..].copy_from_slice(&$PRIME);

		let a_arg = (&a_u64s[..]).try_into().unwrap();
		let b_arg = (&b_u64s[..]).try_into().unwrap();

		let amodp_squared = $div_rem_double(&$mul(a_arg, a_arg), &p_extended).unwrap().1;
		assert_eq!(&amodp_squared[..$len], &[0; $len]);
		assert_eq!(&$amodp.square().$into().0, &amodp_squared[$len..]);

		let abmodp = $div_rem_double(&$mul(a_arg, b_arg), &p_extended).unwrap().1;
		assert_eq!(&abmodp[..$len], &[0; $len]);
		assert_eq!(&$amodp.mul(&$bmodp).$into().0, &abmodp[$len..]);

		let (aplusb, aplusb_overflow) = add(a_arg, b_arg);
		let mut aplusb_extended = [0; $len * 2];
		aplusb_extended[$len..].copy_from_slice(&aplusb);
		if aplusb_overflow { aplusb_extended[$len - 1] = 1; }
		let aplusbmodp = $div_rem_double(&aplusb_extended, &p_extended).unwrap().1;
		assert_eq!(&aplusbmodp[..$len], &[0; $len]);
		assert_eq!(&$amodp.add(&$bmodp).$into().0, &aplusbmodp[$len..]);

		let (mut aminusb, aminusb_underflow) = sub(a_arg, b_arg);
		if aminusb_underflow {
			let mut overflow;
			(aminusb, overflow) = add(&aminusb, &$PRIME);
			if !overflow {
				(aminusb, overflow) = add(&aminusb, &$PRIME);
			}
			assert!(overflow);
		}
		let aminusbmodp = $div_rem(&aminusb, &$PRIME).unwrap().1;
		assert_eq!(&$amodp.sub(&$bmodp).$into().0, &aminusbmodp);
	} }

	if a_u64s.len() == 2 {
		test!(mul_2, sqr_2, div_rem_2, mod_inv_2);
	} else if a_u64s.len() == 4 {
		test!(mul_4, sqr_4, div_rem_4, mod_inv_4);
		let amodp = U256Mod::<fuzz_moduli::P256>::from_u256(U256(a_u64s[..].try_into().unwrap()));
		let bmodp = U256Mod::<fuzz_moduli::P256>::from_u256(U256(b_u64s[..].try_into().unwrap()));
		test_mod!(amodp, bmodp, fuzz_moduli::P256::PRIME.0, 4, into_u256, div_rem_8, div_rem_4, mul_4);
	} else if a_u64s.len() == 6 {
		test!(mul_6, sqr_6, div_rem_6, mod_inv_6);
		let amodp = U384Mod::<fuzz_moduli::P384>::from_u384(U384(a_u64s[..].try_into().unwrap()));
		let bmodp = U384Mod::<fuzz_moduli::P384>::from_u384(U384(b_u64s[..].try_into().unwrap()));
		test_mod!(amodp, bmodp, fuzz_moduli::P384::PRIME.0, 6, into_u384, div_rem_12, div_rem_6, mul_6);
	} else if a_u64s.len() == 8 {
		test!(mul_8, sqr_8, div_rem_8, mod_inv_8);
	} else if input.len() == 512*2 + 4 {
		let mut e_bytes = [0; 4];
		e_bytes.copy_from_slice(&input[512 * 2..512 * 2 + 4]);
		let e = u32::from_le_bytes(e_bytes);
		let a = U4096::from_be_bytes(&a).unwrap();
		let b = U4096::from_be_bytes(&b).unwrap();

		let res = if let Ok(r) = a.expmod_odd_mod(e, &b) { r } else { return };
		let mut res_bytes = Vec::with_capacity(512);
		for i in res.0 {
			res_bytes.extend_from_slice(&i.to_be_bytes());
		}

		let ring = ibig::modular::ModuloRing::new(&bi);
		let ar = ring.from(ai.clone());
		assert_eq!(ar.pow(&e.into()).residue(), ibig::UBig::from_be_bytes(&res_bytes));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn u64s_to_u128(v: [u64; 2]) -> u128 {
		let mut r = 0;
		r |= v[1] as u128;
		r |= (v[0] as u128) << 64;
		r
	}

	fn u64s_to_i128(v: [u64; 2]) -> i128 {
		let mut r = 0;
		r |= v[1] as i128;
		r |= (v[0] as i128) << 64;
		r
	}

	#[test]
	fn test_negate() {
		let mut zero = [0u64; 2];
		negate!(zero);
		assert_eq!(zero, [0; 2]);

		let mut one = [0u64, 1u64];
		negate!(one);
		assert_eq!(u64s_to_i128(one), -1);

		let mut minus_one: [u64; 2] = [u64::MAX, u64::MAX];
		negate!(minus_one);
		assert_eq!(minus_one, [0, 1]);
	}

	#[test]
	fn test_double() {
		let mut zero = [0u64; 2];
		assert!(!double!(zero));
		assert_eq!(zero, [0; 2]);

		let mut one = [0u64, 1u64];
		assert!(!double!(one));
		assert_eq!(one, [0, 2]);

		let mut u64_max = [0, u64::MAX];
		assert!(!double!(u64_max));
		assert_eq!(u64_max, [1, u64::MAX - 1]);

		let mut u64_carry_overflow = [0x7fff_ffff_ffff_ffffu64, 0x8000_0000_0000_0000];
		assert!(!double!(u64_carry_overflow));
		assert_eq!(u64_carry_overflow, [u64::MAX, 0]);

		let mut max = [u64::MAX; 4];
		assert!(double!(max));
		assert_eq!(max, [u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1]);
	}

	#[test]
	fn mul_min_simple_tests() {
		let a = [1, 2];
		let b = [3, 4];
		let res = mul_2(&a, &b);
		assert_eq!(res, [0, 3, 10, 8]);

		let a = [0x1bad_cafe_dead_beef, 2424];
		let b = [0x2bad_beef_dead_cafe, 4242];
		let res = mul_2(&a, &b);
		assert_eq!(res, [340296855556511776, 15015369169016130186, 4248480538569992542, 10282608]);

		let a = [0xf6d9_f8eb_8b60_7a6d, 0x4b93_833e_2194_fc2e];
		let b = [0xfdab_0000_6952_8ab4, 0xd302_0000_8282_0000];
		let res = mul_2(&a, &b);
		assert_eq!(res, [17625486516939878681, 18390748118453258282, 2695286104209847530, 1510594524414214144]);

		let a = [0x8b8b_8b8b_8b8b_8b8b, 0x8b8b_8b8b_8b8b_8b8b];
		let b = [0x8b8b_8b8b_8b8b_8b8b, 0x8b8b_8b8b_8b8b_8b8b];
		let res = mul_2(&a, &b);
		assert_eq!(res, [5481115605507762349, 8230042173354675923, 16737530186064798, 15714555036048702841]);

		let a = [0x0000_0000_0000_0020, 0x002d_362c_005b_7753];
		let b = [0x0900_0000_0030_0003, 0xb708_00fe_0000_00cd];
		let res = mul_2(&a, &b);
		assert_eq!(res, [1, 2306290405521702946, 17647397529888728169, 10271802099389861239]);

		let a = [0x0000_0000_7fff_ffff, 0xffff_ffff_0000_0000];
		let b = [0x0000_0800_0000_0000, 0x0000_1000_0000_00e1];
		let res = mul_2(&a, &b);
		assert_eq!(res, [1024, 0, 483183816703, 18446743107341910016]);

		let a = [0xf6d9_f8eb_ebeb_eb6d, 0x4b93_83a0_bb35_0680];
		let b = [0xfd02_b9b9_b9b9_b9b9, 0xb9b9_b9b9_b9b9_b9b9];
		let res = mul_2(&a, &b);
		assert_eq!(res, [17579814114991930107, 15033987447865175985, 488855932380801351, 5453318140933190272]);

		let a = [u64::MAX; 2];
		let b = [u64::MAX; 2];
		let res = mul_2(&a, &b);
		assert_eq!(res, [18446744073709551615, 18446744073709551614, 0, 1]);
	}

	#[test]
	fn test_add_sub() {
		fn test(a: [u64; 2], b: [u64; 2]) {
			let a_int = u64s_to_u128(a);
			let b_int = u64s_to_u128(b);

			let res = add(&a, &b);
			assert_eq!((u64s_to_u128(res.0), res.1), a_int.overflowing_add(b_int));

			let res = sub(&a, &b);
			assert_eq!((u64s_to_u128(res.0), res.1), a_int.overflowing_sub(b_int));
		}

		test([0; 2], [0; 2]);
		test([0x1bad_cafe_dead_beef, 2424], [0x2bad_cafe_dead_cafe, 4242]);
		test([u64::MAX; 2], [u64::MAX; 2]);
		test([u64::MAX, 0x8000_0000_0000_0000], [0, 0x7fff_ffff_ffff_ffff]);
		test([0, 0x7fff_ffff_ffff_ffff], [u64::MAX, 0x8000_0000_0000_0000]);
		test([u64::MAX, 0], [0, u64::MAX]);
		test([0, u64::MAX], [u64::MAX, 0]);
		test([u64::MAX; 2], [0; 2]);
		test([0; 2], [u64::MAX; 2]);
	}

	#[test]
	fn mul_4_simple_tests() {
		let a = [1; 4];
		let b = [2; 4];
		assert_eq!(mul_4(&a, &b),
			[0, 2, 4, 6, 8, 6, 4, 2]);

		let a = [0x1bad_cafe_dead_beef, 2424, 0x1bad_cafe_dead_beef, 2424];
		let b = [0x2bad_beef_dead_cafe, 4242, 0x2bad_beef_dead_cafe, 4242];
		assert_eq!(mul_4(&a, &b),
			[340296855556511776, 15015369169016130186, 4929074249683016095, 11583994264332991364,
			 8837257932696496860, 15015369169036695402, 4248480538569992542, 10282608]);

		let a = [u64::MAX; 4];
		let b = [u64::MAX; 4];
		assert_eq!(mul_4(&a, &b),
			[18446744073709551615, 18446744073709551615, 18446744073709551615,
			 18446744073709551614, 0, 0, 0, 1]);
	}

	#[test]
	fn double_simple_tests() {
		let mut a = [0xfff5_b32d_01ff_0000, 0x00e7_e7e7_e7e7_e7e7];
		assert!(double!(a));
		assert_eq!(a, [18440945635998695424, 130551405668716494]);

		let mut a = [u64::MAX, u64::MAX];
		assert!(double!(a));
		assert_eq!(a, [18446744073709551615, 18446744073709551614]);
	}
}
