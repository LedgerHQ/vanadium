//! Simple verification of ECDSA signatures over SECP Random curves
//!
//! The group law and the double-and-add ladder below are upstream's, unchanged. What changed is
//! what they run on: field elements are `sdk::bignum::BigNumMod`, so each multiplication,
//! addition, subtraction and inversion is one modular-arithmetic ECALL executed natively rather
//! than a Montgomery routine interpreted instruction by instruction. See `crypto/mod.rs`.

use sdk::bignum::{BigNumMod, ModulusProvider, PrimeModulusProvider};

/// An element of the curve field, i.e. an integer mod `p`.
pub(super) type CurveField<const N: usize, C> = BigNumMod<N, <C as Curve<N>>::CurveModulus>;
/// An element of the scalar field, i.e. an integer mod `n`.
pub(super) type ScalarField<const N: usize, C> = BigNumMod<N, <C as Curve<N>>::ScalarModulus>;

/// `0`, in whichever field is inferred.
const fn zero<const N: usize, M: ModulusProvider<N>>() -> BigNumMod<N, M> {
    BigNumMod::from_be_bytes_noreduce([0u8; N])
}

/// `1`, in whichever field is inferred.
const fn one<const N: usize, M: ModulusProvider<N>>() -> BigNumMod<N, M> {
    let mut buf = [0u8; N];
    buf[N - 1] = 1;
    BigNumMod::from_be_bytes_noreduce(buf)
}

/// The small-multiple helpers the curve formulas are written in terms of. Upstream's Montgomery
/// backend had reason to specialise them; here they are just repeated modular additions, which is
/// what its `double`/`times_three` did too.
trait SmallMultiples: Sized {
    fn square(&self) -> Self;
    fn double(&self) -> Self;
    fn times_three(&self) -> Self;
    fn times_four(&self) -> Self;
    fn times_eight(&self) -> Self;
}

impl<const N: usize, M: ModulusProvider<N>> SmallMultiples for BigNumMod<N, M> {
    fn square(&self) -> Self {
        self * self
    }
    fn double(&self) -> Self {
        self + self
    }
    fn times_three(&self) -> Self {
        &self.double() + self
    }
    fn times_four(&self) -> Self {
        self.double().double()
    }
    fn times_eight(&self) -> Self {
        self.double().double().double()
    }
}

/// A short-Weierstrass curve `y^2 = x^3 + ax + b` over `F_p` whose generator has prime order `n`,
/// with `p` and `n` both `N` bytes wide and `n < p`.
pub(super) trait Curve<const N: usize>: Copy {
    // `Clone` is required only because `BigNumMod` derives it, which bounds its modulus
    // parameter even though it is held in a `PhantomData`.
    /// The curve field modulus `p`.
    type CurveModulus: PrimeModulusProvider<N> + Clone;
    /// The scalar field modulus `n`, i.e. the order of [`Curve::G`].
    type ScalarModulus: PrimeModulusProvider<N> + Clone;

    /// The `a` coefficient.
    const A: CurveField<N, Self>;
    /// The `b` coefficient.
    const B: CurveField<N, Self>;

    /// The generator.
    const G: Point<N, Self>;
}

#[derive(Clone)]
/// A Point, stored in Jacobian coordinates
pub(super) struct Point<const N: usize, C: Curve<N>> {
    x: CurveField<N, C>,
    y: CurveField<N, C>,
    z: CurveField<N, C>,
}

impl<const N: usize, C: Curve<N>> Point<N, C> {
    fn on_curve(x: &CurveField<N, C>, y: &CurveField<N, C>) -> Result<(), ()> {
        let x_2 = x.square();
        let x_3 = &x_2 * x;
        let v = &(&x_3 + &(&C::A * x)) + &C::B;

        let y_2 = y.square();
        if y_2 != v {
            Err(())
        } else {
            Ok(())
        }
    }

    /// The affine `x` coordinate, i.e. `x / z^2`.
    ///
    /// This costs a modular inversion, which the projective comparison in [`Point::eq_x`] exists
    /// to avoid; it is only used by the exact check `eq_x` falls back on under test.
    #[cfg(test)]
    fn normalize_x(&self) -> Result<CurveField<N, C>, ()> {
        if self.z == zero() {
            return Err(());
        }
        let m = self.z.inv();
        Ok(&self.x * &m.square())
    }

    #[cfg(debug_assertions)]
    fn on_curve_z(
        x: &CurveField<N, C>,
        y: &CurveField<N, C>,
        z: &CurveField<N, C>,
    ) -> Result<(), ()> {
        // m = 1 / z
        // x_norm = x * m^2
        // y_norm = y * m^3

        if *z == zero() {
            return Err(());
        }
        let m = z.inv();
        let m_2 = m.square();
        let m_3 = &m_2 * &m;
        let x_norm = x * &m_2;
        let y_norm = y * &m_3;
        Self::on_curve(&x_norm, &y_norm)
    }

    fn from_xy(x: [u8; N], y: [u8; N]) -> Result<Self, ()> {
        let x = CurveField::<N, C>::from_be_bytes(x);
        let y = CurveField::<N, C>::from_be_bytes(y);
        Self::on_curve(&x, &y)?;
        Ok(Point { x, y, z: one() })
    }

    pub(super) const fn from_xy_assuming_on_curve(
        x: CurveField<N, C>,
        y: CurveField<N, C>,
    ) -> Self {
        Point { x, y, z: one() }
    }

    /// Checks that `expected_x` is equal to our X affine coordinate (without modular inversion).
    fn eq_x(&self, expected_x: &ScalarField<N, C>) -> Result<(), ()> {
        // If x is between N and P the below calculation will fail and we'll spuriously reject a
        // signature. We should in theory accept such signatures, but the probability of this
        // happening at random is roughly 1/2^128, i.e. we really don't need to handle it in
        // practice. Thus, we only bother to do the (inversion-costing) exact check in tests,
        // where the wycheproof vectors expect it.
        #[allow(unused_mut, unused_assignments)]
        let mut slow_check = None;
        #[cfg(test)]
        {
            let normalized = self.normalize_x()?;
            slow_check =
                Some(ScalarField::<N, C>::from_be_bytes(normalized.to_be_bytes()) == *expected_x);
        }

        if self.z == zero() {
            return Err(());
        }
        // `expected_x` is reduced mod `n`; re-reading it mod `p` is exact because `n < p`.
        let e = CurveField::<N, C>::from_be_bytes(expected_x.to_be_bytes());
        let ezz = &(&e * &self.z) * &self.z;
        if self.x == ezz || slow_check == Some(true) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn double(&self) -> Result<Self, ()> {
        if self.y == zero() {
            return Err(());
        }
        if self.z == zero() {
            return Err(());
        }

        // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
        // delta = Z1^2
        // gamma = Y1^2
        // beta = X1*gamma
        // alpha = 3*(X1-delta)*(X1+delta)
        // X3 = alpha^2-8*beta
        // Z3 = (Y1+Z1)^2-gamma-delta
        // Y3 = alpha*(4*beta-X3)-8*gamma^2

        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = &self.x * &gamma;
        let alpha = &(&self.x - &delta).times_three() * &(&self.x + &delta);
        let x = &alpha.square() - &beta.times_eight();
        let y = &(&alpha * &(&beta.times_four() - &x)) - &gamma.square().times_eight();
        let z = &(&(&self.y + &self.z).square() - &gamma) - &delta;

        #[cfg(debug_assertions)]
        {
            assert!(Self::on_curve_z(&x, &y, &z).is_ok());
        }
        Ok(Point { x, y, z })
    }

    fn add(&self, o: &Self) -> Result<Self, ()> {
        // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
        // Z1Z1 = Z1^2
        // Z2Z2 = Z2^2
        // U1 = X1*Z2Z2
        // U2 = X2*Z1Z1
        // S1 = Y1*Z2*Z2Z2
        // S2 = Y2*Z1*Z1Z1
        // H = U2-U1
        // I = (2*H)^2
        // J = H*I
        // r = 2*(S2-S1)
        // V = U1*I
        // X3 = r^2-J-2*V
        // Y3 = r*(V-X3)-2*S1*J
        // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H

        let o_z_2 = o.z.square();
        let self_z_2 = self.z.square();

        let u1 = &self.x * &o_z_2;
        let u2 = &o.x * &self_z_2;
        let s1 = &self.y * &(&o.z * &o_z_2);
        let s2 = &o.y * &(&self.z * &self_z_2);
        if u1 == u2 {
            if s1 != s2 {
                /* Point at Infinity */
                return Err(());
            }
            return self.double();
        }
        let h = &u2 - &u1;
        let i = h.double().square();
        let j = &h * &i;
        let r = (&s2 - &s1).double();
        let v = &u1 * &i;
        let x = &(&r.square() - &j) - &v.double();
        let y = &(&r * &(&v - &x)) - &(&s1.double() * &j);
        let z = &(&(&(&self.z + &o.z).square() - &self_z_2) - &o_z_2) * &h;

        #[cfg(debug_assertions)]
        {
            assert!(Self::on_curve_z(&x, &y, &z).is_ok());
        }
        Ok(Point { x, y, z })
    }
}

/// Calculates i * I + j * J
#[allow(non_snake_case)]
fn add_two_mul<const N: usize, C: Curve<N>>(
    i: ScalarField<N, C>,
    I: &Point<N, C>,
    j: ScalarField<N, C>,
    J: &Point<N, C>,
) -> Result<Point<N, C>, ()> {
    let i = i.to_be_bytes();
    let j = j.to_be_bytes();

    if i == [0; N] {
        /* Infinity */
        return Err(());
    }
    if j == [0; N] {
        /* Infinity */
        return Err(());
    }

    let mut res_opt: Result<Point<N, C>, ()> = Err(());
    // Skip the leading bytes in which neither scalar has a set bit, then start at the most
    // significant bit either of them does have, so that the ladder is not run for nothing.
    let skip_bytes = i
        .iter()
        .zip(j.iter())
        .position(|(ib, jb)| *ib != 0 || *jb != 0)
        .unwrap_or(N);
    for (idx, (ib, jb)) in i.iter().zip(j.iter()).skip(skip_bytes).enumerate() {
        let start_bit = if idx == 0 {
            core::cmp::min(ib.leading_zeros(), jb.leading_zeros())
        } else {
            0
        };
        for b in start_bit..8 {
            let i_bit = (*ib & (1 << (7 - b))) != 0;
            let j_bit = (*jb & (1 << (7 - b))) != 0;
            if let Ok(res) = res_opt.as_mut() {
                *res = res.double()?;
            }
            if i_bit {
                if let Ok(res) = res_opt.as_mut() {
                    // The wycheproof tests expect to see signatures pass even if we hit Point at
                    // Infinity (PAI) on an intermediate result. While that's fine, I'm too lazy to
                    // go figure out if all our PAI definitions are right and the probability of
                    // this happening at random is, basically, the probability of guessing a private
                    // key anyway, so its not really worth actually handling outside of tests.
                    #[cfg(test)]
                    {
                        res_opt = res.add(I);
                    }
                    #[cfg(not(test))]
                    {
                        *res = res.add(I)?;
                    }
                } else {
                    res_opt = Ok(I.clone());
                }
            }
            if j_bit {
                if let Ok(res) = res_opt.as_mut() {
                    // See the comment above on hitting the Point at Infinity.
                    #[cfg(test)]
                    {
                        res_opt = res.add(J);
                    }
                    #[cfg(not(test))]
                    {
                        *res = res.add(J)?;
                    }
                } else {
                    res_opt = Ok(J.clone());
                }
            }
        }
    }
    res_opt
}

/// Reads a scalar which must lie in `[1, n-1]`, rejecting anything else.
///
/// The range check is not merely pedantry about signature malleability: `BigNumMod::inv` panics
/// rather than failing when handed a non-invertible value, so `s == 0 (mod n)` has to be turned
/// away here, before it reaches the inversion.
fn read_scalar<const N: usize, C: Curve<N>>(bytes: &[u8]) -> Result<ScalarField<N, C>, ()> {
    let buf: [u8; N] = bytes.try_into().map_err(|_| ())?;
    if buf == [0; N] {
        return Err(());
    }
    // Both are `N`-byte big-endian, so comparing the byte strings compares the integers.
    if buf >= C::ScalarModulus::M {
        return Err(());
    }
    Ok(ScalarField::<N, C>::from_be_bytes(buf))
}

/// Validates the given signature against the given public key and message digest.
pub(super) fn validate_ecdsa<const N: usize, C: Curve<N>>(
    pk: &[u8],
    sig: &[u8],
    hash_input: &[u8],
) -> Result<(), ()> {
    #![allow(non_snake_case)]

    // `eq_x` compares an `x` read mod `p` against a scalar reduced mod `n`, which is only exact
    // because `n < p`. Upstream asserted this too; it is the one thing a newly added curve could
    // get wrong without any test noticing, since for P-256 and P-384 it happens to hold.
    debug_assert!(
        C::ScalarModulus::M < C::CurveModulus::M,
        "the scalar field must be smaller than the curve field"
    );

    if pk.len() != N * 2 {
        return Err(());
    }
    if sig.len() != N * 2 {
        return Err(());
    }

    let (r_bytes, s_bytes) = sig.split_at(N);
    let (pk_x_bytes, pk_y_bytes) = pk.split_at(N);

    let pk_x: [u8; N] = pk_x_bytes.try_into().map_err(|_| ())?;
    let pk_y: [u8; N] = pk_y_bytes.try_into().map_err(|_| ())?;
    let PK = Point::<N, C>::from_xy(pk_x, pk_y)?;

    let r = read_scalar::<N, C>(r_bytes)?;
    let s = read_scalar::<N, C>(s_bytes)?;
    let s_inv = s.inv();

    // A digest shorter than the scalar field is left-padded and then reduced mod `n`. A longer one
    // ought to be truncated to its leftmost bits per FIPS 186-4 §6.4, but no DNSSEC algorithm
    // pairs a curve with a longer hash (13 is P-256/SHA-256, 14 is P-384/SHA-384), so rather than
    // carry the truncation rule we reject it, as upstream does.
    if hash_input.len() > N {
        return Err(());
    }
    let mut z_bytes = [0u8; N];
    z_bytes[N - hash_input.len()..].copy_from_slice(hash_input);
    let z = ScalarField::<N, C>::from_be_bytes(z_bytes);

    let u_a = &z * &s_inv;
    let u_b = &r * &s_inv;

    let V = add_two_mul::<N, C>(u_a, &C::G, u_b, &PK)?;
    V.eq_x(&r)
}
