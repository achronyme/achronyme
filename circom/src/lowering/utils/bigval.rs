//! 256-bit two's complement integer for compile-time evaluation.
//!
//! Circom `var` computations can produce values up to 254 bits (BN254 field).
//! The standard `i64` evaluator overflows on expressions like `1 << 128`.
//! `BigVal` provides full 256-bit arithmetic with signed comparison support.

use std::cmp::Ordering;

use ir::prove_ir::types::FieldConst;

/// A 256-bit two's complement integer stored as 4 little-endian u64 limbs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BigVal(pub [u64; 4]);

// ---------------------------------------------------------------------------
// Constants & constructors
// ---------------------------------------------------------------------------

impl BigVal {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub fn from_i64(v: i64) -> Self {
        let fill = if v < 0 { u64::MAX } else { 0 };
        Self([v as u64, fill, fill, fill])
    }

    pub fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0])
    }

    /// Extract as i64 if the value fits in the signed 64-bit range.
    pub fn to_i64(self) -> Option<i64> {
        if self.is_negative() {
            // Negative: upper limbs must be all-ones, and limb[0] must have bit 63 set
            if self.0[1] == u64::MAX && self.0[2] == u64::MAX && self.0[3] == u64::MAX {
                let v = self.0[0] as i64;
                if v < 0 {
                    return Some(v);
                }
            }
            None
        } else {
            // Positive: upper limbs must be zero, and limb[0] must not have bit 63 set
            if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 && (self.0[0] as i64) >= 0 {
                Some(self.0[0] as i64)
            } else {
                None
            }
        }
    }

    /// Extract as u64 if the value is non-negative and fits.
    pub fn to_u64(self) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            Some(self.0[0])
        } else {
            None
        }
    }

    pub fn to_field_const(self) -> FieldConst {
        let mut bytes = [0u8; 32];
        for (i, &limb) in self.0.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        FieldConst::from_le_bytes(bytes)
    }

    pub fn from_field_const(fc: FieldConst) -> Self {
        let b = fc.bytes();
        let limb = |i: usize| u64::from_le_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
        Self([limb(0), limb(1), limb(2), limb(3)])
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    pub fn is_negative(self) -> bool {
        (self.0[3] >> 63) != 0
    }
}

// ---------------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------------

impl BigVal {
    #[allow(clippy::needless_range_loop)]
    pub fn add(self, rhs: Self) -> Self {
        let mut r = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            r[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        Self(r)
    }

    #[allow(clippy::needless_range_loop)]
    pub fn sub(self, rhs: Self) -> Self {
        let mut r = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (s1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        Self(r)
    }

    pub fn neg(self) -> Self {
        let inv = Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]]);
        inv.add(Self::ONE)
    }

    /// Absolute value (unsigned).
    fn abs(self) -> Self {
        if self.is_negative() {
            self.neg()
        } else {
            self
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        let mut r = [0u64; 4];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..(4 - i) {
                let k = i + j;
                let prod = (self.0[i] as u128) * (rhs.0[j] as u128) + (r[k] as u128) + carry;
                r[k] = prod as u64;
                carry = prod >> 64;
            }
        }
        Self(r)
    }

    /// Unsigned division and modulo. Returns None if divisor is zero.
    fn unsigned_divmod(self, rhs: Self) -> Option<(Self, Self)> {
        if rhs.is_zero() {
            return None;
        }
        // Fast path: both fit in u64
        if self.0[1] == 0
            && self.0[2] == 0
            && self.0[3] == 0
            && rhs.0[1] == 0
            && rhs.0[2] == 0
            && rhs.0[3] == 0
        {
            return Some((
                Self::from_u64(self.0[0] / rhs.0[0]),
                Self::from_u64(self.0[0] % rhs.0[0]),
            ));
        }
        // Binary long division
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for bit in (0..256).rev() {
            remainder = remainder.shl(1);
            if self.bit(bit) {
                remainder.0[0] |= 1;
            }
            if remainder.cmp_unsigned(rhs) != Ordering::Less {
                remainder = remainder.sub(rhs);
                quotient.set_bit(bit);
            }
        }
        Some((quotient, remainder))
    }

    /// Signed division (truncates toward zero). Returns None if divisor is zero.
    pub fn div(self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        let a = self.abs();
        let b = rhs.abs();
        let (q, _) = a.unsigned_divmod(b)?;
        Some(if self.is_negative() != rhs.is_negative() {
            q.neg()
        } else {
            q
        })
    }

    /// Signed remainder (sign follows dividend). Returns None if divisor is zero.
    pub fn rem(self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        let a = self.abs();
        let b = rhs.abs();
        let (_, r) = a.unsigned_divmod(b)?;
        Some(if self.is_negative() { r.neg() } else { r })
    }

    pub fn pow(self, exp: u32) -> Self {
        if exp == 0 {
            return Self::ONE;
        }
        let mut base = self;
        let mut result = Self::ONE;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }
        result
    }

    // ------------------------------------------------------------------
    // Field-aware arithmetic (BN254 scalar field)
    //
    // Circom's `var` semantics are field arithmetic modulo the scalar
    // field order, not signed 256-bit integer arithmetic. For patterns
    // like Edwards-curve `pointAdd` (`(x1*y2 + y1*x2) / (1 + d*x1*...)`)
    // the integer path wraps around and produces garbage; the field
    // path produces the actual curve coordinate. Callers route `+ - * /`
    // on values that may exceed u64 through these — index arithmetic
    // and loop bounds continue to use the plain integer variants.
    // ------------------------------------------------------------------

    /// Reduce the integer representation to a BN254 field element.
    ///
    /// A BigVal with its top bit set is interpreted as a two's
    /// complement negative (so `from_i64(-3)` is `-3`, not
    /// `2^256 - 3`). Negatives canonicalize to `p - |v|`, matching
    /// circom's semantics for `-3` stored in a `var`. Non-negative
    /// values get the straight mod-p reduction via Horner over the
    /// four u64 limbs so values up to `2^256 - 1` flow through.
    fn to_bn254(self) -> memory::FieldElement<memory::Bn254Fr> {
        if self.is_negative() {
            let abs = self.abs();
            return abs.to_bn254_unsigned().neg();
        }
        self.to_bn254_unsigned()
    }

    fn to_bn254_unsigned(self) -> memory::FieldElement<memory::Bn254Fr> {
        let fc = self.to_field_const();
        if let Some(fe) = fc.to_field::<memory::Bn254Fr>() {
            return fe;
        }
        let limbs = self.0;
        // 2^64 as a field element, used as the Horner base. Built
        // via `(1 << 32) * (1 << 32)` since FieldElement lacks a
        // direct `from_u128` constructor.
        let base = {
            let shift32 = memory::FieldElement::<memory::Bn254Fr>::from_u64(1u64 << 32);
            shift32.mul(&shift32)
        };
        let mut acc = memory::FieldElement::<memory::Bn254Fr>::zero();
        for &limb in limbs.iter().rev() {
            acc = acc.mul(&base);
            acc = acc.add(&memory::FieldElement::<memory::Bn254Fr>::from_u64(limb));
        }
        acc
    }

    fn from_bn254(fe: memory::FieldElement<memory::Bn254Fr>) -> Self {
        let fc = FieldConst::from_field::<memory::Bn254Fr>(fe);
        Self::from_field_const(fc)
    }

    /// Field-modular addition.
    pub fn field_add(self, rhs: Self) -> Self {
        Self::from_bn254(self.to_bn254().add(&rhs.to_bn254()))
    }

    pub fn field_sub(self, rhs: Self) -> Self {
        Self::from_bn254(self.to_bn254().sub(&rhs.to_bn254()))
    }

    pub fn field_mul(self, rhs: Self) -> Self {
        Self::from_bn254(self.to_bn254().mul(&rhs.to_bn254()))
    }

    /// Field-modular division (multiplication by modular inverse).
    /// Returns `None` if the divisor is zero in the field.
    pub fn field_div(self, rhs: Self) -> Option<Self> {
        let a = self.to_bn254();
        let b = rhs.to_bn254();
        Some(Self::from_bn254(a.div(&b)?))
    }

    pub fn field_neg(self) -> Self {
        Self::from_bn254(self.to_bn254().neg())
    }

    /// Canonicalize to the BN254 field representation. Negative
    /// two's complement values map to `p - |v|`; out-of-range
    /// positive values reduce modulo p. Used when an externally-
    /// constructed BigVal (e.g. `from_i64(-3)`) enters the
    /// evaluator and needs to be interpreted as a field element.
    pub fn to_field_canonical(self) -> Self {
        Self::from_bn254(self.to_bn254())
    }
}

// ---------------------------------------------------------------------------
// Bitwise & shift
// ---------------------------------------------------------------------------

impl BigVal {
    pub fn bitand(self, rhs: Self) -> Self {
        Self([
            self.0[0] & rhs.0[0],
            self.0[1] & rhs.0[1],
            self.0[2] & rhs.0[2],
            self.0[3] & rhs.0[3],
        ])
    }

    pub fn bitor(self, rhs: Self) -> Self {
        Self([
            self.0[0] | rhs.0[0],
            self.0[1] | rhs.0[1],
            self.0[2] | rhs.0[2],
            self.0[3] | rhs.0[3],
        ])
    }

    pub fn bitxor(self, rhs: Self) -> Self {
        Self([
            self.0[0] ^ rhs.0[0],
            self.0[1] ^ rhs.0[1],
            self.0[2] ^ rhs.0[2],
            self.0[3] ^ rhs.0[3],
        ])
    }

    pub fn bitnot(self) -> Self {
        Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    #[allow(clippy::needless_range_loop, clippy::manual_memcpy)]
    pub fn shl(self, n: u32) -> Self {
        if n >= 256 {
            return Self::ZERO;
        }
        if n == 0 {
            return self;
        }
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let mut r = [0u64; 4];
        if bit_shift == 0 {
            for i in limb_shift..4 {
                r[i] = self.0[i - limb_shift];
            }
        } else {
            for i in limb_shift..4 {
                r[i] = self.0[i - limb_shift] << bit_shift;
                if i > limb_shift {
                    r[i] |= self.0[i - limb_shift - 1] >> (64 - bit_shift);
                }
            }
        }
        Self(r)
    }

    /// Arithmetic right shift (sign-extending).
    #[allow(clippy::needless_range_loop, clippy::manual_memcpy)]
    pub fn shr(self, n: u32) -> Self {
        if n >= 256 {
            return if self.is_negative() {
                Self([u64::MAX; 4])
            } else {
                Self::ZERO
            };
        }
        if n == 0 {
            return self;
        }
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let fill = if self.is_negative() { u64::MAX } else { 0 };
        let mut r = [fill; 4];
        if bit_shift == 0 {
            for i in 0..(4 - limb_shift) {
                r[i] = self.0[i + limb_shift];
            }
        } else {
            for i in 0..(4 - limb_shift) {
                r[i] = self.0[i + limb_shift] >> bit_shift;
                let upper = if i + limb_shift + 1 < 4 {
                    self.0[i + limb_shift + 1]
                } else {
                    fill
                };
                r[i] |= upper << (64 - bit_shift);
            }
        }
        Self(r)
    }

    fn bit(self, n: usize) -> bool {
        if n >= 256 {
            return false;
        }
        (self.0[n / 64] >> (n % 64)) & 1 != 0
    }

    fn set_bit(&mut self, n: usize) {
        if n < 256 {
            self.0[n / 64] |= 1u64 << (n % 64);
        }
    }
}

// ---------------------------------------------------------------------------
// Comparisons
// ---------------------------------------------------------------------------

impl BigVal {
    /// Unsigned comparison.
    pub fn cmp_unsigned(self, rhs: Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&rhs.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }

    /// Signed comparison (two's complement).
    pub fn cmp_signed(self, rhs: Self) -> Ordering {
        let a_neg = self.is_negative();
        let b_neg = rhs.is_negative();
        match (a_neg, b_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.cmp_unsigned(rhs), // same sign → unsigned order works
        }
    }

    /// Field-signed comparison: values in (p/2, p) are treated as
    /// negative, values in [0, p/2] as non-negative. This matches
    /// circom's semantics for `<`, `>`, `<=`, `>=` on `var` values.
    pub fn cmp_field_signed(self, rhs: Self) -> Ordering {
        let a = self.to_field_canonical();
        let b = rhs.to_field_canonical();
        let a_neg = a.is_field_negative();
        let b_neg = b.is_field_negative();
        match (a_neg, b_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => a.cmp_unsigned(b),
        }
    }

    /// True iff this value, interpreted as a BN254 field element,
    /// lies in the "negative" half: `(p/2, p)`. Assumes the value
    /// is already canonicalized to `[0, p)`.
    pub fn is_field_negative(self) -> bool {
        self.cmp_unsigned(Self::bn254_half_order()) == Ordering::Greater
    }

    /// `(p-1)/2` for the BN254 scalar field, cached after first use.
    /// Values strictly greater than this half are treated as
    /// negative under circom's `var` comparison semantics.
    fn bn254_half_order() -> Self {
        use memory::FieldBackend;
        use std::sync::OnceLock;
        static HALF: OnceLock<BigVal> = OnceLock::new();
        *HALF.get_or_init(|| {
            let mod_bytes = memory::Bn254Fr::modulus_le_bytes();
            let fc = FieldConst::from_le_bytes(mod_bytes);
            let p = Self::from_field_const(fc);
            let p_minus_one = p.sub(Self::ONE);
            p_minus_one.shr(1)
        })
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Debug for BigVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_negative() {
            write!(f, "BigVal(-{})", self.neg().fmt_unsigned())
        } else {
            write!(f, "BigVal({})", self.fmt_unsigned())
        }
    }
}

impl BigVal {
    fn fmt_unsigned(&self) -> String {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            format!("{}", self.0[0])
        } else {
            format!(
                "0x{:016x}{:016x}{:016x}{:016x}",
                self.0[3], self.0[2], self.0[1], self.0[0]
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_add_sub() {
        let a = BigVal::from_i64(10);
        let b = BigVal::from_i64(20);
        assert_eq!(a.add(b).to_i64(), Some(30));
        assert_eq!(b.sub(a).to_i64(), Some(10));
        assert_eq!(a.sub(b).to_i64(), Some(-10));
    }

    #[test]
    fn neg_and_abs() {
        let a = BigVal::from_i64(-5);
        assert!(a.is_negative());
        assert_eq!(a.neg().to_i64(), Some(5));
        assert_eq!(a.abs().to_i64(), Some(5));
    }

    #[test]
    fn mul_basic() {
        let a = BigVal::from_i64(12345);
        let b = BigVal::from_i64(67890);
        assert_eq!(a.mul(b).to_i64(), Some(12345 * 67890));
    }

    #[test]
    fn mul_signed() {
        let a = BigVal::from_i64(-3);
        let b = BigVal::from_i64(7);
        assert_eq!(a.mul(b).to_i64(), Some(-21));
    }

    #[test]
    fn shift_left_128() {
        // The critical test case: 1 << 128
        let one = BigVal::ONE;
        let shifted = one.shl(128);
        assert_eq!(shifted.0, [0, 0, 1, 0]);
        assert!(!shifted.is_negative());
        assert!(shifted.to_u64().is_none()); // doesn't fit in u64

        // (1 << 128) - 1 = 2^128 - 1
        let result = shifted.sub(BigVal::ONE);
        assert_eq!(result.0, [u64::MAX, u64::MAX, 0, 0]);
    }

    #[test]
    fn shift_right_extracts_bits() {
        // CompConstant: (ct >> i) & 1
        let val = BigVal([0xFF00, 0, 0, 0]);
        assert_eq!(val.shr(8).bitand(BigVal::ONE).to_i64(), Some(1));
        assert_eq!(val.shr(7).bitand(BigVal::ONE).to_i64(), Some(0));
    }

    #[test]
    fn shift_right_large() {
        let val = BigVal([0, 0, 1, 0]); // 2^128
        let shifted = val.shr(64);
        assert_eq!(shifted.0, [0, 1, 0, 0]); // 2^64
    }

    #[test]
    fn signed_comparison() {
        let pos = BigVal::from_i64(5);
        let neg = BigVal::from_i64(-1);
        let zero = BigVal::ZERO;

        assert_eq!(pos.cmp_signed(neg), Ordering::Greater);
        assert_eq!(neg.cmp_signed(pos), Ordering::Less);
        assert_eq!(neg.cmp_signed(zero), Ordering::Less);
        assert_eq!(zero.cmp_signed(neg), Ordering::Greater);
    }

    #[test]
    fn div_and_rem() {
        let a = BigVal::from_i64(17);
        let b = BigVal::from_i64(5);
        assert_eq!(a.div(b), Some(BigVal::from_i64(3)));
        assert_eq!(a.rem(b), Some(BigVal::from_i64(2)));

        let c = BigVal::from_i64(-17);
        assert_eq!(c.div(b), Some(BigVal::from_i64(-3)));
        assert_eq!(c.rem(b), Some(BigVal::from_i64(-2)));
    }

    #[test]
    fn div_by_zero() {
        assert_eq!(BigVal::ONE.div(BigVal::ZERO), None);
    }

    #[test]
    fn pow_basic() {
        let base = BigVal::from_i64(2);
        assert_eq!(base.pow(10).to_i64(), Some(1024));
        assert_eq!(BigVal::from_i64(3).pow(0).to_i64(), Some(1));
    }

    #[test]
    fn bitwise_ops() {
        let a = BigVal::from_u64(0xFF);
        let b = BigVal::from_u64(0x0F);
        assert_eq!(a.bitand(b).to_u64(), Some(0x0F));
        assert_eq!(a.bitor(b).to_u64(), Some(0xFF));
        assert_eq!(a.bitxor(b).to_u64(), Some(0xF0));
    }

    #[test]
    fn field_const_roundtrip() {
        let val = BigVal::ONE.shl(128).sub(BigVal::ONE); // 2^128 - 1
        let fc = val.to_field_const();
        let back = BigVal::from_field_const(fc);
        assert_eq!(val, back);
    }

    #[test]
    fn to_i64_boundary() {
        assert_eq!(BigVal::from_i64(i64::MAX).to_i64(), Some(i64::MAX));
        assert_eq!(BigVal::from_i64(i64::MIN).to_i64(), Some(i64::MIN));
        assert_eq!(BigVal::from_i64(0).to_i64(), Some(0));
        assert_eq!(BigVal::from_i64(-1).to_i64(), Some(-1));
    }

    #[test]
    fn loop_variable_goes_negative() {
        // Simulate: for (var i = 2; i >= 0; i--)
        let mut i = BigVal::from_i64(2);
        let zero = BigVal::ZERO;
        let mut iterations = 0;
        while i.cmp_signed(zero) != Ordering::Less {
            iterations += 1;
            i = i.sub(BigVal::ONE);
        }
        assert_eq!(iterations, 3); // i=2, i=1, i=0
        assert_eq!(i.to_i64(), Some(-1));
    }

    #[test]
    fn compconstant_simulation() {
        // Simulate the CompConstant var computation:
        // var b = (1 << 128) - 1;
        // var a = 1; var e = 1;
        // for i in 0..127: b = b - e; a = a + e; e = e * 2;
        let mut b = BigVal::ONE.shl(128).sub(BigVal::ONE);
        let mut a = BigVal::ONE;
        let mut e = BigVal::ONE;

        let initial_b = b;
        assert_eq!(initial_b.0, [u64::MAX, u64::MAX, 0, 0]); // 2^128 - 1

        for _ in 0..127 {
            b = b.sub(e);
            a = a.add(e);
            e = e.mul(BigVal::from_i64(2));
        }

        // After 127 iterations: e = 2^127
        // sum of e values = 1+2+4+...+2^126 = 2^127 - 1
        // b = (2^128-1) - (2^127-1) = 2^127
        // a = 1 + (2^127-1) = 2^127
        assert_eq!(e.0, [0, 1 << 63, 0, 0]); // 2^127
        assert_eq!(b.0, [0, 1 << 63, 0, 0]); // 2^127
        assert_eq!(a.0, [0, 1 << 63, 0, 0]); // 2^127
    }
}
