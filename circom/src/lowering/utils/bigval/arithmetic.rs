use super::BigVal;
use std::cmp::Ordering;

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
    pub(super) fn abs(self) -> Self {
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
}
