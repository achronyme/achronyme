use super::{BigInt, BigIntError};
use crate::limb_ops::{adc, mac, sbb};

impl BigInt {
    /// Addition with overflow error.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let a = BigInt::from_u64(100, BigIntWidth::W256);
    /// let b = BigInt::from_u64(200, BigIntWidth::W256);
    /// let c = a.add(&b).unwrap();
    /// assert_eq!(c, BigInt::from_u64(300, BigIntWidth::W256));
    /// ```
    pub fn add(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        let mut result = vec![0u64; self.limbs.len()];
        let mut carry = 0u64;
        for (i, res) in result.iter_mut().enumerate() {
            let (r, c) = adc(self.limbs[i], other.limbs[i], carry);
            *res = r;
            carry = c;
        }
        if carry != 0 {
            return Err(BigIntError::Overflow);
        }
        Ok(Self {
            limbs: result,
            width: self.width,
        })
    }

    /// Subtraction with underflow error.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let a = BigInt::from_u64(300, BigIntWidth::W256);
    /// let b = BigInt::from_u64(100, BigIntWidth::W256);
    /// let c = a.sub(&b).unwrap();
    /// assert_eq!(c, BigInt::from_u64(200, BigIntWidth::W256));
    /// ```
    pub fn sub(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        let mut result = vec![0u64; self.limbs.len()];
        let mut borrow = 0u64;
        for (i, res) in result.iter_mut().enumerate() {
            let (r, b) = sbb(self.limbs[i], other.limbs[i], borrow);
            *res = r;
            borrow = b;
        }
        if borrow != 0 {
            return Err(BigIntError::Underflow);
        }
        Ok(Self {
            limbs: result,
            width: self.width,
        })
    }

    /// Multiplication with overflow error.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let a = BigInt::from_u64(6, BigIntWidth::W256);
    /// let b = BigInt::from_u64(7, BigIntWidth::W256);
    /// let c = a.mul(&b).unwrap();
    /// assert_eq!(c, BigInt::from_u64(42, BigIntWidth::W256));
    /// ```
    pub fn mul(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        let n = self.limbs.len();
        // Produce 2N limbs via schoolbook multiplication
        let mut wide = vec![0u64; 2 * n];
        for i in 0..n {
            let mut carry = 0u64;
            for j in 0..n {
                let (lo, hi) = mac(self.limbs[i], other.limbs[j], wide[i + j], carry);
                wide[i + j] = lo;
                carry = hi;
            }
            wide[i + n] = carry;
        }
        // Check upper N limbs are zero (no overflow)
        if wide[n..2 * n].iter().any(|&l| l != 0) {
            return Err(BigIntError::Overflow);
        }
        Ok(Self {
            limbs: wide[..n].to_vec(),
            width: self.width,
        })
    }

    /// Division (truncating). Errors on division by zero.
    pub fn div(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        if other.is_zero() {
            return Err(BigIntError::DivisionByZero);
        }
        let (q, _) = self.divmod(other);
        Ok(q)
    }

    /// Modulo. Errors on division by zero.
    pub fn modulo(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        if other.is_zero() {
            return Err(BigIntError::DivisionByZero);
        }
        let (_, r) = self.divmod(other);
        Ok(r)
    }

    /// Shift-subtract division: returns (quotient, remainder).
    fn divmod(&self, divisor: &Self) -> (Self, Self) {
        let n = self.limbs.len();
        let total_bits = n * 64;
        let mut quotient = Self::zero(self.width);
        let mut remainder = Self::zero(self.width);

        // Bit-by-bit long division, MSB first
        for i in (0..total_bits).rev() {
            // Shift remainder left by 1
            let mut carry = 0u64;
            for limb in remainder.limbs.iter_mut() {
                let new_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = new_carry;
            }
            // Bring down bit i from self
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            remainder.limbs[0] |= (self.limbs[limb_idx] >> bit_idx) & 1;

            // If remainder >= divisor, subtract and set quotient bit
            if remainder.gte(divisor) {
                let mut borrow = 0u64;
                for j in 0..n {
                    let (r, b) = sbb(remainder.limbs[j], divisor.limbs[j], borrow);
                    remainder.limbs[j] = r;
                    borrow = b;
                }
                quotient.limbs[limb_idx] |= 1u64 << bit_idx;
            }
        }
        (quotient, remainder)
    }

    /// self >= other (same width assumed)
    fn gte(&self, other: &Self) -> bool {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] > other.limbs[i] {
                return true;
            }
            if self.limbs[i] < other.limbs[i] {
                return false;
            }
        }
        true // equal
    }
}
