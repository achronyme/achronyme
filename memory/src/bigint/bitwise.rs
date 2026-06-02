use super::{BigInt, BigIntError};

impl BigInt {
    /// Bitwise AND.
    pub fn bit_and(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        let limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .map(|(&a, &b)| a & b)
            .collect();
        Ok(Self {
            limbs,
            width: self.width,
        })
    }

    /// Bitwise OR.
    pub fn bit_or(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        let limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .map(|(&a, &b)| a | b)
            .collect();
        Ok(Self {
            limbs,
            width: self.width,
        })
    }

    /// Bitwise XOR.
    pub fn bit_xor(&self, other: &Self) -> Result<Self, BigIntError> {
        self.check_width(other)?;
        let limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .map(|(&a, &b)| a ^ b)
            .collect();
        Ok(Self {
            limbs,
            width: self.width,
        })
    }

    /// Bitwise NOT (flip all bits within the width).
    pub fn bit_not(&self) -> Self {
        let limbs = self.limbs.iter().map(|&l| !l).collect();
        Self {
            limbs,
            width: self.width,
        }
    }

    /// Shift left by `amount` bits. Errors if any bits would be shifted out.
    pub fn shl(&self, amount: u32) -> Result<Self, BigIntError> {
        let total_bits = self.width.num_bits() as u32;
        if amount >= total_bits {
            // Only ok if self is zero
            if self.is_zero() {
                return Ok(self.clone());
            }
            return Err(BigIntError::Overflow);
        }
        if amount == 0 {
            return Ok(self.clone());
        }

        let n = self.limbs.len();
        let limb_shift = (amount / 64) as usize;
        let bit_shift = amount % 64;

        // Check if any bits would be lost
        // Bits at positions >= (total_bits - amount) must be zero
        let check_start_bit = total_bits - amount;
        for bit_pos in check_start_bit..total_bits {
            let li = (bit_pos / 64) as usize;
            let bi = bit_pos % 64;
            if li < n && (self.limbs[li] >> bi) & 1 != 0 {
                return Err(BigIntError::Overflow);
            }
        }

        let mut result = vec![0u64; n];
        for (i, res) in result.iter_mut().enumerate() {
            if i >= limb_shift {
                let src = i - limb_shift;
                if bit_shift == 0 {
                    *res = self.limbs[src];
                } else {
                    *res |= self.limbs[src] << bit_shift;
                    if src > 0 {
                        *res |= self.limbs[src - 1] >> (64 - bit_shift);
                    }
                }
            }
        }
        Ok(Self {
            limbs: result,
            width: self.width,
        })
    }

    /// Shift right by `amount` bits. Infallible (fills with zeros).
    pub fn shr(&self, amount: u32) -> Self {
        let total_bits = self.width.num_bits() as u32;
        if amount >= total_bits {
            return Self::zero(self.width);
        }
        if amount == 0 {
            return self.clone();
        }

        let n = self.limbs.len();
        let limb_shift = (amount / 64) as usize;
        let bit_shift = amount % 64;

        let mut result = vec![0u64; n];
        for (i, res) in result.iter_mut().enumerate() {
            let src = i + limb_shift;
            if src < n {
                if bit_shift == 0 {
                    *res = self.limbs[src];
                } else {
                    *res = self.limbs[src] >> bit_shift;
                    if src + 1 < n {
                        *res |= self.limbs[src + 1] << (64 - bit_shift);
                    }
                }
            }
        }
        Self {
            limbs: result,
            width: self.width,
        }
    }
}
