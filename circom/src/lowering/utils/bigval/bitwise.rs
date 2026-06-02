use super::BigVal;

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

    pub(super) fn bit(self, n: usize) -> bool {
        if n >= 256 {
            return false;
        }
        (self.0[n / 64] >> (n % 64)) & 1 != 0
    }

    pub(super) fn set_bit(&mut self, n: usize) {
        if n < 256 {
            self.0[n / 64] |= 1u64 << (n % 64);
        }
    }
}
