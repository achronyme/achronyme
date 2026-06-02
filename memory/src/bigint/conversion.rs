use super::{BigInt, BigIntWidth};

impl BigInt {
    /// Convert to a vector of bits (LSB-first, each element is 0 or 1).
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let b = BigInt::from_u64(5, BigIntWidth::W256); // binary: 101
    /// let bits = b.to_bits();
    /// assert_eq!(bits[0], 1); // LSB
    /// assert_eq!(bits[1], 0);
    /// assert_eq!(bits[2], 1);
    /// assert_eq!(bits.len(), 256);
    /// ```
    pub fn to_bits(&self) -> Vec<u8> {
        let total = self.width.num_bits();
        let mut bits = Vec::with_capacity(total);
        for i in 0..total {
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            bits.push(((self.limbs[limb_idx] >> bit_idx) & 1) as u8);
        }
        bits
    }

    /// Construct from a vector of bits (LSB-first).
    pub fn from_bits(bits: &[u8], width: BigIntWidth) -> Option<Self> {
        let total = width.num_bits();
        if bits.len() != total {
            return None;
        }
        let n = width.num_limbs();
        let mut limbs = vec![0u64; n];
        for (i, &bit) in bits.iter().enumerate() {
            if bit > 1 {
                return None;
            }
            let limb_idx = i / 64;
            let bit_idx = i % 64;
            limbs[limb_idx] |= (bit as u64) << bit_idx;
        }
        Some(Self { limbs, width })
    }

    /// Format as hex string (no prefix, lowercase, minimal).
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let b = BigInt::from_u64(255, BigIntWidth::W256);
    /// assert_eq!(b.to_hex_string(), "ff");
    /// assert_eq!(BigInt::zero(BigIntWidth::W256).to_hex_string(), "0");
    /// ```
    pub fn to_hex_string(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let mut hex = String::new();
        let mut started = false;
        for i in (0..self.limbs.len()).rev() {
            if !started {
                if self.limbs[i] != 0 {
                    hex.push_str(&format!("{:x}", self.limbs[i]));
                    started = true;
                }
            } else {
                hex.push_str(&format!("{:016x}", self.limbs[i]));
            }
        }
        hex
    }

    /// Format as decimal string.
    pub fn to_decimal_string(&self) -> String {
        if self.is_zero() {
            return "0".to_string();
        }
        let mut limbs = self.limbs.clone();
        let mut digits = Vec::new();
        loop {
            if limbs.iter().all(|&l| l == 0) {
                break;
            }
            let mut remainder = 0u128;
            for i in (0..limbs.len()).rev() {
                let combined = (remainder << 64) | limbs[i] as u128;
                limbs[i] = (combined / 10) as u64;
                remainder = combined % 10;
            }
            digits.push((remainder as u8) + b'0');
        }
        if digits.is_empty() {
            "0".to_string()
        } else {
            digits.reverse();
            String::from_utf8(digits).unwrap()
        }
    }
}
