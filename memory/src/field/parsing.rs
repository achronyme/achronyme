use super::arithmetic::{gte, sbb, MODULUS};
use super::FieldElement;

impl FieldElement {
    /// Convert to 32 bytes in little-endian canonical form.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let fe = FieldElement::from_u64(42);
    /// let bytes = fe.to_le_bytes();
    /// let recovered = FieldElement::from_le_bytes(&bytes).unwrap();
    /// assert_eq!(fe, recovered);
    /// ```
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let canonical = self.to_canonical();
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&canonical[i].to_le_bytes());
        }
        bytes
    }

    /// Create from 32 bytes in little-endian canonical form.
    /// Returns `None` if the value is >= the BN254 prime modulus.
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        if gte(&limbs, &MODULUS) {
            return None;
        }
        Some(Self::from_canonical(limbs))
    }

    /// Parse from decimal string.
    ///
    /// ```
    /// use memory::FieldElement;
    ///
    /// let fe = FieldElement::from_decimal_str("123456789").unwrap();
    /// assert_eq!(fe.to_decimal_string(), "123456789");
    /// ```
    pub fn from_decimal_str(s: &str) -> Option<Self> {
        // Parse into [u64; 4] canonical form using repeated multiply-add
        let mut result = [0u64; 4];
        for ch in s.chars() {
            let digit = ch.to_digit(10)? as u64;
            // result = result * 10 + digit (in 256-bit arithmetic)
            let mut carry = 0u128;
            for limb in result.iter_mut() {
                let wide = *limb as u128 * 10 + carry;
                *limb = wide as u64;
                carry = wide >> 64;
            }
            // Add digit
            let mut add_carry = digit as u128;
            for limb in result.iter_mut() {
                let wide = *limb as u128 + add_carry;
                *limb = wide as u64;
                add_carry = wide >> 64;
            }
        }
        // Reduce mod p if needed
        while gte(&result, &MODULUS) {
            let (r0, borrow) = sbb(result[0], MODULUS[0], 0);
            let (r1, borrow) = sbb(result[1], MODULUS[1], borrow);
            let (r2, borrow) = sbb(result[2], MODULUS[2], borrow);
            let (r3, _) = sbb(result[3], MODULUS[3], borrow);
            result = [r0, r1, r2, r3];
        }
        Some(Self::from_canonical(result))
    }

    /// Parse from hex string (with or without "0x" prefix)
    pub fn from_hex_str(s: &str) -> Option<Self> {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        if hex.is_empty() || hex.len() > 64 {
            return None;
        }
        // Parse hex string into [u64; 4] little-endian
        let padded = format!("{:0>64}", hex);
        let mut result = [0u64; 4];
        // Big-endian hex: first chars are most significant
        result[3] = u64::from_str_radix(&padded[0..16], 16).ok()?;
        result[2] = u64::from_str_radix(&padded[16..32], 16).ok()?;
        result[1] = u64::from_str_radix(&padded[32..48], 16).ok()?;
        result[0] = u64::from_str_radix(&padded[48..64], 16).ok()?;
        // Reduce mod p
        while gte(&result, &MODULUS) {
            let (r0, borrow) = sbb(result[0], MODULUS[0], 0);
            let (r1, borrow) = sbb(result[1], MODULUS[1], borrow);
            let (r2, borrow) = sbb(result[2], MODULUS[2], borrow);
            let (r3, _) = sbb(result[3], MODULUS[3], borrow);
            result = [r0, r1, r2, r3];
        }
        Some(Self::from_canonical(result))
    }

    /// Parse from binary string (only '0'/'1' chars, max 256 chars)
    pub fn from_binary_str(s: &str) -> Option<Self> {
        if s.is_empty() || s.len() > 256 {
            return None;
        }
        let mut result = [0u64; 4];
        for ch in s.chars() {
            let digit = match ch {
                '0' => 0u64,
                '1' => 1u64,
                _ => return None,
            };
            // result = result * 2 + digit (in 256-bit arithmetic)
            let mut carry = 0u64;
            for limb in result.iter_mut() {
                let new_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = new_carry;
            }
            // Add digit
            let mut add_carry = digit as u128;
            for limb in result.iter_mut() {
                let wide = *limb as u128 + add_carry;
                *limb = wide as u64;
                add_carry = wide >> 64;
            }
        }
        // Reduce mod p if needed
        while gte(&result, &MODULUS) {
            let (r0, borrow) = sbb(result[0], MODULUS[0], 0);
            let (r1, borrow) = sbb(result[1], MODULUS[1], borrow);
            let (r2, borrow) = sbb(result[2], MODULUS[2], borrow);
            let (r3, _) = sbb(result[3], MODULUS[3], borrow);
            result = [r0, r1, r2, r3];
        }
        Some(Self::from_canonical(result))
    }

    /// Display as canonical decimal string
    pub fn to_decimal_string(&self) -> String {
        let canonical = self.to_canonical();
        if canonical == [0; 4] {
            return "0".to_string();
        }
        // Convert [u64; 4] to decimal via repeated division by 10
        let mut limbs = canonical;
        let mut digits = Vec::new();
        loop {
            if limbs[0] == 0 && limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                break;
            }
            // Divide 256-bit number by 10
            let mut remainder = 0u128;
            for i in (0..4).rev() {
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
