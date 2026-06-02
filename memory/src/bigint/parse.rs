use super::{BigInt, BigIntWidth};

impl BigInt {
    /// Parse from hex string (without "0x" prefix).
    pub fn from_hex_str(s: &str, width: BigIntWidth) -> Option<Self> {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        if hex.is_empty() {
            return None;
        }
        let max_hex_chars = width.num_limbs() * 16;
        if hex.len() > max_hex_chars {
            return None;
        }
        // Validate all chars are hex digits
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let padded = format!("{:0>width$}", hex, width = max_hex_chars);
        let n = width.num_limbs();
        let mut limbs = vec![0u64; n];
        // Big-endian hex: first chars are most significant
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = (n - 1 - i) * 16;
            *limb = u64::from_str_radix(&padded[start..start + 16], 16).ok()?;
        }
        Some(Self { limbs, width })
    }

    /// Parse from decimal string.
    pub fn from_decimal_str(s: &str, width: BigIntWidth) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        let n = width.num_limbs();
        let mut limbs = vec![0u64; n];
        for ch in s.chars() {
            let digit = ch.to_digit(10)? as u64;
            // limbs = limbs * 10 + digit
            let mut carry = 0u128;
            for limb in limbs.iter_mut() {
                let wide = *limb as u128 * 10 + carry;
                *limb = wide as u64;
                carry = wide >> 64;
            }
            if carry != 0 {
                return None; // overflow during parse
            }
            let mut add_carry = digit as u128;
            for limb in limbs.iter_mut() {
                let wide = *limb as u128 + add_carry;
                *limb = wide as u64;
                add_carry = wide >> 64;
            }
            if add_carry != 0 {
                return None;
            }
        }
        Some(Self { limbs, width })
    }

    /// Parse from binary string (only '0'/'1' chars).
    pub fn from_binary_str(s: &str, width: BigIntWidth) -> Option<Self> {
        if s.is_empty() || s.len() > width.num_bits() {
            return None;
        }
        let n = width.num_limbs();
        let mut limbs = vec![0u64; n];
        for ch in s.chars() {
            let digit = match ch {
                '0' => 0u64,
                '1' => 1u64,
                _ => return None,
            };
            // limbs = limbs * 2 + digit
            let mut carry = 0u64;
            for limb in limbs.iter_mut() {
                let new_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = new_carry;
            }
            if carry != 0 {
                return None;
            }
            limbs[0] |= digit;
        }
        Some(Self { limbs, width })
    }
}
