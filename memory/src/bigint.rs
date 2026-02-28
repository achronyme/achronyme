//! Fixed-width unsigned big integers: 256-bit (4 limbs) and 512-bit (8 limbs).
//!
//! Non-modular arithmetic with overflow/underflow errors.
//! VM-only — not supported in circuit mode.

use std::fmt;

/// Width of a BigInt: 256 or 512 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BigIntWidth {
    W256,
    W512,
}

impl BigIntWidth {
    /// Number of 64-bit limbs for this width.
    #[inline]
    pub fn num_limbs(self) -> usize {
        match self {
            BigIntWidth::W256 => 4,
            BigIntWidth::W512 => 8,
        }
    }

    /// Number of bits for this width.
    #[inline]
    pub fn num_bits(self) -> usize {
        match self {
            BigIntWidth::W256 => 256,
            BigIntWidth::W512 => 512,
        }
    }
}

/// Errors from BigInt arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BigIntError {
    Overflow,
    Underflow,
    DivisionByZero,
    WidthMismatch,
}

impl fmt::Display for BigIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BigIntError::Overflow => write!(f, "BigInt overflow"),
            BigIntError::Underflow => write!(f, "BigInt underflow"),
            BigIntError::DivisionByZero => write!(f, "BigInt division by zero"),
            BigIntError::WidthMismatch => write!(f, "BigInt width mismatch"),
        }
    }
}

/// Fixed-width unsigned big integer.
///
/// Limbs are stored in little-endian order (limbs[0] is least significant).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigInt {
    limbs: Vec<u64>,
    width: BigIntWidth,
}

// ============================================================================
// Low-level helpers
// ============================================================================

/// Add with carry: (result, carry) = a + b + carry_in
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let tmp = a as u128 + b as u128 + carry as u128;
    (tmp as u64, (tmp >> 64) as u64)
}

/// Subtract with borrow: (result, borrow) = a - b - borrow_in
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let tmp = (a as u128)
        .wrapping_sub(b as u128)
        .wrapping_sub(borrow as u128);
    (tmp as u64, (tmp >> 127) as u64)
}

/// Multiply-accumulate: (lo, carry) = a * b + c + carry_in
#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let tmp = a as u128 * b as u128 + c as u128 + carry as u128;
    (tmp as u64, (tmp >> 64) as u64)
}

// ============================================================================
// BigInt public API
// ============================================================================

impl BigInt {
    /// Construct from raw limbs (LE order). The limbs length must match the width.
    pub fn from_limbs(limbs: Vec<u64>, width: BigIntWidth) -> Option<Self> {
        if limbs.len() != width.num_limbs() {
            return None;
        }
        Some(Self { limbs, width })
    }

    /// Create a zero BigInt of the given width.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let z = BigInt::zero(BigIntWidth::W256);
    /// assert!(z.is_zero());
    /// assert_eq!(z.width(), BigIntWidth::W256);
    /// ```
    pub fn zero(width: BigIntWidth) -> Self {
        Self {
            limbs: vec![0u64; width.num_limbs()],
            width,
        }
    }

    /// Create a BigInt with value 1.
    pub fn one(width: BigIntWidth) -> Self {
        let mut limbs = vec![0u64; width.num_limbs()];
        limbs[0] = 1;
        Self { limbs, width }
    }

    /// Create a BigInt from a u64 value.
    ///
    /// ```
    /// use memory::bigint::{BigInt, BigIntWidth};
    ///
    /// let b = BigInt::from_u64(42, BigIntWidth::W256);
    /// assert_eq!(b.to_hex_string(), "2a");
    /// ```
    pub fn from_u64(val: u64, width: BigIntWidth) -> Self {
        let mut limbs = vec![0u64; width.num_limbs()];
        limbs[0] = val;
        Self { limbs, width }
    }

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

    /// Width of this BigInt.
    #[inline]
    pub fn width(&self) -> BigIntWidth {
        self.width
    }

    /// Number of 64-bit limbs.
    #[inline]
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    /// Whether this value is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Get limbs slice (LE order).
    #[inline]
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    fn check_width(&self, other: &Self) -> Result<(), BigIntError> {
        if self.width != other.width {
            Err(BigIntError::WidthMismatch)
        } else {
            Ok(())
        }
    }

    // ========================================================================
    // Arithmetic
    // ========================================================================

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

    // ========================================================================
    // Bitwise operations
    // ========================================================================

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

    // ========================================================================
    // Conversion
    // ========================================================================

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

// ============================================================================
// Trait impls
// ============================================================================

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Different widths compare by width first (256 < 512)
        match self.width.num_bits().cmp(&other.width.num_bits()) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        // Same width: compare limbs from MSB to LSB
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.width {
            BigIntWidth::W256 => write!(f, "BigInt256(0x{})", self.to_hex_string()),
            BigIntWidth::W512 => write!(f, "BigInt512(0x{})", self.to_hex_string()),
        }
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.width {
            BigIntWidth::W256 => write!(f, "BigInt256(0x{})", self.to_hex_string()),
            BigIntWidth::W512 => write!(f, "BigInt512(0x{})", self.to_hex_string()),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constructors ---

    #[test]
    fn test_zero() {
        let z256 = BigInt::zero(BigIntWidth::W256);
        assert!(z256.is_zero());
        assert_eq!(z256.num_limbs(), 4);
        assert_eq!(z256.width(), BigIntWidth::W256);

        let z512 = BigInt::zero(BigIntWidth::W512);
        assert!(z512.is_zero());
        assert_eq!(z512.num_limbs(), 8);
    }

    #[test]
    fn test_one() {
        let one = BigInt::one(BigIntWidth::W256);
        assert!(!one.is_zero());
        assert_eq!(one.limbs()[0], 1);
    }

    #[test]
    fn test_from_u64() {
        let b = BigInt::from_u64(42, BigIntWidth::W256);
        assert_eq!(b.limbs()[0], 42);
        assert_eq!(b.to_hex_string(), "2a");
    }

    #[test]
    fn test_from_u64_max() {
        let b = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
        assert_eq!(b.limbs()[0], u64::MAX);
        assert_eq!(b.to_hex_string(), "ffffffffffffffff");
    }

    // --- Parsing ---

    #[test]
    fn test_from_hex_str() {
        let b = BigInt::from_hex_str("ff", BigIntWidth::W256).unwrap();
        assert_eq!(b, BigInt::from_u64(255, BigIntWidth::W256));

        let b2 = BigInt::from_hex_str("0x2a", BigIntWidth::W256).unwrap();
        assert_eq!(b2, BigInt::from_u64(42, BigIntWidth::W256));
    }

    #[test]
    fn test_from_hex_str_large() {
        let hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let b = BigInt::from_hex_str(hex, BigIntWidth::W256).unwrap();
        assert!(b.limbs().iter().all(|&l| l == u64::MAX));
    }

    #[test]
    fn test_from_hex_str_too_long() {
        // 65 hex chars = 260 bits, too long for 256
        let hex = "1".to_string() + &"0".repeat(64);
        assert!(BigInt::from_hex_str(&hex, BigIntWidth::W256).is_none());
    }

    #[test]
    fn test_from_decimal_str() {
        let b = BigInt::from_decimal_str("42", BigIntWidth::W256).unwrap();
        assert_eq!(b, BigInt::from_u64(42, BigIntWidth::W256));
    }

    #[test]
    fn test_from_binary_str() {
        let b = BigInt::from_binary_str("101010", BigIntWidth::W256).unwrap();
        assert_eq!(b, BigInt::from_u64(42, BigIntWidth::W256));
    }

    #[test]
    fn test_from_binary_str_invalid() {
        assert!(BigInt::from_binary_str("102", BigIntWidth::W256).is_none());
        assert!(BigInt::from_binary_str("", BigIntWidth::W256).is_none());
    }

    // --- Arithmetic ---

    #[test]
    fn test_add_basic() {
        let a = BigInt::from_u64(100, BigIntWidth::W256);
        let b = BigInt::from_u64(200, BigIntWidth::W256);
        let c = a.add(&b).unwrap();
        assert_eq!(c, BigInt::from_u64(300, BigIntWidth::W256));
    }

    #[test]
    fn test_add_carry() {
        let a = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
        let b = BigInt::from_u64(1, BigIntWidth::W256);
        let c = a.add(&b).unwrap();
        assert_eq!(c.limbs()[0], 0);
        assert_eq!(c.limbs()[1], 1);
    }

    #[test]
    fn test_add_overflow() {
        let max = BigInt::from_hex_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            BigIntWidth::W256,
        )
        .unwrap();
        let one = BigInt::one(BigIntWidth::W256);
        assert_eq!(max.add(&one), Err(BigIntError::Overflow));
    }

    #[test]
    fn test_sub_basic() {
        let a = BigInt::from_u64(300, BigIntWidth::W256);
        let b = BigInt::from_u64(100, BigIntWidth::W256);
        assert_eq!(a.sub(&b).unwrap(), BigInt::from_u64(200, BigIntWidth::W256));
    }

    #[test]
    fn test_sub_underflow() {
        let a = BigInt::from_u64(0, BigIntWidth::W256);
        let b = BigInt::from_u64(1, BigIntWidth::W256);
        assert_eq!(a.sub(&b), Err(BigIntError::Underflow));
    }

    #[test]
    fn test_mul_basic() {
        let a = BigInt::from_u64(6, BigIntWidth::W256);
        let b = BigInt::from_u64(7, BigIntWidth::W256);
        assert_eq!(a.mul(&b).unwrap(), BigInt::from_u64(42, BigIntWidth::W256));
    }

    #[test]
    fn test_mul_large() {
        let a = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
        let b = BigInt::from_u64(u64::MAX, BigIntWidth::W256);
        let c = a.mul(&b).unwrap();
        // u64::MAX * u64::MAX = (2^64-1)^2 = 2^128 - 2^65 + 1
        assert_eq!(c.limbs()[0], 1);
        assert_eq!(c.limbs()[1], 0xfffffffffffffffe);
        assert_eq!(c.limbs()[2], 0);
    }

    #[test]
    fn test_mul_overflow() {
        let max = BigInt::from_hex_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            BigIntWidth::W256,
        )
        .unwrap();
        let two = BigInt::from_u64(2, BigIntWidth::W256);
        assert_eq!(max.mul(&two), Err(BigIntError::Overflow));
    }

    #[test]
    fn test_div_basic() {
        let a = BigInt::from_u64(42, BigIntWidth::W256);
        let b = BigInt::from_u64(7, BigIntWidth::W256);
        assert_eq!(a.div(&b).unwrap(), BigInt::from_u64(6, BigIntWidth::W256));
    }

    #[test]
    fn test_div_truncates() {
        let a = BigInt::from_u64(10, BigIntWidth::W256);
        let b = BigInt::from_u64(3, BigIntWidth::W256);
        assert_eq!(a.div(&b).unwrap(), BigInt::from_u64(3, BigIntWidth::W256));
    }

    #[test]
    fn test_div_by_zero() {
        let a = BigInt::from_u64(42, BigIntWidth::W256);
        let z = BigInt::zero(BigIntWidth::W256);
        assert_eq!(a.div(&z), Err(BigIntError::DivisionByZero));
    }

    #[test]
    fn test_modulo() {
        let a = BigInt::from_u64(10, BigIntWidth::W256);
        let b = BigInt::from_u64(3, BigIntWidth::W256);
        assert_eq!(
            a.modulo(&b).unwrap(),
            BigInt::from_u64(1, BigIntWidth::W256)
        );
    }

    // --- Bitwise ---

    #[test]
    fn test_bit_and() {
        let a = BigInt::from_u64(0xFF, BigIntWidth::W256);
        let b = BigInt::from_u64(0x0F, BigIntWidth::W256);
        assert_eq!(
            a.bit_and(&b).unwrap(),
            BigInt::from_u64(0x0F, BigIntWidth::W256)
        );
    }

    #[test]
    fn test_bit_or() {
        let a = BigInt::from_u64(0xF0, BigIntWidth::W256);
        let b = BigInt::from_u64(0x0F, BigIntWidth::W256);
        assert_eq!(
            a.bit_or(&b).unwrap(),
            BigInt::from_u64(0xFF, BigIntWidth::W256)
        );
    }

    #[test]
    fn test_bit_xor() {
        let a = BigInt::from_u64(0xFF, BigIntWidth::W256);
        let b = BigInt::from_u64(0x0F, BigIntWidth::W256);
        assert_eq!(
            a.bit_xor(&b).unwrap(),
            BigInt::from_u64(0xF0, BigIntWidth::W256)
        );
    }

    #[test]
    fn test_bit_not() {
        let a = BigInt::zero(BigIntWidth::W256);
        let not_a = a.bit_not();
        assert!(not_a.limbs().iter().all(|&l| l == u64::MAX));
    }

    #[test]
    fn test_shl() {
        let a = BigInt::from_u64(1, BigIntWidth::W256);
        let b = a.shl(8).unwrap();
        assert_eq!(b, BigInt::from_u64(256, BigIntWidth::W256));
    }

    #[test]
    fn test_shl_overflow() {
        let a = BigInt::from_u64(1, BigIntWidth::W256);
        // Shift 1 left by 256 should overflow
        assert_eq!(a.shl(256), Err(BigIntError::Overflow));
    }

    #[test]
    fn test_shr() {
        let a = BigInt::from_u64(256, BigIntWidth::W256);
        let b = a.shr(8);
        assert_eq!(b, BigInt::from_u64(1, BigIntWidth::W256));
    }

    #[test]
    fn test_shr_large() {
        let a = BigInt::from_u64(42, BigIntWidth::W256);
        let b = a.shr(256);
        assert!(b.is_zero());
    }

    // --- Comparison ---

    #[test]
    fn test_comparison() {
        let a = BigInt::from_u64(10, BigIntWidth::W256);
        let b = BigInt::from_u64(20, BigIntWidth::W256);
        assert!(a < b);
        assert!(b > a);
        assert!(a <= a);
        assert!(a >= a);
    }

    // --- Width mismatch ---

    #[test]
    fn test_width_mismatch() {
        let a = BigInt::from_u64(1, BigIntWidth::W256);
        let b = BigInt::from_u64(1, BigIntWidth::W512);
        assert_eq!(a.add(&b), Err(BigIntError::WidthMismatch));
    }

    // --- Roundtrips ---

    #[test]
    fn test_hex_roundtrip() {
        let hex = "deadbeef12345678";
        let b = BigInt::from_hex_str(hex, BigIntWidth::W256).unwrap();
        assert_eq!(b.to_hex_string(), hex);
    }

    #[test]
    fn test_decimal_roundtrip() {
        let dec = "123456789012345678901234567890";
        let b = BigInt::from_decimal_str(dec, BigIntWidth::W256).unwrap();
        assert_eq!(b.to_decimal_string(), dec);
    }

    #[test]
    fn test_bits_roundtrip() {
        let b = BigInt::from_u64(42, BigIntWidth::W256);
        let bits = b.to_bits();
        let recovered = BigInt::from_bits(&bits, BigIntWidth::W256).unwrap();
        assert_eq!(b, recovered);
    }

    // --- Display ---

    #[test]
    fn test_display_256() {
        let b = BigInt::from_u64(255, BigIntWidth::W256);
        assert_eq!(format!("{}", b), "BigInt256(0xff)");
    }

    #[test]
    fn test_display_512() {
        let b = BigInt::from_u64(255, BigIntWidth::W512);
        assert_eq!(format!("{}", b), "BigInt512(0xff)");
    }

    // --- 512-bit tests ---

    #[test]
    fn test_512_add() {
        let a = BigInt::from_u64(100, BigIntWidth::W512);
        let b = BigInt::from_u64(200, BigIntWidth::W512);
        assert_eq!(a.add(&b).unwrap(), BigInt::from_u64(300, BigIntWidth::W512));
    }

    #[test]
    fn test_512_mul() {
        let a = BigInt::from_u64(1000, BigIntWidth::W512);
        let b = BigInt::from_u64(2000, BigIntWidth::W512);
        assert_eq!(
            a.mul(&b).unwrap(),
            BigInt::from_u64(2_000_000, BigIntWidth::W512)
        );
    }

    #[test]
    fn test_shl_cross_limb() {
        let a = BigInt::from_u64(1, BigIntWidth::W256);
        let b = a.shl(64).unwrap();
        assert_eq!(b.limbs()[0], 0);
        assert_eq!(b.limbs()[1], 1);
    }

    #[test]
    fn test_shr_cross_limb() {
        let mut limbs = vec![0u64; 4];
        limbs[1] = 1; // 2^64
        let a = BigInt {
            limbs,
            width: BigIntWidth::W256,
        };
        let b = a.shr(64);
        assert_eq!(b, BigInt::from_u64(1, BigIntWidth::W256));
    }
}
