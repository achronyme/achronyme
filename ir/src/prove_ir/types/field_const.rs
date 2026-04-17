//! Field-erased 256-bit constant shared by all prime backends.
//!
//! `FieldConst` stores a value as 32 canonical little-endian bytes so
//! ProveIR can stay non-generic while still carrying constants from any
//! supported prime field. The `PrimeId` in the serialization header tells
//! the instantiator which `FieldElement<F>` to reconstruct.

use memory::{FieldBackend, FieldElement};
use serde::{Deserialize, Serialize};

/// Read a little-endian `u64` from an 8-byte window of `buf` starting
/// at `offset`. Panic-free variant of
/// `u64::from_le_bytes(buf[offset..offset+8].try_into().unwrap())` —
/// `copy_from_slice` has the same bounds check as the slice index but
/// doesn't require the fallible `TryFrom<&[u8]>` conversion, so no
/// `.unwrap()` lurks in the final byte.
#[inline]
fn read_le_u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// A field-erased constant stored as 32 canonical little-endian bytes.
///
/// This allows ProveIR to remain non-generic while storing constants from
/// any supported prime field. The `PrimeId` in the serialization header
/// tells the instantiator which `FieldElement<F>` to reconstruct.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldConst([u8; 32]);

impl std::fmt::Debug for FieldConst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show as hex for readability. Panic-free: slice `self.0`
        // (always 32 bytes) into known 8-byte arrays without going
        // through the fallible `.try_into()` path.
        let limbs = [
            read_le_u64(&self.0, 0),
            read_le_u64(&self.0, 8),
            read_le_u64(&self.0, 16),
            read_le_u64(&self.0, 24),
        ];
        if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
            write!(f, "FieldConst({})", limbs[0])
        } else {
            write!(
                f,
                "FieldConst(0x{:016x}{:016x}{:016x}{:016x})",
                limbs[3], limbs[2], limbs[1], limbs[0]
            )
        }
    }
}

impl FieldConst {
    /// The additive identity (zero) — same in all fields.
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// The multiplicative identity (one) — same in all fields.
    pub fn one() -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        Self(bytes)
    }

    /// Create from a small integer. Valid in all fields (all moduli > 2^64).
    pub fn from_u64(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&v.to_le_bytes());
        Self(bytes)
    }

    /// Create from a `FieldElement<F>` by extracting canonical LE bytes.
    pub fn from_field<F: FieldBackend>(fe: FieldElement<F>) -> Self {
        Self(fe.to_le_bytes())
    }

    /// Reconstruct a `FieldElement<F>` from the stored bytes.
    /// Returns `None` if the bytes are not valid in field `F` (e.g., >= modulus).
    pub fn to_field<F: FieldBackend>(&self) -> Option<FieldElement<F>> {
        FieldElement::<F>::from_le_bytes(&self.0)
    }

    /// Extract as u64 if the value fits. Returns `None` if upper bytes are nonzero.
    pub fn to_u64(&self) -> Option<u64> {
        if self.0[8..].iter().any(|&b| b != 0) {
            return None;
        }
        Some(read_le_u64(&self.0, 0))
    }

    /// Check if this is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Create from a decimal string (e.g., `"218882428718392752..."`).
    ///
    /// Stores the raw integer as LE bytes — no modular reduction.
    /// Returns `None` if the string is invalid or the value exceeds 32 bytes.
    pub fn from_decimal_str(s: &str) -> Option<Self> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut bytes = [0u8; 32];
        for &ch in s.as_bytes() {
            let digit = (ch - b'0') as u16;
            // Multiply current value by 10, then add digit
            let mut carry = digit;
            for byte in bytes.iter_mut() {
                let v = (*byte as u16) * 10 + carry;
                *byte = v as u8;
                carry = v >> 8;
            }
            if carry != 0 {
                return None; // overflow: value doesn't fit in 256 bits
            }
        }
        Some(Self(bytes))
    }

    /// Create from a hex string (with or without `0x`/`0X` prefix).
    ///
    /// Stores the raw integer as LE bytes — no modular reduction.
    /// Returns `None` if the string is invalid or exceeds 32 bytes (64 hex digits).
    pub fn from_hex_str(s: &str) -> Option<Self> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if hex.is_empty() || hex.len() > 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let digits = hex.as_bytes();
        let mut byte_idx = 0;
        let mut i = digits.len();
        while i > 0 {
            let lo = fc_hex_val(digits[i - 1])?;
            i -= 1;
            let hi = if i > 0 {
                i -= 1;
                fc_hex_val(digits[i])?
            } else {
                0
            };
            bytes[byte_idx] = (hi << 4) | lo;
            byte_idx += 1;
        }
        Some(Self(bytes))
    }

    /// Create from raw little-endian bytes.
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes access.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Parse a single hex digit to its value.
fn fc_hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
