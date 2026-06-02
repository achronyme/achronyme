use super::{BigInt, BigIntWidth};
use std::fmt;

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
