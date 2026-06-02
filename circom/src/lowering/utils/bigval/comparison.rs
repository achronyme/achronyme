use super::BigVal;
use std::cmp::Ordering;

// ---------------------------------------------------------------------------
// Comparisons
// ---------------------------------------------------------------------------

impl BigVal {
    /// Unsigned comparison.
    pub fn cmp_unsigned(self, rhs: Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&rhs.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }

    /// Signed comparison (two's complement).
    pub fn cmp_signed(self, rhs: Self) -> Ordering {
        let a_neg = self.is_negative();
        let b_neg = rhs.is_negative();
        match (a_neg, b_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.cmp_unsigned(rhs), // same sign -> unsigned order works
        }
    }

    /// Field-signed comparison: values in (p/2, p) are treated as
    /// negative, values in [0, p/2] as non-negative. This matches
    /// circom's semantics for `<`, `>`, `<=`, `>=` on `var` values.
    pub fn cmp_field_signed(self, rhs: Self) -> Ordering {
        let a = self.to_field_canonical();
        let b = rhs.to_field_canonical();
        let a_neg = a.is_field_negative();
        let b_neg = b.is_field_negative();
        match (a_neg, b_neg) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => a.cmp_unsigned(b),
        }
    }

    /// True iff this value, interpreted as a BN254 field element,
    /// lies in the "negative" half: `(p/2, p)`. Assumes the value
    /// is already canonicalized to `[0, p)`.
    pub fn is_field_negative(self) -> bool {
        self.cmp_unsigned(Self::bn254_half_order()) == Ordering::Greater
    }

    /// `(p-1)/2` for the BN254 scalar field, cached after first use.
    /// Values strictly greater than this half are treated as
    /// negative under circom's `var` comparison semantics.
    fn bn254_half_order() -> Self {
        use memory::FieldBackend;
        use std::sync::OnceLock;
        static HALF: OnceLock<BigVal> = OnceLock::new();
        *HALF.get_or_init(|| {
            let mod_bytes = memory::Bn254Fr::modulus_le_bytes();
            let fc = ir_forge::types::FieldConst::from_le_bytes(mod_bytes);
            let p = Self::from_field_const(fc);
            let p_minus_one = p.sub(Self::ONE);
            p_minus_one.shr(1)
        })
    }
}
