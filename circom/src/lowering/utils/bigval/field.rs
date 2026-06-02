use super::BigVal;
use ir_forge::types::FieldConst;

// ------------------------------------------------------------------
// Field-aware arithmetic (BN254 scalar field)
//
// Circom's `var` semantics are field arithmetic modulo the scalar
// field order, not signed 256-bit integer arithmetic. For patterns
// like Edwards-curve `pointAdd` (`(x1*y2 + y1*x2) / (1 + d*x1*...)`)
// the integer path wraps around and produces garbage; the field
// path produces the actual curve coordinate. Callers route `+ - * /`
// on values that may exceed u64 through these -- index arithmetic
// and loop bounds continue to use the plain integer variants.
// ------------------------------------------------------------------

impl BigVal {
    /// Reduce the integer representation to a BN254 field element.
    ///
    /// A BigVal with its top bit set is interpreted as a two's
    /// complement negative (so `from_i64(-3)` is `-3`, not
    /// `2^256 - 3`). Negatives canonicalize to `p - |v|`, matching
    /// circom's semantics for `-3` stored in a `var`. Non-negative
    /// values get the straight mod-p reduction via Horner over the
    /// four u64 limbs so values up to `2^256 - 1` flow through.
    fn to_bn254(self) -> memory::FieldElement<memory::Bn254Fr> {
        if self.is_negative() {
            let abs = self.abs();
            return abs.to_bn254_unsigned().neg();
        }
        self.to_bn254_unsigned()
    }

    fn to_bn254_unsigned(self) -> memory::FieldElement<memory::Bn254Fr> {
        let fc = self.to_field_const();
        if let Some(fe) = fc.to_field::<memory::Bn254Fr>() {
            return fe;
        }
        let limbs = self.0;
        // 2^64 as a field element, used as the Horner base. Built
        // via `(1 << 32) * (1 << 32)` since FieldElement lacks a
        // direct `from_u128` constructor.
        let base = {
            let shift32 = memory::FieldElement::<memory::Bn254Fr>::from_u64(1u64 << 32);
            shift32.mul(&shift32)
        };
        let mut acc = memory::FieldElement::<memory::Bn254Fr>::zero();
        for &limb in limbs.iter().rev() {
            acc = acc.mul(&base);
            acc = acc.add(&memory::FieldElement::<memory::Bn254Fr>::from_u64(limb));
        }
        acc
    }

    fn from_bn254(fe: memory::FieldElement<memory::Bn254Fr>) -> Self {
        let fc = FieldConst::from_field::<memory::Bn254Fr>(fe);
        Self::from_field_const(fc)
    }

    /// Field-modular addition.
    pub fn field_add(self, rhs: Self) -> Self {
        Self::from_bn254(self.to_bn254().add(&rhs.to_bn254()))
    }

    pub fn field_sub(self, rhs: Self) -> Self {
        Self::from_bn254(self.to_bn254().sub(&rhs.to_bn254()))
    }

    pub fn field_mul(self, rhs: Self) -> Self {
        Self::from_bn254(self.to_bn254().mul(&rhs.to_bn254()))
    }

    /// Field-modular division (multiplication by modular inverse).
    /// Returns `None` if the divisor is zero in the field.
    pub fn field_div(self, rhs: Self) -> Option<Self> {
        let a = self.to_bn254();
        let b = rhs.to_bn254();
        Some(Self::from_bn254(a.div(&b)?))
    }

    pub fn field_neg(self) -> Self {
        Self::from_bn254(self.to_bn254().neg())
    }

    /// Canonicalize to the BN254 field representation. Negative
    /// two's complement values map to `p - |v|`; out-of-range
    /// positive values reduce modulo p. Used when an externally-
    /// constructed BigVal (e.g. `from_i64(-3)`) enters the
    /// evaluator and needs to be interpreted as a field element.
    pub fn to_field_canonical(self) -> Self {
        Self::from_bn254(self.to_bn254())
    }
}
