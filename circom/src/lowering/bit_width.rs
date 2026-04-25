//! Bit-width inference for circom-lowered `CircuitExpr`.
//!
//! Tightens the conservative `DEFAULT_MAX_BITS = 254` annotations
//! (BN254 field-width) on `Decompose`, `RangeCheck`, `BitAnd`/`BitOr`/
//! `BitXor`, `ShiftR`/`ShiftL`, and friends to the actual proven
//! upper bound of the operand. Wins:
//!
//! 1. Fewer R1CS constraints — a `Decompose(254)` becomes
//!    `Decompose(32)` for a 32-bit value, dropping ~222 bit-product
//!    constraints per operation.
//! 2. Lysis VM bytecode fits in the 255-slot frame cap for circuits
//!    that previously overflowed (SHA-256(64) is the canonical
//!    example — its `>>` operations on 32-bit words otherwise emit
//!    `SymbolicShift(num_bits=254)` which can't fit any frame).
//! 3. Faster proving downstream — fewer constraints to commit to.
//!
//! ## Soundness
//!
//! The inference is **monotone-conservative**: every rule returns an
//! upper bound on the true runtime range. Tighter is better but never
//! required for soundness — defaulting to [`BitWidth::Field`] always
//! works, just leaves potential wins on the table. Mutating an IR
//! `num_bits` field with a value tighter than its true range produces
//! incorrect constraints (silent miscompilation), so the rewrite path
//! that consumes inference results MUST never raise the inferred
//! width above the actual runtime range. The static invariant: every
//! [`BitWidth::join`] / [`BitWidth::widen`] call returns at least its
//! input.
//!
//! ## Stage 1 (leaf inference)
//!
//! This file ships with leaf-only rules — literals, captures bound to
//! literals via `LoweringContext::param_values`, `Comparison`/`BoolOp`
//! → `Exact(1)`, and bit-op merging (`BitAnd` = `min`, `BitOr`/`BitXor`
//! = `max`). No cross-template propagation, no `Num2Bits` library
//! table, no `<==` constrained-signal lookups. Stage 2 layers those
//! on top.
//!
//! Rationale for staging: Stage 1 is a pure analysis function with no
//! side effects on the lowering pipeline, ~250 LOC, easy to test in
//! isolation. Stage 2 hooks into the lowering and mutates IR
//! in-place, requiring careful regression coverage on circomlib
//! fixtures. Landing them separately keeps risk localised.

use std::collections::HashMap;

use ir_forge::types::{CircuitExpr, CircuitUnaryOp, FieldConst};

/// Inferred bit-width of a `CircuitExpr`'s runtime value.
///
/// The lattice ordering is `Exact(n) ≤ AtMost(n) ≤ AtMost(m) ≤ Field`
/// for `m ≥ n`. [`Self::join`] returns the least upper bound,
/// matching `Mux` / `if-else` branch merging. [`Self::widen`] saturates
/// toward `Field` once an arithmetic propagation crosses the 254-bit
/// BN254 limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitWidth {
    /// Exact bit-width — the value is provably in `[0, 2^n)` and the
    /// width is *known* (e.g. from a `Num2Bits(n)` constraint or a
    /// numeric literal). Carries the strongest claim and is required
    /// for downstream optimisations like RangeCheck elimination
    /// (Stage 3) where a tautological check can be dropped.
    Exact(u32),
    /// Upper bound only — the value is provably in `[0, 2^n)` but the
    /// inference path was through arithmetic (`Add`, `Mul`, ...) that
    /// composes upper bounds without preserving exactness.
    AtMost(u32),
    /// 254-bit fallback (BN254 field-width). Unconstrained witnesses,
    /// modular subtractions, and any expression involving signals
    /// without provenance default here. Always sound.
    Field,
}

/// Field-width fallback constant. Matches `DEFAULT_MAX_BITS` at the
/// lowering layer (`circom/src/lowering/expressions/mod.rs`). Both
/// must change together if/when the prime field changes.
pub const FIELD_BITS: u32 = 254;

impl BitWidth {
    /// Concrete bit-count for downstream consumers (Decompose,
    /// RangeCheck, …). Always returns ≥ the actual range — sound to
    /// substitute for `DEFAULT_MAX_BITS`.
    pub fn to_num_bits(self) -> u32 {
        match self {
            Self::Exact(n) => n,
            Self::AtMost(n) => n,
            Self::Field => FIELD_BITS,
        }
    }

    /// Saturate-to-`Field` constructor. Use whenever an arithmetic
    /// rule could produce a width ≥ `FIELD_BITS`. Without this guard,
    /// `u32` arithmetic would wrap and we'd silently miscompile.
    pub fn widen(n: u32) -> Self {
        if n >= FIELD_BITS {
            Self::Field
        } else {
            Self::AtMost(n)
        }
    }

    /// Least-upper-bound merge for branch joins (`Mux`, `if-else`).
    ///
    /// `join(Exact(a), Exact(b)) = Exact(max(a, b))` only when `a == b`
    /// — the post-join width is no longer "exactly that bit-count" if
    /// the branches differ. Otherwise widens to `AtMost` or `Field`.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Field, _) | (_, Self::Field) => Self::Field,
            (Self::Exact(a), Self::Exact(b)) if a == b => Self::Exact(a),
            (Self::Exact(a), Self::Exact(b))
            | (Self::Exact(a), Self::AtMost(b))
            | (Self::AtMost(a), Self::Exact(b))
            | (Self::AtMost(a), Self::AtMost(b)) => Self::widen(a.max(b)),
        }
    }
}

/// Inference context carried through `infer_expr`. Stage 1 only reads
/// from this; Stage 2 will extend it with the constrained-signal
/// table and `Num2Bits` library lookups.
#[derive(Debug, Clone, Default)]
pub struct InferenceCtx<'a> {
    /// Captures bound to compile-time `FieldConst`s. Mirrors
    /// `LoweringContext::param_values` — passed in directly to avoid a
    /// circular dep between `circom::lowering` and this module.
    pub param_values: Option<&'a HashMap<String, FieldConst>>,
    /// Known constants from the `LoweringEnv` (signals whose value the
    /// const-fold pass has resolved). Stage 1 reads these the same way
    /// as `param_values` — both yield exact bit-widths.
    pub known_constants: Option<&'a HashMap<String, FieldConst>>,
}

impl<'a> InferenceCtx<'a> {
    /// Build a context with both maps. Convenience for call sites
    /// that have access to both `LoweringContext` and `LoweringEnv`.
    pub fn new(
        param_values: &'a HashMap<String, FieldConst>,
        known_constants: &'a HashMap<String, FieldConst>,
    ) -> Self {
        Self {
            param_values: Some(param_values),
            known_constants: Some(known_constants),
        }
    }

    fn lookup(&self, name: &str) -> Option<FieldConst> {
        if let Some(map) = self.param_values {
            if let Some(v) = map.get(name) {
                return Some(*v);
            }
        }
        if let Some(map) = self.known_constants {
            if let Some(v) = map.get(name) {
                return Some(*v);
            }
        }
        None
    }
}

/// Bit-length of a `FieldConst` interpreted as an unsigned integer.
/// Returns `0` for the zero constant; `1` for `1`; `n` for a value in
/// `[2^(n-1), 2^n)`.
fn bits_of_field_const(fc: &FieldConst) -> u32 {
    // FieldConst is stored as 32 little-endian bytes. Walk bytes
    // MSB-first to find the highest non-zero one.
    let bytes = fc.bytes();
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b != 0 {
            let byte_msb = 8 - b.leading_zeros();
            return byte_msb + (i as u32) * 8;
        }
    }
    0
}

/// Stage 1 inference for `CircuitExpr`. Returns a sound upper bound
/// on the runtime value's bit-width.
pub fn infer_expr(expr: &CircuitExpr, ctx: &InferenceCtx<'_>) -> BitWidth {
    match expr {
        // ---- Leaves ----
        CircuitExpr::Const(fc) => BitWidth::Exact(bits_of_field_const(fc)),
        CircuitExpr::Capture(name) | CircuitExpr::Var(name) => {
            // If the capture/var resolves to a compile-time constant
            // via param_values or known_constants, the binding's
            // bit-width is known *exactly*. Otherwise fall back to
            // Field — Stage 2 will tighten this via constrained-signal
            // tables.
            if let Some(fc) = ctx.lookup(name) {
                BitWidth::Exact(bits_of_field_const(&fc))
            } else {
                BitWidth::Field
            }
        }
        // Stage 1 doesn't model signal-input bit-widths — no
        // constraint context is consulted. Stage 2 will hook in
        // `Num2Bits(n)`-detected widths here.
        CircuitExpr::Input(_) => BitWidth::Field,

        // ---- Predicate-shaped exprs always produce 0 or 1 ----
        CircuitExpr::Comparison { .. } | CircuitExpr::BoolOp { .. } => BitWidth::Exact(1),

        // ---- Bitwise ops ----
        CircuitExpr::BitAnd { lhs, rhs, .. } => {
            // AND can only narrow: result has at most min(lhs, rhs) bits.
            let l = infer_expr(lhs, ctx);
            let r = infer_expr(rhs, ctx);
            min_width(l, r)
        }
        CircuitExpr::BitOr { lhs, rhs, .. } | CircuitExpr::BitXor { lhs, rhs, .. } => {
            // OR/XOR cap at max(lhs, rhs) bits.
            let l = infer_expr(lhs, ctx);
            let r = infer_expr(rhs, ctx);
            max_width(l, r)
        }
        CircuitExpr::BitNot { num_bits, .. } => {
            // BitNot's width is the explicitly declared num_bits — the
            // result is the bitwise complement within that fixed
            // window. Inferring tighter would require knowing the
            // operand's width *and* trusting that all higher bits are
            // zero in the operand's range, which holds when the
            // operand inference is also bit-bounded. Stage 2 may
            // tighten this.
            BitWidth::widen(*num_bits)
        }

        // ---- Mux: branch join ----
        CircuitExpr::Mux {
            if_true, if_false, ..
        } => {
            let t = infer_expr(if_true, ctx);
            let f = infer_expr(if_false, ctx);
            t.join(f)
        }

        // ---- UnaryOp ----
        CircuitExpr::UnaryOp { op, operand: _ } => match op {
            // Logical Not produces 0 or 1.
            CircuitUnaryOp::Not => BitWidth::Exact(1),
            // Field negation maps `x` to `p - x` (or `0` if `x == 0`),
            // which spans the whole field. No width tightening
            // possible without a sign-bit model.
            CircuitUnaryOp::Neg => BitWidth::Field,
        },

        // ---- BinOp: arithmetic propagation deferred to Stage 2 ----
        // Stage 1 returns Field for arithmetic — it's sound but
        // pessimistic. The propagation rules (`Add: max+1`, `Mul: a+b`,
        // `Sub: Field`, `Div: Field`) need careful saturation handling
        // that will land in Stage 2 alongside the bigger
        // constrained-signal infrastructure.
        CircuitExpr::BinOp { .. } => BitWidth::Field,

        // ---- Hashes / Merkle / RangeCheck ----
        CircuitExpr::PoseidonHash { .. } | CircuitExpr::PoseidonMany(_) => BitWidth::Field,
        CircuitExpr::MerkleVerify { .. } => BitWidth::Exact(1),
        CircuitExpr::RangeCheck { bits, .. } => {
            // RangeCheck is itself a typed bound — the inferred width
            // mirrors the constraint exactly. (RangeCheck appears
            // mid-expression rarely; usually it's a statement-level
            // assertion. Including it for completeness.)
            BitWidth::Exact(*bits)
        }

        // ---- Array / runtime-only nodes ----
        // Array indexing depends on element type, which Stage 1 has
        // no view into. Stage 2 will plumb the array-element-width
        // table.
        CircuitExpr::ArrayIndex { .. } | CircuitExpr::ArrayLen(_) => BitWidth::Field,

        // ---- Pow / IntDiv / IntMod ----
        CircuitExpr::Pow { .. } => BitWidth::Field,
        CircuitExpr::IntDiv { max_bits, .. } | CircuitExpr::IntMod { max_bits, .. } => {
            BitWidth::widen(*max_bits)
        }

        // ---- Shifts ----
        CircuitExpr::ShiftR { operand, shift, .. } => {
            // Right shift can only narrow: if the shift amount is a
            // compile-time constant, subtract it from the operand's
            // bit-width.
            let op_w = infer_expr(operand, ctx);
            if let Some(s) = const_eval_shift(shift, ctx) {
                shift_right_width(op_w, s)
            } else {
                // Symbolic shift — the result spans up to the operand's
                // full width.
                op_w
            }
        }
        CircuitExpr::ShiftL { operand, shift, .. } => {
            // Left shift widens by the shift amount, saturating at
            // field-width.
            let op_w = infer_expr(operand, ctx);
            if let Some(s) = const_eval_shift(shift, ctx) {
                shift_left_width(op_w, s)
            } else {
                BitWidth::Field
            }
        }
    }
}

/// `min` over `BitWidth`'s lattice. Used by `BitAnd`.
fn min_width(a: BitWidth, b: BitWidth) -> BitWidth {
    match (a, b) {
        (BitWidth::Exact(x), BitWidth::Exact(y)) => BitWidth::Exact(x.min(y)),
        (BitWidth::Exact(x), BitWidth::AtMost(y))
        | (BitWidth::AtMost(x), BitWidth::Exact(y))
        | (BitWidth::AtMost(x), BitWidth::AtMost(y)) => BitWidth::AtMost(x.min(y)),
        (BitWidth::Exact(x), BitWidth::Field) | (BitWidth::AtMost(x), BitWidth::Field) => {
            BitWidth::AtMost(x)
        }
        (BitWidth::Field, BitWidth::Exact(y)) | (BitWidth::Field, BitWidth::AtMost(y)) => {
            BitWidth::AtMost(y)
        }
        (BitWidth::Field, BitWidth::Field) => BitWidth::Field,
    }
}

/// `max` over `BitWidth`'s lattice. Used by `BitOr` / `BitXor`.
fn max_width(a: BitWidth, b: BitWidth) -> BitWidth {
    match (a, b) {
        (BitWidth::Field, _) | (_, BitWidth::Field) => BitWidth::Field,
        (BitWidth::Exact(x), BitWidth::Exact(y)) if x == y => BitWidth::Exact(x),
        (BitWidth::Exact(x), BitWidth::Exact(y))
        | (BitWidth::Exact(x), BitWidth::AtMost(y))
        | (BitWidth::AtMost(x), BitWidth::Exact(y))
        | (BitWidth::AtMost(x), BitWidth::AtMost(y)) => BitWidth::AtMost(x.max(y)),
    }
}

/// `ShiftR` width rule — narrows by `shift` bits, clamped to 0.
fn shift_right_width(op_w: BitWidth, shift: u32) -> BitWidth {
    match op_w {
        BitWidth::Exact(n) => BitWidth::AtMost(n.saturating_sub(shift)),
        BitWidth::AtMost(n) => BitWidth::AtMost(n.saturating_sub(shift)),
        BitWidth::Field => BitWidth::AtMost(FIELD_BITS.saturating_sub(shift)),
    }
}

/// `ShiftL` width rule — widens by `shift` bits, saturating at
/// `FIELD_BITS`.
fn shift_left_width(op_w: BitWidth, shift: u32) -> BitWidth {
    let n = op_w.to_num_bits();
    BitWidth::widen(n.saturating_add(shift))
}

/// Try to const-fold a shift expression to a concrete `u32` amount.
/// Stage 1 handles the simple cases: literal constants and captures
/// bound to literals. Anything more complex (e.g. arithmetic on
/// captures) falls through to `None`.
fn const_eval_shift(expr: &CircuitExpr, ctx: &InferenceCtx<'_>) -> Option<u32> {
    let fc = match expr {
        CircuitExpr::Const(fc) => *fc,
        CircuitExpr::Capture(name) | CircuitExpr::Var(name) => ctx.lookup(name)?,
        _ => return None,
    };
    let bits = bits_of_field_const(&fc);
    if bits > 32 {
        return None;
    }
    // Field constants are stored as 32 little-endian bytes; values
    // that fit in u32 occupy the first 4 bytes.
    fc.to_u64().and_then(|v| u32::try_from(v).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir_forge::types::{CircuitBinOp, CircuitBoolOp, CircuitCmpOp};

    fn fc(value: u64) -> FieldConst {
        FieldConst::from_u64(value)
    }

    fn fc_from_limbs(limbs: [u64; 4]) -> FieldConst {
        let mut bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        FieldConst::from_le_bytes(bytes)
    }

    fn empty_ctx() -> InferenceCtx<'static> {
        InferenceCtx::default()
    }

    // ------------------------------------------------------------------
    // bits_of_field_const
    // ------------------------------------------------------------------

    #[test]
    fn bits_of_zero_is_zero() {
        assert_eq!(bits_of_field_const(&fc(0)), 0);
    }

    #[test]
    fn bits_of_one_is_one() {
        assert_eq!(bits_of_field_const(&fc(1)), 1);
    }

    #[test]
    fn bits_of_small_values() {
        assert_eq!(bits_of_field_const(&fc(0xff)), 8);
        assert_eq!(bits_of_field_const(&fc(0x100)), 9);
        assert_eq!(bits_of_field_const(&fc(0xffff_ffff)), 32);
        assert_eq!(bits_of_field_const(&fc(0x1_0000_0000)), 33);
    }

    #[test]
    fn bits_of_high_limb() {
        // Set the top bit of limb 0 → bits = 64.
        let v = fc_from_limbs([1u64 << 63, 0, 0, 0]);
        assert_eq!(bits_of_field_const(&v), 64);
        // Set the lowest bit of limb 1 → bits = 65.
        let v = fc_from_limbs([0, 1, 0, 0]);
        assert_eq!(bits_of_field_const(&v), 65);
        // Set the top bit of limb 3 → bits = 256.
        let v = fc_from_limbs([0, 0, 0, 1u64 << 63]);
        assert_eq!(bits_of_field_const(&v), 256);
    }

    // ------------------------------------------------------------------
    // BitWidth::widen / join
    // ------------------------------------------------------------------

    #[test]
    fn widen_saturates_at_field() {
        assert_eq!(BitWidth::widen(0), BitWidth::AtMost(0));
        assert_eq!(BitWidth::widen(32), BitWidth::AtMost(32));
        assert_eq!(BitWidth::widen(253), BitWidth::AtMost(253));
        assert_eq!(BitWidth::widen(254), BitWidth::Field);
        assert_eq!(BitWidth::widen(255), BitWidth::Field);
        assert_eq!(BitWidth::widen(u32::MAX), BitWidth::Field);
    }

    #[test]
    fn join_preserves_exact_when_equal() {
        assert_eq!(
            BitWidth::Exact(8).join(BitWidth::Exact(8)),
            BitWidth::Exact(8)
        );
    }

    #[test]
    fn join_widens_to_atmost_when_unequal_exact() {
        assert_eq!(
            BitWidth::Exact(8).join(BitWidth::Exact(16)),
            BitWidth::AtMost(16)
        );
    }

    #[test]
    fn join_with_field_yields_field() {
        assert_eq!(BitWidth::Exact(8).join(BitWidth::Field), BitWidth::Field);
        assert_eq!(BitWidth::Field.join(BitWidth::AtMost(32)), BitWidth::Field);
    }

    #[test]
    fn to_num_bits_returns_concrete_count() {
        assert_eq!(BitWidth::Exact(8).to_num_bits(), 8);
        assert_eq!(BitWidth::AtMost(32).to_num_bits(), 32);
        assert_eq!(BitWidth::Field.to_num_bits(), FIELD_BITS);
    }

    // ------------------------------------------------------------------
    // infer_expr — leaves
    // ------------------------------------------------------------------

    #[test]
    fn infer_const_returns_exact_bit_count() {
        let ctx = empty_ctx();
        assert_eq!(
            infer_expr(&CircuitExpr::Const(fc(0xff)), &ctx),
            BitWidth::Exact(8)
        );
        assert_eq!(
            infer_expr(&CircuitExpr::Const(fc(0)), &ctx),
            BitWidth::Exact(0)
        );
    }

    #[test]
    fn infer_input_defaults_to_field() {
        let ctx = empty_ctx();
        assert_eq!(
            infer_expr(&CircuitExpr::Input("x".into()), &ctx),
            BitWidth::Field
        );
    }

    #[test]
    fn infer_capture_resolves_via_param_values() {
        let mut params = HashMap::new();
        params.insert("n".to_string(), fc(64));
        let known = HashMap::new();
        let ctx = InferenceCtx::new(&params, &known);
        assert_eq!(
            infer_expr(&CircuitExpr::Capture("n".into()), &ctx),
            BitWidth::Exact(7)
        );
    }

    #[test]
    fn infer_capture_unknown_falls_back_to_field() {
        let ctx = empty_ctx();
        assert_eq!(
            infer_expr(&CircuitExpr::Capture("n".into()), &ctx),
            BitWidth::Field
        );
    }

    #[test]
    fn infer_var_resolves_via_known_constants() {
        let params = HashMap::new();
        let mut known = HashMap::new();
        known.insert("k".to_string(), fc(0x1234));
        let ctx = InferenceCtx::new(&params, &known);
        assert_eq!(
            infer_expr(&CircuitExpr::Var("k".into()), &ctx),
            BitWidth::Exact(13) // 0x1234 = 4660 → 13 bits
        );
    }

    // ------------------------------------------------------------------
    // infer_expr — predicates
    // ------------------------------------------------------------------

    #[test]
    fn infer_comparison_is_bool() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::Comparison {
            op: CircuitCmpOp::Eq,
            lhs: Box::new(CircuitExpr::Const(fc(1))),
            rhs: Box::new(CircuitExpr::Const(fc(2))),
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(1));
    }

    #[test]
    fn infer_boolop_is_bool() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BoolOp {
            op: CircuitBoolOp::And,
            lhs: Box::new(CircuitExpr::Const(fc(0))),
            rhs: Box::new(CircuitExpr::Const(fc(1))),
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(1));
    }

    #[test]
    fn infer_logical_not_is_bool() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Not,
            operand: Box::new(CircuitExpr::Const(fc(5))),
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(1));
    }

    // ------------------------------------------------------------------
    // infer_expr — bitwise propagation
    // ------------------------------------------------------------------

    #[test]
    fn infer_bitand_takes_min() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BitAnd {
            lhs: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32 bits
            num_bits: FIELD_BITS,
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
    }

    #[test]
    fn infer_bitor_takes_max() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BitOr {
            lhs: Box::new(CircuitExpr::Const(fc(0xff))),
            rhs: Box::new(CircuitExpr::Const(fc(0xffff))),
            num_bits: FIELD_BITS,
        };
        // Inputs have *different* exact widths; merging through OR
        // produces an upper bound, not an exact width — the actual
        // value could land anywhere in [0, 2^16).
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(16));
    }

    #[test]
    fn infer_bitor_same_exact_widths_preserves_exact() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BitOr {
            lhs: Box::new(CircuitExpr::Const(fc(0xa5))), // 8 bits (top bit set)
            rhs: Box::new(CircuitExpr::Const(fc(0xc3))), // 8 bits (top bit set)
            num_bits: FIELD_BITS,
        };
        // Both Exact(8). Lattice keeps Exact when widths match.
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
    }

    #[test]
    fn infer_bitxor_takes_max() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BitXor {
            lhs: Box::new(CircuitExpr::Const(fc(0xff))),
            rhs: Box::new(CircuitExpr::Const(fc(0xffff))),
            num_bits: FIELD_BITS,
        };
        // Same rationale as BitOr.
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(16));
    }

    #[test]
    fn infer_bitand_with_field_input_yields_atmost_const_width() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BitAnd {
            lhs: Box::new(CircuitExpr::Const(fc(0xff))),   // Exact(8)
            rhs: Box::new(CircuitExpr::Input("x".into())), // Field
            num_bits: FIELD_BITS,
        };
        // min(Exact(8), Field) = AtMost(8) — we know one input has at
        // most 8 bits, so AND can't widen past that.
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(8));
    }

    // ------------------------------------------------------------------
    // infer_expr — Mux
    // ------------------------------------------------------------------

    #[test]
    fn infer_mux_joins_branches() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::Mux {
            cond: Box::new(CircuitExpr::Const(fc(1))),
            if_true: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            if_false: Box::new(CircuitExpr::Const(fc(0x10))), // 5 bits
        };
        // join(Exact(8), Exact(5)) = AtMost(8)
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(8));
    }

    #[test]
    fn infer_mux_same_width_keeps_exact() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::Mux {
            cond: Box::new(CircuitExpr::Const(fc(1))),
            if_true: Box::new(CircuitExpr::Const(fc(0xff))),
            if_false: Box::new(CircuitExpr::Const(fc(0xff))),
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
    }

    // ------------------------------------------------------------------
    // infer_expr — shifts
    // ------------------------------------------------------------------

    #[test]
    fn infer_shift_right_const_narrows() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32 bits
            shift: Box::new(CircuitExpr::Const(fc(8))),
            num_bits: FIELD_BITS,
        };
        // 32 - 8 = 24
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(24));
    }

    #[test]
    fn infer_shift_right_full_drop_yields_zero() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            shift: Box::new(CircuitExpr::Const(fc(16))),
            num_bits: FIELD_BITS,
        };
        // 8 - 16 saturates to 0
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(0));
    }

    #[test]
    fn infer_shift_right_via_capture() {
        let mut params = HashMap::new();
        params.insert("n".to_string(), fc(7));
        let known = HashMap::new();
        let ctx = InferenceCtx::new(&params, &known);
        let expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32 bits
            shift: Box::new(CircuitExpr::Capture("n".into())),      // = 7
            num_bits: FIELD_BITS,
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(25));
    }

    #[test]
    fn infer_shift_right_symbolic_returns_operand_width() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Const(fc(0xff))),
            shift: Box::new(CircuitExpr::Input("k".into())),
            num_bits: FIELD_BITS,
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
    }

    #[test]
    fn infer_shift_left_const_widens() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftL {
            operand: Box::new(CircuitExpr::Const(fc(0xff))),
            shift: Box::new(CircuitExpr::Const(fc(8))),
            num_bits: FIELD_BITS,
        };
        // 8 + 8 = 16 bits
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(16));
    }

    #[test]
    fn infer_shift_left_saturates_at_field() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftL {
            operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            shift: Box::new(CircuitExpr::Const(fc(250))),
            num_bits: FIELD_BITS,
        };
        // 8 + 250 = 258 ≥ FIELD_BITS → Field
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
    }

    #[test]
    fn infer_shift_left_symbolic_yields_field() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftL {
            operand: Box::new(CircuitExpr::Const(fc(0xff))),
            shift: Box::new(CircuitExpr::Input("k".into())),
            num_bits: FIELD_BITS,
        };
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
    }

    // ------------------------------------------------------------------
    // infer_expr — arithmetic (Stage 1 returns Field)
    // ------------------------------------------------------------------

    #[test]
    fn stage1_binop_falls_back_to_field() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Const(fc(0xff))),
            rhs: Box::new(CircuitExpr::Const(fc(1))),
        };
        // Stage 2 will tighten this to AtMost(9). Stage 1 punts.
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
    }
}
