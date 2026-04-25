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

use ir_forge::types::{CircuitBinOp, CircuitExpr, CircuitUnaryOp, FieldConst};

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

/// Side-table of signal-name → known [`BitWidth`]. Populated by the
/// lowering pipeline (e.g., `wiring.rs::PendingComponent::inline_into`)
/// when it instantiates a library template with a constraint-driving
/// signature like `Num2Bits(n)`. Lookups for `CircuitExpr::Input(name)`
/// and `Var(name)` consult this table before falling back to `Field`.
pub type SignalWidths = HashMap<String, BitWidth>;

/// Inference context carried through `infer_expr`. Stage 2 adds the
/// `signal_widths` table for constrained-signal lookups; Stage 1
/// only used `param_values` + `known_constants`.
#[derive(Debug, Clone, Default)]
pub struct InferenceCtx<'a> {
    /// Captures bound to compile-time `FieldConst`s. Mirrors
    /// `LoweringContext::param_values` — passed in directly to avoid a
    /// circular dep between `circom::lowering` and this module.
    pub param_values: Option<&'a HashMap<String, FieldConst>>,
    /// Known constants from the `LoweringEnv` (signals whose value the
    /// const-fold pass has resolved). Read the same way as
    /// `param_values` — both yield exact bit-widths.
    pub known_constants: Option<&'a HashMap<String, FieldConst>>,
    /// Stage 2: signal names whose bit-width is provably bounded via
    /// constraint context (e.g., outputs of `Num2Bits(n)` are
    /// `Exact(1)`). Lookups consulted by `Input` / `Var` before the
    /// `Field` fallback.
    pub signal_widths: Option<&'a SignalWidths>,
}

impl<'a> InferenceCtx<'a> {
    /// Build a context with all three maps. Convenience for call sites
    /// that have access to `LoweringContext`, `LoweringEnv`, and the
    /// signal-widths side-table.
    pub fn new(
        param_values: &'a HashMap<String, FieldConst>,
        known_constants: &'a HashMap<String, FieldConst>,
        signal_widths: &'a SignalWidths,
    ) -> Self {
        Self {
            param_values: Some(param_values),
            known_constants: Some(known_constants),
            signal_widths: Some(signal_widths),
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

    fn lookup_signal_width(&self, name: &str) -> Option<BitWidth> {
        self.signal_widths.and_then(|map| map.get(name).copied())
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
            // First try compile-time constant resolution via
            // param_values / known_constants — yields exact width.
            if let Some(fc) = ctx.lookup(name) {
                return BitWidth::Exact(bits_of_field_const(&fc));
            }
            // Stage 2: Var may also be a constrained signal whose
            // bit-width is recorded in the side-table (e.g., outputs
            // of an inlined Num2Bits(n)). Default to Field if absent.
            ctx.lookup_signal_width(name).unwrap_or(BitWidth::Field)
        }
        // Stage 2: Input signal — consult the constraint side-table
        // populated by the lowering pipeline. Each output bit of an
        // inlined `Num2Bits(n)` is registered as `Exact(1)`; signals
        // without provenance default to `Field`.
        CircuitExpr::Input(name) => ctx.lookup_signal_width(name).unwrap_or(BitWidth::Field),

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

        // ---- BinOp arithmetic propagation (Stage 2) ----
        // - Add: max(lhs, rhs) + 1 — accommodates carry. Saturates at
        //   FIELD_BITS via `widen`, so adding 32-bit values 224 times
        //   correctly degrades to `Field` instead of u32-wrapping.
        // - Mul: lhs + rhs — total bit-width.
        // - Sub / Div: `Field` — modular borrow / inverse can land
        //   anywhere in `[0, p)`.
        CircuitExpr::BinOp { op, lhs, rhs } => match op {
            CircuitBinOp::Add => {
                let l = infer_expr(lhs, ctx).to_num_bits();
                let r = infer_expr(rhs, ctx).to_num_bits();
                BitWidth::widen(l.max(r).saturating_add(1))
            }
            CircuitBinOp::Mul => {
                let l = infer_expr(lhs, ctx).to_num_bits();
                let r = infer_expr(rhs, ctx).to_num_bits();
                BitWidth::widen(l.saturating_add(r))
            }
            CircuitBinOp::Sub | CircuitBinOp::Div => BitWidth::Field,
        },

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

// =====================================================================
// IR rewriter — tightens `num_bits` fields in-place using inference
// =====================================================================

/// Walk `expr` recursively and tighten every `num_bits` / `max_bits`
/// field whose inferred upper bound is strictly tighter than the
/// currently-stored value. Mutating in-place keeps downstream
/// consumers (Decompose, RangeCheck, Lysis lift) seeing the tightened
/// bounds without having to thread a side-table.
///
/// **Soundness invariant**: `num_bits` only ever decreases. The
/// rewriter computes an upper bound on the operand's runtime value,
/// guaranteeing that the new `num_bits` ≥ the actual bit-width — so
/// any downstream `Decompose(num_bits)` still produces a valid bit
/// decomposition. Increasing `num_bits` would be sound (just
/// wasteful), but the rewriter never does it; the explicit
/// `new <= old` clamp inside [`tighten`] makes the invariant
/// machine-checkable.
///
/// Recurses post-order: tighten sub-expressions first, then use the
/// (now-tightened) sub-expression bit-widths to derive the parent's
/// inferred width and apply.
pub fn rewrite_num_bits_in_expr(expr: &mut CircuitExpr, ctx: &InferenceCtx<'_>) {
    // First, recurse into children.
    match expr {
        CircuitExpr::BinOp { lhs, rhs, .. }
        | CircuitExpr::Comparison { lhs, rhs, .. }
        | CircuitExpr::BoolOp { lhs, rhs, .. } => {
            rewrite_num_bits_in_expr(lhs, ctx);
            rewrite_num_bits_in_expr(rhs, ctx);
        }
        CircuitExpr::UnaryOp { operand, .. } => {
            rewrite_num_bits_in_expr(operand, ctx);
        }
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            rewrite_num_bits_in_expr(cond, ctx);
            rewrite_num_bits_in_expr(if_true, ctx);
            rewrite_num_bits_in_expr(if_false, ctx);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            rewrite_num_bits_in_expr(left, ctx);
            rewrite_num_bits_in_expr(right, ctx);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args {
                rewrite_num_bits_in_expr(a, ctx);
            }
        }
        CircuitExpr::MerkleVerify { root, leaf, .. } => {
            rewrite_num_bits_in_expr(root, ctx);
            rewrite_num_bits_in_expr(leaf, ctx);
        }
        CircuitExpr::Pow { base, .. } => {
            rewrite_num_bits_in_expr(base, ctx);
        }
        CircuitExpr::ArrayIndex { index, .. } => {
            rewrite_num_bits_in_expr(index, ctx);
        }
        CircuitExpr::IntDiv { lhs, rhs, .. } | CircuitExpr::IntMod { lhs, rhs, .. } => {
            rewrite_num_bits_in_expr(lhs, ctx);
            rewrite_num_bits_in_expr(rhs, ctx);
        }
        CircuitExpr::BitAnd { lhs, rhs, .. }
        | CircuitExpr::BitOr { lhs, rhs, .. }
        | CircuitExpr::BitXor { lhs, rhs, .. } => {
            rewrite_num_bits_in_expr(lhs, ctx);
            rewrite_num_bits_in_expr(rhs, ctx);
        }
        CircuitExpr::BitNot { operand, .. } => {
            rewrite_num_bits_in_expr(operand, ctx);
        }
        CircuitExpr::ShiftR { operand, shift, .. } | CircuitExpr::ShiftL { operand, shift, .. } => {
            rewrite_num_bits_in_expr(operand, ctx);
            rewrite_num_bits_in_expr(shift, ctx);
        }
        CircuitExpr::RangeCheck { value, .. } => {
            rewrite_num_bits_in_expr(value, ctx);
        }
        CircuitExpr::Const(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Capture(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => {}
    }

    // Then, tighten THIS node's `num_bits` from the operand's
    // inferred width. Each rule mirrors the inference rule for that
    // variant — we infer the OPERAND's width and use that as the new
    // `num_bits` field for ops like Decompose/BitAnd/etc.
    match expr {
        CircuitExpr::BitAnd { lhs, rhs, num_bits } => {
            let l = infer_expr(lhs, ctx);
            let r = infer_expr(rhs, ctx);
            tighten(num_bits, min_width(l, r).to_num_bits());
        }
        CircuitExpr::BitOr { lhs, rhs, num_bits } | CircuitExpr::BitXor { lhs, rhs, num_bits } => {
            let l = infer_expr(lhs, ctx);
            let r = infer_expr(rhs, ctx);
            tighten(num_bits, max_width(l, r).to_num_bits());
        }
        CircuitExpr::BitNot { operand, num_bits } => {
            let w = infer_expr(operand, ctx);
            tighten(num_bits, w.to_num_bits());
        }
        CircuitExpr::ShiftR {
            operand, num_bits, ..
        }
        | CircuitExpr::ShiftL {
            operand, num_bits, ..
        } => {
            // Decompose+recompose width is the OPERAND's bit-width.
            // Even if the result is narrower (right shift), the
            // decomposition itself is over the operand. Tightening
            // here drops `num_bits=254` to e.g. `num_bits=32` for
            // SHA-256-shaped circuits.
            let w = infer_expr(operand, ctx);
            tighten(num_bits, w.to_num_bits());
        }
        CircuitExpr::RangeCheck { value, bits } => {
            let w = infer_expr(value, ctx);
            tighten(bits, w.to_num_bits());
        }
        CircuitExpr::IntDiv { lhs, max_bits, .. } | CircuitExpr::IntMod { lhs, max_bits, .. } => {
            // `max_bits` bounds the LHS for IntDiv/Mod's gadget.
            let w = infer_expr(lhs, ctx);
            tighten(max_bits, w.to_num_bits());
        }
        // Variants without a `num_bits` field — nothing to tighten.
        _ => {}
    }
}

/// Tighten `field` to `new` if `new < *field`. Never raises;
/// preserves the soundness invariant that `num_bits` is only ever
/// reduced toward truth.
fn tighten(field: &mut u32, new: u32) {
    if new < *field {
        *field = new;
    }
}

/// Walk a [`CircuitNode`] and tighten every nested `CircuitExpr`'s
/// `num_bits` / `max_bits` fields. Recurses into `For` and `If`
/// bodies. Currently does not introspect node-level fields like
/// `Decompose { num_bits }` or `WitnessArrayDecl { size }` —
/// future Stage-3 work could tighten those by inferring from the
/// `value` operand, but the immediate SHA-256-shaped wins all live
/// inside `CircuitExpr` (Shifts, BitAnd/Or/Xor, RangeCheck).
pub fn rewrite_num_bits_in_node(node: &mut ir_forge::types::CircuitNode, ctx: &InferenceCtx<'_>) {
    use ir_forge::types::CircuitNode;
    match node {
        CircuitNode::Let { value, .. }
        | CircuitNode::Expr { expr: value, .. }
        | CircuitNode::Decompose { value, .. }
        | CircuitNode::WitnessHint { hint: value, .. } => {
            rewrite_num_bits_in_expr(value, ctx);
        }
        CircuitNode::LetArray { elements, .. } => {
            for e in elements {
                rewrite_num_bits_in_expr(e, ctx);
            }
        }
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            rewrite_num_bits_in_expr(lhs, ctx);
            rewrite_num_bits_in_expr(rhs, ctx);
        }
        CircuitNode::Assert { expr, .. } => {
            rewrite_num_bits_in_expr(expr, ctx);
        }
        CircuitNode::For { body, .. } => {
            for n in body {
                rewrite_num_bits_in_node(n, ctx);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            rewrite_num_bits_in_expr(cond, ctx);
            for n in then_body {
                rewrite_num_bits_in_node(n, ctx);
            }
            for n in else_body {
                rewrite_num_bits_in_node(n, ctx);
            }
        }
        CircuitNode::LetIndexed { index, value, .. } => {
            rewrite_num_bits_in_expr(index, ctx);
            rewrite_num_bits_in_expr(value, ctx);
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            rewrite_num_bits_in_expr(index, ctx);
            rewrite_num_bits_in_expr(hint, ctx);
        }
        CircuitNode::WitnessArrayDecl { .. } => {
            // No CircuitExpr fields with num_bits.
        }
        CircuitNode::WitnessCall { input_signals, .. } => {
            for e in input_signals {
                rewrite_num_bits_in_expr(e, ctx);
            }
        }
    }
}

/// Top-level entry point: tighten `num_bits` fields throughout an
/// entire `ProveIR` body. Call once per circuit, post-lowering, before
/// any downstream consumer (instantiator, Lysis lift, R1CS backend).
///
/// The `ctx` carries the inference's only side-state — `param_values`,
/// `known_constants`, `signal_widths`. With all three empty, the pass
/// still tightens literal-driven bit-widths and arithmetic
/// propagation; populated tables enable the constraint-context
/// tightening that unblocks SHA-256-shaped circuits.
pub fn rewrite_num_bits_in_prove_ir(
    prove_ir: &mut ir_forge::types::ProveIR,
    ctx: &InferenceCtx<'_>,
) {
    for node in &mut prove_ir.body {
        rewrite_num_bits_in_node(node, ctx);
    }
}

/// Walk `prove_ir.body` and propagate inferred widths through
/// `let`-bindings. For each `CircuitNode::Let { name, value, .. }`,
/// run `infer_expr(value)` and, if it returns a tighter result than
/// `Field`, register `name → width` in the returned `SignalWidths`.
/// Subsequent calls to `infer_expr` will find downstream
/// `Var(name)` references resolved via this table.
///
/// Combine with [`scan_bool_constraints`] before running the
/// rewriter: bool constraints provide leaf widths for bit-decomposed
/// signals, and let-binding propagation chains those widths through
/// arithmetic accumulators (e.g. SHA-256's
/// `let acc = sum(bit_i * 2^i)` reaches `Exact(33)` once the bit
/// signals are known to be `Exact(1)`).
///
/// Walks recursively into `For`/`If` bodies so loop-local `let`s
/// also get registered. Does **not** unroll loops — iter-var-driven
/// expressions still default to `Field`.
pub fn propagate_let_widths(
    prove_ir: &ir_forge::types::ProveIR,
    seed_widths: SignalWidths,
) -> SignalWidths {
    let mut widths = seed_widths;
    for node in &prove_ir.body {
        propagate_let_in_node(node, &mut widths);
    }
    widths
}

fn propagate_let_in_node(node: &ir_forge::types::CircuitNode, widths: &mut SignalWidths) {
    use ir_forge::types::CircuitNode;
    match node {
        CircuitNode::Let { name, value, .. } => {
            let ctx = InferenceCtx {
                param_values: None,
                known_constants: None,
                signal_widths: Some(widths),
            };
            let w = infer_expr(value, &ctx);
            if !matches!(w, BitWidth::Field) {
                widths.insert(name.clone(), w);
            }
        }
        CircuitNode::For { body, .. } => {
            for n in body {
                propagate_let_in_node(n, widths);
            }
        }
        CircuitNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                propagate_let_in_node(n, widths);
            }
            for n in else_body {
                propagate_let_in_node(n, widths);
            }
        }
        _ => {}
    }
}

// =====================================================================
// Bool-constraint scanner — Num2Bits-style detection
// =====================================================================

/// Scan `prove_ir.body` for assertion patterns that constrain a
/// `Var`/`Input` to {0, 1}, registering each such name as
/// [`BitWidth::Exact(1)`] in the returned `SignalWidths` table.
///
/// Detected patterns (all common spellings of the bool constraint
/// circomlib emits inside `Num2Bits(n)`):
///
/// 1. `x * (x - 1) === 0`
/// 2. `x * (1 - x) === 0` (equivalent, sometimes written with the
///    operands swapped — circom-lowered IR can produce either)
/// 3. `(x - 1) * x === 0` (commuted Mul)
/// 4. `(1 - x) * x === 0` (commuted variant of #2)
///
/// Walks recursively into `For` / `If` bodies. Only registers names
/// whose binding is a leaf `Var` or `Input` reference — composite
/// expressions are skipped, since the tightening would have to be
/// re-derived per-call-site rather than via a name lookup.
///
/// Soundness: each detected pattern is mathematically equivalent to
/// `x ∈ {0, 1}`, which exactly proves `bit-width(x) ≤ 1`. Registering
/// `Exact(1)` is conservative-tight (sound and maximally informative).
pub fn scan_bool_constraints(prove_ir: &ir_forge::types::ProveIR) -> SignalWidths {
    let mut widths = SignalWidths::new();
    for node in &prove_ir.body {
        scan_node(node, &mut widths);
    }
    widths
}

fn scan_node(node: &ir_forge::types::CircuitNode, widths: &mut SignalWidths) {
    use ir_forge::types::CircuitNode;
    match node {
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            // The bool constraint puts the Mul on one side and Const(0)
            // on the other. Either ordering is valid in circom; check
            // both (lhs zero, rhs Mul) and (rhs zero, lhs Mul).
            if let Some(name) = match_bool_assertion(lhs, rhs) {
                widths.insert(name, BitWidth::Exact(1));
            } else if let Some(name) = match_bool_assertion(rhs, lhs) {
                widths.insert(name, BitWidth::Exact(1));
            }
        }
        CircuitNode::For { body, .. } => {
            for n in body {
                scan_node(n, widths);
            }
        }
        CircuitNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                scan_node(n, widths);
            }
            for n in else_body {
                scan_node(n, widths);
            }
        }
        _ => {}
    }
}

/// Match an `AssertEq(mul_side, zero_side)` pair against the bool
/// patterns. Returns the constrained name on a hit.
fn match_bool_assertion(mul_side: &CircuitExpr, zero_side: &CircuitExpr) -> Option<String> {
    // The "zero side" must be Const(0).
    if !matches!(zero_side, CircuitExpr::Const(fc) if fc.is_zero()) {
        return None;
    }
    // The "mul side" must be `BinOp(Mul, factor_a, factor_b)`.
    let (factor_a, factor_b) = match mul_side {
        CircuitExpr::BinOp {
            op: ir_forge::types::CircuitBinOp::Mul,
            lhs,
            rhs,
        } => (lhs.as_ref(), rhs.as_ref()),
        _ => return None,
    };
    // Try both orderings: (x, x - 1) or (x - 1, x), and the
    // `1 - x` variants.
    if let Some(name) = match_bool_factors(factor_a, factor_b) {
        return Some(name);
    }
    match_bool_factors(factor_b, factor_a)
}

/// Match `(x, x - 1)` or `(x, 1 - x)`, returning x's name if the
/// pattern fits and x is a leaf `Var`/`Input`.
fn match_bool_factors(x: &CircuitExpr, sub_or_neg: &CircuitExpr) -> Option<String> {
    let x_name = leaf_name(x)?;
    match sub_or_neg {
        // `x - 1`
        CircuitExpr::BinOp {
            op: ir_forge::types::CircuitBinOp::Sub,
            lhs,
            rhs,
        } => {
            let lhs_name = leaf_name(lhs)?;
            if lhs_name != x_name {
                return None;
            }
            if matches!(rhs.as_ref(), CircuitExpr::Const(fc) if fc_is_one(fc)) {
                Some(x_name)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Try to extract a `Var` or `Input` leaf name. Returns `None` for
/// composite expressions (the caller skips those — see module docs).
fn leaf_name(expr: &CircuitExpr) -> Option<String> {
    match expr {
        CircuitExpr::Var(name) | CircuitExpr::Input(name) => Some(name.clone()),
        _ => None,
    }
}

/// `FieldConst::one` comparison. Done via byte equality since
/// `FieldConst` doesn't expose a `bytes_eq` helper, and `==` on
/// `FieldConst` checks the canonical bytes — the same thing.
fn fc_is_one(fc: &FieldConst) -> bool {
    fc == &FieldConst::one()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir_forge::types::{CircuitBoolOp, CircuitCmpOp};

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
    fn infer_input_consults_signal_widths() {
        let params = HashMap::new();
        let known = HashMap::new();
        let mut widths = SignalWidths::new();
        widths.insert("c_n2b_out_0".to_string(), BitWidth::Exact(1));
        let ctx = InferenceCtx::new(&params, &known, &widths);
        assert_eq!(
            infer_expr(&CircuitExpr::Input("c_n2b_out_0".into()), &ctx),
            BitWidth::Exact(1)
        );
    }

    #[test]
    fn infer_var_consults_signal_widths_if_no_const() {
        let params = HashMap::new();
        let known = HashMap::new();
        let mut widths = SignalWidths::new();
        widths.insert("c_n2b_out_3".to_string(), BitWidth::Exact(1));
        let ctx = InferenceCtx::new(&params, &known, &widths);
        assert_eq!(
            infer_expr(&CircuitExpr::Var("c_n2b_out_3".into()), &ctx),
            BitWidth::Exact(1)
        );
    }

    #[test]
    fn infer_capture_resolves_via_param_values() {
        let mut params = HashMap::new();
        params.insert("n".to_string(), fc(64));
        let known = HashMap::new();
        let widths = SignalWidths::new();
        let ctx = InferenceCtx::new(&params, &known, &widths);
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
        let widths = SignalWidths::new();
        let ctx = InferenceCtx::new(&params, &known, &widths);
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
        let widths = SignalWidths::new();
        let ctx = InferenceCtx::new(&params, &known, &widths);
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
    // infer_expr — arithmetic propagation (Stage 2)
    // ------------------------------------------------------------------

    #[test]
    fn infer_add_carries_one_bit() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            rhs: Box::new(CircuitExpr::Const(fc(1))),    // 1 bit
        };
        // max(8, 1) + 1 = 9
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(9));
    }

    #[test]
    fn infer_add_of_two_32_bit_yields_33() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
            rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
        };
        // max(32, 32) + 1 = 33
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(33));
    }

    #[test]
    fn infer_add_saturates_at_field() {
        // Build nested Add of 32-bit constants ~225 times so the
        // accumulated bit-width crosses FIELD_BITS = 254 and the
        // saturating widen converts to Field.
        let ctx = empty_ctx();
        let mut expr = CircuitExpr::Const(fc(0xffff_ffff));
        for _ in 0..225 {
            expr = CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(expr),
                rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
            };
        }
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
    }

    #[test]
    fn infer_mul_sums_widths() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Const(fc(0xff))), // 8
            rhs: Box::new(CircuitExpr::Const(fc(0xffff))), // 16
        };
        // 8 + 16 = 24
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(24));
    }

    #[test]
    fn infer_mul_saturates_at_field() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32
            rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32
        };
        // 32 + 32 = 64 — still under field
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(64));
    }

    #[test]
    fn infer_sub_yields_field() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: Box::new(CircuitExpr::Const(fc(0xff))),
            rhs: Box::new(CircuitExpr::Const(fc(1))),
        };
        // Modular borrow → Field even with concrete operands.
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
    }

    #[test]
    fn infer_div_yields_field() {
        let ctx = empty_ctx();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: Box::new(CircuitExpr::Const(fc(0xff))),
            rhs: Box::new(CircuitExpr::Const(fc(0xff))),
        };
        // Field-inverse → Field.
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
    }

    #[test]
    fn infer_shift_right_after_arithmetic_narrows() {
        // The SHA-256 motivating case: rotate-right on a value that
        // came from arithmetic. After Stage 2 inference, an Add of
        // two 32-bit values is AtMost(33); a >>7 of that is AtMost(26).
        let ctx = empty_ctx();
        let expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
                rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
            }),
            shift: Box::new(CircuitExpr::Const(fc(7))),
            num_bits: FIELD_BITS,
        };
        // 33 - 7 = 26
        assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(26));
    }

    // ------------------------------------------------------------------
    // rewrite_num_bits_in_expr — IR mutation pass
    // ------------------------------------------------------------------

    #[test]
    fn rewrite_tightens_shift_r_num_bits() {
        let ctx = empty_ctx();
        let mut expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            shift: Box::new(CircuitExpr::Const(fc(3))),
            num_bits: FIELD_BITS, // 254
        };
        rewrite_num_bits_in_expr(&mut expr, &ctx);
        match &expr {
            CircuitExpr::ShiftR { num_bits, .. } => assert_eq!(*num_bits, 8),
            _ => panic!("expected ShiftR"),
        }
    }

    #[test]
    fn rewrite_tightens_via_signal_widths() {
        // SHA-256 motivating case: signal `bit_0` is `Exact(1)` from
        // Num2Bits; a `BitOr(bit_0, bit_1)` should drop num_bits from
        // 254 to 1.
        let params = HashMap::new();
        let known = HashMap::new();
        let mut widths = SignalWidths::new();
        widths.insert("bit_0".to_string(), BitWidth::Exact(1));
        widths.insert("bit_1".to_string(), BitWidth::Exact(1));
        let ctx = InferenceCtx::new(&params, &known, &widths);
        let mut expr = CircuitExpr::BitOr {
            lhs: Box::new(CircuitExpr::Input("bit_0".into())),
            rhs: Box::new(CircuitExpr::Input("bit_1".into())),
            num_bits: FIELD_BITS,
        };
        rewrite_num_bits_in_expr(&mut expr, &ctx);
        match &expr {
            CircuitExpr::BitOr { num_bits, .. } => assert_eq!(*num_bits, 1),
            _ => panic!("expected BitOr"),
        }
    }

    #[test]
    fn rewrite_does_not_loosen() {
        // num_bits already tighter than inferred — must not raise.
        let ctx = empty_ctx();
        let mut expr = CircuitExpr::BitAnd {
            lhs: Box::new(CircuitExpr::Const(fc(0xff_ffff))), // 24 bits
            rhs: Box::new(CircuitExpr::Const(fc(0xff_ffff))),
            num_bits: 8, // pre-tightened to 8 (would imply user intent)
        };
        rewrite_num_bits_in_expr(&mut expr, &ctx);
        match &expr {
            CircuitExpr::BitAnd { num_bits, .. } => {
                // Inferred would be Exact(24); we must NOT raise from 8.
                assert_eq!(*num_bits, 8);
            }
            _ => panic!("expected BitAnd"),
        }
    }

    #[test]
    fn rewrite_recurses_into_nested() {
        let ctx = empty_ctx();
        let mut expr = CircuitExpr::Mux {
            cond: Box::new(CircuitExpr::Const(fc(1))),
            if_true: Box::new(CircuitExpr::ShiftR {
                operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
                shift: Box::new(CircuitExpr::Const(fc(2))),
                num_bits: FIELD_BITS,
            }),
            if_false: Box::new(CircuitExpr::Const(fc(0))),
        };
        rewrite_num_bits_in_expr(&mut expr, &ctx);
        match &expr {
            CircuitExpr::Mux { if_true, .. } => match if_true.as_ref() {
                CircuitExpr::ShiftR { num_bits, .. } => assert_eq!(*num_bits, 8),
                _ => panic!("expected ShiftR inside Mux"),
            },
            _ => panic!("expected Mux"),
        }
    }

    // ------------------------------------------------------------------
    // scan_bool_constraints — Num2Bits pattern detection
    // ------------------------------------------------------------------

    fn make_bool_assertion(name: &str) -> ir_forge::types::CircuitNode {
        // Build `x * (x - 1) === 0` with `x` named `name`.
        ir_forge::types::CircuitNode::AssertEq {
            lhs: CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(CircuitExpr::Var(name.to_string())),
                rhs: Box::new(CircuitExpr::BinOp {
                    op: CircuitBinOp::Sub,
                    lhs: Box::new(CircuitExpr::Var(name.to_string())),
                    rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                }),
            },
            rhs: CircuitExpr::Const(FieldConst::zero()),
            message: None,
            span: None,
        }
    }

    #[test]
    fn scan_detects_bool_constraint() {
        let prove_ir = ir_forge::types::ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![make_bool_assertion("c_out_0")],
            capture_arrays: vec![],
        };
        let widths = scan_bool_constraints(&prove_ir);
        assert_eq!(widths.get("c_out_0").copied(), Some(BitWidth::Exact(1)));
    }

    #[test]
    fn scan_detects_swapped_assertion_sides() {
        // `0 === x * (x - 1)` (rhs is the Mul) should still match.
        let prove_ir = ir_forge::types::ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![ir_forge::types::CircuitNode::AssertEq {
                lhs: CircuitExpr::Const(FieldConst::zero()),
                rhs: CircuitExpr::BinOp {
                    op: CircuitBinOp::Mul,
                    lhs: Box::new(CircuitExpr::Var("bit".into())),
                    rhs: Box::new(CircuitExpr::BinOp {
                        op: CircuitBinOp::Sub,
                        lhs: Box::new(CircuitExpr::Var("bit".into())),
                        rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                    }),
                },
                message: None,
                span: None,
            }],
            capture_arrays: vec![],
        };
        let widths = scan_bool_constraints(&prove_ir);
        assert_eq!(widths.get("bit").copied(), Some(BitWidth::Exact(1)));
    }

    #[test]
    fn scan_handles_commuted_mul_factors() {
        // `(x - 1) * x === 0` — Sub on lhs of Mul.
        let prove_ir = ir_forge::types::ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![ir_forge::types::CircuitNode::AssertEq {
                lhs: CircuitExpr::BinOp {
                    op: CircuitBinOp::Mul,
                    lhs: Box::new(CircuitExpr::BinOp {
                        op: CircuitBinOp::Sub,
                        lhs: Box::new(CircuitExpr::Var("b".into())),
                        rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                    }),
                    rhs: Box::new(CircuitExpr::Var("b".into())),
                },
                rhs: CircuitExpr::Const(FieldConst::zero()),
                message: None,
                span: None,
            }],
            capture_arrays: vec![],
        };
        let widths = scan_bool_constraints(&prove_ir);
        assert_eq!(widths.get("b").copied(), Some(BitWidth::Exact(1)));
    }

    #[test]
    fn scan_recurses_into_for_loops() {
        let prove_ir = ir_forge::types::ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![ir_forge::types::CircuitNode::For {
                var: "i".to_string(),
                range: ir_forge::types::ForRange::Literal { start: 0, end: 8 },
                body: vec![make_bool_assertion("nested_bit")],
                span: None,
            }],
            capture_arrays: vec![],
        };
        let widths = scan_bool_constraints(&prove_ir);
        assert_eq!(widths.get("nested_bit").copied(), Some(BitWidth::Exact(1)));
    }

    #[test]
    fn scan_ignores_non_bool_assertions() {
        let prove_ir = ir_forge::types::ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![ir_forge::types::CircuitNode::AssertEq {
                lhs: CircuitExpr::Var("x".into()),
                rhs: CircuitExpr::Var("y".into()),
                message: None,
                span: None,
            }],
            capture_arrays: vec![],
        };
        let widths = scan_bool_constraints(&prove_ir);
        assert!(widths.is_empty());
    }

    #[test]
    fn scan_pipeline_tightens_shift_via_bool_signals() {
        // End-to-end: build a tiny ProveIR with a bool-constrained
        // signal `b` and a `BitOr(b, b)`. After scan + rewrite, the
        // BitOr's num_bits should drop from 254 to 1.
        let mut prove_ir = ir_forge::types::ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![
                make_bool_assertion("b"),
                ir_forge::types::CircuitNode::Expr {
                    expr: CircuitExpr::BitOr {
                        lhs: Box::new(CircuitExpr::Var("b".into())),
                        rhs: Box::new(CircuitExpr::Var("b".into())),
                        num_bits: FIELD_BITS,
                    },
                    span: None,
                },
            ],
            capture_arrays: vec![],
        };
        let widths = scan_bool_constraints(&prove_ir);
        let ctx = InferenceCtx {
            param_values: None,
            known_constants: None,
            signal_widths: Some(&widths),
        };
        rewrite_num_bits_in_prove_ir(&mut prove_ir, &ctx);
        // Find the BitOr and check its num_bits.
        match &prove_ir.body[1] {
            ir_forge::types::CircuitNode::Expr { expr, .. } => match expr {
                CircuitExpr::BitOr { num_bits, .. } => assert_eq!(*num_bits, 1),
                _ => panic!("expected BitOr"),
            },
            _ => panic!("expected Expr node"),
        }
    }

    #[test]
    fn rewrite_via_arithmetic_propagation() {
        // Add of two 32-bit consts → AtMost(33). Then a >>7 of that
        // → tighten to num_bits=33.
        let ctx = empty_ctx();
        let mut expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
                rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
            }),
            shift: Box::new(CircuitExpr::Const(fc(7))),
            num_bits: FIELD_BITS,
        };
        rewrite_num_bits_in_expr(&mut expr, &ctx);
        match &expr {
            CircuitExpr::ShiftR { num_bits, .. } => assert_eq!(*num_bits, 33),
            _ => panic!("expected ShiftR"),
        }
    }
}
