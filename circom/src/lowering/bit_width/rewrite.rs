use std::collections::HashMap;

use ir_forge::types::{CircuitExpr, FieldConst};

use super::infer::{infer_expr, max_width, min_width};
use super::propagation::propagate_let_in_node;
use super::scan::scan_node;
use super::{InferenceCtx, SignalWidths};

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
        // R1″ placeholder is a leaf — nothing to rewrite.
        CircuitExpr::LoopVar(_) => {}
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
        CircuitNode::ComponentCall { param_subs, .. } => {
            // The shared body was bit-width-rewritten when first
            // lowered; only the caller-built substitution
            // expressions remain to tighten here.
            for (_, e) in param_subs {
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

/// Apply the full scan → propagate → rewrite bit-width sequence to
/// each shared component body.
///
/// The eager inline path materializes a component body into
/// `prove_ir.body`, so the body-level passes above rewrite its
/// `num_bits`/`max_bits` in place. A deferred `ComponentCall` instead
/// keeps one shared body in `prove_ir.component_bodies` and expands it
/// at instantiation; that shared body must receive the identical
/// width treatment, or its expansion emits constraints that differ
/// from an inlined copy.
///
/// Each shared body is scanned in isolation. This is exact for the
/// promotion predicate (`const_inputs.is_empty() && array_args
/// .is_empty()`): with runtime-signal inputs and no constant/array
/// captures, a body's provable widths come from its own internal
/// bool constraints, independent of the instance name prefix. Width
/// inference is monotone-conservative, so any residual cross-body
/// context only ever widens (never miscomputes) a bound.
pub fn rewrite_num_bits_in_component_bodies(
    prove_ir: &mut ir_forge::types::ProveIR,
    param_values: Option<&HashMap<String, FieldConst>>,
) {
    for body in prove_ir.component_bodies.values_mut() {
        let mut widths = SignalWidths::new();
        for node in body.iter() {
            scan_node(node, &mut widths);
        }
        for node in body.iter() {
            propagate_let_in_node(node, &mut widths);
        }
        let ctx = InferenceCtx {
            param_values,
            known_constants: None,
            signal_widths: Some(&widths),
        };
        for node in body.iter_mut() {
            rewrite_num_bits_in_node(node, &ctx);
        }
    }
}
