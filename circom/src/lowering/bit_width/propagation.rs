use super::infer::infer_expr;
use super::{BitWidth, InferenceCtx, SignalWidths};

/// Walk `prove_ir.body` and propagate inferred widths through
/// `let`-bindings. For each `CircuitNode::Let { name, value, .. }`,
/// run `infer_expr(value)` and, if it returns a tighter result than
/// `Field`, register `name → width` in the returned `SignalWidths`.
/// Subsequent calls to `infer_expr` will find downstream
/// `Var(name)` references resolved via this table.
///
/// Combine with [`crate::lowering::bit_width::scan_bool_constraints`] before running the
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

pub(super) fn propagate_let_in_node(
    node: &ir_forge::types::CircuitNode,
    widths: &mut SignalWidths,
) {
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
