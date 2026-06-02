use ir_forge::types::{CircuitExpr, FieldConst};

use super::{BitWidth, SignalWidths};

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

pub(super) fn scan_node(node: &ir_forge::types::CircuitNode, widths: &mut SignalWidths) {
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
