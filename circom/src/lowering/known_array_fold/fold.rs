use std::collections::HashMap;

use ir_forge::types::{ArraySize, CircuitExpr, CircuitNode, FieldConst, ForRange};

use super::super::const_fold::try_fold_const;
use super::super::env::LoweringEnv;
use super::super::expressions::indexing::eval_value_to_field_const;
use super::super::utils::EvalValue;

/// Walk `slice` and rewrite every `CircuitExpr::ArrayIndex { array,
/// index }` whose `array` keys into `kav` AND whose `index` constant-
/// folds to a single `FieldConst` indexable to a scalar leaf, into the
/// resulting `CircuitExpr::Const(fc)`.
///
/// `kav` must be the snapshot of `LoweringEnv::known_array_values`
/// taken at memoize-loop entry (see `memoize_loop` in
/// `statements/loops.rs`). Late-bound entries created during body
/// lowering are rare today but a dedicated risk noted in the Option II
///; verify per call site.
///
/// `env`, when `Some`, additionally collapses a residual
/// `ArrayIndex { array, index }` whose `array` is a template-local
/// `var` array (`LoweringEnv::local_var_arrays`) and whose index has
/// folded to a constant, into the flat-scalar `Var("{array}_{linear}")`
/// — the same rewrite the direct-unroll path performs eagerly in
/// `expressions::indexing::lower_multi_index`. Local `var` arrays have
/// no ProveIR array binding (only per-element zero-init `Let`s), so an
/// uncollapsed residual dangles at instantiate (`… is not an array`).
/// `None` reproduces the kav-only behaviour exactly (byte-identical).
pub fn fold_known_array_indices(
    slice: &mut [CircuitNode],
    kav: &HashMap<String, EvalValue>,
    env: Option<&LoweringEnv>,
) {
    for node in slice {
        fold_node(node, kav, env);
    }
}

fn fold_node(node: &mut CircuitNode, kav: &HashMap<String, EvalValue>, env: Option<&LoweringEnv>) {
    match node {
        CircuitNode::Let { name: _, value, .. } => {
            fold_expr(value, kav, env);
        }
        CircuitNode::LetArray {
            name: _, elements, ..
        } => {
            for e in elements.iter_mut() {
                fold_expr(e, kav, env);
            }
        }
        CircuitNode::AssertEq {
            lhs,
            rhs,
            message: _,
            ..
        } => {
            fold_expr(lhs, kav, env);
            fold_expr(rhs, kav, env);
        }
        CircuitNode::Assert {
            expr, message: _, ..
        } => {
            fold_expr(expr, kav, env);
        }
        CircuitNode::For {
            var: _,
            range,
            body,
            ..
        } => {
            fold_range(range, kav, env);
            for n in body.iter_mut() {
                fold_node(n, kav, env);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            fold_expr(cond, kav, env);
            for n in then_body.iter_mut() {
                fold_node(n, kav, env);
            }
            for n in else_body.iter_mut() {
                fold_node(n, kav, env);
            }
        }
        CircuitNode::Expr { expr, .. } => {
            fold_expr(expr, kav, env);
        }
        CircuitNode::Decompose {
            name: _,
            value,
            num_bits: _,
            ..
        } => {
            fold_expr(value, kav, env);
        }
        CircuitNode::WitnessHint { name: _, hint, .. } => {
            fold_expr(hint, kav, env);
        }
        CircuitNode::WitnessArrayDecl { name: _, size, .. } => {
            fold_array_size(size, kav, env);
        }
        CircuitNode::LetIndexed {
            array: _,
            index,
            value,
            ..
        } => {
            fold_expr(index, kav, env);
            fold_expr(value, kav, env);
        }
        CircuitNode::WitnessHintIndexed {
            array: _,
            index,
            hint,
            ..
        } => {
            fold_expr(index, kav, env);
            fold_expr(hint, kav, env);
        }
        CircuitNode::WitnessCall {
            output_bindings: _,
            input_signals,
            program_bytes: _,
            ..
        } => {
            for is in input_signals.iter_mut() {
                fold_expr(is, kav, env);
            }
            // program_bytes is opaque Artik bytecode — same caveat as
            // loop_var_subst's WitnessCall arm.
        }
        CircuitNode::ComponentCall { param_subs, .. } => {
            // The shared body had known-array folding applied when
            // first lowered; only the caller-built substitution
            // expressions remain to fold here.
            for (_, e) in param_subs.iter_mut() {
                fold_expr(e, kav, env);
            }
        }
    }
}

pub(super) fn fold_expr(
    expr: &mut CircuitExpr,
    kav: &HashMap<String, EvalValue>,
    env: Option<&LoweringEnv>,
) {
    match expr {
        CircuitExpr::Const(_)
        | CircuitExpr::LoopVar(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Capture(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => {}

        CircuitExpr::BinOp { op: _, lhs, rhs }
        | CircuitExpr::Comparison { op: _, lhs, rhs }
        | CircuitExpr::BoolOp { op: _, lhs, rhs } => {
            fold_expr(lhs, kav, env);
            fold_expr(rhs, kav, env);
        }
        CircuitExpr::UnaryOp { op: _, operand } => {
            fold_expr(operand, kav, env);
        }
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            fold_expr(cond, kav, env);
            fold_expr(if_true, kav, env);
            fold_expr(if_false, kav, env);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            fold_expr(left, kav, env);
            fold_expr(right, kav, env);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args.iter_mut() {
                fold_expr(a, kav, env);
            }
        }
        CircuitExpr::RangeCheck { value, bits: _ } => {
            fold_expr(value, kav, env);
        }
        CircuitExpr::MerkleVerify {
            root,
            leaf,
            path: _,
            indices: _,
        } => {
            fold_expr(root, kav, env);
            fold_expr(leaf, kav, env);
        }

        CircuitExpr::ArrayIndex { array, index } => {
            fold_expr(index, kav, env);
            if let Some(arr_val) = kav.get(array.as_str()) {
                if let Some(idx_fc) = try_fold_const(index) {
                    if let Some(idx_u64) = idx_fc.to_u64() {
                        if let Some(fc) = lookup_kav_linear(arr_val, idx_u64 as usize) {
                            *expr = CircuitExpr::Const(fc);
                        }
                    }
                }
            }

            if let Some(env) = env {
                if let CircuitExpr::ArrayIndex { array, index } = &*expr {
                    if env.local_var_arrays.contains(array.as_str()) {
                        if let Some(idx_fc) = try_fold_const(index) {
                            if let Some(linear) = idx_fc.to_u64() {
                                if let Some(elem) =
                                    env.resolve_array_element(array, linear as usize)
                                {
                                    *expr = CircuitExpr::Var(elem);
                                }
                            }
                        }
                    }
                }
            }
        }

        CircuitExpr::Pow { base, exp: _ } => {
            fold_expr(base, kav, env);
        }
        CircuitExpr::IntDiv {
            lhs,
            rhs,
            max_bits: _,
        }
        | CircuitExpr::IntMod {
            lhs,
            rhs,
            max_bits: _,
        } => {
            fold_expr(lhs, kav, env);
            fold_expr(rhs, kav, env);
        }
        CircuitExpr::BitAnd {
            lhs,
            rhs,
            num_bits: _,
        }
        | CircuitExpr::BitOr {
            lhs,
            rhs,
            num_bits: _,
        }
        | CircuitExpr::BitXor {
            lhs,
            rhs,
            num_bits: _,
        } => {
            fold_expr(lhs, kav, env);
            fold_expr(rhs, kav, env);
        }
        CircuitExpr::BitNot {
            operand,
            num_bits: _,
        } => {
            fold_expr(operand, kav, env);
        }
        CircuitExpr::ShiftR {
            operand,
            shift,
            num_bits: _,
        }
        | CircuitExpr::ShiftL {
            operand,
            shift,
            num_bits: _,
        } => {
            fold_expr(operand, kav, env);
            fold_expr(shift, kav, env);
        }
    }
}

fn fold_range(range: &mut ForRange, kav: &HashMap<String, EvalValue>, env: Option<&LoweringEnv>) {
    match range {
        ForRange::Literal { .. } | ForRange::WithCapture { .. } | ForRange::Array(_) => {}
        ForRange::WithExpr { start: _, end_expr } => fold_expr(end_expr, kav, env),
    }
}

fn fold_array_size(
    _size: &mut ArraySize,
    _kav: &HashMap<String, EvalValue>,
    _env: Option<&LoweringEnv>,
) {
    // ArraySize variants carry no expressions — Literal / Capture only.
    // Kept as an explicit no-op so future variants force review here.
}

/// Look up a row-major flattened linear index against a known-array
/// value, supporting 1-D and uniformly-dimensioned 2-D shapes.
fn lookup_kav_linear(arr_val: &EvalValue, linear: usize) -> Option<FieldConst> {
    let outer = match arr_val {
        EvalValue::Array(elems) => elems,
        _ => return None,
    };
    let first = outer.first()?;
    if matches!(first, EvalValue::Array(_)) {
        let inner_len = first.len()?;
        if inner_len == 0 {
            return None;
        }
        let row = linear / inner_len;
        let col = linear % inner_len;
        let row_val = outer.get(row)?;
        match row_val {
            EvalValue::Array(_) if row_val.len() == Some(inner_len) => {
                eval_value_to_field_const(row_val.index(col)?)
            }
            _ => None,
        }
    } else {
        eval_value_to_field_const(outer.get(linear)?)
    }
}
