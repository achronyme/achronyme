use super::*;

/// Scan inlined circuit nodes for `Let` and `WitnessHint` with constant
/// values, and add them to `env.known_constants`.
///
/// This enables constant propagation ACROSS component boundaries: after
/// inlining Edwards2Montgomery with constant inputs, its output signals
/// (e.g., `e2m.out_0`) become known constants in the parent scope, so
/// subsequent components (Window4, MontgomeryDouble) can also fold.
/// Walk `nodes` and collect the `(name, value)` pairs that constant
/// propagation lifts, in body-walk order (duplicates preserved — a
/// later write to the same name shadows an earlier one exactly as a
/// sequence of map inserts would). This is the single source of truth
/// shared by [`propagate_const_nodes`] (which injects them into an
/// env) and the deferred-body signature captured at cache time, so the
/// two can never drift.
pub(crate) fn collect_const_lifts(nodes: &[CircuitNode]) -> Vec<(String, FieldConst)> {
    let mut out = Vec::new();
    for node in nodes {
        match node {
            CircuitNode::Let { name, value, .. } => {
                if let Some(fc) = try_fold_const(value) {
                    out.push((name.clone(), fc));
                }
            }
            CircuitNode::LetIndexed {
                array,
                index,
                value,
                ..
            } => {
                if let (Some(idx_fc), Some(val_fc)) = (try_fold_const(index), try_fold_const(value))
                {
                    if let Some(idx) = idx_fc.to_u64() {
                        out.push((format!("{array}_{idx}"), val_fc));
                    }
                }
            }
            CircuitNode::WitnessHint { name, hint, .. } => {
                if let Some(fc) = try_fold_const(hint) {
                    out.push((name.clone(), fc));
                }
            }
            CircuitNode::WitnessHintIndexed {
                array, index, hint, ..
            } => {
                if let (Some(idx_fc), Some(val_fc)) = (try_fold_const(index), try_fold_const(hint))
                {
                    if let Some(idx) = idx_fc.to_u64() {
                        out.push((format!("{array}_{idx}"), val_fc));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

pub(crate) fn propagate_const_nodes(nodes: &[CircuitNode], env: &mut LoweringEnv) {
    for (name, fc) in collect_const_lifts(nodes) {
        env.known_constants.insert(name, fc);
    }
}
