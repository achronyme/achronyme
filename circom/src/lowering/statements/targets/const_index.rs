use super::*;

/// Resolve constant index using ctx+env (avoids creating merged HashMap).
///
/// Mirrors [`resolve_const_index`]'s capability set so the two variants
/// stay interchangeable from the caller's perspective. Earlier this
/// function only handled `Add` / `Sub` and relied on the BigVal
/// fallback for everything else; subbing `extract_assign_target_ctx`
/// for `extract_assign_target_with_constants` exposed the gap on
/// circomlib's Poseidon (`ark[nRoundsF\2]` = IntDiv on a capture).
pub(super) fn resolve_const_index_ctx(
    expr: &Expr,
    ctx: &LoweringContext,
    env: &LoweringEnv,
) -> Option<u64> {
    if let Some(v) = const_eval_u64(expr) {
        return Some(v);
    }
    if let Expr::Ident { name, .. } = expr {
        return ctx.resolve_constant(name, env)?.to_u64();
    }
    if let Expr::BinOp { op, lhs, rhs, .. } = expr {
        if let (Expr::Ident { name, .. }, Some(rhs_val)) = (lhs.as_ref(), const_eval_u64(rhs)) {
            if let Some(lhs_val) = ctx.resolve_constant(name, env)?.to_u64() {
                return match op {
                    crate::ast::BinOp::Add => lhs_val.checked_add(rhs_val),
                    crate::ast::BinOp::Sub => lhs_val.checked_sub(rhs_val),
                    crate::ast::BinOp::Mul => lhs_val.checked_mul(rhs_val),
                    crate::ast::BinOp::IntDiv => lhs_val.checked_div(rhs_val),
                    _ => None,
                };
            }
        }
    }
    // Recursive constant fold over O(1) per-identifier lookups,
    // covering affine / nested integer-arithmetic index shapes such
    // as `n * i + j` (component-array targets in the secp256k1
    // scalar-multiplication ladder) that the single-level fast paths
    // above miss because their `lhs` is itself a `BinOp` and their
    // `rhs` is an identifier rather than a literal. Returns `None` for
    // any operator or shape it does not fully model, so the merged-map
    // BigVal path below stays authoritative and the set of resolvable
    // indices is unchanged - this only avoids materializing
    // `all_constants` plus its BigVal clone on every such target.
    if let Some(v) = try_const_index_fold_ctx(expr, ctx, env) {
        return Some(v);
    }
    // Fallback
    let all = ctx.all_constants(env);
    resolve_const_index(expr, &all)
}

/// Resolve a constant index expression using only O(1) per-identifier
/// lookups via [`LoweringContext::resolve_constant`], with no merged
/// constant map or BigVal allocation. Handles literals, resolvable
/// identifiers, and `Add` / `Sub` / `Mul` / `IntDiv` over recursively
/// foldable operands - the exact `u64` arithmetic the single-level
/// fast paths use, extended to arbitrary nesting. Any other operator
/// or shape (or an identifier only present in `bound_const_vars`,
/// which `resolve_constant` does not consult) yields `None`, so the
/// caller falls back to the merged-map BigVal evaluation and the
/// resolvable-index set is unchanged.
fn try_const_index_fold_ctx(expr: &Expr, ctx: &LoweringContext, env: &LoweringEnv) -> Option<u64> {
    if let Some(v) = const_eval_u64(expr) {
        return Some(v);
    }
    match expr {
        Expr::Ident { name, .. } => ctx.resolve_constant(name, env)?.to_u64(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = try_const_index_fold_ctx(lhs, ctx, env)?;
            let r = try_const_index_fold_ctx(rhs, ctx, env)?;
            match op {
                crate::ast::BinOp::Add => l.checked_add(r),
                crate::ast::BinOp::Sub => l.checked_sub(r),
                crate::ast::BinOp::Mul => l.checked_mul(r),
                crate::ast::BinOp::IntDiv => l.checked_div(r),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Resolve an index expression to a constant u64 using literals + known_constants.
///
/// Returns `None` for negative values (e.g., `n-2` where `n=1`), which
/// indicate out-of-bounds component array access. This prevents wrapping
/// to u64::MAX and generating invalid component names like `bits_18446744073709551615`.
pub(super) fn resolve_const_index(
    expr: &Expr,
    known_constants: &HashMap<String, FieldConst>,
) -> Option<u64> {
    if let Some(v) = const_eval_u64(expr) {
        return Some(v);
    }
    // Fast path: simple identifier lookup (avoids creating BigVal HashMap)
    if let Expr::Ident { name, .. } = expr {
        return known_constants.get(name.as_str())?.to_u64();
    }
    // Fast path: ident op literal (e.g., `i-1`, `i+1`, `n\2`)
    if let Expr::BinOp { op, lhs, rhs, .. } = expr {
        if let (Expr::Ident { name, .. }, Some(rhs_val)) = (lhs.as_ref(), const_eval_u64(rhs)) {
            if let Some(lhs_val) = known_constants.get(name.as_str())?.to_u64() {
                return match op {
                    crate::ast::BinOp::Add => lhs_val.checked_add(rhs_val),
                    crate::ast::BinOp::Sub => lhs_val.checked_sub(rhs_val),
                    crate::ast::BinOp::Mul => lhs_val.checked_mul(rhs_val),
                    crate::ast::BinOp::IntDiv => lhs_val.checked_div(rhs_val),
                    _ => None,
                };
            }
        }
    }
    // Fallback: full BigVal evaluation for complex expressions
    let vars = super::super::super::utils::fc_map_to_bigval(known_constants);
    let empty_fns = HashMap::new();
    let empty_arrays: HashMap<String, crate::lowering::utils::EvalValue> = HashMap::new();
    let result = super::super::super::utils::eval_expr(expr, &vars, &empty_arrays, &empty_fns, 0)?;
    if result.is_negative() {
        None
    } else {
        result.to_u64()
    }
}
