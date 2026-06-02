use super::super::context::LoweringContext;

/// Const-eval an array's dimension expressions using the lowering
/// context's `param_values`. Returns the total flat element count
/// when every dimension resolves; `None` if any dimension references
/// something not yet resolved (e.g., a runtime signal). Used by the
/// Lysis-frontend `WitnessArrayDecl` emission to decide whether the
/// internal signal array can be pre-allocated.
pub(super) fn total_dim_size(dims: &[crate::ast::Expr], ctx: &LoweringContext) -> Option<u64> {
    let mut total: u64 = 1;
    for d in dims {
        let val = super::super::utils::const_eval_with_params(d, &ctx.param_values)?.to_u64()?;
        total = total.checked_mul(val)?;
    }
    Some(total)
}
