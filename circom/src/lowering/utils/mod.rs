//! Shared lowering utilities.
//!
//! Helper functions used across multiple lowering modules (signals,
//! expressions, statements). These operate on the Circom AST and
//! don't depend on ProveIR types.

pub mod bigval;
mod eval;
pub mod eval_value;
mod precompute;

use std::collections::HashMap;

use ir_forge::types::FieldConst;

use crate::ast::Expr;

// Re-export public API — some are used by sibling lowering modules, some by lib.rs/template.rs
#[allow(unused_imports)]
pub use bigval::BigVal;
#[allow(unused_imports)]
pub use eval::{eval_expr, eval_function, eval_function_to_value, VarLookup};
#[allow(unused_imports)]
pub use eval_value::{EvalValue, PrecomputeResult};
#[allow(unused_imports)]
pub use precompute::{
    const_eval_with_functions, fc_map_to_bigval, precompute_all, precompute_array_vars,
    precompute_vars, try_eval_expr, try_eval_function_call, try_eval_function_call_to_value,
    try_eval_stmt_in_place,
};

/// Extract a simple identifier name from an expression.
///
/// Returns `Some("x")` for `Expr::Ident { name: "x" }`, `None` for
/// anything more complex (index, dot access, etc.).
pub fn extract_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Try to evaluate a Circom AST expression as a constant u64.
///
/// Used for array dimensions, loop bounds, and power exponents that must
/// be compile-time constants.
pub fn const_eval_u64(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

/// Try to evaluate a Circom AST expression as a signed `i64` constant.
///
/// Recognises plain decimal literals plus a leading unary negation
/// (`-N`). Used for loop conditions like `i != -1` where the
/// canonical descending bound is the literal -1.
pub fn const_eval_signed(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::UnaryOp {
            op: crate::ast::UnaryOp::Neg,
            operand,
            ..
        } => {
            let v: i64 = const_eval_u64(operand)?.try_into().ok()?;
            Some(-v)
        }
        _ => None,
    }
}

/// Evaluate a Circom expression as FieldConst by substituting known parameter values.
///
/// Like `const_eval_u64` but also resolves identifiers from the param map
/// and handles binary/unary operations, ternaries, and function calls.
///
/// Allocates a fresh `HashMap<String, BigVal>` from `params` on every call.
/// Hot lowering paths that already maintain the BigVal form should call
/// [`const_eval_with_bigvals`] instead and skip the per-call conversion.
pub fn const_eval_with_params(
    expr: &Expr,
    params: &HashMap<String, FieldConst>,
) -> Option<FieldConst> {
    let vars = precompute::fc_map_to_bigval(params);
    let empty_fns = HashMap::new();
    let empty_arrays: HashMap<String, eval_value::EvalValue> = HashMap::new();
    eval::eval_expr(expr, &vars, &empty_arrays, &empty_fns, 0).map(|v| v.to_field_const())
}

/// Evaluate a Circom expression as `FieldConst` using a pre-built
/// `HashMap<String, BigVal>` of known variables.
///
/// Sister of [`const_eval_with_params`] for callers that already hold
/// a merged BigVal map. Hot statement-lowering paths should prefer
/// [`const_eval_ctx`] instead, which avoids materialising the merge.
pub fn const_eval_with_bigvals(expr: &Expr, vars: &HashMap<String, BigVal>) -> Option<FieldConst> {
    let empty_fns = HashMap::new();
    let empty_arrays: HashMap<String, eval_value::EvalValue> = HashMap::new();
    eval::eval_expr(expr, vars, &empty_arrays, &empty_fns, 0).map(|v| v.to_field_const())
}

/// Lookup adaptor that queries `LoweringContext::param_values`,
/// `LoweringEnv::known_constants`, and `LoweringEnv::bound_const_vars`
/// in that order without merging them into a temporary HashMap.
///
/// Hot lowering paths (`eval_index_expr`, ternary fold, loop bounds,
/// indexed substitution lhs) build one of these per evaluation and
/// hand it to [`eval_expr`] / [`const_eval_ctx`]. Each Ident lookup
/// walks the three source maps in precedence order:
/// `param_values` shadows `known_constants`, which shadows
/// `bound_const_vars`.
pub struct CtxEnvLookup<'a, 'ctx> {
    ctx: &'a super::context::LoweringContext<'ctx>,
    env: &'a super::env::LoweringEnv,
}

impl<'a, 'ctx> CtxEnvLookup<'a, 'ctx> {
    #[inline]
    pub fn new(
        ctx: &'a super::context::LoweringContext<'ctx>,
        env: &'a super::env::LoweringEnv,
    ) -> Self {
        Self { ctx, env }
    }
}

impl<'a, 'ctx> VarLookup for CtxEnvLookup<'a, 'ctx> {
    #[inline]
    fn get_var(&self, name: &str) -> Option<BigVal> {
        if let Some(&fc) = self.ctx.param_values.get(name) {
            return Some(BigVal::from_field_const(fc));
        }
        if let Some(&fc) = self.env.known_constants.get(name) {
            return Some(BigVal::from_field_const(fc));
        }
        if let Some(&fc) = self.env.bound_const_vars.get(name) {
            return Some(BigVal::from_field_const(fc));
        }
        None
    }
}

/// Evaluate a Circom expression as `FieldConst` against a
/// [`LoweringContext`] + [`LoweringEnv`] without materialising a
/// merged variable map.
///
/// The hot statement-lowering entry point. Each `Ident` resolution
/// walks `param_values`, `known_constants`, and `bound_const_vars` in
/// precedence order; expressions with few identifiers pay only the
/// per-name lookup cost rather than rebuilding a HashMap of every
/// constant in scope.
pub fn const_eval_ctx(
    expr: &Expr,
    ctx: &super::context::LoweringContext<'_>,
    env: &super::env::LoweringEnv,
) -> Option<FieldConst> {
    let lookup = CtxEnvLookup::new(ctx, env);
    let empty_fns = HashMap::new();
    let empty_arrays: HashMap<String, eval_value::EvalValue> = HashMap::new();
    eval::eval_expr(expr, &lookup, &empty_arrays, &empty_fns, 0).map(|v| v.to_field_const())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
