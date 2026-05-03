//! Expression lowering: Circom expressions → ProveIR `CircuitExpr`.
//!
//! Maps the Circom expression tree to ProveIR's circuit expression tree.
//! Key mappings:
//! - Number/HexNumber literals → `CircuitExpr::Const(FieldConst)`
//! - Identifiers → `Var`, `Input`, or `Capture` (resolved by environment)
//! - Arithmetic `+,-,*,/` → `CircuitExpr::BinOp`
//! - Integer division `\`, modulo `%` → `CircuitExpr::IntDiv`, `CircuitExpr::IntMod`
//! - Power `**` → `CircuitExpr::Pow`
//! - Comparisons → `CircuitExpr::Comparison`
//! - Boolean `&&, ||` → `CircuitExpr::BoolOp`
//! - Ternary `? :` → `CircuitExpr::Mux`
//! - Array index → `CircuitExpr::ArrayIndex`
//! - Unary `-`, `!` → `CircuitExpr::UnaryOp`

mod calls;
pub(in crate::lowering) mod indexing;
pub(crate) mod operators;

use ir_forge::types::{CircuitExpr, CircuitUnaryOp, FieldConst};

use crate::ast::{self, Expr};

use super::context::LoweringContext;
use super::env::{LoweringEnv, VarKind};
use super::error::LoweringError;
use super::suggest::find_similar;
use super::utils::{const_eval_u64, extract_ident_name};

use calls::lower_call;
use indexing::{
    eval_index_expr, lower_multi_index, resolve_component_array_expr_full,
    try_resolve_known_array_index,
};
use operators::lower_binop;

/// The default max bits for IntDiv/IntMod. Circom operates over BN254 (~254 bits).
/// BN254 scalar field prime is ~2^253.85, requiring 254 bits for full range.
const DEFAULT_MAX_BITS: u32 = 254;

/// Lower a Circom expression to a ProveIR `CircuitExpr`.
pub fn lower_expr(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<CircuitExpr, LoweringError> {
    match expr {
        // ── Literals ────────────────────────────────────────────────
        Expr::Number { value, span } => {
            if let Ok(n) = value.parse::<u64>() {
                Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
            } else {
                FieldConst::from_decimal_str(value)
                    .map(CircuitExpr::Const)
                    .ok_or_else(|| {
                        LoweringError::new(
                            format!("number literal `{value}` exceeds 256-bit field range"),
                            span,
                        )
                    })
            }
        }

        Expr::HexNumber { value, span } => {
            let hex_str = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            if let Ok(n) = u64::from_str_radix(hex_str, 16) {
                Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
            } else {
                FieldConst::from_hex_str(value)
                    .map(CircuitExpr::Const)
                    .ok_or_else(|| {
                        LoweringError::new(
                            format!("hex literal `{value}` exceeds 256-bit field range"),
                            span,
                        )
                    })
            }
        }

        // ── Identifiers ─────────────────────────────────────────────
        Expr::Ident { name, span } => {
            // Memoization placeholder. When the lowering is inside
            // an iter-0 capture window, the loop variable is emitted
            // as a `LoopVar(token)` placeholder so the captured node
            // slice can be cloned + substituted for each remaining
            // iteration. This branch fires *before* the
            // `known_constants` lookup so the unroll path that drives
            // the placeholder doesn't have to also delete the loop
            // variable from `env.known_constants` to suppress a const
            // fold — keeping the two regimes' state-management
            // symmetric makes the integration in `lower_for_loop`
            // simpler.
            if let Some(token) = ctx.placeholder_token_for(name) {
                return Ok(CircuitExpr::LoopVar(token));
            }
            if let Some(&val) = env.known_constants.get(name.as_str()) {
                return Ok(CircuitExpr::Const(val));
            }
            match env.resolve(name) {
                Some(VarKind::Input) => Ok(CircuitExpr::Input(name.clone())),
                Some(VarKind::Local) => Ok(CircuitExpr::Var(name.clone())),
                Some(VarKind::Capture) => Ok(CircuitExpr::Capture(name.clone())),
                None => {
                    let candidates = env.all_names();
                    let mut err = LoweringError::with_code(
                        format!("undefined variable `{name}` in circuit context"),
                        "E200",
                        span,
                    );
                    if let Some(similar) = find_similar(name, candidates.iter().map(|s| s.as_str()))
                    {
                        err.add_suggestion(
                            diagnostics::SpanRange::from_span(span),
                            similar,
                            "a similar name exists in scope",
                        );
                    }
                    Err(err)
                }
            }
        }

        // ── Binary operations ───────────────────────────────────────
        Expr::BinOp { op, lhs, rhs, span } => {
            let l = lower_expr(lhs, env, ctx)?;
            let r = lower_expr(rhs, env, ctx)?;
            lower_binop(*op, l, r, span)
        }

        // ── Unary operations ────────────────────────────────────────
        Expr::UnaryOp { op, operand, .. } => {
            let inner = lower_expr(operand, env, ctx)?;
            match op {
                ast::UnaryOp::Neg => {
                    let expr = CircuitExpr::UnaryOp {
                        op: CircuitUnaryOp::Neg,
                        operand: Box::new(inner),
                    };
                    Ok(super::const_fold::try_fold_const(&expr)
                        .map(CircuitExpr::Const)
                        .unwrap_or(expr))
                }
                ast::UnaryOp::Not => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Not,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::BitNot => Ok(CircuitExpr::BitNot {
                    operand: Box::new(inner),
                    num_bits: DEFAULT_MAX_BITS,
                }),
            }
        }

        // ── Ternary → Mux ───────────────────────────────────────────
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            // Constant-fold: if the condition is a compile-time constant,
            // select the branch directly (avoids lowering dead branches
            // that may contain invalid array accesses like xL[-1]).
            let all = ctx.all_constants_bigval(env);
            if let Some(cond_val) = super::utils::const_eval_with_bigvals(condition, &all) {
                return if !cond_val.is_zero() {
                    lower_expr(if_true, env, ctx)
                } else {
                    lower_expr(if_false, env, ctx)
                };
            }
            let cond = lower_expr(condition, env, ctx)?;
            let t = lower_expr(if_true, env, ctx)?;
            let f = lower_expr(if_false, env, ctx)?;
            Ok(CircuitExpr::Mux {
                cond: Box::new(cond),
                if_true: Box::new(t),
                if_false: Box::new(f),
            })
        }

        // ── Array index ─────────────────────────────────────────────
        Expr::Index {
            object,
            index,
            span,
        } => lower_index(object, index, span, env, ctx),

        // ── Function calls ──────────────────────────────────────────
        Expr::Call { callee, args, span } => lower_call(callee, args, env, ctx, span),

        // ── Array literals ──────────────────────────────────────────
        Expr::ArrayLit { span, .. } => Err(LoweringError::new(
            "array literal is not supported as a circuit expression; \
             use signal array declarations instead",
            span,
        )),

        // ── Dot access (component output) ───────────────────────────
        Expr::DotAccess {
            object,
            field,
            span,
        } => {
            let obj_name = if let Some(name) = extract_ident_name(object) {
                name
            } else if let Some(comp) = resolve_component_array_expr_full(object, env, ctx) {
                comp
            } else if matches!(object.as_ref(), Expr::Index { .. }) {
                // Circom-compatible: if a component array index is invalid
                // (e.g., bits[n-2] where n=1 → negative index), treat the
                // access as 0. This matches Circom's behavior where
                // nonexistent component signals have value 0.
                return Ok(CircuitExpr::Const(FieldConst::zero()));
            } else {
                return Err(LoweringError::new(
                    "dot access target must be a simple identifier or indexed component array",
                    span,
                ));
            };
            let mangled = format!("{obj_name}.{field}");
            match env.resolve(&mangled) {
                Some(VarKind::Input) => Ok(CircuitExpr::Input(mangled)),
                Some(VarKind::Local) => Ok(CircuitExpr::Var(mangled)),
                Some(VarKind::Capture) => Ok(CircuitExpr::Capture(mangled)),
                None => Ok(CircuitExpr::Var(mangled)),
            }
        }

        // ── Unsupported in circuit context ──────────────────────────
        Expr::PostfixOp { span, .. } | Expr::PrefixOp { span, .. } => Err(LoweringError::new(
            "increment/decrement is not supported in circuit expressions",
            span,
        )),

        Expr::AnonComponent { span, .. } => Err(LoweringError::new(
            "anonymous component instantiation will be handled at statement level",
            span,
        )),

        Expr::Tuple { span, .. } => Err(LoweringError::new(
            "tuples are not supported in circuit expressions",
            span,
        )),

        Expr::ParallelOp { operand, .. } => lower_expr(operand, env, ctx),

        Expr::Underscore { span } => Err(LoweringError::new(
            "underscore `_` is not a valid circuit expression",
            span,
        )),

        Expr::Error { span } => Err(LoweringError::new("cannot lower an error expression", span)),
    }
}

/// Lower an array index expression.
fn lower_index(
    object: &Expr,
    index: &Expr,
    _span: &diagnostics::Span,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<CircuitExpr, LoweringError> {
    // Case 0: Known compile-time array (e.g. `C[i+r]` where C = POSEIDON_C(t))
    if let Some(fc) = try_resolve_known_array_index(object, index, env, ctx) {
        return Ok(CircuitExpr::Const(fc));
    }

    // Case 1: Simple ident `arr[i]`, DotAccess `comp.signal[i]`,
    // or component array signal `comp[i].signal[j]`
    if let Some(array_name) = extract_ident_name(object).or_else(|| {
        if let Expr::DotAccess {
            object: inner_obj,
            field,
            ..
        } = object
        {
            extract_ident_name(inner_obj)
                .or_else(|| resolve_component_array_expr_full(inner_obj, env, ctx))
                .map(|obj_name| format!("{obj_name}.{field}"))
        } else {
            None
        }
    }) {
        if let Some(idx_val) = const_eval_u64(index)
            .map(|v| v as usize)
            .or_else(|| eval_index_expr(index, env, ctx))
        {
            if let Some(elem_name) = env.resolve_array_element(&array_name, idx_val) {
                // Check if the element is a known constant (e.g., base[0]
                // where base_0 was injected via constant propagation).
                if let Some(&fc) = env.known_constants.get(&elem_name) {
                    return Ok(CircuitExpr::Const(fc));
                }
                return Ok(CircuitExpr::Var(elem_name));
            }
            // Circom-compatible: out-of-bounds access on a known-size signal
            // array returns 0 (uninitialized signal). This occurs in templates
            // like SegmentMulAny(1) where e[1] is accessed on a size-1 array.
            if let Some(&size) = env.arrays.get(&array_name) {
                if idx_val >= size {
                    return Ok(CircuitExpr::Const(FieldConst::zero()));
                }
            }
        }

        // placeholder index handling: previously this site
        // emitted E213 when `ctx.placeholder_appears_in(index)` AND the
        // base lived only in `known_array_values` (kav). Option II
        // accepts that shape — the IR carries `ArrayIndex { array:
        // <kav-name>, index: <symbolic-with-LoopVar> }` through iter-0
        // capture, then `memoize_loop` invokes
        // `known_array_fold::fold_known_array_indices` after each
        // `substitute_loop_var` pass to collapse the now-foldable node
        // to `CircuitExpr::Const(fc)`. The post-substitute fold mirrors
        // what legacy `try_resolve_known_array_index` (Case 0 above)
        // produces for non-placeholder shapes. If the fold pass
        // doesn't collapse the node (placeholder leaked, multi-dim kav
        // shape unreachable today, etc.) the residual reaches
        // instantiate and fails loudly there — preserving the original
        // safety net's intent without rejecting the legitimate Option
        // II Ark / MixS-loop shapes.
        let idx = lower_expr(index, env, ctx)?;
        return Ok(CircuitExpr::ArrayIndex {
            array: array_name,
            index: Box::new(idx),
        });
    }

    // Case 2: Multi-dim index: arr[i][j]...[k]
    {
        let mut indices: Vec<&Expr> = vec![index];
        let mut current: &Expr = object;
        loop {
            match current {
                Expr::Ident { name, .. } => {
                    indices.reverse();
                    return lower_multi_index(name, &indices, env, ctx);
                }
                Expr::DotAccess {
                    object: da_obj,
                    field,
                    ..
                } => {
                    if let Some(obj) = extract_ident_name(da_obj)
                        .or_else(|| resolve_component_array_expr_full(da_obj, env, ctx))
                    {
                        let base = format!("{obj}.{field}");
                        indices.reverse();
                        return lower_multi_index(&base, &indices, env, ctx);
                    }
                    break;
                }
                Expr::Index {
                    object: inner_obj,
                    index: inner_idx,
                    ..
                } => {
                    indices.push(inner_idx.as_ref());
                    current = inner_obj.as_ref();
                }
                _ => break,
            }
        }
    }

    // Circom-compatible: if the index target couldn't be resolved (e.g.,
    // component array with a negative index like bits[n-2] where n=1),
    // treat the access as 0. This matches Circom's behavior where
    // nonexistent signals have value 0.
    Ok(CircuitExpr::Const(FieldConst::zero()))
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{make_ctx, make_env, parse_expr};
    use super::super::utils::const_eval_u64;
    use super::*;
    use ir_forge::types::{CircuitBinOp, CircuitBoolOp, CircuitCmpOp};

    // ── Literals ────────────────────────────────────────────────────

    #[test]
    fn lower_decimal_number() {
        let expr = parse_expr("42");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn lower_hex_number() {
        let expr = parse_expr("0xFF");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(255)));
    }

    #[test]
    fn lower_zero() {
        let expr = parse_expr("0");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::zero()));
    }

    // ── Identifiers ─────────────────────────────────────────────────

    #[test]
    fn lower_input_ident() {
        let expr = parse_expr("a");
        assert_eq!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Input("a".to_string())
        );
    }

    #[test]
    fn lower_local_ident() {
        let expr = parse_expr("x");
        assert_eq!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Var("x".to_string())
        );
    }

    #[test]
    fn lower_capture_ident() {
        let expr = parse_expr("n");
        assert_eq!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Capture("n".to_string())
        );
    }

    #[test]
    fn lower_placeholder_loop_var_emits_loopvar_node() {
        // memoized unroll: when the lowering context carries an
        // active memoization placeholder, an `Ident` matching that name
        // resolves to `CircuitExpr::LoopVar(token)` regardless of what
        // `env.known_constants` or `env.resolve` would otherwise say.
        // The test asserts the placeholder takes precedence over the
        // const-fold path that would normally fold `i` to `Const(0)`
        // (the canonical legacy unroll behaviour for iter 0).
        let expr = parse_expr("i");
        let mut env = make_env();
        // Seed the legacy unroll state too — `placeholder_loop_var`
        // must override it so the regimes don't have to coordinate
        // env mutations.
        env.known_constants
            .insert("i".to_string(), FieldConst::from_u64(0));

        let mut ctx = make_ctx();
        ctx.placeholder_loop_var = Some(("i".to_string(), 7));

        assert_eq!(
            lower_expr(&expr, &env, &mut ctx).unwrap(),
            CircuitExpr::LoopVar(7),
        );
    }

    #[test]
    fn lower_placeholder_signal_array_index_produces_arrayindex_loopvar() {
        // The full Option D contract: with the placeholder active, an
        // `arr[i]` read where `arr` is a registered signal array
        // skips the const-fold-then-resolve_array_element fast path
        // (because `i` is no longer in `known_constants`) and lands
        // in the symbolic fall-through that emits
        // `ArrayIndex { array, index: LoopVar(t) }`. After
        // `substitute_loop_var(slice, t, N)` the index becomes
        // `Const(N)` and instantiate's existing fast path resolves
        // `arr_N` from the env's `InstEnvValue::Array`.
        let expr = parse_expr("arr[i]");
        let mut env = make_env();
        env.register_array("arr".to_string(), 4);
        for i in 0..4 {
            env.locals.insert(format!("arr_{i}"));
        }

        let mut ctx = make_ctx();
        ctx.placeholder_loop_var = Some(("i".to_string(), 7));

        let lowered = lower_expr(&expr, &env, &mut ctx).unwrap();
        match lowered {
            CircuitExpr::ArrayIndex { array, index } => {
                assert_eq!(array, "arr");
                assert_eq!(*index, CircuitExpr::LoopVar(7));
            }
            other => panic!("expected ArrayIndex {{ array, index: LoopVar(7) }}, got {other:?}",),
        }
    }

    #[test]
    fn lower_placeholder_does_not_affect_other_idents() {
        // Sanity: only the named placeholder ident takes the LoopVar
        // branch. Other idents still resolve via the env (`a` is an
        // input in `make_env`).
        let expr = parse_expr("a");
        let env = make_env();
        let mut ctx = make_ctx();
        ctx.placeholder_loop_var = Some(("i".to_string(), 7));

        assert_eq!(
            lower_expr(&expr, &env, &mut ctx).unwrap(),
            CircuitExpr::Input("a".to_string()),
        );
    }

    #[test]
    fn lower_undefined_ident_is_error() {
        let expr = parse_expr("unknown");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .diagnostic
            .message
            .contains("undefined variable"));
    }

    // ── Arithmetic ──────────────────────────────────────────────────

    #[test]
    fn lower_addition() {
        let expr = parse_expr("a + b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                ..
            }
        ));
    }

    #[test]
    fn lower_subtraction() {
        let expr = parse_expr("a - b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BinOp {
                op: CircuitBinOp::Sub,
                ..
            }
        ));
    }

    #[test]
    fn lower_multiplication() {
        let expr = parse_expr("a * b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn lower_division() {
        let expr = parse_expr("a / b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BinOp {
                op: CircuitBinOp::Div,
                ..
            }
        ));
    }

    #[test]
    fn lower_int_div() {
        let expr = parse_expr(r"a \ b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::IntDiv { .. }
        ));
    }

    #[test]
    fn lower_modulo() {
        let expr = parse_expr("a % b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::IntMod { .. }
        ));
    }

    #[test]
    fn lower_power() {
        let expr = parse_expr("a ** 3");
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::Pow { exp, .. } => assert_eq!(exp, 3),
            other => panic!("expected Pow, got {:?}", other),
        }
    }

    #[test]
    fn lower_power_non_const_is_error() {
        let expr = parse_expr("a ** b");
        assert!(lower_expr(&expr, &make_env(), &mut make_ctx()).is_err());
    }

    // ── Comparisons ─────────────────────────────────────────────────

    #[test]
    fn lower_equality() {
        let expr = parse_expr("a == b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn lower_neq() {
        let expr = parse_expr("a != b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Neq,
                ..
            }
        ));
    }

    #[test]
    fn lower_less_than() {
        let expr = parse_expr("a < b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Lt,
                ..
            }
        ));
    }

    // ── Boolean ─────────────────────────────────────────────────────

    #[test]
    fn lower_and() {
        let expr = parse_expr("a && b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::And,
                ..
            }
        ));
    }

    #[test]
    fn lower_or() {
        let expr = parse_expr("a || b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::Or,
                ..
            }
        ));
    }

    // ── Unary ───────────────────────────────────────────────────────

    #[test]
    fn lower_negation() {
        let expr = parse_expr("-a");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                ..
            }
        ));
    }

    #[test]
    fn lower_not() {
        let expr = parse_expr("!a");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Not,
                ..
            }
        ));
    }

    #[test]
    fn lower_bitnot_via_unary() {
        let expr = parse_expr("~a");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BitNot { num_bits: 254, .. }
        ));
    }

    // ── Ternary → Mux ───────────────────────────────────────────────

    #[test]
    fn lower_ternary_to_mux() {
        let expr = parse_expr("a == 0 ? 1 : 0");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Mux { .. }
        ));
    }

    // ── Array index ─────────────────────────────────────────────────

    #[test]
    fn lower_array_index() {
        let expr = parse_expr("bits[0]");
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::ArrayIndex { array, .. } => assert_eq!(array, "bits"),
            other => panic!("expected ArrayIndex, got {:?}", other),
        }
    }

    // ── Nested expression ───────────────────────────────────────────

    #[test]
    fn lower_nested_arithmetic() {
        let expr = parse_expr("(a + b) * (a - b)");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn lower_complex_iszero_pattern() {
        let expr = parse_expr("a != 0 ? 1 : 0");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Mux { .. }
        ));
    }

    // ── Bitwise operations ────────────────────────────────────────

    #[test]
    fn lower_bitwise_and() {
        let expr = parse_expr("a & b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BitAnd { num_bits: 254, .. }
        ));
    }

    #[test]
    fn lower_bitwise_or() {
        let expr = parse_expr("a | b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BitOr { num_bits: 254, .. }
        ));
    }

    #[test]
    fn lower_bitwise_xor() {
        let expr = parse_expr("a ^ b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BitXor { num_bits: 254, .. }
        ));
    }

    #[test]
    fn lower_bitwise_not() {
        let expr = parse_expr("~a");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BitNot { num_bits: 254, .. }
        ));
    }

    #[test]
    fn lower_shift_right() {
        let expr = parse_expr("a >> 3");
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::ShiftR {
                shift, num_bits, ..
            } => {
                assert_eq!(*shift, CircuitExpr::Const(FieldConst::from_u64(3)));
                assert_eq!(num_bits, 254);
            }
            other => panic!("expected ShiftR, got {:?}", other),
        }
    }

    #[test]
    fn lower_shift_left() {
        let expr = parse_expr("a << 1");
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::ShiftL {
                shift, num_bits, ..
            } => {
                assert_eq!(*shift, CircuitExpr::Const(FieldConst::from_u64(1)));
                assert_eq!(num_bits, 254);
            }
            other => panic!("expected ShiftL, got {:?}", other),
        }
    }

    #[test]
    fn lower_shift_variable_amount() {
        let expr = parse_expr("a >> b");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::ShiftR { .. }
        ));
    }

    #[test]
    fn lower_shift_non_const_is_now_ok() {
        let expr = parse_expr("a >> b");
        assert!(lower_expr(&expr, &make_env(), &mut make_ctx()).is_ok());
    }

    // ── Parallel is transparent ─────────────────────────────────────

    #[test]
    fn lower_parallel_is_transparent() {
        let expr = parse_expr("parallel a");
        assert_eq!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Input("a".to_string())
        );
    }

    // ── Large number literals ────────────────────────────────────────

    #[test]
    fn lower_large_decimal_number() {
        let expr = parse_expr(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        );
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::Const(fc) => {
                assert!(fc.to_u64().is_none());
                assert!(!fc.is_zero());
            }
            other => panic!("expected Const, got {:?}", other),
        }
    }

    #[test]
    fn lower_large_hex_number() {
        let expr = parse_expr("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::Const(fc) => assert!(fc.to_u64().is_none()),
            other => panic!("expected Const, got {:?}", other),
        }
    }

    // ── const_eval_u64 (moved to utils, verify still works) ─────────

    #[test]
    fn const_eval_decimal() {
        assert_eq!(const_eval_u64(&parse_expr("42")), Some(42));
    }

    #[test]
    fn const_eval_hex() {
        assert_eq!(const_eval_u64(&parse_expr("0x10")), Some(16));
    }

    #[test]
    fn const_eval_non_const() {
        assert_eq!(const_eval_u64(&parse_expr("a + 1")), None);
    }

    #[test]
    fn nested_dot_access_error() {
        let expr = parse_expr("c.sub.x");
        let mut env = make_env();
        env.locals.insert("c.sub".to_string());
        let result = lower_expr(&expr, &env, &mut make_ctx());
        assert!(result.is_err());
        let msg = result.unwrap_err().diagnostic.message;
        assert!(
            msg.contains("dot access target"),
            "expected dot access error, got: {msg}"
        );
    }
}
