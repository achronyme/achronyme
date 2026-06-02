use ir_forge::types::CircuitExpr;

use crate::ast::Expr;

use super::super::super::artik_lift::{ConstInt, ParamShape};
use super::super::super::context::LoweringContext;
use super::super::super::env::{LoweringEnv, VarKind};
use super::super::super::error::LoweringError;
use super::super::super::utils::EvalValue;
use super::super::lower_expr;

/// Try to fold a call-site argument expression to a compile-time
/// integer that fits `i64`. Walks `Number`, `HexNumber`, common
/// arithmetic / shift / bit `BinOp`s, and looks up identifier args in
/// the caller's `param_values` (template params + outer-call known
/// scalars). Returns `None` for anything signal-derived or out of
/// `i64` range — the lift then treats the param as runtime-only.
///
/// Used to populate the lifted callee's `const_locals` so patterns
/// like `1 << n` recognize a const-pow-2 divisor at lift time.
pub(super) fn try_eval_arg_const(expr: &Expr, ctx: &LoweringContext<'_>) -> Option<ConstInt> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            ConstInt::from_str_radix(trimmed, 16).ok()
        }
        Expr::Ident { name, .. } => {
            let fc = ctx.param_values.get(name.as_str()).copied()?;
            let v = fc.to_u64()?;
            ConstInt::try_from(v).ok()
        }
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = try_eval_arg_const(lhs, ctx)?;
            let b = try_eval_arg_const(rhs, ctx)?;
            match op {
                crate::ast::BinOp::Add => a.checked_add(b),
                crate::ast::BinOp::Sub => a.checked_sub(b),
                crate::ast::BinOp::Mul => a.checked_mul(b),
                crate::ast::BinOp::Eq => Some(ConstInt::from(a == b)),
                crate::ast::BinOp::Neq => Some(ConstInt::from(a != b)),
                crate::ast::BinOp::Lt => Some(ConstInt::from(a < b)),
                crate::ast::BinOp::Le => Some(ConstInt::from(a <= b)),
                crate::ast::BinOp::Gt => Some(ConstInt::from(a > b)),
                crate::ast::BinOp::Ge => Some(ConstInt::from(a >= b)),
                _ => None,
            }
        }
        Expr::UnaryOp {
            op: crate::ast::UnaryOp::Neg,
            operand,
            ..
        } => try_eval_arg_const(operand, ctx).and_then(ConstInt::checked_neg),
        _ => None,
    }
}

/// Build the per-element `CircuitExpr` stream the Artik lift consumes
/// as its input signals. Scalars contribute one expression; array
/// parameters contribute `len` expressions (compile-time arrays expand
/// to `Const` cells, runtime signal arrays expand to per-index
/// `Input` / `Var` / `Capture` based on the base name's resolution).
pub(super) fn build_lowered_args_for_artik(
    args: &[Expr],
    param_shapes: &[(String, ParamShape)],
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<Vec<CircuitExpr>, LoweringError> {
    let mut lowered_args: Vec<CircuitExpr> = Vec::new();
    for (arg, (_, shape)) in args.iter().zip(param_shapes.iter()) {
        match shape {
            ParamShape::Scalar => {
                let lowered = lower_expr(arg, env, ctx)?;
                lowered_args.push(lowered);
            }
            ParamShape::Array(len) => {
                let (arg_name, arg_span) = match arg {
                    crate::ast::Expr::Ident { name, span } => (name, span),
                    _ => unreachable!("shape Array(_) was derived from an Ident arg by the caller"),
                };

                if let Some(eval_value) = env.known_array_values.get(arg_name) {
                    let elems = match eval_value {
                        EvalValue::Array(es) => es,
                        _ => {
                            return Err(LoweringError::new(
                                format!(
                                    "array argument `{arg_name}` has a known compile-time \
                                     value but is not an array shape"
                                ),
                                arg_span,
                            ));
                        }
                    };
                    if elems.len() < *len as usize {
                        return Err(LoweringError::new(
                            format!(
                                "array argument `{arg_name}` has {} compile-time elements \
                                 but the lift expected {}",
                                elems.len(),
                                *len
                            ),
                            arg_span,
                        ));
                    }
                    for (i, elem) in elems.iter().enumerate().take(*len as usize) {
                        let scalar = elem.as_scalar().ok_or_else(|| {
                            LoweringError::new(
                                format!(
                                    "compile-time array `{arg_name}` element {i} is not a \
                                     scalar value — Artik can only bind scalar field constants"
                                ),
                                arg_span,
                            )
                        })?;
                        lowered_args.push(CircuitExpr::Const(scalar.to_field_const()));
                    }
                    continue;
                }

                let kind = env.resolve(arg_name).ok_or_else(|| {
                    LoweringError::new(
                        format!("array argument `{arg_name}` is not resolvable in scope"),
                        arg_span,
                    )
                })?;
                for i in 0..(*len as usize) {
                    let elem_name = env.resolve_array_element(arg_name, i).ok_or_else(|| {
                        LoweringError::new(
                            format!(
                                "array argument `{arg_name}` has no element at index {i} \
                                 — shape mismatch during Artik lift"
                            ),
                            arg_span,
                        )
                    })?;
                    let expr = match kind {
                        VarKind::Input => CircuitExpr::Input(elem_name),
                        VarKind::Local => CircuitExpr::Var(elem_name),
                        VarKind::Capture => CircuitExpr::Capture(elem_name),
                    };
                    lowered_args.push(expr);
                }
            }
        }
    }
    Ok(lowered_args)
}
