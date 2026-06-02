//! Compile-time expression and statement evaluation.
//!
//! Evaluates Circom expressions and statements at compile time. Scalar
//! state lives in `vars: HashMap<String, BigVal>`; array state (1-D or
//! nested) lives alongside in `arrays: HashMap<String, EvalValue>`.
//! Keeping the two maps separate lets scalar-only callers keep their
//! existing signatures while array-aware callers (e.g. circomlib's
//! `EscalarMulW4Table`) pass a mutable array state through.

use std::collections::HashMap;

use crate::ast::{self, CompoundOp, Expr, FunctionDef};

use super::bigval::BigVal;
use super::eval_value::EvalValue;
use super::extract_ident_name;

mod statements;

pub(super) use statements::eval_stmt;

/// Read-only lookup for compile-time scalar variables.
///
/// `eval_expr` and `eval_expr_value` are generic over this trait so
/// callers can avoid building an intermediate `HashMap<String, BigVal>`
/// when the source-of-truth lives in some other shape (e.g. spread
/// across `LoweringContext` + `LoweringEnv`).
pub trait VarLookup {
    fn get_var(&self, name: &str) -> Option<BigVal>;
}

impl VarLookup for HashMap<String, BigVal> {
    #[inline]
    fn get_var(&self, name: &str) -> Option<BigVal> {
        self.get(name).copied()
    }
}

/// Maximum loop iterations during compile-time function evaluation.
pub(super) const MAX_EVAL_ITERATIONS: usize = 10_000;

/// Maximum recursion depth for compile-time evaluation.
pub(super) const MAX_EVAL_DEPTH: usize = 64;

/// Evaluate a Circom function body at compile time with concrete BigVal arguments.
///
/// Returns `Some(result)` if the function can be fully evaluated to a constant,
/// `None` if evaluation fails.
pub fn eval_function(
    func: &FunctionDef,
    args: &[BigVal],
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<BigVal> {
    eval_function_to_value(func, args, &HashMap::new(), &[], functions, depth)?.as_scalar()
}

/// Evaluate a Circom function body at compile time, returning scalar or array.
///
/// `scalar_args` are positional BigVal arguments that bind into the
/// `vars` state. `array_caller_env` holds array values already known
/// in the caller's scope (e.g. template array params); these are
/// copied into the function-local `arrays` state keyed by parameter
/// name when `array_args` names them positionally. `array_args`
/// positionally maps function params to caller array keys for
/// entries that should be bound as arrays rather than scalars.
pub fn eval_function_to_value(
    func: &FunctionDef,
    args: &[BigVal],
    array_caller_env: &HashMap<String, EvalValue>,
    array_arg_names: &[Option<String>],
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<EvalValue> {
    if depth > MAX_EVAL_DEPTH {
        return None;
    }
    if args.len() != func.params.len() {
        return None;
    }

    let mut vars: HashMap<String, BigVal> = HashMap::new();
    let mut arrays: HashMap<String, EvalValue> = HashMap::new();

    for (i, param) in func.params.iter().enumerate() {
        // Array argument takes precedence if the caller named one.
        if let Some(Some(src)) = array_arg_names.get(i) {
            if let Some(val) = array_caller_env.get(src) {
                arrays.insert(param.clone(), val.clone());
                continue;
            }
        }
        // Canonicalize the incoming BigVal to field form. Callers
        // sometimes pass `BigVal::from_i64(-3)` (two's complement),
        // but the evaluator treats `var` arithmetic as BN254 field
        // arithmetic — `p - 3` is the field representation of -3,
        // not `2^256 - 3`. Without canonicalization, a subsequent
        // `0 - x` would produce garbage.
        vars.insert(param.clone(), args[i].to_field_canonical());
    }

    match statements::eval_stmts(&func.body.stmts, &mut vars, &mut arrays, functions, depth)? {
        super::eval_value::StmtResult::Return(val) => Some(val),
        super::eval_value::StmtResult::Continue => None,
    }
}

/// Unwrap a chain of `Expr::Index` to its base Ident, returning the
/// name and the index expressions in outermost-to-innermost order.
///
/// `out[i][j]` parses as `Index { object: Index { object: Ident("out"),
/// index: i }, index: j }`, so unwrapping produces `("out", [i, j])`.
fn unwrap_indexed(expr: &Expr) -> Option<(&str, Vec<&Expr>)> {
    let mut indices: Vec<&Expr> = Vec::new();
    let mut cursor = expr;
    while let Expr::Index { object, index, .. } = cursor {
        indices.push(index);
        cursor = object;
    }
    if let Expr::Ident { name, .. } = cursor {
        indices.reverse();
        Some((name.as_str(), indices))
    } else {
        None
    }
}

/// Evaluate an expression to an [`EvalValue`] (scalar, array, or raw expr).
pub(super) fn eval_expr_value<L: VarLookup>(
    expr: &Expr,
    vars: &L,
    arrays: &HashMap<String, EvalValue>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<EvalValue> {
    match expr {
        Expr::Ident { name, .. } => {
            if let Some(val) = arrays.get(name.as_str()) {
                return Some(val.clone());
            }
            vars.get_var(name.as_str()).map(EvalValue::Scalar)
        }
        Expr::ArrayLit { elements, .. } => {
            let vals: Vec<EvalValue> = elements
                .iter()
                .map(|e| {
                    eval_expr_value(e, vars, arrays, functions, depth)
                        .or_else(|| Some(EvalValue::Expr(Box::new(e.clone()))))
                })
                .collect::<Option<_>>()?;
            Some(EvalValue::Array(vals))
        }
        Expr::Call { callee, args, .. } => {
            let name = extract_ident_name(callee)?;
            let func = *functions.get(name.as_str())?;
            // Split args into scalar BigVals + array-name positional
            // hints so the callee's binding loop can pick up arrays
            // from the caller's env when an Ident arg refers to one.
            let mut arg_vals: Vec<BigVal> = Vec::with_capacity(args.len());
            let mut array_arg_names: Vec<Option<String>> = Vec::with_capacity(args.len());
            for a in args {
                if let Expr::Ident { name, .. } = a {
                    if arrays.contains_key(name.as_str()) {
                        array_arg_names.push(Some(name.clone()));
                        arg_vals.push(BigVal::ZERO);
                        continue;
                    }
                }
                let v = eval_expr(a, vars, arrays, functions, depth)?;
                arg_vals.push(v);
                array_arg_names.push(None);
            }
            eval_function_to_value(
                func,
                &arg_vals,
                arrays,
                &array_arg_names,
                functions,
                depth + 1,
            )
        }
        Expr::Index { .. } => {
            // Walk the chain of indices back to the base Ident and
            // traverse nested EvalValue::Array slots. If the base
            // isn't an array, fall back to evaluating recursively
            // via eval_expr_value so `arr[i]` over an ArrayLit or
            // function-call result still works.
            let (base, indices) = unwrap_indexed(expr)?;
            if let Some(arr) = arrays.get(base) {
                let mut cursor = arr;
                for idx_expr in &indices {
                    let i = eval_expr(idx_expr, vars, arrays, functions, depth)?;
                    cursor = cursor.index(i.to_u64()? as usize)?;
                }
                return Some(cursor.clone());
            }
            // Recursive path: evaluate the object as a value, then
            // step through each index.
            if let Expr::Index { object, index, .. } = expr {
                let arr = eval_expr_value(object, vars, arrays, functions, depth)?;
                let idx = eval_expr(index, vars, arrays, functions, depth)?;
                let idx_usize = idx.to_u64()? as usize;
                return arr.index(idx_usize).cloned();
            }
            None
        }
        Expr::Number { .. } | Expr::HexNumber { .. } => {
            if let Some(v) = eval_expr(expr, vars, arrays, functions, depth) {
                Some(EvalValue::Scalar(v))
            } else {
                Some(EvalValue::Expr(Box::new(expr.clone())))
            }
        }
        _ => eval_expr(expr, vars, arrays, functions, depth).map(EvalValue::Scalar),
    }
}

pub fn eval_expr<L: VarLookup>(
    expr: &Expr,
    vars: &L,
    arrays: &HashMap<String, EvalValue>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<BigVal> {
    match expr {
        Expr::Number { value, .. } => {
            // Try i64 first (handles negative literals), then decimal string for large values
            if let Ok(v) = value.parse::<i64>() {
                Some(BigVal::from_i64(v))
            } else {
                let fc = ir_forge::types::FieldConst::from_decimal_str(value)?;
                Some(BigVal::from_field_const(fc))
            }
        }
        Expr::HexNumber { value, .. } => {
            let fc = ir_forge::types::FieldConst::from_hex_str(value)?;
            Some(BigVal::from_field_const(fc))
        }
        Expr::Ident { name, .. } => vars.get_var(name.as_str()),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = eval_expr(lhs, vars, arrays, functions, depth)?;
            let r = eval_expr(rhs, vars, arrays, functions, depth)?;
            eval_binop(l, *op, r)
        }
        Expr::UnaryOp { op, operand, .. } => {
            let val = eval_expr(operand, vars, arrays, functions, depth)?;
            match op {
                ast::UnaryOp::Neg => Some(val.neg()),
                ast::UnaryOp::Not => Some(if val.is_zero() {
                    BigVal::ONE
                } else {
                    BigVal::ZERO
                }),
                ast::UnaryOp::BitNot => Some(val.bitnot()),
            }
        }
        Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            if let Expr::Ident { name, .. } = operand.as_ref() {
                vars.get_var(name.as_str())
            } else {
                None
            }
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let cond = eval_expr(condition, vars, arrays, functions, depth)?;
            if !cond.is_zero() {
                eval_expr(if_true, vars, arrays, functions, depth)
            } else {
                eval_expr(if_false, vars, arrays, functions, depth)
            }
        }
        Expr::Index { .. } => eval_expr_value(expr, vars, arrays, functions, depth)?.as_scalar(),
        Expr::Call { callee, args, .. } => {
            let name = extract_ident_name(callee)?;
            let func = *functions.get(name.as_str())?;
            let arg_vals: Vec<BigVal> = args
                .iter()
                .map(|a| eval_expr(a, vars, arrays, functions, depth))
                .collect::<Option<_>>()?;
            eval_function(func, &arg_vals, functions, depth + 1)
        }
        _ => None,
    }
}

fn eval_binop(l: BigVal, op: ast::BinOp, r: BigVal) -> Option<BigVal> {
    use std::cmp::Ordering;
    match op {
        // Arithmetic in circom `var` context is field arithmetic
        // modulo the scalar field order — division is modular
        // inverse, not integer division. Route through the BN254
        // field path so patterns like Edwards curve `pointAdd`
        // (`(x1*y2 + y1*x2) / (1 + d*x1*...)`) produce the
        // correct coordinate instead of overflowing to -1.
        // `IntDiv` (`\` in circom) still uses truncating integer
        // semantics for the rare cases that need it (loop bounds
        // derived from byte counts etc.).
        ast::BinOp::Add => Some(l.field_add(r)),
        ast::BinOp::Sub => Some(l.field_sub(r)),
        ast::BinOp::Mul => Some(l.field_mul(r)),
        ast::BinOp::Div => l.field_div(r),
        ast::BinOp::IntDiv => l.div(r),
        ast::BinOp::Mod => l.rem(r),
        ast::BinOp::Pow => {
            // Exponent must fit in u32 for practical use
            let exp = r.to_u64()?;
            if exp > u32::MAX as u64 {
                return None;
            }
            Some(l.pow(exp as u32))
        }
        ast::BinOp::Eq => Some(if l == r { BigVal::ONE } else { BigVal::ZERO }),
        ast::BinOp::Neq => Some(if l != r { BigVal::ONE } else { BigVal::ZERO }),
        ast::BinOp::Lt => Some(if l.cmp_field_signed(r) == Ordering::Less {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Le => Some(if l.cmp_field_signed(r) != Ordering::Greater {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Gt => Some(if l.cmp_field_signed(r) == Ordering::Greater {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Ge => Some(if l.cmp_field_signed(r) != Ordering::Less {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::And => Some(if !l.is_zero() && !r.is_zero() {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Or => Some(if !l.is_zero() || !r.is_zero() {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::BitAnd => Some(l.bitand(r)),
        ast::BinOp::BitOr => Some(l.bitor(r)),
        ast::BinOp::BitXor => Some(l.bitxor(r)),
        ast::BinOp::ShiftL => {
            let shift = r.to_u64().unwrap_or(256);
            Some(l.shl(shift.min(255) as u32))
        }
        ast::BinOp::ShiftR => {
            let shift = r.to_u64().unwrap_or(256);
            Some(l.shr(shift.min(255) as u32))
        }
    }
}

fn apply_compound_op(current: BigVal, op: CompoundOp, rhs: BigVal) -> Option<BigVal> {
    match op {
        CompoundOp::Add => Some(current.add(rhs)),
        CompoundOp::Sub => Some(current.sub(rhs)),
        CompoundOp::Mul => Some(current.mul(rhs)),
        CompoundOp::Div | CompoundOp::IntDiv => current.div(rhs),
        CompoundOp::Mod => current.rem(rhs),
        CompoundOp::Pow => {
            let exp = rhs.to_u64()?;
            if exp > u32::MAX as u64 {
                return None;
            }
            Some(current.pow(exp as u32))
        }
        CompoundOp::ShiftL => {
            let shift = rhs.to_u64().unwrap_or(256);
            Some(current.shl(shift.min(255) as u32))
        }
        CompoundOp::ShiftR => {
            let shift = rhs.to_u64().unwrap_or(256);
            Some(current.shr(shift.min(255) as u32))
        }
        CompoundOp::BitAnd => Some(current.bitand(rhs)),
        CompoundOp::BitOr => Some(current.bitor(rhs)),
        CompoundOp::BitXor => Some(current.bitxor(rhs)),
    }
}
