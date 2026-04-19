//! Compile-time expression and statement evaluation.
//!
//! Evaluates Circom expressions and statements at compile time. Scalar
//! state lives in `vars: HashMap<String, BigVal>`; array state (1-D or
//! nested) lives alongside in `arrays: HashMap<String, EvalValue>`.
//! Keeping the two maps separate lets scalar-only callers keep their
//! existing signatures while array-aware callers (e.g. circomlib's
//! `EscalarMulW4Table`) pass a mutable array state through.

use std::collections::HashMap;

use crate::ast::{self, AssignOp, CompoundOp, ElseBranch, Expr, FunctionDef, PostfixOp, Stmt};

use super::bigval::BigVal;
use super::eval_value::{EvalValue, StmtResult};
use super::extract_ident_name;

/// Maximum loop iterations during compile-time function evaluation.
const MAX_EVAL_ITERATIONS: usize = 10_000;

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
        vars.insert(param.clone(), args[i]);
    }

    match eval_stmts(&func.body.stmts, &mut vars, &mut arrays, functions, depth)? {
        StmtResult::Return(val) => Some(val),
        StmtResult::Continue => None,
    }
}

pub(super) fn eval_stmts(
    stmts: &[Stmt],
    vars: &mut HashMap<String, BigVal>,
    arrays: &mut HashMap<String, EvalValue>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<StmtResult> {
    for stmt in stmts {
        match eval_stmt(stmt, vars, arrays, functions, depth)? {
            StmtResult::Continue => {}
            ret @ StmtResult::Return(_) => return Some(ret),
        }
    }
    Some(StmtResult::Continue)
}

pub(super) fn eval_stmt(
    stmt: &Stmt,
    vars: &mut HashMap<String, BigVal>,
    arrays: &mut HashMap<String, EvalValue>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<StmtResult> {
    match stmt {
        Stmt::VarDecl {
            names,
            dimensions,
            init,
            ..
        } => {
            // Array declaration: `var arr[N];` or `var arr[N][M];`.
            // Materialize a zero-filled EvalValue::Array with the
            // declared shape so subsequent indexed writes have a slot
            // to land in.
            if !dimensions.is_empty() {
                let mut dim_values: Vec<usize> = Vec::with_capacity(dimensions.len());
                for d in dimensions {
                    let v = eval_expr(d, vars, arrays, functions, depth)?;
                    dim_values.push(v.to_u64()? as usize);
                }
                let initial = if let Some(expr) = init {
                    eval_expr_value(expr, vars, arrays, functions, depth)?
                } else {
                    build_zero_array(&dim_values)
                };
                for name in names {
                    arrays.insert(name.clone(), initial.clone());
                }
                return Some(StmtResult::Continue);
            }

            // Scalar (or array-valued scalar-shaped) var.
            match init {
                Some(expr) => {
                    // Prefer a value-typed eval so Ident-to-array
                    // aliasing (`var dbl = base;` with `base` an array
                    // template param) propagates correctly.
                    let val = eval_expr_value(expr, vars, arrays, functions, depth)?;
                    match val {
                        EvalValue::Scalar(v) => {
                            for name in names {
                                vars.insert(name.clone(), v);
                                arrays.remove(name);
                            }
                        }
                        EvalValue::Array(_) => {
                            for name in names {
                                arrays.insert(name.clone(), val.clone());
                                vars.remove(name);
                            }
                        }
                        EvalValue::Expr(_) => return None,
                    }
                }
                None => {
                    for name in names {
                        vars.insert(name.clone(), BigVal::ZERO);
                        arrays.remove(name);
                    }
                }
            }
            Some(StmtResult::Continue)
        }

        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            value,
            ..
        } => {
            // Indexed assign: `arr[i] = expr` or `arr[i][j] = expr`.
            // Walk the chain of Index expressions back to the base
            // Ident, evaluate each index, and mutate the nested
            // EvalValue::Array in `arrays`.
            if let Expr::Index { .. } = target {
                let (base_name, indices) = unwrap_indexed(target)?;
                let mut idx_usizes: Vec<usize> = Vec::with_capacity(indices.len());
                for idx_expr in &indices {
                    let v = eval_expr(idx_expr, vars, arrays, functions, depth)?;
                    idx_usizes.push(v.to_u64()? as usize);
                }
                let rhs = eval_expr_value(value, vars, arrays, functions, depth)?;
                let slot = arrays.get_mut(base_name)?;
                assign_nested(slot, &idx_usizes, rhs)?;
                return Some(StmtResult::Continue);
            }

            if let Expr::Ident { name, .. } = target {
                let val = eval_expr_value(value, vars, arrays, functions, depth)?;
                match val {
                    EvalValue::Scalar(v) => {
                        vars.insert(name.clone(), v);
                        arrays.remove(name);
                    }
                    EvalValue::Array(_) => {
                        arrays.insert(name.clone(), val);
                        vars.remove(name);
                    }
                    EvalValue::Expr(_) => return None,
                }
                Some(StmtResult::Continue)
            } else {
                None
            }
        }

        Stmt::CompoundAssign {
            target, op, value, ..
        } => {
            if let Expr::Ident { name, .. } = target {
                let current = *vars.get(name.as_str())?;
                let rhs = eval_expr(value, vars, arrays, functions, depth)?;
                let result = apply_compound_op(current, *op, rhs)?;
                vars.insert(name.clone(), result);
                Some(StmtResult::Continue)
            } else {
                None
            }
        }

        Stmt::Expr { expr, .. } => {
            if let Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } = expr {
                if let Expr::Ident { name, .. } = operand.as_ref() {
                    let current = *vars.get(name.as_str())?;
                    match op {
                        PostfixOp::Increment => {
                            vars.insert(name.clone(), current.add(BigVal::ONE));
                        }
                        PostfixOp::Decrement => {
                            vars.insert(name.clone(), current.sub(BigVal::ONE));
                        }
                    }
                    return Some(StmtResult::Continue);
                }
            }
            eval_expr(expr, vars, arrays, functions, depth)?;
            Some(StmtResult::Continue)
        }

        Stmt::While {
            condition, body, ..
        } => {
            for _ in 0..MAX_EVAL_ITERATIONS {
                let cond = eval_expr(condition, vars, arrays, functions, depth)?;
                if cond.is_zero() {
                    return Some(StmtResult::Continue);
                }
                match eval_stmts(&body.stmts, vars, arrays, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
            }
            None
        }

        Stmt::DoWhile {
            condition, body, ..
        } => {
            for _ in 0..MAX_EVAL_ITERATIONS {
                match eval_stmts(&body.stmts, vars, arrays, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
                let cond = eval_expr(condition, vars, arrays, functions, depth)?;
                if cond.is_zero() {
                    return Some(StmtResult::Continue);
                }
            }
            None
        }

        Stmt::For {
            init,
            condition,
            step,
            body,
            ..
        } => {
            eval_stmt(init, vars, arrays, functions, depth)?;
            for _ in 0..MAX_EVAL_ITERATIONS {
                let cond = eval_expr(condition, vars, arrays, functions, depth)?;
                if cond.is_zero() {
                    return Some(StmtResult::Continue);
                }
                match eval_stmts(&body.stmts, vars, arrays, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
                eval_stmt(step, vars, arrays, functions, depth)?;
            }
            None
        }

        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            let cond = eval_expr(condition, vars, arrays, functions, depth)?;
            if !cond.is_zero() {
                eval_stmts(&then_body.stmts, vars, arrays, functions, depth)
            } else if let Some(branch) = else_body {
                match branch {
                    ElseBranch::Block(block) => {
                        eval_stmts(&block.stmts, vars, arrays, functions, depth)
                    }
                    ElseBranch::IfElse(stmt) => eval_stmt(stmt, vars, arrays, functions, depth),
                }
            } else {
                Some(StmtResult::Continue)
            }
        }

        Stmt::Return { value, .. } => {
            let val = eval_expr_value(value, vars, arrays, functions, depth)?;
            Some(StmtResult::Return(val))
        }

        Stmt::Log { .. } | Stmt::Assert { .. } => Some(StmtResult::Continue),

        Stmt::Block(block) => eval_stmts(&block.stmts, vars, arrays, functions, depth),

        _ => None,
    }
}

/// Build a zero-filled nested EvalValue::Array for the given shape.
///
/// `[16, 2]` produces an Array of 16 Arrays of 2 Scalar(0).
fn build_zero_array(dims: &[usize]) -> EvalValue {
    if dims.is_empty() {
        return EvalValue::Scalar(BigVal::ZERO);
    }
    let inner = build_zero_array(&dims[1..]);
    EvalValue::Array(vec![inner; dims[0]])
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

/// Write `rhs` into the nested EvalValue at `indices`. Returns `None`
/// if an intermediate slot is not an Array or an index is OOB.
fn assign_nested(slot: &mut EvalValue, indices: &[usize], rhs: EvalValue) -> Option<()> {
    if indices.is_empty() {
        *slot = rhs;
        return Some(());
    }
    let EvalValue::Array(elems) = slot else {
        return None;
    };
    let inner = elems.get_mut(indices[0])?;
    assign_nested(inner, &indices[1..], rhs)
}

/// Evaluate an expression to an [`EvalValue`] (scalar, array, or raw expr).
pub(super) fn eval_expr_value(
    expr: &Expr,
    vars: &HashMap<String, BigVal>,
    arrays: &HashMap<String, EvalValue>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<EvalValue> {
    match expr {
        Expr::Ident { name, .. } => {
            if let Some(val) = arrays.get(name.as_str()) {
                return Some(val.clone());
            }
            vars.get(name.as_str()).copied().map(EvalValue::Scalar)
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

pub fn eval_expr(
    expr: &Expr,
    vars: &HashMap<String, BigVal>,
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
                let fc = ir::prove_ir::types::FieldConst::from_decimal_str(value)?;
                Some(BigVal::from_field_const(fc))
            }
        }
        Expr::HexNumber { value, .. } => {
            let fc = ir::prove_ir::types::FieldConst::from_hex_str(value)?;
            Some(BigVal::from_field_const(fc))
        }
        Expr::Ident { name, .. } => vars.get(name.as_str()).copied(),
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
                vars.get(name.as_str()).copied()
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
        ast::BinOp::Add => Some(l.add(r)),
        ast::BinOp::Sub => Some(l.sub(r)),
        ast::BinOp::Mul => Some(l.mul(r)),
        ast::BinOp::Div | ast::BinOp::IntDiv => l.div(r),
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
        ast::BinOp::Lt => Some(if l.cmp_signed(r) == Ordering::Less {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Le => Some(if l.cmp_signed(r) != Ordering::Greater {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Gt => Some(if l.cmp_signed(r) == Ordering::Greater {
            BigVal::ONE
        } else {
            BigVal::ZERO
        }),
        ast::BinOp::Ge => Some(if l.cmp_signed(r) != Ordering::Less {
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
