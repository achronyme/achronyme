//! Compile-time expression and statement evaluation.
//!
//! Evaluates Circom expressions and statements at compile time using concrete
//! i64 values. Supports arithmetic, comparisons, control flow (if/else, for,
//! while), function calls, and array construction.

use std::collections::HashMap;

use crate::ast::{self, AssignOp, CompoundOp, ElseBranch, Expr, FunctionDef, PostfixOp, Stmt};

use super::eval_value::{EvalValue, StmtResult};
use super::extract_ident_name;

/// Maximum loop iterations during compile-time function evaluation.
const MAX_EVAL_ITERATIONS: usize = 10_000;

/// Maximum recursion depth for compile-time evaluation.
pub(super) const MAX_EVAL_DEPTH: usize = 64;

/// Evaluate a Circom function body at compile time with concrete i64 arguments.
///
/// Returns `Some(result)` if the function can be fully evaluated to a constant,
/// `None` if evaluation fails.
pub fn eval_function(
    func: &FunctionDef,
    args: &[i64],
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<i64> {
    eval_function_to_value(func, args, functions, depth)?.as_scalar()
}

/// Evaluate a Circom function body at compile time, returning scalar or array.
///
/// This is the array-aware version of [`eval_function`].
pub fn eval_function_to_value(
    func: &FunctionDef,
    args: &[i64],
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<EvalValue> {
    if depth > MAX_EVAL_DEPTH {
        return None;
    }
    if args.len() != func.params.len() {
        return None;
    }

    let mut vars: HashMap<String, i64> = HashMap::new();
    for (param, &val) in func.params.iter().zip(args) {
        vars.insert(param.clone(), val);
    }

    match eval_stmts(&func.body.stmts, &mut vars, functions, depth)? {
        StmtResult::Return(val) => Some(val),
        StmtResult::Continue => None,
    }
}

pub(super) fn eval_stmts(
    stmts: &[Stmt],
    vars: &mut HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<StmtResult> {
    for stmt in stmts {
        match eval_stmt(stmt, vars, functions, depth)? {
            StmtResult::Continue => {}
            ret @ StmtResult::Return(_) => return Some(ret),
        }
    }
    Some(StmtResult::Continue)
}

pub(super) fn eval_stmt(
    stmt: &Stmt,
    vars: &mut HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<StmtResult> {
    match stmt {
        Stmt::VarDecl { names, init, .. } => {
            let val = match init {
                Some(expr) => eval_expr_i64(expr, vars, functions, depth)?,
                None => 0,
            };
            for name in names {
                vars.insert(name.clone(), val);
            }
            Some(StmtResult::Continue)
        }

        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            value,
            ..
        } => {
            if let Expr::Ident { name, .. } = target {
                let val = eval_expr_i64(value, vars, functions, depth)?;
                vars.insert(name.clone(), val);
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
                let rhs = eval_expr_i64(value, vars, functions, depth)?;
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
                            vars.insert(name.clone(), current + 1);
                        }
                        PostfixOp::Decrement => {
                            vars.insert(name.clone(), current - 1);
                        }
                    }
                    return Some(StmtResult::Continue);
                }
            }
            eval_expr_i64(expr, vars, functions, depth)?;
            Some(StmtResult::Continue)
        }

        Stmt::While {
            condition, body, ..
        } => {
            for _ in 0..MAX_EVAL_ITERATIONS {
                let cond = eval_expr_i64(condition, vars, functions, depth)?;
                if cond == 0 {
                    return Some(StmtResult::Continue);
                }
                match eval_stmts(&body.stmts, vars, functions, depth)? {
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
                match eval_stmts(&body.stmts, vars, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
                let cond = eval_expr_i64(condition, vars, functions, depth)?;
                if cond == 0 {
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
            eval_stmt(init, vars, functions, depth)?;
            for _ in 0..MAX_EVAL_ITERATIONS {
                let cond = eval_expr_i64(condition, vars, functions, depth)?;
                if cond == 0 {
                    return Some(StmtResult::Continue);
                }
                match eval_stmts(&body.stmts, vars, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
                eval_stmt(step, vars, functions, depth)?;
            }
            None
        }

        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            let cond = eval_expr_i64(condition, vars, functions, depth)?;
            if cond != 0 {
                eval_stmts(&then_body.stmts, vars, functions, depth)
            } else if let Some(branch) = else_body {
                match branch {
                    ElseBranch::Block(block) => eval_stmts(&block.stmts, vars, functions, depth),
                    ElseBranch::IfElse(stmt) => eval_stmt(stmt, vars, functions, depth),
                }
            } else {
                Some(StmtResult::Continue)
            }
        }

        Stmt::Return { value, .. } => {
            let val = eval_expr_value(value, vars, functions, depth)?;
            Some(StmtResult::Return(val))
        }

        Stmt::Log { .. } | Stmt::Assert { .. } => Some(StmtResult::Continue),

        Stmt::Block(block) => eval_stmts(&block.stmts, vars, functions, depth),

        _ => None,
    }
}

/// Evaluate an expression to an [`EvalValue`] (scalar, array, or raw expr).
pub(super) fn eval_expr_value(
    expr: &Expr,
    vars: &HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<EvalValue> {
    match expr {
        Expr::ArrayLit { elements, .. } => {
            let vals: Vec<EvalValue> = elements
                .iter()
                .map(|e| {
                    eval_expr_value(e, vars, functions, depth)
                        .or_else(|| Some(EvalValue::Expr(Box::new(e.clone()))))
                })
                .collect::<Option<_>>()?;
            Some(EvalValue::Array(vals))
        }
        Expr::Call { callee, args, .. } => {
            let name = extract_ident_name(callee)?;
            let func = *functions.get(name.as_str())?;
            let arg_vals: Vec<i64> = args
                .iter()
                .map(|a| eval_expr_i64(a, vars, functions, depth))
                .collect::<Option<_>>()?;
            eval_function_to_value(func, &arg_vals, functions, depth + 1)
        }
        Expr::Index { object, index, .. } => {
            let arr = eval_expr_value(object, vars, functions, depth)?;
            let idx = eval_expr_i64(index, vars, functions, depth)?;
            arr.index(idx as usize).cloned()
        }
        Expr::Number { .. } | Expr::HexNumber { .. } => {
            if let Some(v) = eval_expr_i64(expr, vars, functions, depth) {
                Some(EvalValue::Scalar(v))
            } else {
                Some(EvalValue::Expr(Box::new(expr.clone())))
            }
        }
        _ => eval_expr_i64(expr, vars, functions, depth).map(EvalValue::Scalar),
    }
}

pub fn eval_expr_i64(
    expr: &Expr,
    vars: &HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<i64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            i64::from_str_radix(hex, 16).ok()
        }
        Expr::Ident { name, .. } => vars.get(name.as_str()).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = eval_expr_i64(lhs, vars, functions, depth)?;
            let r = eval_expr_i64(rhs, vars, functions, depth)?;
            eval_binop_i64(l, *op, r)
        }
        Expr::UnaryOp { op, operand, .. } => {
            let val = eval_expr_i64(operand, vars, functions, depth)?;
            match op {
                ast::UnaryOp::Neg => Some(-val),
                ast::UnaryOp::Not => Some(if val == 0 { 1 } else { 0 }),
                ast::UnaryOp::BitNot => Some(!val),
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
            let cond = eval_expr_i64(condition, vars, functions, depth)?;
            if cond != 0 {
                eval_expr_i64(if_true, vars, functions, depth)
            } else {
                eval_expr_i64(if_false, vars, functions, depth)
            }
        }
        Expr::Call { callee, args, .. } => {
            let name = extract_ident_name(callee)?;
            let func = *functions.get(name.as_str())?;
            let arg_vals: Vec<i64> = args
                .iter()
                .map(|a| eval_expr_i64(a, vars, functions, depth))
                .collect::<Option<_>>()?;
            eval_function(func, &arg_vals, functions, depth + 1)
        }
        _ => None,
    }
}

fn eval_binop_i64(l: i64, op: ast::BinOp, r: i64) -> Option<i64> {
    match op {
        ast::BinOp::Add => Some(l.wrapping_add(r)),
        ast::BinOp::Sub => Some(l.wrapping_sub(r)),
        ast::BinOp::Mul => Some(l.wrapping_mul(r)),
        ast::BinOp::Div | ast::BinOp::IntDiv => {
            if r != 0 { Some(l / r) } else { None }
        }
        ast::BinOp::Mod => {
            if r != 0 { Some(l % r) } else { None }
        }
        ast::BinOp::Pow => Some(l.pow(r as u32)),
        ast::BinOp::Eq => Some(if l == r { 1 } else { 0 }),
        ast::BinOp::Neq => Some(if l != r { 1 } else { 0 }),
        ast::BinOp::Lt => Some(if l < r { 1 } else { 0 }),
        ast::BinOp::Le => Some(if l <= r { 1 } else { 0 }),
        ast::BinOp::Gt => Some(if l > r { 1 } else { 0 }),
        ast::BinOp::Ge => Some(if l >= r { 1 } else { 0 }),
        ast::BinOp::And => Some(if l != 0 && r != 0 { 1 } else { 0 }),
        ast::BinOp::Or => Some(if l != 0 || r != 0 { 1 } else { 0 }),
        ast::BinOp::BitAnd => Some(l & r),
        ast::BinOp::BitOr => Some(l | r),
        ast::BinOp::BitXor => Some(l ^ r),
        ast::BinOp::ShiftL => Some(l << (r & 63)),
        ast::BinOp::ShiftR => Some(l >> (r & 63)),
    }
}

fn apply_compound_op(current: i64, op: CompoundOp, rhs: i64) -> Option<i64> {
    match op {
        CompoundOp::Add => Some(current.wrapping_add(rhs)),
        CompoundOp::Sub => Some(current.wrapping_sub(rhs)),
        CompoundOp::Mul => Some(current.wrapping_mul(rhs)),
        CompoundOp::Div | CompoundOp::IntDiv => {
            if rhs != 0 { Some(current / rhs) } else { None }
        }
        CompoundOp::Mod => {
            if rhs != 0 { Some(current % rhs) } else { None }
        }
        CompoundOp::Pow => Some(current.pow(rhs as u32)),
        CompoundOp::ShiftL => Some(current << (rhs & 63)),
        CompoundOp::ShiftR => Some(current >> (rhs & 63)),
        CompoundOp::BitAnd => Some(current & rhs),
        CompoundOp::BitOr => Some(current | rhs),
        CompoundOp::BitXor => Some(current ^ rhs),
    }
}
