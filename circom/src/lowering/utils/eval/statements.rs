use std::collections::HashMap;

use crate::ast::{AssignOp, ElseBranch, Expr, FunctionDef, PostfixOp, Stmt};

use super::super::bigval::BigVal;
use super::super::eval_value::{EvalValue, StmtResult};
use super::{apply_compound_op, eval_expr, eval_expr_value, unwrap_indexed, MAX_EVAL_ITERATIONS};

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

pub(in crate::lowering::utils) fn eval_stmt(
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
