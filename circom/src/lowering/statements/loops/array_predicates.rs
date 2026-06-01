use super::*;

/// Check if a loop body contains if/else branches with signal operations
/// inside AND var mutations outside those branches.
///
/// This detects the CompConstant pattern:
/// ```circom
/// if ((cmsb==0)&&(clsb==0)) {
///     parts[i] <== -b*smsb*slsb + b*smsb + b*slsb;  // signal op inside if
/// } ...
/// b = b - e;  // var mutation outside if
/// ```
///
/// These loops MUST be unrolled because:
/// 1. The if/else condition depends on compile-time vars → needs constant folding
/// 2. The vars used as coefficients must be concrete constants for valid R1CS
///
/// Does NOT match simple loops like Num2Bits where `lc1 += out[i] * 2**i`
/// `true` if any statement (possibly nested in if/for/while/block) is
/// an indexed `=` Substitution or compound-assign whose target's base
/// identifier is registered in `env.local_var_arrays`.
///
/// Filtering by `env.local_var_arrays` discriminates from component-
/// array element instantiation (`muls[i] = Template()`), which shares
/// the same `Substitution { op: Assign, target: Index{...} }` outer
/// shape but uses `env.component_arrays`. The classifier still routes
/// component-array bodies to `ComponentArrayOps` via the fall-through.
pub(super) fn body_has_local_var_array_indexed_writes(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_local_var_array_indexed_write(s, env))
}

/// Shape-only variant of `body_has_local_var_array_indexed_writes`:
/// fires on any `=` or compound assign whose target is `Index{...}`,
/// without checking `env.local_var_arrays`. The memoize gate uses
/// this because it has no `env` in scope and the goal there is to
/// disqualify *any* indexed assignment shape — component-array
/// instantiations, var-array shadows, and signal-array writes through
/// component fields all break the capture-once / replay-many
/// invariant the memoize path relies on.
pub(super) fn body_has_indexed_assign_shape(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_indexed_assign_shape)
}

pub(super) fn stmt_has_indexed_assign_shape(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            ..
        } => matches!(target, Expr::Index { .. }),
        Stmt::CompoundAssign { target, .. } => matches!(target, Expr::Index { .. }),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.stmts.iter().any(stmt_has_indexed_assign_shape)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_indexed_assign_shape),
                    Some(ElseBranch::IfElse(s)) => stmt_has_indexed_assign_shape(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_indexed_assign_shape),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_indexed_assign_shape)
        }
        _ => false,
    }
}

pub(super) fn stmt_has_local_var_array_indexed_write(stmt: &Stmt, env: &LoweringEnv) -> bool {
    match stmt {
        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            ..
        } => is_local_var_array_indexed(target, env),
        Stmt::CompoundAssign { target, .. } => is_local_var_array_indexed(target, env),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_has_local_var_array_indexed_write(s, env))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_local_var_array_indexed_write(s, env)),
                    Some(ElseBranch::IfElse(s)) => stmt_has_local_var_array_indexed_write(s, env),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_local_var_array_indexed_write(s, env)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_local_var_array_indexed_write(s, env)),
        _ => false,
    }
}

/// `true` if `expr` is an `Index` chain rooted at an `Ident` whose
/// name is registered in `env.local_var_arrays`. Used to filter writes
/// and reads that touch a template-local `var` array slot.
pub(super) fn is_local_var_array_indexed(expr: &Expr, env: &LoweringEnv) -> bool {
    let mut cursor = expr;
    while let Expr::Index { object, .. } = cursor {
        cursor = object;
    }
    matches!(cursor, Expr::Ident { name, .. } if env.local_var_arrays.contains(name))
}

/// `true` if any statement (possibly nested) reads through an
/// `Index` chain whose base identifier is in `env.local_var_arrays`.
/// Reads need a concrete iter constant for the same reason writes do —
/// `env.resolve_array_element` resolves to a flat slot name only when
/// the index const-folds, and a phantom `ArrayIndex` against a
/// compile-time-only base would fail at instantiate.
pub(super) fn body_has_local_var_array_indexed_reads(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_local_var_array_indexed_read(s, env))
}

pub(super) fn stmt_has_local_var_array_indexed_read(stmt: &Stmt, env: &LoweringEnv) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_reads_local_var_array(target, env) || expr_reads_local_var_array(value, env)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_reads_local_var_array(target, env) || expr_reads_local_var_array(value, env)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_reads_local_var_array(lhs, env) || expr_reads_local_var_array(rhs, env)
        }
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .is_some_and(|v| expr_reads_local_var_array(v, env)),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_reads_local_var_array(condition, env)
                || then_body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_local_var_array_indexed_read(s, env))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_local_var_array_indexed_read(s, env)),
                    Some(ElseBranch::IfElse(s)) => stmt_has_local_var_array_indexed_read(s, env),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_local_var_array_indexed_read(s, env)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_local_var_array_indexed_read(s, env)),
        _ => false,
    }
}

pub(super) fn expr_reads_local_var_array(expr: &Expr, env: &LoweringEnv) -> bool {
    match expr {
        Expr::Index { object, index, .. } => {
            is_local_var_array_indexed(expr, env)
                || expr_reads_local_var_array(object, env)
                || expr_reads_local_var_array(index, env)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            expr_reads_local_var_array(lhs, env) || expr_reads_local_var_array(rhs, env)
        }
        Expr::UnaryOp { operand, .. } => expr_reads_local_var_array(operand, env),
        Expr::Call { args, .. } => args.iter().any(|a| expr_reads_local_var_array(a, env)),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_reads_local_var_array(condition, env)
                || expr_reads_local_var_array(if_true, env)
                || expr_reads_local_var_array(if_false, env)
        }
        Expr::DotAccess { object, .. } => expr_reads_local_var_array(object, env),
        Expr::Tuple { elements, .. } | Expr::ArrayLit { elements, .. } => {
            elements.iter().any(|e| expr_reads_local_var_array(e, env))
        }
        _ => false,
    }
}

pub(super) fn body_mixes_signals_and_vars(stmts: &[Stmt]) -> bool {
    // Pattern: if/else containing signal ops + var mutations at the same level
    let has_branched_signal_ops = stmts.iter().any(|s| match s {
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            let then_has = then_body.stmts.iter().any(stmt_has_signal_ops);
            let else_has = match else_body {
                Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_signal_ops),
                Some(ElseBranch::IfElse(s)) => stmt_has_signal_ops(s),
                None => false,
            };
            then_has || else_has
        }
        _ => false,
    });
    let has_var_mutations = stmts.iter().any(|s| {
        matches!(
            s,
            Stmt::CompoundAssign { .. }
                | Stmt::Substitution {
                    op: AssignOp::Assign,
                    target: Expr::Ident { .. },
                    ..
                }
        )
    });
    has_branched_signal_ops && has_var_mutations
}

pub(super) fn stmt_has_signal_ops(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution {
            op:
                AssignOp::ConstraintAssign
                | AssignOp::SignalAssign
                | AssignOp::RConstraintAssign
                | AssignOp::RSignalAssign,
            ..
        } => true,
        Stmt::ConstraintEq { .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.stmts.iter().any(stmt_has_signal_ops)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_signal_ops),
                    Some(ElseBranch::IfElse(s)) => stmt_has_signal_ops(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_signal_ops),
        _ => false,
    }
}
