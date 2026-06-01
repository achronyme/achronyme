use super::*;

/// Check if a list of statements only touches variables (no signals, components,
/// or constraint operations). Used to determine if a while loop can be evaluated
/// at compile time.
pub(in crate::lowering::statements) fn stmts_are_var_only(stmts: &[Stmt]) -> bool {
    stmts.iter().all(stmt_is_var_only)
}

pub(super) fn stmt_is_var_only(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::VarDecl { .. } => true,
        Stmt::CompoundAssign { .. } => true,
        Stmt::Expr { .. } => true,
        Stmt::Substitution {
            op: AssignOp::Assign,
            ..
        } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            stmts_are_var_only(&then_body.stmts)
                && match else_body {
                    Some(ElseBranch::Block(b)) => stmts_are_var_only(&b.stmts),
                    Some(ElseBranch::IfElse(s)) => stmt_is_var_only(s),
                    None => true,
                }
        }
        Stmt::For { body, .. } => stmts_are_var_only(&body.stmts),
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => stmts_are_var_only(&body.stmts),
        Stmt::Block(b) => stmts_are_var_only(&b.stmts),
        Stmt::Return { .. } => true,
        Stmt::Assert { .. } => true,
        Stmt::Log { .. } => true,
        Stmt::Error { .. } => false,
        // Signal ops, component decls, constraint ops → not var-only
        Stmt::SignalDecl { .. } | Stmt::ComponentDecl { .. } | Stmt::ConstraintEq { .. } => false,
        Stmt::Substitution { .. } => false, // <==, <--, ==>, --> ops
    }
}

/// Evaluate a while or do-while loop at compile time.
///
/// All variables referenced must be in `env.known_constants` or
/// `ctx.param_values`. Results are written back to `env.known_constants`.
pub(in crate::lowering::statements) fn eval_while_compile_time(
    condition: &Expr,
    body_stmts: &[Stmt],
    do_while: bool,
    env: &mut LoweringEnv,
    ctx: &LoweringContext,
    span: &diagnostics::Span,
) -> Result<(), LoweringError> {
    // Build evaluation environment from known constants + param values
    let mut vars: HashMap<String, BigVal> = HashMap::new();
    for (k, v) in &env.known_constants {
        vars.insert(k.clone(), BigVal::from_field_const(*v));
    }
    for (k, v) in &ctx.param_values {
        vars.insert(k.clone(), BigVal::from_field_const(*v));
    }

    let functions: HashMap<&str, &ast::FunctionDef> =
        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();

    const MAX_WHILE_ITERS: usize = 10_000;

    if do_while {
        for _ in 0..MAX_WHILE_ITERS {
            for stmt in body_stmts {
                if crate::lowering::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions)
                    .is_none()
                {
                    return Err(LoweringError::with_code(
                        "do-while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        "E209",
                        span,
                    ));
                }
            }
            let cond = crate::lowering::utils::try_eval_expr(condition, &vars, &functions)
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "do-while loop condition could not be evaluated at compile time",
                        "E209",
                        span,
                    )
                })?;
            if cond.is_zero() {
                // Write back computed vars
                for (k, v) in &vars {
                    if !v.is_negative() {
                        env.known_constants.insert(k.clone(), v.to_field_const());
                    }
                }
                return Ok(());
            }
        }
    } else {
        for _ in 0..MAX_WHILE_ITERS {
            let cond = crate::lowering::utils::try_eval_expr(condition, &vars, &functions)
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "while loop condition could not be evaluated at compile time",
                        "E209",
                        span,
                    )
                })?;
            if cond.is_zero() {
                // Write back computed vars
                for (k, v) in &vars {
                    if !v.is_negative() {
                        env.known_constants.insert(k.clone(), v.to_field_const());
                    }
                }
                return Ok(());
            }
            for stmt in body_stmts {
                if crate::lowering::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions)
                    .is_none()
                {
                    return Err(LoweringError::with_code(
                        "while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        "E209",
                        span,
                    ));
                }
            }
        }
    }

    Err(LoweringError::with_code(
        format!(
            "while loop did not terminate within {MAX_WHILE_ITERS} iterations \
             during compile-time evaluation"
        ),
        "E209",
        span,
    ))
}
