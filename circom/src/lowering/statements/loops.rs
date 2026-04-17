//! Loop lowering: for loops, while loops, and compile-time loop evaluation.
//!
//! Circom for loops must have deterministic bounds for circuit compilation.
//! While loops are only allowed when they touch variables (not signals/components)
//! and are evaluated entirely at compile time.

use std::collections::HashMap;

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitNode, FieldConst, ForRange};

use crate::ast::{self, AssignOp, BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt};

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::utils::{const_eval_u64, BigVal};
use super::arrays::{body_has_component_array_ops, body_references_known_arrays};
use super::targets::extract_target_name;
use super::wiring::PendingComponent;

/// Lower a C-style for loop to a ProveIR `For` node.
///
/// Circom for loops must have deterministic bounds for circuit compilation.
/// We try to extract `for (var i = start; i < end; i++)` patterns.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_for_loop<'a>(
    init: &Stmt,
    condition: &Expr,
    step: &Stmt,
    body: &'a ast::Block,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Extract loop variable and start value from init
    let (var_name, start) = match init {
        Stmt::VarDecl {
            names,
            init: Some(init_expr),
            ..
        } if names.len() == 1 => {
            let start = const_eval_u64(init_expr).ok_or_else(|| {
                LoweringError::with_code(
                    "for loop init must be a compile-time constant",
                    "E208",
                    span,
                )
            })?;
            (names[0].clone(), start)
        }
        // `for (i = 0; ...)` where `i` is already declared via `var i;`
        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            value,
            ..
        } => {
            let name = extract_target_name(target).ok_or_else(|| {
                LoweringError::with_code(
                    "for loop init must assign to a simple variable",
                    "E208",
                    span,
                )
            })?;
            let all = ctx.all_constants(env);
            let start = const_eval_u64(value)
                .or_else(|| super::super::utils::const_eval_with_params(value, &all)?.to_u64())
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "for loop init must be a compile-time constant",
                        "E208",
                        span,
                    )
                })?;
            (name, start)
        }
        _ => {
            return Err(LoweringError::with_code(
                "for loop must use `var i = <const>` or `i = <const>` initialization",
                "E208",
                span,
            ));
        }
    };

    // Extract end bound from condition: `i < end` or `i <= end`
    let bound = extract_loop_bound(condition, &var_name, env).ok_or_else(|| {
        LoweringError::with_code(
            "for loop condition must be `i < <bound>` or `i <= <bound>` \
             where <bound> is a constant or template parameter",
            "E208",
            span,
        )
    })?;

    // Validate step is `i++` or `i += 1`
    validate_loop_step(step, &var_name, span)?;

    // Register loop variable
    env.locals.insert(var_name.clone());

    // Check if body requires lowering-time unrolling:
    // 1. Component array operations (inlining needs concrete names)
    // 2. Known array references (C[i] needs i resolved at lowering time)
    let has_component_array_ops = body_has_component_array_ops(&body.stmts, env);
    let has_known_array_refs = body_references_known_arrays(&body.stmts, env);

    // 3. Mixed signal+var loops: body has signal ops AND var mutations.
    //    Vars like `b`, `a`, `e` in CompConstant change each iteration
    //    and are used as coefficients in signal expressions. These must
    //    be concrete constants, not circuit variables, for valid R1CS.
    let has_mixed_signal_var = body_mixes_signals_and_vars(&body.stmts);

    // Compute the new enum-based classification in parallel. Not yet
    // consumed — the boolean dispatch below is still authoritative.
    // The debug_assert guards that both representations agree.
    let strategy = classify_loop_body(&body.stmts, env);
    debug_assert_eq!(
        strategy,
        match (
            has_mixed_signal_var,
            has_component_array_ops,
            has_known_array_refs,
        ) {
            (true, _, _) => Some(LoopLowering::MixedSignalVar),
            (false, true, _) => Some(LoopLowering::ComponentArrayOps),
            (false, false, true) => Some(LoopLowering::KnownArrayRefs),
            (false, false, false) => None,
        },
        "LoopLowering classification diverged from the legacy boolean flags",
    );

    if has_component_array_ops || has_known_array_refs || has_mixed_signal_var {
        // Resolve bound to a concrete number
        let end = match &bound {
            LoopBound::Literal(n) => *n,
            LoopBound::Capture(name) => {
                let all = ctx.all_constants(env);
                all.get(name).and_then(|fc| fc.to_u64()).ok_or_else(|| {
                    LoweringError::new(
                        format!(
                            "component array loop bound `{name}` must be resolvable \
                                 at compile time"
                        ),
                        span,
                    )
                })?
            }
            LoopBound::Expr(expr) => {
                let all = ctx.all_constants(env);
                super::super::utils::const_eval_with_params(expr, &all)
                    .and_then(|fc| fc.to_u64())
                    .ok_or_else(|| {
                        LoweringError::new(
                            "component array loop bound expression must be resolvable \
                                 at compile time",
                            span,
                        )
                    })?
            }
        };

        // Unroll: for each iteration, set loop var as known constant, lower body.
        // For mixed signal+var loops (e.g. CompConstant), evaluate var-only
        // statements at compile time so vars like `b`, `a`, `e` become concrete
        // constants usable as coefficients in signal expressions.
        let mut eval_vars: HashMap<String, BigVal> = HashMap::new();
        if has_mixed_signal_var {
            // Seed evaluator with all known compile-time values
            for (k, v) in &ctx.param_values {
                eval_vars.insert(k.clone(), BigVal::from_field_const(*v));
            }
            for (k, v) in &env.known_constants {
                eval_vars.insert(k.clone(), BigVal::from_field_const(*v));
            }
        }
        for i in start..end {
            env.known_constants
                .insert(var_name.clone(), FieldConst::from_u64(i));
            if has_mixed_signal_var {
                eval_vars.insert(var_name.clone(), BigVal::from_u64(i));
            }
            for stmt in &body.stmts {
                if has_mixed_signal_var && stmt_is_var_only(stmt) {
                    // Evaluate var-only statements at compile time
                    let functions: HashMap<&str, &crate::ast::FunctionDef> =
                        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();
                    if super::super::utils::try_eval_stmt_in_place(stmt, &mut eval_vars, &functions)
                        .is_some()
                    {
                        // Write back evaluated vars to param_values AND
                        // known_constants so lower_expr emits Const(val)
                        // instead of Var(name) for compile-time vars.
                        //
                        // Do NOT write back the loop variable itself — it is
                        // managed by env.known_constants at the top of each
                        // iteration. Writing it to ctx.param_values would
                        // pollute the persistent map with the iteration-0 value,
                        // which then shadows the correct iteration value (via
                        // `or_insert` in `all_constants`) for all later iterations.
                        for (k, v) in &eval_vars {
                            if k == &var_name {
                                continue;
                            }
                            if !v.is_negative() {
                                let fc = v.to_field_const();
                                ctx.param_values.insert(k.clone(), fc);
                                env.known_constants.insert(k.clone(), fc);
                            }
                        }
                        continue;
                    }
                }
                // Fallthrough: lower the stmt normally. After emission, if
                // we're in the mixed-signal-var eval path (e.g., MiMC7's
                // var `t`) AND the stmt was a plain `Ident = expr`
                // Substitution that fell through here (because its RHS
                // referenced an intermediate signal array element like
                // `t7[i-1]` that wasn't visible to `eval_vars`), keep
                // `env.known_constants` in sync with the newly pushed
                // `Let { name, value }` so subsequent stmts in the same
                // unrolled iteration fold against the up-to-date value
                // instead of the stale one written back by the previous
                // iteration's var-only eval.
                //
                // Gated on `has_mixed_signal_var` because that is the only
                // regime where iteration N's var-only eval may seed
                // `env.known_constants` with a stale value that iteration
                // N+1's fallthrough needs to overwrite. Other unroll
                // regimes (component_array_ops / known_array_refs without
                // mixed_signal_var — e.g. Poseidon's `Mix` template) run
                // CompoundAssign loops that bind a var name to a
                // non-const circuit expression; touching
                // `env.known_constants` there would fold the var to its
                // initial literal and silently zero out the accumulator.
                let pre_len = nodes.len();
                super::lower_stmt(stmt, env, nodes, ctx, pending)?;
                if has_mixed_signal_var {
                    if let Stmt::Substitution {
                        op: AssignOp::Assign,
                        target:
                            Expr::Ident {
                                name: target_name, ..
                            },
                        ..
                    } = stmt
                    {
                        if let Some(CircuitNode::Let { name, value, .. }) =
                            nodes.get(pre_len..).and_then(|new_nodes| new_nodes.last())
                        {
                            if name == target_name {
                                if let Some(fc) = super::super::const_fold::try_fold_const(value) {
                                    env.known_constants.insert(name.clone(), fc);
                                    eval_vars.insert(name.clone(), BigVal::from_field_const(fc));
                                } else {
                                    env.known_constants.remove(name);
                                }
                            }
                        }
                    }
                }
            }
        }
        env.known_constants.remove(&var_name);
        // Clean up vars injected during mixed-loop unrolling
        if has_mixed_signal_var {
            for k in eval_vars.keys() {
                if k != &var_name {
                    env.known_constants.remove(k);
                }
            }
        }

        return Ok(());
    }

    // Lower body — propagate pending so component wirings in loops
    // (like `mux.c[0][i] <== c[i]`) update the parent's pending map.
    // Don't flush remaining at end — that's the parent's job.
    let body_nodes = {
        let mut lowered = Vec::new();
        for stmt in &body.stmts {
            super::lower_stmt(stmt, env, &mut lowered, ctx, pending)?;
        }
        lowered
    };

    let range = match bound {
        LoopBound::Literal(end) => ForRange::Literal { start, end },
        LoopBound::Capture(name) => ForRange::WithCapture {
            start,
            end_capture: name,
        },
        LoopBound::Expr(ast_expr) => {
            // Try to resolve the expression to a constant using known param values
            // (e.g., `nb` from `var nb = nbits(n)` where n is known)
            if let Some(end) =
                super::super::utils::const_eval_with_params(&ast_expr, &ctx.param_values)
                    .and_then(|fc| fc.to_u64())
            {
                ForRange::Literal { start, end }
            } else {
                let circuit_expr = lower_expr(&ast_expr, env, ctx)?;
                ForRange::WithExpr {
                    start,
                    end_expr: Box::new(circuit_expr),
                }
            }
        }
    };

    nodes.push(CircuitNode::For {
        var: var_name,
        range,
        body: body_nodes,
        span: Some(SpanRange::from_span(span)),
    });

    Ok(())
}

/// Check if a list of statements only touches variables (no signals, components,
/// or constraint operations). Used to determine if a while loop can be evaluated
/// at compile time.
pub(super) fn stmts_are_var_only(stmts: &[Stmt]) -> bool {
    stmts.iter().all(stmt_is_var_only)
}

fn stmt_is_var_only(stmt: &Stmt) -> bool {
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
/// is a direct var mutation (no if-branched signal ops).
fn body_mixes_signals_and_vars(stmts: &[Stmt]) -> bool {
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

fn stmt_has_signal_ops(stmt: &Stmt) -> bool {
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

/// Evaluate a while or do-while loop at compile time.
///
/// All variables referenced must be in `env.known_constants` or
/// `ctx.param_values`. Results are written back to `env.known_constants`.
pub(super) fn eval_while_compile_time(
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
                if super::super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions)
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
            let cond = super::super::utils::try_eval_expr(condition, &vars, &functions)
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
            let cond = super::super::utils::try_eval_expr(condition, &vars, &functions)
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
                if super::super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions)
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

/// A loop bound: literal constant, template parameter, or AST expression.
pub(super) enum LoopBound {
    Literal(u64),
    Capture(String),
    /// Expression bound (e.g., `n + 1`) — the AST Expr, lowered in lower_for_loop.
    Expr(Expr),
}

/// Extract the upper bound from a loop condition like `i < N` or `i <= N`.
///
/// `N` can be a numeric literal or a template parameter (capture).
fn extract_loop_bound(condition: &Expr, var_name: &str, env: &LoweringEnv) -> Option<LoopBound> {
    match condition {
        Expr::BinOp { op, lhs, rhs, .. } => {
            // Check that LHS is the loop variable
            if let Expr::Ident { name, .. } = lhs.as_ref() {
                if name != var_name {
                    return None;
                }
            } else {
                return None;
            }

            // Try literal constant first
            if let Some(bound) = const_eval_u64(rhs) {
                return match op {
                    BinOp::Lt => Some(LoopBound::Literal(bound)),
                    BinOp::Le => Some(LoopBound::Literal(bound + 1)),
                    _ => None,
                };
            }

            // Try template parameter (capture)
            if let Expr::Ident { name, .. } = rhs.as_ref() {
                if env.captures.contains(name) {
                    return match op {
                        BinOp::Lt => Some(LoopBound::Capture(name.clone())),
                        // i <= capture: not directly representable as WithCapture
                        // (would need capture + 1). For now, only support <.
                        _ => None,
                    };
                }
            }

            // Expression bound (e.g., `i < n + 1`) — defer lowering to caller
            if matches!(op, BinOp::Lt) {
                return Some(LoopBound::Expr(rhs.as_ref().clone()));
            }

            None
        }
        _ => None,
    }
}

/// Validate that the loop step is `i++` or `i += 1`.
fn validate_loop_step(
    step: &Stmt,
    var_name: &str,
    span: &diagnostics::Span,
) -> Result<(), LoweringError> {
    match step {
        // i++
        Stmt::Expr {
            expr:
                Expr::PostfixOp {
                    op: PostfixOp::Increment,
                    operand,
                    ..
                },
            ..
        } => {
            if let Expr::Ident { name, .. } = operand.as_ref() {
                if name == var_name {
                    return Ok(());
                }
            }
            Err(LoweringError::new(
                format!("for loop step must increment `{var_name}`"),
                span,
            ))
        }
        // i += 1
        Stmt::CompoundAssign {
            target,
            op: CompoundOp::Add,
            value,
            ..
        } => {
            if let Expr::Ident { name, .. } = target {
                if name == var_name {
                    if let Some(1) = const_eval_u64(value) {
                        return Ok(());
                    }
                }
            }
            Err(LoweringError::new(
                format!("for loop step must be `{var_name}++` or `{var_name} += 1`"),
                span,
            ))
        }
        _ => Err(LoweringError::new(
            "for loop step must be `i++` or `i += 1` in circuit context",
            span,
        )),
    }
}

/// Which unroll strategy applies to a given `for` loop body.
///
/// Computed once up-front by `classify_loop_body` and consumed by the
/// dispatch in `lower_for_loop`. Mutually exclusive and exhaustive:
/// exactly one variant applies to any loop we choose to unroll at
/// lowering time.
///
/// `None` from `classify_loop_body` means the loop stays as an
/// IR-level `CircuitNode::For` — the dispatch handles that in the
/// fall-through branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LoopLowering {
    /// Body contains `component c[i] = Template()` or similar, where
    /// component inlining needs a concrete numeric `i` at lowering time.
    ComponentArrayOps,

    /// Body references compile-time arrays (`C[i]`, `M[i][j]`) that
    /// must be resolved before emission.
    KnownArrayRefs,

    /// Body mixes signal statements with `var` mutations
    /// (`CompConstant`, `MiMC7`, `MiMCSponge`). Compile-time vars
    /// drive coefficients in signal expressions, so they need to
    /// be concrete constants, not circuit variables.
    MixedSignalVar,
}

/// Classify a `for` loop body into a [`LoopLowering`] strategy, or
/// return `None` if the body can stay as a `CircuitNode::For` node.
///
/// Priority: `MixedSignalVar` > `ComponentArrayOps` > `KnownArrayRefs`.
/// A mixed-signal-var body can also contain component ops and known-
/// array refs, but it additionally requires the compile-time eval
/// machinery that the other two don't need — picking `MixedSignalVar`
/// when multiple conditions match gives the correct behaviour.
pub(super) fn classify_loop_body(stmts: &[Stmt], env: &LoweringEnv) -> Option<LoopLowering> {
    if body_mixes_signals_and_vars(stmts) {
        return Some(LoopLowering::MixedSignalVar);
    }
    if body_has_component_array_ops(stmts, env) {
        return Some(LoopLowering::ComponentArrayOps);
    }
    if body_references_known_arrays(stmts, env) {
        return Some(LoopLowering::KnownArrayRefs);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::super::test_helpers::parse_program;
    use super::*;
    use crate::ast::Definition;

    fn extract_template_body(src: &str) -> Vec<Stmt> {
        let prog = parse_program(src);
        for def in prog.definitions {
            if let Definition::Template(t) = def {
                return t.body.stmts;
            }
        }
        panic!("expected a template definition");
    }

    #[test]
    fn classify_pure_signal_loop_is_none() {
        // Num2Bits-style loop: signal assign + var mutation (lc1) but
        // no branched signal ops → not MixedSignalVar. Also no
        // component arrays and no known-array refs → None.
        let stmts = extract_template_body(
            r#"
            template T(n) {
                signal input in;
                signal output out[n];
                var lc1 = 0;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    lc1 += out[i];
                }
            }
            "#,
        );
        let for_body = match stmts.iter().find_map(|s| match s {
            Stmt::For { body, .. } => Some(&body.stmts),
            _ => None,
        }) {
            Some(b) => b.clone(),
            None => panic!("expected a for loop"),
        };
        let env = LoweringEnv::new();
        assert_eq!(classify_loop_body(&for_body, &env), None);
    }

    #[test]
    fn classify_mixed_signal_var_wins_over_other_signals() {
        // CompConstant-style: if/else containing signal op + var mutation
        // at same level → MixedSignalVar.
        let stmts = extract_template_body(
            r#"
            template T(n) {
                signal input in[n];
                signal output out[n];
                var b = 1;
                for (var i = 0; i < n; i++) {
                    if (i == 0) {
                        out[i] <== in[i] * b;
                    } else {
                        out[i] <== in[i];
                    }
                    b = b + 1;
                }
            }
            "#,
        );
        let for_body = match stmts.iter().find_map(|s| match s {
            Stmt::For { body, .. } => Some(&body.stmts),
            _ => None,
        }) {
            Some(b) => b.clone(),
            None => panic!("expected a for loop"),
        };
        let env = LoweringEnv::new();
        assert_eq!(
            classify_loop_body(&for_body, &env),
            Some(LoopLowering::MixedSignalVar),
        );
    }
}
