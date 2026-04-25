//! Loop lowering: for loops, while loops, and compile-time loop evaluation.
//!
//! Circom for loops must have deterministic bounds for circuit compilation.
//! While loops are only allowed when they touch variables (not signals/components)
//! and are evaluated entirely at compile time.

use std::collections::HashMap;

use diagnostics::SpanRange;
use ir_forge::types::{CircuitNode, FieldConst, ForRange};

use crate::ast::{self, AssignOp, BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt};

use super::super::compile_time::CompileTimeEnv;
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
            // Fall back to param-aware evaluation for the common pattern
            // `for (var k = nBits+1; ...)` where `nBits` is a template
            // parameter — circomlib SHA256 uses this in padding loops.
            let all = ctx.all_constants(env);
            let start = const_eval_u64(init_expr)
                .or_else(|| super::super::utils::const_eval_with_params(init_expr, &all)?.to_u64())
                .ok_or_else(|| {
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

    // Classify the body to decide whether to unroll at lowering time
    // and — if so — which strategy governs the unroll.
    let Some(strategy) = classify_loop_body(&body.stmts, env, &var_name) else {
        return emit_for_node(var_name, bound, start, body, span, env, nodes, ctx, pending);
    };

    let is_mixed = strategy == LoopLowering::MixedSignalVar;
    let end = resolve_bound_to_u64(&bound, env, ctx, span)?;

    // Unroll: for each iteration, set loop var as known constant, lower body.
    // For mixed signal+var loops (e.g. CompConstant), evaluate var-only
    // statements at compile time so vars like `b`, `a`, `e` become concrete
    // constants usable as coefficients in signal expressions.
    //
    // `CompileTimeEnv` is the single source of truth for the compile-time
    // var snapshot. For non-mixed strategies it stays empty — that path
    // drives `env.known_constants` directly and never consults `cte`.
    let mut cte = if is_mixed {
        CompileTimeEnv::from_constants(&ctx.param_values, &env.known_constants)
    } else {
        CompileTimeEnv::new()
    };
    for i in start..end {
        env.known_constants
            .insert(var_name.clone(), FieldConst::from_u64(i));
        if is_mixed {
            cte.insert(var_name.clone(), BigVal::from_u64(i));
        }
        for stmt in &body.stmts {
            if is_mixed && stmt_is_var_only(stmt) && try_eval_at_compile_time(stmt, &mut cte, ctx) {
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
                for (k, fc) in cte.field_const_iter() {
                    if k == &var_name {
                        continue;
                    }
                    ctx.param_values.insert(k.clone(), fc);
                    env.known_constants.insert(k.clone(), fc);
                }
                continue;
            }
            // Fallthrough: lower the stmt normally. After emission, if
            // we're in the mixed-signal-var eval path (e.g., MiMC7's
            // var `t`) AND the stmt was a plain `Ident = expr`
            // Substitution that fell through here (because its RHS
            // referenced an intermediate signal array element like
            // `t7[i-1]` that wasn't visible to `cte`), keep
            // `env.known_constants` in sync with the newly pushed
            // `Let { name, value }` so subsequent stmts in the same
            // unrolled iteration fold against the up-to-date value
            // instead of the stale one written back by the previous
            // iteration's var-only eval.
            //
            // Gated on MixedSignalVar because that is the only regime
            // where iteration N's var-only eval may seed
            // `env.known_constants` with a stale value that iteration
            // N+1's fallthrough needs to overwrite. Other unroll
            // regimes (ComponentArrayOps / KnownArrayRefs — e.g.
            // Poseidon's `Mix` template) run CompoundAssign loops that
            // bind a var name to a non-const circuit expression;
            // touching `env.known_constants` there would fold the var
            // to its initial literal and silently zero out the
            // accumulator.
            let pre_len = nodes.len();
            super::lower_stmt(stmt, env, nodes, ctx, pending)?;
            if is_mixed {
                sync_post_emission(stmt, nodes, pre_len, &mut cte, env);
            }
        }
    }
    env.known_constants.remove(&var_name);
    // Clean up vars injected during mixed-loop unrolling
    if is_mixed {
        for name in cte.var_names() {
            if name != &var_name {
                env.known_constants.remove(name);
            }
        }
    }

    Ok(())
}

/// Evaluate a var-only statement at compile time inside
/// `CompileTimeEnv`. Returns `true` iff the stmt's effect was
/// captured (the loop unroll then skips the real `lower_stmt` call
/// for that stmt).
fn try_eval_at_compile_time(stmt: &Stmt, cte: &mut CompileTimeEnv, ctx: &LoweringContext) -> bool {
    let functions: HashMap<&str, &crate::ast::FunctionDef> =
        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();
    super::super::utils::try_eval_stmt_in_place(stmt, cte.as_bigval_map_mut(), &functions).is_some()
}

/// If the most-recently-emitted node was a const-foldable `Let`
/// targeting the same name as the AST `Substitution`, mirror that
/// binding into `env.known_constants` and `cte` so the next
/// iteration's compile-time eval reads the fresh value. Handles the
/// MiMC7 `t = t7[i-1] + c[i]` case.
fn sync_post_emission(
    stmt: &Stmt,
    nodes: &[CircuitNode],
    pre_len: usize,
    cte: &mut CompileTimeEnv,
    env: &mut LoweringEnv,
) {
    let Stmt::Substitution {
        op: AssignOp::Assign,
        target: Expr::Ident {
            name: target_name, ..
        },
        ..
    } = stmt
    else {
        return;
    };
    let Some(CircuitNode::Let { name, value, .. }) =
        nodes.get(pre_len..).and_then(|new_nodes| new_nodes.last())
    else {
        return;
    };
    if name != target_name {
        return;
    }
    match super::super::const_fold::try_fold_const(value) {
        Some(fc) => {
            env.known_constants.insert(name.clone(), fc);
            cte.insert(name.clone(), BigVal::from_field_const(fc));
        }
        None => {
            env.known_constants.remove(name);
        }
    }
}

/// Resolve a [`LoopBound`] to a concrete `u64` end value. Used by the
/// lowering-time unroll paths where iteration counts must be known
/// before emission. Literal bounds are returned as-is; captures and
/// expressions are looked up in `ctx.all_constants(env)`.
fn resolve_bound_to_u64(
    bound: &LoopBound,
    env: &LoweringEnv,
    ctx: &LoweringContext,
    span: &diagnostics::Span,
) -> Result<u64, LoweringError> {
    match bound {
        LoopBound::Literal(n) => Ok(*n),
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
            })
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
                })
        }
    }
}

/// Emit a `CircuitNode::For` node for the fall-through case (no
/// lowering-time unroll needed). Propagates `pending` so component
/// wirings inside the loop (like `mux.c[0][i] <== c[i]`) update the
/// parent's pending map — we deliberately do NOT flush remaining
/// wirings at the end because that is the parent scope's job.
#[allow(clippy::too_many_arguments)]
fn emit_for_node<'a>(
    var_name: String,
    bound: LoopBound,
    start: u64,
    body: &'a ast::Block,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
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

    /// Body contains an array indexing expression `arr[idx]` whose
    /// index references the loop variable — either as an assignment
    /// target (`arr[i] <== ...`, `arr[i] <-- ...`) or as a read
    /// inside any expression (`acc += a[i]`, `mux.c[0][i]`, nested
    /// component `comp.in[i]`). The downstream emission pipeline
    /// (ProveIR `LetIndexed` / `WitnessHintIndexed` /
    /// `CircuitExpr::ArrayIndex`) needs a compile-time constant
    /// index at instantiate time; the Lysis Symbolic path in
    /// particular cannot resolve a loop-var SSA slot there. Unroll
    /// at lowering so every per-iteration expansion sees a concrete
    /// `i`. Example: SHA-256 `paddedIn[k] <-- 0` (write) and
    /// `sigmaPlus.sum.in[i] <== prior[i]` (read + write).
    IndexedAssignmentLoop,
}

/// Classify a `for` loop body into a [`LoopLowering`] strategy, or
/// return `None` if the body can stay as a `CircuitNode::For` node.
///
/// Priority chain: `MixedSignalVar`, `ComponentArrayOps`,
/// `KnownArrayRefs`, `IndexedAssignmentLoop`. The first three depend
/// on compile-time eval semantics that preempt a pure indexed-
/// assignment classification; `IndexedAssignmentLoop` is the
/// catch-all for loops whose only lowering-time requirement is
/// concrete indices in assignment targets.
pub(super) fn classify_loop_body(
    stmts: &[Stmt],
    env: &LoweringEnv,
    loop_var: &str,
) -> Option<LoopLowering> {
    if body_mixes_signals_and_vars(stmts) {
        return Some(LoopLowering::MixedSignalVar);
    }
    if body_has_component_array_ops(stmts, env) {
        return Some(LoopLowering::ComponentArrayOps);
    }
    if body_references_known_arrays(stmts, env) {
        return Some(LoopLowering::KnownArrayRefs);
    }
    if body_has_loop_var_indexed_assignments(stmts, loop_var) {
        return Some(LoopLowering::IndexedAssignmentLoop);
    }
    // Catch-all: any loop whose body emits signal work (constraints,
    // witness hints, component wiring) is not safe for the Lysis
    // Symbolic `LoopUnroll` path today — the walker's per-iteration
    // register file is capped at 255 and heavy bodies overflow, and
    // not every signal op in a loop body has a const-index shape the
    // Symbolic emitter accepts. Phase 1 policy: if signal ops are
    // present, unroll at lowering so downstream only sees
    // `CircuitNode::Let` / assignments with concrete indices. Loops
    // with only compile-time `var` arithmetic (accumulators,
    // counters) remain as `CircuitNode::For` and still go through
    // the Symbolic fast path.
    if body_has_any_signal_ops(stmts) {
        return Some(LoopLowering::IndexedAssignmentLoop);
    }
    None
}

/// `true` if the body contains any signal-level statement —
/// constraint/signal assignment, constraint-eq, signal-decl init,
/// or component-decl init. Walks into `IfElse`, nested `Block`, and
/// nested loop bodies (those loops get their own classification
/// when lowered, but a signal op *somewhere* in the tree means we
/// cannot leave the current loop rolled for Lysis Symbolic v1).
fn body_has_any_signal_ops(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_any_signal_op)
}

fn stmt_has_any_signal_op(stmt: &Stmt) -> bool {
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
        Stmt::SignalDecl {
            init: Some((AssignOp::ConstraintAssign | AssignOp::SignalAssign, _)),
            ..
        } => true,
        Stmt::ComponentDecl { init: Some(_), .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.stmts.iter().any(stmt_has_any_signal_op)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_any_signal_op),
                    Some(ElseBranch::IfElse(s)) => stmt_has_any_signal_op(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_any_signal_op),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_any_signal_op)
        }
        _ => false,
    }
}

/// `true` if the body contains any `arr[idx]` expression — as an
/// assignment target or anywhere inside an expression — whose
/// `idx` references `loop_var`. Covers reads (`in[i]`,
/// `comp.x[i]`), writes (`out[i] <== ...`), and mixed uses
/// (`sum += in[i] * K[i]`).
///
/// Walks into `IfElse`, nested `Block`, `CompoundAssign` and
/// `Substitution` RHS expressions. Does not descend into nested
/// `For` loops — those are classified separately when they are
/// lowered.
fn body_has_loop_var_indexed_assignments(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_loop_var_dependent_index(s, loop_var))
}

fn stmt_has_loop_var_dependent_index(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_has_loop_var_indexed(target, loop_var)
                || expr_has_loop_var_indexed(value, loop_var)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_has_loop_var_indexed(target, loop_var)
                || expr_has_loop_var_indexed(value, loop_var)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_has_loop_var_indexed(lhs, loop_var) || expr_has_loop_var_indexed(rhs, loop_var)
        }
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .is_some_and(|v| expr_has_loop_var_indexed(v, loop_var)),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_loop_var_indexed(condition, loop_var)
                || then_body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_loop_var_dependent_index(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => stmt_has_loop_var_dependent_index(s, loop_var),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
        // Descend into nested `for` / `while` / `do-while` bodies
        // keeping the same target `loop_var`. A nested loop's own
        // iterator is a different name, so references to the outer
        // `loop_var` inside the inner body are exactly what we need
        // to detect (e.g., BinSum's
        // `for (k) { for (j) { lin += in[j][k] * e2 } }`).
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
        _ => false,
    }
}

/// `true` if `expr` contains an `Expr::Index { index }` anywhere in
/// its subtree whose `index` references `loop_var`.
fn expr_has_loop_var_indexed(expr: &Expr, loop_var: &str) -> bool {
    match expr {
        Expr::Index { object, index, .. } => {
            expr_references_ident(index, loop_var) || expr_has_loop_var_indexed(object, loop_var)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            expr_has_loop_var_indexed(lhs, loop_var) || expr_has_loop_var_indexed(rhs, loop_var)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_loop_var_indexed(operand, loop_var),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_has_loop_var_indexed(condition, loop_var)
                || expr_has_loop_var_indexed(if_true, loop_var)
                || expr_has_loop_var_indexed(if_false, loop_var)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_has_loop_var_indexed(a, loop_var)),
        Expr::DotAccess { object, .. } => expr_has_loop_var_indexed(object, loop_var),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => elements
            .iter()
            .any(|e| expr_has_loop_var_indexed(e, loop_var)),
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args
                .iter()
                .any(|a| expr_has_loop_var_indexed(a, loop_var))
                || signal_args
                    .iter()
                    .any(|a| expr_has_loop_var_indexed(&a.value, loop_var))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Ident { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
}

fn expr_references_ident(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Ident { name: n, .. } => n == name,
        Expr::BinOp { lhs, rhs, .. } => {
            expr_references_ident(lhs, name) || expr_references_ident(rhs, name)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_references_ident(operand, name),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_references_ident(condition, name)
                || expr_references_ident(if_true, name)
                || expr_references_ident(if_false, name)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_references_ident(a, name)),
        Expr::Index { object, index, .. } => {
            expr_references_ident(object, name) || expr_references_ident(index, name)
        }
        Expr::DotAccess { object, .. } => expr_references_ident(object, name),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(|e| expr_references_ident(e, name))
        }
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args.iter().any(|a| expr_references_ident(a, name))
                || signal_args
                    .iter()
                    .any(|a| expr_references_ident(&a.value, name))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
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
    fn classify_num2bits_loop_is_indexed_assignment_loop() {
        // Num2Bits-style loop: `out[i] <-- ...` is an indexed
        // assignment whose target references the loop var `i`. The
        // downstream Lysis Symbolic path cannot resolve `i` at
        // instantiate time, so the loop must be unrolled here.
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
        assert_eq!(
            classify_loop_body(&for_body, &env, "i"),
            Some(LoopLowering::IndexedAssignmentLoop),
        );
    }

    #[test]
    fn classify_noindex_var_only_loop_is_none() {
        // Loop body has no array indexing on the loop var — stays
        // as `CircuitNode::For`. Instantiate time still unrolls per
        // iteration, but nothing needs the loop var as a const at
        // emission time.
        let stmts = extract_template_body(
            r#"
            template T(n) {
                signal output s;
                var sum = 0;
                for (var i = 0; i < n; i++) {
                    sum = sum + 1;
                }
                s <== sum;
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
        assert_eq!(classify_loop_body(&for_body, &env, "i"), None);
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
            classify_loop_body(&for_body, &env, "i"),
            Some(LoopLowering::MixedSignalVar),
        );
    }

    #[test]
    fn classify_sha256_padding_loop_is_indexed_assignment_loop() {
        // Reproduces SHA-256 padding: `paddedIn[k] <-- 0` in a
        // for-loop whose index depends on the loop var.
        let stmts = extract_template_body(
            r#"
            template T(nBits, nBlocks) {
                signal input in[nBits];
                signal paddedIn[nBlocks * 512];
                for (var k = nBits + 1; k < nBlocks * 512 - 64; k++) {
                    paddedIn[k] <-- 0;
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
            classify_loop_body(&for_body, &env, "k"),
            Some(LoopLowering::IndexedAssignmentLoop),
        );
    }
}
