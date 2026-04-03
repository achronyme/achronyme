//! Statement lowering: Circom statements → ProveIR `CircuitNode` sequences.
//!
//! Key mappings:
//! - `signal <== expr`  → `Let { name, value }` + `AssertEq { lhs: Var(name), rhs: value }`
//! - `signal <-- expr`  → `Let { name, value }` (witness hint only, `===` handled separately)
//! - `lhs === rhs`      → `AssertEq { lhs, rhs }`
//! - `var x = expr`     → `Let { name, value }` (compile-time only, no constraint)
//! - `for (...) { ... }` → `For { var, range, body }`
//! - `if (...) { ... }`  → `If { cond, then_body, else_body }`
//! - `assert(expr)`      → `Assert { expr }`

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitExpr, CircuitNode, ForRange};

use crate::ast::{self, AssignOp, ElseBranch, Expr, Stmt};

use super::env::LoweringEnv;
use super::error::LoweringError;
use super::expressions::lower_expr;
use super::utils::{const_eval_u64, extract_ident_name};

/// Lower a sequence of Circom statements to ProveIR `CircuitNode`s.
pub fn lower_stmts(
    stmts: &[Stmt],
    env: &mut LoweringEnv,
) -> Result<Vec<CircuitNode>, LoweringError> {
    let mut nodes = Vec::new();
    for stmt in stmts {
        lower_stmt(stmt, env, &mut nodes)?;
    }
    Ok(nodes)
}

/// Lower a single Circom statement, appending results to `nodes`.
fn lower_stmt(
    stmt: &Stmt,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
) -> Result<(), LoweringError> {
    match stmt {
        // ── Signal declarations ─────────────────────────────────────
        // Signal declarations themselves don't produce CircuitNodes directly;
        // they are handled by the signal layout extraction (signals.rs).
        // However, inline initialization (`signal output c <== expr`) does.
        Stmt::SignalDecl {
            declarations,
            init: Some((op, value)),
            span,
            ..
        } => {
            for decl in declarations {
                let lowered_value = lower_expr(value, env)?;
                let sr = Some(SpanRange::from_span(span));

                match op {
                    AssignOp::ConstraintAssign => {
                        // `signal c <== expr` → Let + AssertEq
                        nodes.push(CircuitNode::Let {
                            name: decl.name.clone(),
                            value: lowered_value.clone(),
                            span: sr.clone(),
                        });
                        nodes.push(CircuitNode::AssertEq {
                            lhs: CircuitExpr::Var(decl.name.clone()),
                            rhs: lowered_value,
                            message: None,
                            span: sr,
                        });
                    }
                    AssignOp::SignalAssign => {
                        // `signal c <-- expr` → Let only (witness hint)
                        nodes.push(CircuitNode::Let {
                            name: decl.name.clone(),
                            value: lowered_value,
                            span: sr,
                        });
                    }
                    _ => {
                        return Err(LoweringError::new(
                            "unsupported signal init operator in declaration",
                            span,
                        ));
                    }
                }
                // Register the signal name as a local binding for subsequent expressions
                env.locals.insert(decl.name.clone());
            }
        }

        // Signal declarations without initialization — just register names.
        Stmt::SignalDecl { declarations, .. } => {
            for decl in declarations {
                env.locals.insert(decl.name.clone());
            }
        }

        // ── Variable declarations ───────────────────────────────────
        Stmt::VarDecl {
            names,
            init,
            span,
        } => {
            if let Some(value) = init {
                if names.len() == 1 {
                    let lowered = lower_expr(value, env)?;
                    nodes.push(CircuitNode::Let {
                        name: names[0].clone(),
                        value: lowered,
                        span: Some(SpanRange::from_span(span)),
                    });
                    env.locals.insert(names[0].clone());
                } else {
                    // Tuple var decl: `var (a, b) = expr` — not directly
                    // expressible in ProveIR. For now, error.
                    return Err(LoweringError::new(
                        "tuple variable declarations are not supported in circuit context",
                        span,
                    ));
                }
            } else {
                // Uninitialized var — just register name, will be assigned later.
                for name in names {
                    env.locals.insert(name.clone());
                }
            }
        }

        // ── Substitutions (signal assignments) ──────────────────────
        Stmt::Substitution {
            target,
            op,
            value,
            span,
        } => {
            lower_substitution(target, *op, value, span, env, nodes)?;
        }

        // ── Constraint equality ─────────────────────────────────────
        Stmt::ConstraintEq { lhs, rhs, span } => {
            let l = lower_expr(lhs, env)?;
            let r = lower_expr(rhs, env)?;
            nodes.push(CircuitNode::AssertEq {
                lhs: l,
                rhs: r,
                message: None,
                span: Some(SpanRange::from_span(span)),
            });
        }

        // ── Compound assignment ─────────────────────────────────────
        Stmt::CompoundAssign {
            target,
            op,
            value,
            span,
        } => {
            let name = extract_ident_name(target).ok_or_else(|| {
                LoweringError::new(
                    "compound assignment target must be a simple identifier",
                    span,
                )
            })?;
            let current = CircuitExpr::Var(name.clone());
            let rhs = lower_expr(value, env)?;
            let bin_op = compound_to_binop(*op, &current, rhs, span)?;

            // In circuit context, variables are SSA-like. We create a new
            // binding with the same name (shadowing).
            nodes.push(CircuitNode::Let {
                name: name.clone(),
                value: bin_op,
                span: Some(SpanRange::from_span(span)),
            });
        }

        // ── If/else ─────────────────────────────────────────────────
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            span,
        } => {
            let cond = lower_expr(condition, env)?;
            let then_nodes = lower_stmts(&then_body.stmts, env)?;
            let else_nodes = match else_body {
                Some(ElseBranch::Block(block)) => lower_stmts(&block.stmts, env)?,
                Some(ElseBranch::IfElse(if_stmt)) => {
                    let mut sub = Vec::new();
                    lower_stmt(if_stmt, env, &mut sub)?;
                    sub
                }
                None => Vec::new(),
            };
            nodes.push(CircuitNode::If {
                cond,
                then_body: then_nodes,
                else_body: else_nodes,
                span: Some(SpanRange::from_span(span)),
            });
        }

        // ── For loop ────────────────────────────────────────────────
        Stmt::For {
            init,
            condition,
            step,
            body,
            span,
        } => {
            lower_for_loop(init, condition, step, body, span, env, nodes)?;
        }

        // ── While loop ──────────────────────────────────────────────
        // While loops are not directly supported in ProveIR because they
        // require dynamic termination. Circom while loops should be
        // compile-time deterministic.
        Stmt::While { span, .. } => {
            return Err(LoweringError::new(
                "while loops are not supported in circuit context; \
                 use for loops with known bounds",
                span,
            ));
        }

        // ── Assert ──────────────────────────────────────────────────
        Stmt::Assert { arg, span } => {
            let expr = lower_expr(arg, env)?;
            nodes.push(CircuitNode::Assert {
                expr,
                message: None,
                span: Some(SpanRange::from_span(span)),
            });
        }

        // ── Return ──────────────────────────────────────────────────
        Stmt::Return { span, .. } => {
            return Err(LoweringError::new(
                "return statements are only valid inside functions, \
                 not in template circuit context",
                span,
            ));
        }

        // ── Log ─────────────────────────────────────────────────────
        // log() is a debug-only construct — no circuit semantics.
        Stmt::Log { .. } => {
            // No-op in circuit context.
        }

        // ── Component declarations ──────────────────────────────────
        // Component declarations are handled during component inlining (Fase 6).
        Stmt::ComponentDecl { names, .. } => {
            // Register component names as locals for now.
            for name in names {
                env.locals.insert(name.name.clone());
            }
        }

        // ── Bare block ──────────────────────────────────────────────
        Stmt::Block(block) => {
            let inner = lower_stmts(&block.stmts, env)?;
            nodes.extend(inner);
        }

        // ── Bare expression statement ───────────────────────────────
        Stmt::Expr { expr, span } => {
            // Postfix ops (i++) in for-loop steps are handled as compound
            // assignment. Other bare expressions are usually no-ops.
            match expr {
                Expr::PostfixOp {
                    op: ast::PostfixOp::Increment,
                    operand,
                    ..
                } => {
                    let name = extract_ident_name(operand).ok_or_else(|| {
                        LoweringError::new("increment target must be an identifier", span)
                    })?;
                    let inc = CircuitExpr::BinOp {
                        op: ir::prove_ir::types::CircuitBinOp::Add,
                        lhs: Box::new(CircuitExpr::Var(name.clone())),
                        rhs: Box::new(CircuitExpr::Const(ir::prove_ir::types::FieldConst::one())),
                    };
                    nodes.push(CircuitNode::Let {
                        name,
                        value: inc,
                        span: Some(SpanRange::from_span(span)),
                    });
                }
                Expr::PostfixOp {
                    op: ast::PostfixOp::Decrement,
                    operand,
                    ..
                } => {
                    let name = extract_ident_name(operand).ok_or_else(|| {
                        LoweringError::new("decrement target must be an identifier", span)
                    })?;
                    let dec = CircuitExpr::BinOp {
                        op: ir::prove_ir::types::CircuitBinOp::Sub,
                        lhs: Box::new(CircuitExpr::Var(name.clone())),
                        rhs: Box::new(CircuitExpr::Const(ir::prove_ir::types::FieldConst::one())),
                    };
                    nodes.push(CircuitNode::Let {
                        name,
                        value: dec,
                        span: Some(SpanRange::from_span(span)),
                    });
                }
                _ => {
                    // Other bare expressions are no-ops in circuit context.
                }
            }
        }

        // ── Error recovery placeholder ──────────────────────────────
        Stmt::Error { span } => {
            return Err(LoweringError::new(
                "cannot lower error placeholder statement",
                span,
            ));
        }
    }

    Ok(())
}

/// Lower a substitution statement (`target op value`).
fn lower_substitution(
    target: &Expr,
    op: AssignOp,
    value: &Expr,
    span: &diagnostics::Span,
    env: &LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
) -> Result<(), LoweringError> {
    let sr = Some(SpanRange::from_span(span));

    match op {
        // `target <== expr` → Let + AssertEq
        AssignOp::ConstraintAssign => {
            let name = extract_ident_name(target).ok_or_else(|| {
                LoweringError::new(
                    "constraint assignment target must be a simple identifier",
                    span,
                )
            })?;
            let lowered = lower_expr(value, env)?;
            nodes.push(CircuitNode::Let {
                name: name.clone(),
                value: lowered.clone(),
                span: sr.clone(),
            });
            nodes.push(CircuitNode::AssertEq {
                lhs: CircuitExpr::Var(name),
                rhs: lowered,
                message: None,
                span: sr,
            });
        }

        // `expr ==> target` → same as `target <== expr`
        AssignOp::RConstraintAssign => {
            let name = extract_ident_name(value).ok_or_else(|| {
                LoweringError::new(
                    "reverse constraint assignment target must be a simple identifier",
                    span,
                )
            })?;
            let lowered = lower_expr(target, env)?;
            nodes.push(CircuitNode::Let {
                name: name.clone(),
                value: lowered.clone(),
                span: sr.clone(),
            });
            nodes.push(CircuitNode::AssertEq {
                lhs: CircuitExpr::Var(name),
                rhs: lowered,
                message: None,
                span: sr,
            });
        }

        // `target <-- expr` → Let only (witness hint, no constraint)
        AssignOp::SignalAssign => {
            let name = extract_ident_name(target).ok_or_else(|| {
                LoweringError::new(
                    "signal assignment target must be a simple identifier",
                    span,
                )
            })?;
            let lowered = lower_expr(value, env)?;
            nodes.push(CircuitNode::Let {
                name,
                value: lowered,
                span: sr,
            });
        }

        // `expr --> target` → same as `target <-- expr`
        AssignOp::RSignalAssign => {
            let name = extract_ident_name(value).ok_or_else(|| {
                LoweringError::new(
                    "reverse signal assignment target must be a simple identifier",
                    span,
                )
            })?;
            let lowered = lower_expr(target, env)?;
            nodes.push(CircuitNode::Let {
                name,
                value: lowered,
                span: sr,
            });
        }

        // `target = expr` → variable reassignment (SSA shadowing)
        AssignOp::Assign => {
            let name = extract_ident_name(target).ok_or_else(|| {
                LoweringError::new(
                    "assignment target must be a simple identifier in circuit context",
                    span,
                )
            })?;
            let lowered = lower_expr(value, env)?;
            nodes.push(CircuitNode::Let {
                name,
                value: lowered,
                span: sr,
            });
        }
    }

    Ok(())
}

/// Lower a C-style for loop to a ProveIR `For` node.
///
/// Circom for loops must have deterministic bounds for circuit compilation.
/// We try to extract `for (var i = start; i < end; i++)` patterns.
fn lower_for_loop(
    init: &Stmt,
    condition: &Expr,
    step: &Stmt,
    body: &ast::Block,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
) -> Result<(), LoweringError> {
    // Extract loop variable and start value from init
    let (var_name, start) = match init {
        Stmt::VarDecl {
            names,
            init: Some(init_expr),
            ..
        } if names.len() == 1 => {
            let start = const_eval_u64(init_expr).ok_or_else(|| {
                LoweringError::new(
                    "for loop init must be a compile-time constant",
                    span,
                )
            })?;
            (names[0].clone(), start)
        }
        _ => {
            return Err(LoweringError::new(
                "for loop must use `var i = <const>` initialization",
                span,
            ));
        }
    };

    // Extract end bound from condition: `i < end` or `i <= end`
    let end = extract_loop_bound(condition, &var_name).ok_or_else(|| {
        LoweringError::new(
            "for loop condition must be `i < <const>` or `i <= <const>`",
            span,
        )
    })?;

    // Validate step is `i++` or `i += 1`
    validate_loop_step(step, &var_name, span)?;

    // Register loop variable
    env.locals.insert(var_name.clone());

    // Lower body
    let body_nodes = lower_stmts(&body.stmts, env)?;

    nodes.push(CircuitNode::For {
        var: var_name,
        range: ForRange::Literal { start, end },
        body: body_nodes,
        span: Some(SpanRange::from_span(span)),
    });

    Ok(())
}

/// Extract the upper bound from a loop condition like `i < N` or `i <= N`.
fn extract_loop_bound(condition: &Expr, var_name: &str) -> Option<u64> {
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

            let bound = const_eval_u64(rhs)?;

            match op {
                ast::BinOp::Lt => Some(bound),       // i < N → end = N
                ast::BinOp::Le => Some(bound + 1),   // i <= N → end = N+1
                _ => None,
            }
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
            expr: Expr::PostfixOp {
                op: ast::PostfixOp::Increment,
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
            op: ast::CompoundOp::Add,
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

/// Convert a compound assignment operator to a CircuitExpr binary op.
fn compound_to_binop(
    op: ast::CompoundOp,
    lhs: &CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    use ir::prove_ir::types::CircuitBinOp;

    let l = Box::new(lhs.clone());
    let r = Box::new(rhs);

    match op {
        ast::CompoundOp::Add => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Add, lhs: l, rhs: r }),
        ast::CompoundOp::Sub => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Sub, lhs: l, rhs: r }),
        ast::CompoundOp::Mul => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Mul, lhs: l, rhs: r }),
        ast::CompoundOp::Div => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Div, lhs: l, rhs: r }),
        ast::CompoundOp::IntDiv => Ok(CircuitExpr::IntDiv {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        ast::CompoundOp::Mod => Ok(CircuitExpr::IntMod {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        ast::CompoundOp::Pow => {
            let exp = match r.as_ref() {
                CircuitExpr::Const(fc) => fc.to_u64().ok_or_else(|| {
                    LoweringError::new("power exponent must be a small constant", span)
                })?,
                _ => {
                    return Err(LoweringError::new(
                        "power exponent must be a compile-time constant",
                        span,
                    ));
                }
            };
            Ok(CircuitExpr::Pow { base: l, exp })
        }
        ast::CompoundOp::ShiftL | ast::CompoundOp::ShiftR
        | ast::CompoundOp::BitAnd | ast::CompoundOp::BitOr | ast::CompoundOp::BitXor => {
            Err(LoweringError::new(
                "bitwise compound assignment is not supported in circuit context",
                span,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;
    use ir::prove_ir::types::FieldConst;

    /// Parse a template and lower its body statements.
    fn lower_template(src: &str) -> Result<Vec<CircuitNode>, LoweringError> {
        let full = format!("template T() {{ {src} }}");
        let (prog, errors) = parse_circom(&full).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        let template = match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };

        let mut env = LoweringEnv::new();
        // Pre-register common signal names for testing
        env.inputs.insert("in".to_string());
        env.inputs.insert("a".to_string());
        env.inputs.insert("b".to_string());
        lower_stmts(&template.body.stmts, &mut env)
    }

    // ── Constraint assignment (<==) ─────────────────────────────────

    #[test]
    fn constraint_assign_produces_let_and_assert_eq() {
        let nodes = lower_template("signal output c; c <== a + b;").unwrap();
        // signal decl doesn't produce nodes, substitution produces Let + AssertEq
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
    }

    #[test]
    fn inline_constraint_assign_signal_decl() {
        let nodes = lower_template("signal output c <== 42;").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
    }

    // ── Signal assignment (<--) ─────────────────────────────────────

    #[test]
    fn signal_assign_produces_let_only() {
        let nodes = lower_template("signal inv; inv <-- 1;").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "inv"));
    }

    // ── Constraint equality (===) ───────────────────────────────────

    #[test]
    fn constraint_eq_produces_assert_eq() {
        let nodes = lower_template("signal x; x <-- 1; a === x;").unwrap();
        // x <-- 1 → Let, a === x → AssertEq
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { .. }));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
    }

    // ── Variable declaration ────────────────────────────────────────

    #[test]
    fn var_decl_with_init() {
        let nodes = lower_template("var x = 42;").unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "x");
                assert_eq!(*value, CircuitExpr::Const(FieldConst::from_u64(42)));
            }
            other => panic!("expected Let, got {:?}", other),
        }
    }

    #[test]
    fn var_decl_without_init() {
        // No node produced, just registers the name
        let nodes = lower_template("var x;").unwrap();
        assert!(nodes.is_empty());
    }

    // ── Variable assignment (=) ─────────────────────────────────────

    #[test]
    fn var_reassignment() {
        let nodes = lower_template("var x = 0; x = 1;").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "x"));
        assert!(matches!(&nodes[1], CircuitNode::Let { name, .. } if name == "x"));
    }

    // ── Compound assignment ─────────────────────────────────────────

    #[test]
    fn compound_add_assignment() {
        let nodes = lower_template("var x = 0; x += 1;").unwrap();
        assert_eq!(nodes.len(), 2);
        match &nodes[1] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "x");
                assert!(matches!(value, CircuitExpr::BinOp { op: ir::prove_ir::types::CircuitBinOp::Add, .. }));
            }
            other => panic!("expected Let with BinOp, got {:?}", other),
        }
    }

    // ── If/else ─────────────────────────────────────────────────────

    #[test]
    fn if_else_produces_if_node() {
        let nodes = lower_template(
            "signal x; if (a == 0) { x <-- 1; } else { x <-- 2; }",
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0] {
            CircuitNode::If {
                then_body,
                else_body,
                ..
            } => {
                assert_eq!(then_body.len(), 1);
                assert_eq!(else_body.len(), 1);
            }
            other => panic!("expected If, got {:?}", other),
        }
    }

    #[test]
    fn if_without_else() {
        let nodes = lower_template("signal x; if (a == 0) { x <-- 1; }").unwrap();
        match &nodes[0] {
            CircuitNode::If { else_body, .. } => {
                assert!(else_body.is_empty());
            }
            other => panic!("expected If, got {:?}", other),
        }
    }

    // ── For loop ────────────────────────────────────────────────────

    #[test]
    fn for_loop_with_literal_bounds() {
        let nodes = lower_template(
            "signal x; for (var i = 0; i < 8; i++) { x <-- 1; }",
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0] {
            CircuitNode::For { var, range, body, .. } => {
                assert_eq!(var, "i");
                assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
                assert_eq!(body.len(), 1);
            }
            other => panic!("expected For, got {:?}", other),
        }
    }

    #[test]
    fn for_loop_le_condition() {
        let nodes = lower_template(
            "signal x; for (var i = 0; i <= 7; i++) { x <-- 1; }",
        )
        .unwrap();
        match &nodes[0] {
            CircuitNode::For { range, .. } => {
                // i <= 7 → end = 8
                assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
            }
            other => panic!("expected For, got {:?}", other),
        }
    }

    // ── Assert ──────────────────────────────────────────────────────

    #[test]
    fn assert_produces_assert_node() {
        let nodes = lower_template("assert(a == 1);").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Assert { .. }));
    }

    // ── Log is no-op ────────────────────────────────────────────────

    #[test]
    fn log_is_noop() {
        let nodes = lower_template("log(a);").unwrap();
        assert!(nodes.is_empty());
    }

    // ── While is error ──────────────────────────────────────────────

    #[test]
    fn while_is_error() {
        let result = lower_template("var i = 0; while (i < 5) { i += 1; }");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("while loops"));
    }

    // ── Reverse operators ───────────────────────────────────────────

    #[test]
    fn reverse_constraint_assign() {
        let nodes = lower_template("signal output c; a ==> c;").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
    }

    #[test]
    fn reverse_signal_assign() {
        let nodes = lower_template("signal inv; a --> inv;").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "inv"));
    }

    // ── Postfix ops in expression statements ────────────────────────

    #[test]
    fn postfix_increment_stmt() {
        let nodes = lower_template("var i = 0; i++;").unwrap();
        assert_eq!(nodes.len(), 2);
        match &nodes[1] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "i");
                assert!(matches!(value, CircuitExpr::BinOp { op: ir::prove_ir::types::CircuitBinOp::Add, .. }));
            }
            other => panic!("expected Let, got {:?}", other),
        }
    }

    // ── IsZero pattern ──────────────────────────────────────────────

    #[test]
    fn iszero_pattern() {
        // The canonical IsZero: <-- for witness hint, <== for verification, === for final check
        let nodes = lower_template(
            r#"
            signal inv;
            signal output out;
            inv <-- 1;
            out <== 0 - a * inv + 1;
            a * out === 0;
            "#,
        )
        .unwrap();
        // inv <-- 1 → Let
        // out <== expr → Let + AssertEq
        // a * out === 0 → AssertEq
        assert_eq!(nodes.len(), 4);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "inv"));
        assert!(matches!(&nodes[1], CircuitNode::Let { name, .. } if name == "out"));
        assert!(matches!(&nodes[2], CircuitNode::AssertEq { .. }));
        assert!(matches!(&nodes[3], CircuitNode::AssertEq { .. }));
    }
}
