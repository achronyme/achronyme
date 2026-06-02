use super::*;
use crate::parser::parse_circom;
use ir_forge::types::{FieldConst, ForRange};

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
    let mut ctx = LoweringContext::from_program(&prog);
    // Pre-evaluate compile-time vars (like lower_template does in the real pipeline)
    let known_vars = crate::lowering::utils::precompute_vars(
        &template.body.stmts,
        &ctx.param_values,
        &ctx.functions,
    );
    for (name, val) in known_vars {
        ctx.param_values.insert(name, val);
    }
    lower_stmts(&template.body.stmts, &mut env, &mut ctx)
}

// ── Constraint assignment (<==) ─────────────────────────────────

#[test]
fn constraint_assign_produces_let() {
    let nodes = lower_template("signal output c; c <== a + b;").unwrap();
    // signal decl doesn't produce nodes, <== produces only a Let (no AssertEq)
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
}

#[test]
fn inline_constraint_assign_signal_decl() {
    let nodes = lower_template("signal output c <== 42;").unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
}

// ── Signal assignment (<--) ─────────────────────────────────────

#[test]
fn signal_assign_produces_witness_hint() {
    let nodes = lower_template("signal inv; inv <-- 1;").unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
}

// ── Constraint equality (===) ───────────────────────────────────

#[test]
fn constraint_eq_produces_assert_eq() {
    let nodes = lower_template("signal x; x <-- 1; a === x;").unwrap();
    // x <-- 1 → WitnessHint, a === x → AssertEq
    assert_eq!(nodes.len(), 2);
    assert!(matches!(&nodes[0], CircuitNode::WitnessHint { .. }));
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
            assert!(matches!(
                value,
                CircuitExpr::BinOp {
                    op: ir_forge::types::CircuitBinOp::Add,
                    ..
                }
            ));
        }
        other => panic!("expected Let with BinOp, got {:?}", other),
    }
}

// ── If/else ─────────────────────────────────────────────────────

#[test]
fn if_else_produces_if_node() {
    let nodes = lower_template("signal x; if (a == 0) { x <-- 1; } else { x <-- 2; }").unwrap();
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
    // Pure var-only body: `classify_loop_body` returns `None`
    // and the loop stays as a `CircuitNode::For`. A body with
    // any signal op would be unrolled at lowering by the
    // `IndexedAssignmentLoop` catch-all.
    let nodes =
        lower_template("var sum = 0; for (var i = 0; i < 8; i++) { sum = sum + 1; }").unwrap();
    let for_node = nodes
        .iter()
        .find(|n| matches!(n, CircuitNode::For { .. }))
        .expect("expected a For node");
    match for_node {
        CircuitNode::For {
            var, range, body, ..
        } => {
            assert_eq!(var, "i");
            assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
            assert_eq!(body.len(), 1);
        }
        other => panic!("expected For, got {:?}", other),
    }
}

#[test]
fn for_loop_le_condition() {
    let nodes =
        lower_template("var sum = 0; for (var i = 0; i <= 7; i++) { sum = sum + 1; }").unwrap();
    let for_node = nodes
        .iter()
        .find(|n| matches!(n, CircuitNode::For { .. }))
        .expect("expected a For node");
    match for_node {
        CircuitNode::For { range, .. } => {
            // i <= 7 → end = 8
            assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
        }
        other => panic!("expected For, got {:?}", other),
    }
}

// ── Assert ──────────────────────────────────────────────────────

#[test]
fn assert_emits_witness_check() {
    let nodes = lower_template("assert(a == 1);").unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(matches!(nodes[0], CircuitNode::Assert { .. }));
}

// ── Log is no-op ────────────────────────────────────────────────

#[test]
fn log_is_noop() {
    let nodes = lower_template("log(a);").unwrap();
    assert!(nodes.is_empty());
}

// ── Tag value assignment ──────────────────────────────────────

#[test]
fn tag_value_assignment_is_noop() {
    let nodes = lower_template("signal input {maxbit} a; a.maxbit = 8;").unwrap();
    assert!(nodes.is_empty());
}

// ── While loops ────────────────────────────────────────────────

#[test]
fn while_var_only_succeeds() {
    let nodes = lower_template("var i = 0; while (i < 5) { i += 1; }").unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "i"));
}

#[test]
fn while_with_signals_is_error() {
    let result = lower_template("signal output x; var i = 0; while (i < 5) { x <== i; i += 1; }");
    assert!(result.is_err());
}

// ── Reverse operators ───────────────────────────────────────────

#[test]
fn reverse_constraint_assign() {
    let nodes = lower_template("signal output c; a ==> c;").unwrap();
    // ==> is reverse <==, produces only a Let (no AssertEq)
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
}

#[test]
fn reverse_signal_assign() {
    let nodes = lower_template("signal inv; a --> inv;").unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
}

// ── Postfix ops in expression statements ────────────────────────

#[test]
fn postfix_increment_stmt() {
    let nodes = lower_template("var i = 0; i++;").unwrap();
    assert_eq!(nodes.len(), 2);
    match &nodes[1] {
        CircuitNode::Let { name, value, .. } => {
            assert_eq!(name, "i");
            assert!(matches!(
                value,
                CircuitExpr::BinOp {
                    op: ir_forge::types::CircuitBinOp::Add,
                    ..
                }
            ));
        }
        other => panic!("expected Let, got {:?}", other),
    }
}

// ── IsZero pattern ──────────────────────────────────────────────

#[test]
fn iszero_pattern() {
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
    // inv <-- 1 → WitnessHint, out <== ... → Let (no AssertEq), a * out === 0 → AssertEq
    assert_eq!(nodes.len(), 3);
    assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
    assert!(matches!(&nodes[1], CircuitNode::Let { name, .. } if name == "out"));
    assert!(matches!(&nodes[2], CircuitNode::AssertEq { .. }));
}
