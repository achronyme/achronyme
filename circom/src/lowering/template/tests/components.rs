use super::*;
use ir_forge::types::CircuitNode;

// ── Component inlining ─────────────────────────────────────────

#[test]
fn component_inlining_multiplier() {
    let ir = parse_and_lower(
        r#"
        template Multiplier() {
            signal input a;
            signal input b;
            signal output c;
            c <== a * b;
        }
        template Main() {
            signal input x;
            signal input y;
            signal output out;
            component m = Multiplier();
            m.a <== x;
            m.b <== y;
            out <== m.c;
        }
        component main = Main();
        "#,
    );

    assert_eq!(ir.name, Some("Main".to_string()));
    assert_eq!(ir.witness_inputs.len(), 2); // x, y

    // Body should contain:
    // m.a = x (wiring Let + AssertEq)
    // m.b = y (wiring Let + AssertEq)
    // [inlined Multiplier body: m.c = m.a * m.b (Let + AssertEq)]
    // out = m.c (Let + AssertEq)
    // Check that inlined body references mangled names
    let has_mangled_let = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "m.c"));
    assert!(has_mangled_let, "should have Let for m.c from inlined body");
}

#[test]
fn component_no_inputs() {
    let ir = parse_and_lower(
        r#"
        template Constant() {
            signal output out;
            out <== 42;
        }
        template Main() {
            signal output result;
            component c = Constant();
            result <== c.out;
        }
        component main = Main();
        "#,
    );

    // Constant has no inputs → inlined immediately at ComponentDecl
    let has_mangled = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "c.out"));
    assert!(has_mangled, "should have Let for c.out from inlined body");
}

#[test]
fn component_with_template_args() {
    let ir = parse_and_lower(
        r#"
        template Scale(factor) {
            signal input in;
            signal output out;
            out <== in * factor;
        }
        template Main() {
            signal input x;
            signal output y;
            component s = Scale(3);
            s.in <== x;
            y <== s.out;
        }
        component main = Main();
        "#,
    );

    // The inlined body should have substituted `factor` with 3
    let has_scale_out = ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "s.out"));
    assert!(has_scale_out, "should have Let for s.out");
}

// ── Function inlining ──────────────────────────────────────────

#[test]
fn function_inlining_simple() {
    let ir = parse_and_lower(
        r#"
        function square(x) {
            return x * x;
        }
        template Main() {
            signal input a;
            signal output b;
            b <== square(a);
        }
        component main = Main();
        "#,
    );

    assert_eq!(ir.witness_inputs.len(), 1);
    // b <== square(a) should inline to b <== a * a
    assert_eq!(ir.body.len(), 1); // Let only (no AssertEq)
}

#[test]
fn function_inlining_with_two_args() {
    let ir = parse_and_lower(
        r#"
        function add_mul(a, b) {
            return (a + b) * a;
        }
        template Main() {
            signal input x;
            signal input y;
            signal output z;
            z <== add_mul(x, y);
        }
        component main = Main();
        "#,
    );

    assert_eq!(ir.body.len(), 1); // Let only (no AssertEq)
}

#[test]
fn function_inlining_nested_call() {
    let ir = parse_and_lower(
        r#"
        function double(x) {
            return x + x;
        }
        function quad(x) {
            return double(double(x));
        }
        template Main() {
            signal input a;
            signal output b;
            b <== quad(a);
        }
        component main = Main();
        "#,
    );

    assert_eq!(ir.body.len(), 1); // Let only (no AssertEq)
}

#[test]
fn function_undefined_errors() {
    let src = r#"
        template Main() {
            signal input a;
            signal output b;
            b <== unknown_fn(a);
        }
        component main = Main();
    "#;
    let (prog, errors) = parse_circom(src).expect("parse failed");
    assert!(errors.is_empty());
    let template = match &prog.definitions[0] {
        crate::ast::Definition::Template(t) => t,
        _ => panic!("expected template"),
    };
    let result = lower_template(template, prog.main_component.as_ref(), &prog);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .diagnostic
        .message
        .contains("undefined function"));
}
