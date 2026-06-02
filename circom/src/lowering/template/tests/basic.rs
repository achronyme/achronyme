use super::*;
use ir_forge::types::{CircuitNode, ForRange};

// ── Basic template ──────────────────────────────────────────────

#[test]
fn simple_multiplier() {
    let result = parse_and_lower_full(
        r#"
        template Multiplier() {
            signal input a;
            signal input b;
            signal output c;
            c <== a * b;
        }
        component main = Multiplier();
        "#,
    );
    let ir = &result.prove_ir;

    assert_eq!(ir.name, Some("Multiplier".to_string()));
    // No public signals declared in main, so all inputs are witness
    // But output c is always public
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "c");
    assert!(result.output_names.contains("c"));
    assert_eq!(ir.witness_inputs.len(), 2);
    assert_eq!(ir.witness_inputs[0].name, "a");
    assert_eq!(ir.witness_inputs[1].name, "b");

    // c <== a * b → Let(c) only (no AssertEq)
    assert_eq!(ir.body.len(), 1);
    assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "c"));
}

#[test]
fn multiplier_with_public_inputs() {
    let result = parse_and_lower_full(
        r#"
        template Multiplier() {
            signal input a;
            signal input b;
            signal output c;
            c <== a * b;
        }
        component main {public [a]} = Multiplier();
        "#,
    );
    let ir = &result.prove_ir;

    // a is public input, c is public output
    assert_eq!(ir.public_inputs.len(), 2);
    assert_eq!(ir.public_inputs[0].name, "a");
    assert_eq!(ir.public_inputs[1].name, "c");
    assert!(result.output_names.contains("c"));
    assert!(!result.output_names.contains("a"));
    assert_eq!(ir.witness_inputs.len(), 1);
    assert_eq!(ir.witness_inputs[0].name, "b");
}

// ── IsZero pattern ──────────────────────────────────────────────

#[test]
fn iszero_template() {
    let ir = parse_and_lower(
        r#"
        template IsZero() {
            signal input in;
            signal output out;
            signal inv;
            inv <-- 1;
            out <== 0 - in * inv + 1;
            in * out === 0;
        }
        component main = IsZero();
        "#,
    );

    assert_eq!(ir.name, Some("IsZero".to_string()));
    assert_eq!(ir.witness_inputs.len(), 1);
    assert_eq!(ir.witness_inputs[0].name, "in");

    // inv <-- 1 → WitnessHint
    // out <== ... → Let (no AssertEq)
    // in * out === 0 → AssertEq
    assert_eq!(ir.body.len(), 3);
}

// ── For loop template ───────────────────────────────────────────

#[test]
fn num2bits_style() {
    // Pure var-only body (no signal ops) so the loop stays as
    // `CircuitNode::For` — a body with any `<--` / `<==` would be
    // unrolled at lowering by the `IndexedAssignmentLoop` catch-all.
    let ir = parse_and_lower(
        r#"
        template VarLoop() {
            signal input in;
            signal output out;
            var lc = 0;
            for (var i = 0; i < 8; i++) {
                lc += 1;
            }
            out <-- lc;
            lc === in;
        }
        component main = VarLoop();
        "#,
    );

    // var lc = 0 → Let(lc)
    // for loop → For
    // out <-- lc → Let(out)
    // lc === in → AssertEq
    assert_eq!(ir.body.len(), 4);
    match &ir.body[1] {
        CircuitNode::For {
            var, range, body, ..
        } => {
            assert_eq!(var, "i");
            assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
            // lc += 1 → Let
            assert_eq!(body.len(), 1);
        }
        other => panic!("expected For, got {:?}", other),
    }
}

// ── If/else template ────────────────────────────────────────────

#[test]
fn conditional_template() {
    let ir = parse_and_lower(
        r#"
        template Cond() {
            signal input sel;
            signal output out;
            if (sel == 0) {
                out <-- 1;
            } else {
                out <-- 2;
            }
            out === sel + 1;
        }
        component main = Cond();
        "#,
    );

    // if/else → If, out === ... → AssertEq
    assert_eq!(ir.body.len(), 2);
    assert!(matches!(&ir.body[0], CircuitNode::If { .. }));
    assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
}

// ── Assert template ─────────────────────────────────────────────

#[test]
fn assert_emits_witness_check_in_template() {
    // In Circom, assert() is a prover-side runtime check during witness
    // computation. We emit Assert nodes for the witness evaluator.
    let ir = parse_and_lower(
        r#"
        template CheckNonZero() {
            signal input x;
            assert(x != 0);
        }
        component main = CheckNonZero();
        "#,
    );

    assert_eq!(ir.body.len(), 1);
    assert!(matches!(&ir.body[0], CircuitNode::Assert { .. }));
}

// ── Empty template ──────────────────────────────────────────────

#[test]
fn empty_template() {
    let ir = parse_and_lower(
        r#"
        template Empty() {}
        component main = Empty();
        "#,
    );

    assert_eq!(ir.name, Some("Empty".to_string()));
    assert!(ir.public_inputs.is_empty()); // no inputs, no outputs
    assert!(ir.witness_inputs.is_empty());
    assert!(ir.body.is_empty());
}

// ── Template name ───────────────────────────────────────────────

#[test]
fn template_name_preserved() {
    let ir = parse_and_lower(
        r#"
        template MyCircuit() {
            signal input x;
            signal output y;
            y <== x;
        }
        component main = MyCircuit();
        "#,
    );

    assert_eq!(ir.name, Some("MyCircuit".to_string()));
}

// ── BabyAdd-style pattern ───────────────────────────────────────

#[test]
fn babyadd_pattern() {
    let ir = parse_and_lower(
        r#"
        template BabyAdd() {
            signal input x1;
            signal input y1;
            signal output xout;
            signal output yout;
            signal beta;
            signal gamma;
            xout <-- 1;
            yout <-- 1;
            xout === beta + gamma;
            yout === beta - gamma;
        }
        component main = BabyAdd();
        "#,
    );

    // 2 witness inputs (x1, y1), 2 public outputs (xout, yout), 4 body nodes
    assert_eq!(ir.witness_inputs.len(), 2); // x1, y1
    assert_eq!(ir.public_inputs.len(), 2); // xout, yout (outputs are public)
    assert_eq!(ir.body.len(), 4);
}
