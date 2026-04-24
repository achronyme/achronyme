//! Tests for template lowering.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `template/mod.rs`.

use super::*;
use crate::parser::parse_circom;
use ir_forge::types::{CaptureUsage, CircuitNode, ForRange};

fn parse_and_lower_full(src: &str) -> LowerTemplateResult {
    let (prog, errors) = parse_circom(src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {:?}", errors);

    let main_name = prog
        .main_component
        .as_ref()
        .map(|m| m.template_name.as_str());
    let template = prog
        .definitions
        .iter()
        .find_map(|d| match d {
            crate::ast::Definition::Template(t)
                if main_name.is_none() || main_name == Some(t.name.as_str()) =>
            {
                Some(t)
            }
            _ => None,
        })
        .expect("no matching template found");

    lower_template(template, prog.main_component.as_ref(), &prog).unwrap()
}

fn parse_and_lower(src: &str) -> ProveIR {
    parse_and_lower_full(src).prove_ir
}

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
    // unrolled at lowering by the Phase 1 `IndexedAssignmentLoop`
    // catch-all.
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

// ── Capture classification ─────────────────────────────────────

#[test]
fn capture_circuit_input() {
    let ir = parse_and_lower(
        r#"
        template Scale(factor) {
            signal input x;
            signal output y;
            y <== x * factor;
        }
        component main = Scale();
        "#,
    );

    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "factor");
    assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
}

#[test]
fn capture_unused_is_structure_only() {
    let ir = parse_and_lower(
        r#"
        template T(unused_param) {
            signal input x;
            signal output y;
            y <== x;
        }
        component main = T();
        "#,
    );

    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "unused_param");
    assert_eq!(ir.captures[0].usage, CaptureUsage::StructureOnly);
}

#[test]
fn capture_no_params_no_captures() {
    let ir = parse_and_lower(
        r#"
        template T() {
            signal input x;
            signal output y;
            y <== x;
        }
        component main = T();
        "#,
    );

    assert!(ir.captures.is_empty());
}

// ── Array literal expansion ────────────────────────────────────

#[test]
fn array_literal_expands_to_individual_lets() {
    let ir = parse_and_lower(
        r#"
        template T() {
            signal input x;
            signal output out;
            var coeffs = [1, 2, 3];
            out <== x * coeffs[1];
        }
        component main = T();
        "#,
    );

    // coeffs = [1, 2, 3] → Let(coeffs_0=1), Let(coeffs_1=2), Let(coeffs_2=3)
    // out <== x * coeffs[1] → Let(out) + AssertEq
    // coeffs[1] should resolve to Var("coeffs_1")
    let let_names: Vec<&str> = ir
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::Let { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(let_names.contains(&"coeffs_0"));
    assert!(let_names.contains(&"coeffs_1"));
    assert!(let_names.contains(&"coeffs_2"));
    assert!(let_names.contains(&"out"));
}

// ── Real circomlib Num2Bits ────────────────────────────────────

#[test]
fn real_num2bits_lowering() {
    let ir = parse_and_lower(
        r#"
        template Num2Bits(n) {
            signal input in;
            signal output out[n];
            var lc1 = 0;
            var e2 = 1;
            for (var i = 0; i < n; i++) {
                out[i] <-- (in >> i) & 1;
                out[i] * (out[i] - 1) === 0;
                lc1 += out[i] * e2;
                e2 = e2 + e2;
            }
            lc1 === in;
        }
        component main {public [in]} = Num2Bits(8);
        "#,
    );

    assert_eq!(ir.name, Some("Num2Bits".to_string()));
    // "in" is public input, "out" is public output
    assert_eq!(ir.public_inputs.len(), 2);
    assert_eq!(ir.public_inputs[0].name, "in");
    assert_eq!(ir.public_inputs[1].name, "out");
    // n is a capture (template parameter)
    assert!(!ir.captures.is_empty());
    assert_eq!(ir.captures[0].name, "n");
    // Loop body contains `out[i] <-- ...` where the index references
    // the loop var `i`, so lowering unrolls it at compile time. The
    // resulting body is several per-iteration nodes plus the outer
    // `AssertEq(lc1 === in)`, not a single `CircuitNode::For`.
    assert!(ir.body.len() >= 3, "body has {} nodes", ir.body.len());
    assert!(
        !ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
        "Num2Bits loop should be unrolled at lowering time \
         (IndexedAssignmentLoop classification), not emitted as For"
    );
}

#[test]
fn real_num2bits_e2e_instantiate() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::HashMap;

    let src = r#"
        template Num2Bits(n) {
            signal input in;
            signal output out[n];
            var lc1 = 0;
            var e2 = 1;
            for (var i = 0; i < n; i++) {
                out[i] <-- (in >> i) & 1;
                out[i] * (out[i] - 1) === 0;
                lc1 += out[i] * e2;
                e2 = e2 + e2;
            }
            lc1 === in;
        }
        component main {public [in]} = Num2Bits(8);
    "#;

    // 1. Compile to ProveIR
    let result = crate::compile_to_prove_ir(src).expect("compilation failed");
    let prove_ir = result.prove_ir;
    let capture_values = result.capture_values;

    assert_eq!(capture_values.get("n"), Some(&8));

    // 2. Compute witness hints (in = 13 → bits = [1,0,1,1,0,0,0,0])
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(13));

    let witness =
        crate::witness::compute_witness_hints_with_captures(&prove_ir, &inputs, &capture_values)
            .unwrap();

    // Verify bit decomposition: 13 = 1101 in binary
    assert_eq!(
        witness.get("out_0"),
        Some(&FieldElement::<Bn254Fr>::from_u64(1))
    ); // bit 0
    assert_eq!(
        witness.get("out_1"),
        Some(&FieldElement::<Bn254Fr>::from_u64(0))
    ); // bit 1
    assert_eq!(
        witness.get("out_2"),
        Some(&FieldElement::<Bn254Fr>::from_u64(1))
    ); // bit 2
    assert_eq!(
        witness.get("out_3"),
        Some(&FieldElement::<Bn254Fr>::from_u64(1))
    ); // bit 3
    assert_eq!(
        witness.get("out_4"),
        Some(&FieldElement::<Bn254Fr>::from_u64(0))
    ); // bit 4
    assert_eq!(
        witness.get("out_5"),
        Some(&FieldElement::<Bn254Fr>::from_u64(0))
    ); // bit 5
    assert_eq!(
        witness.get("out_6"),
        Some(&FieldElement::<Bn254Fr>::from_u64(0))
    ); // bit 6
    assert_eq!(
        witness.get("out_7"),
        Some(&FieldElement::<Bn254Fr>::from_u64(0))
    ); // bit 7

    // 3. Instantiate ProveIR → IR
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let program = prove_ir
        .instantiate(&fe_captures)
        .expect("instantiation failed");

    // Verify the IR program has instructions (loop was unrolled)
    assert!(
        program.len() > 10,
        "expected many instructions after unrolling, got {}",
        program.len()
    );
}

// ── E2E helper: compile + prove pipeline ─────────────────────

/// Full Circom→ProveIR→R1CS→Groth16 pipeline for E2E tests.
/// Returns (num_constraints, num_variables, num_pub_inputs, proof_result).
fn circom_prove_e2e(
    src: &str,
    user_inputs: &[(&str, u64)],
) -> (usize, usize, usize, akron::ProveResult) {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::HashMap;
    use zkc::r1cs_backend::R1CSCompiler;

    let result = crate::compile_to_prove_ir(src).expect("compilation failed");
    let prove_ir = result.prove_ir;
    let capture_values = result.capture_values;

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (name, val) in user_inputs {
        inputs.insert(name.to_string(), FieldElement::<Bn254Fr>::from_u64(*val));
    }

    let mut all_signals =
        crate::witness::compute_witness_hints_with_captures(&prove_ir, &inputs, &capture_values)
            .unwrap();

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    // Captures with CaptureUsage::Both become witness inputs in the IR
    // and need values in the input map for R1CS compilation.
    for (name, fe) in &fe_captures {
        all_signals.entry(name.clone()).or_insert(*fe);
    }

    let mut program = prove_ir
        .instantiate_with_outputs(&fe_captures, &result.output_names)
        .expect("instantiation failed");

    ir::passes::optimize(&mut program);

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .expect("R1CS compilation failed");

    r1cs_compiler
        .cs
        .verify(&witness)
        .expect("R1CS verification failed");

    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");
    let proof_result =
        proving::groth16_bn254::generate_proof(&r1cs_compiler.cs, &witness, cache_dir.path())
            .expect("Groth16 proof generation failed");

    (
        r1cs_compiler.cs.num_constraints(),
        r1cs_compiler.cs.num_variables(),
        r1cs_compiler.cs.num_pub_inputs(),
        proof_result,
    )
}
