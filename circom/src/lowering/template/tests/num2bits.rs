use super::*;
use ir_forge::types::CircuitNode;

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
        .instantiate_lysis(&fe_captures)
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
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
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
