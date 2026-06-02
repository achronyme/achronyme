use super::*;

/// Fase 5.1 — array parameters in the Artik lift. A function with
/// `arr[N]` as a formal parameter binds to N input signals (one
/// per element). Verified by lifting `array_sum(arr[4])`, pushing
/// it through instantiate + R1CS + Groth16, and confirming the
/// proof verifies when the template constraints match the Artik
/// witness.
#[test]
fn fn_witness_lift_array_param_e2e_groth16() {
    use std::collections::{HashMap, HashSet};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_param_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-param lift failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    // array_sum(inp) = inp[0] + 2*inp[1] + 3*inp[2] + 4*inp[3].
    let inp = [3u64, 5, 7, 11];
    let expected_out = inp[0] + 2 * inp[1] + 3 * inp[2] + 4 * inp[3];

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (i, v) in inp.iter().enumerate() {
        inputs.insert(format!("inp_{i}"), FieldElement::<Bn254Fr>::from_u64(*v));
    }
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verify failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ array_sum(inp[4]={inp:?}) = {expected_out} — Artik→Groth16 VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 5.1 (array-literal init): a function body declares
/// `var k[N] = [literal, ...];` and indexes `k[i]` in a loop.
/// The lift allocates the backing store at declaration time and
/// StoreArrs each literal into its slot, so later reads resolve
/// via `LoadArr`. This is the `sha256K` shape: a constant table
/// packed into a `var` at the top of a helper function.
///
/// Verifies `n * (1+2+3+4) = 10*n` through Groth16 with n=7.
#[test]
fn fn_witness_lift_array_literal_e2e_groth16() {
    use std::collections::{HashMap, HashSet};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_literal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-literal lift failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    let n = 7u64;
    let expected_out = 10 * n;

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("n".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verify failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ table_sum() * {n} = {expected_out} — Artik→Groth16 VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 4 deliverable check: a circom template whose `out <--`
/// value comes from an Artik witness program goes all the way
/// through Groth16 proof generation and verification on BN-254.
/// This is the end-to-end "can I ship this" test — the same path
/// `ach prove file.circom --input inputs.toml` will walk once the
/// CLI gets wired up.
///
/// Uses `triangle_sum` (for-loop lift producing `6*in`) so the
/// constraint `out === 6 * in` is non-trivial and the proof
/// actually has something to prove.
#[test]
fn fn_witness_lift_e2e_groth16_triangle_sum() {
    use std::collections::HashSet;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Artik→Groth16 compile failed: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    // triangle_sum(n) = 6*n; template enforces `out === 6 * in`.
    let n = 11u64;
    let expected_out = 6 * n;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof generation failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verification failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ Artik→Groth16: triangle_sum({n}) = {expected_out} — PROOF VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 3+4 end-to-end on a SHA-style bit-op body: the same σ0
/// function that exercises `& | ^ >> <<` in the lift gets pushed
/// through instantiate + R1CS + witness verify. The template pins
/// `out === out` so there's no independent constraint on the σ0
/// value — this test is specifically for "the Artik dispatch
/// produces *some* value that satisfies the circuit", confirming
/// the bit-op witness path runs end-to-end (decode → IntFromField →
/// IBin at u32 → FieldFromInt → write slot → R1CS witness wire).
#[test]
fn fn_witness_lift_e2e_r1cs_bitops_dispatch() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::{HashMap, HashSet};
    use zkc::r1cs_backend::R1CSCompiler;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bitops_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("bit-op E2E compile failed: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");

    ir::passes::optimize(&mut program);

    // Compute σ0 reference on the chosen input so we can supply the
    // matching public-output value: `out === out` only tautologizes
    // once `out` has a concrete binding on both sides of the R1CS
    // wire, which requires a user-supplied public-input value.
    fn sigma0_ref(x: u32) -> u32 {
        let r7 = (x >> 7) | (x.wrapping_shl(25));
        let r18 = (x >> 18) | (x.wrapping_shl(14));
        let r3 = x >> 3;
        (r7 ^ r18) ^ r3
    }
    let input_val: u32 = 0xDEAD_BEEF;
    let expected_out = sigma0_ref(input_val);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert(
        "in".to_string(),
        FieldElement::<Bn254Fr>::from_u64(input_val as u64),
    );
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out as u64),
    );

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc
        .compile_ir_with_witness(&program, &inputs)
        .expect("compile_ir_with_witness");
    rc.cs
        .verify(&witness)
        .expect("R1CS should verify with Artik-dispatched σ0 witness");
}

/// Fase 3+4 end-to-end: an Artik-lifted circom function survives
/// through instantiate → optimize → R1CS compile, with the lifted
/// Artik program executed at witness-gen time to fill the output
/// wires. Verified by running `compile_ir_with_witness` and checking
/// that the R1CS verifier accepts the generated witness — this is
/// only possible if the Artik executor produced the same value the
/// downstream `===` constraint expects.
#[test]
fn fn_witness_lift_e2e_r1cs_artik_dispatch() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::{HashMap, HashSet};
    use zkc::r1cs_backend::R1CSCompiler;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Artik R1CS E2E test failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");

    ir::passes::optimize(&mut program);

    // The loop-test function `triangle_sum(n)` returns
    // `sum_{i=0..3} (n * i)` = 6*n; its template fixes that as the
    // `===` constraint. We pick n = 7 → expected out = 42.
    let n = 7u64;
    let expected_out = 6 * n;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc
        .compile_ir_with_witness(&program, &inputs)
        .expect("compile_ir_with_witness");
    rc.cs
        .verify(&witness)
        .expect("R1CS should verify after Artik dispatch");
}

/// Fase 2.4 mux extension: nested function calls on the RHS of
/// assignments inside either arm of a runtime if/else are admissible.
/// Each call inlines at nested_depth > 0 (return captured via
/// nested_result, no WriteWitness), so both arms execute their call
/// under the mux without corrupting the top-level witness write.
/// Validated by decoding the payload and running the Artik executor
/// with cond ∈ {0, 1} against a hand-computed reference.
#[test]
fn fn_witness_lift_mux_admits_nested_calls() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_mux_calls_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mux+calls lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("mux+calls payload must decode and validate");

    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    // cond=1 → triple(x) == 3x.
    let sigs = [FE::from_u64(1), FE::from_u64(17)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=1");
    assert_eq!(slots[0], FE::from_u64(51), "cond=1 should pick triple(x)");

    // cond=0 → quadruple(x) == 4x.
    let sigs = [FE::from_u64(0), FE::from_u64(17)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=0");
    assert_eq!(
        slots[0],
        FE::from_u64(68),
        "cond=0 should pick quadruple(x)"
    );
}
