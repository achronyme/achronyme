use super::*;

// ============================================================================
// Control flow
// ============================================================================

#[test]
fn ir_if_else() {
    // if flag { x } else { y } = out
    ir_pipeline_verify(
        &[("out", 10)],
        &[("flag", 1), ("x", 10), ("y", 20)],
        "assert_eq(if flag { x } else { y }, out)",
    );
}

#[test]
fn ir_if_else_false() {
    ir_pipeline_verify(
        &[("out", 20)],
        &[("flag", 0), ("x", 10), ("y", 20)],
        "assert_eq(if flag { x } else { y }, out)",
    );
}

#[test]
fn ir_for_loop() {
    // Sum x three times via loop
    ir_pipeline_verify(
        &[("out", 15)],
        &[("x", 5)],
        "let acc = x\nfor i in 0..2 {\nlet acc = acc + x\n}\nassert_eq(acc, out)",
    );
}

// ============================================================================
// Builtins
// ============================================================================

#[test]
fn ir_mux() {
    ir_pipeline_verify(
        &[("out", 42)],
        &[("flag", 1), ("a", 42), ("b", 99)],
        "assert_eq(mux(flag, a, b), out)",
    );
}

#[test]
fn ir_poseidon() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(1);
    let right = FieldElement::from_u64(2);
    let expected = poseidon_hash(&params, left, right);

    ir_pipeline_verify_fe(
        &[("out", expected)],
        &[("l", left), ("r", right)],
        "assert_eq(poseidon(l, r), out)",
    );
}

// ============================================================================
// Complex circuits
// ============================================================================

#[test]
fn ir_quadratic() {
    // x^2 + x + 5 = out → x=5, out=35
    ir_pipeline_verify(&[("out", 35)], &[("x", 5)], "assert_eq(x ^ 2 + x + 5, out)");
}

#[test]
fn ir_multi_constraint() {
    // x * y = z, z + 1 = out
    ir_pipeline_verify(
        &[("out", 43)],
        &[("x", 6), ("y", 7)],
        "let z = x * y\nassert_eq(z + 1, out)",
    );
}

// ============================================================================
// Optimized pipeline
// ============================================================================

#[test]
fn ir_optimized_constant_folding() {
    // 2 + 3 should fold, leaving no extra constraints
    ir_pipeline_optimized_verify(&[("out", 15)], &[("x", 10)], "assert_eq(x + 2 + 3, out)");
}

#[test]
fn ir_optimized_quadratic() {
    ir_pipeline_optimized_verify(&[("out", 35)], &[("x", 5)], "assert_eq(x ^ 2 + x + 5, out)");
}

#[test]
fn ir_optimized_poseidon() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(1);
    let right = FieldElement::from_u64(2);
    let expected = poseidon_hash(&params, left, right);

    let pub_names: Vec<&str> = vec!["out"];
    let wit_names: Vec<&str> = vec!["l", "r"];
    let source = "assert_eq(poseidon(l, r), out)";

    let mut program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("out".into(), expected);
    inputs.insert("l".into(), left);
    inputs.insert("r".into(), right);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).unwrap();
}
