use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::IrLowering;
use memory::FieldElement;

/// Full pipeline: source → IR → (optimize) → R1CS → witness → verify.
/// Also checks constraint count parity with the direct compile_circuit pipeline.
fn ir_pipeline_verify(
    public: &[(&str, u64)],
    witness: &[(&str, u64)],
    source: &str,
) {
    ir_pipeline_verify_fe(
        &public
            .iter()
            .map(|(n, v)| (*n, FieldElement::from_u64(*v)))
            .collect::<Vec<_>>(),
        &witness
            .iter()
            .map(|(n, v)| (*n, FieldElement::from_u64(*v)))
            .collect::<Vec<_>>(),
        source,
    );
}

fn ir_pipeline_verify_fe(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    // --- Direct pipeline (reference) ---
    let mut direct = R1CSCompiler::new();
    for (name, _) in public {
        direct.declare_public(name);
    }
    for (name, _) in witness {
        direct.declare_witness(name);
    }
    direct.compile_circuit(source).unwrap();
    let direct_constraints = direct.cs.num_constraints();

    // --- IR pipeline ---
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut ir_compiler = R1CSCompiler::new();
    ir_compiler.compile_ir(&program).unwrap();

    let ir_constraints = ir_compiler.cs.num_constraints();

    // Constraint count parity
    assert_eq!(
        ir_constraints, direct_constraints,
        "IR pipeline ({ir_constraints}) != direct pipeline ({direct_constraints}) constraint count"
    );

    // Witness generation + verification
    let gen = WitnessGenerator::from_compiler(&ir_compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), *val);
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), *val);
    }

    let w = gen.generate(&inputs).unwrap();
    ir_compiler
        .cs
        .verify(&w)
        .expect("IR pipeline witness failed verification");
}

/// IR-only pipeline (no direct compile_circuit comparison).
/// Used for features only supported via IR path (comparisons, etc.).
fn ir_only_verify_fe(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), *val);
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), *val);
    }

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("IR-only pipeline witness failed verification");
}

/// Same but with optimization enabled.
fn ir_pipeline_optimized_verify(
    public: &[(&str, u64)],
    witness: &[(&str, u64)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("optimized IR pipeline witness failed verification");
}

// ============================================================================
// Basic arithmetic
// ============================================================================

#[test]
fn ir_simple_add() {
    ir_pipeline_verify(
        &[("out", 30)],
        &[("x", 10), ("y", 20)],
        "assert_eq(x + y, out)",
    );
}

#[test]
fn ir_simple_sub() {
    ir_pipeline_verify(
        &[("out", 5)],
        &[("x", 15), ("y", 10)],
        "assert_eq(x - y, out)",
    );
}

#[test]
fn ir_simple_mul() {
    ir_pipeline_verify(
        &[("out", 42)],
        &[("x", 6), ("y", 7)],
        "assert_eq(x * y, out)",
    );
}

#[test]
fn ir_simple_div() {
    ir_pipeline_verify(
        &[("out", 5)],
        &[("x", 30), ("y", 6)],
        "assert_eq(x / y, out)",
    );
}

#[test]
fn ir_negation() {
    // -x + y = out → x=10, y=15, out=5
    ir_pipeline_verify(
        &[("out", 5)],
        &[("x", 10), ("y", 15)],
        "assert_eq(-x + y, out)",
    );
}

#[test]
fn ir_power() {
    // x^3 = out → x=3, out=27
    ir_pipeline_verify(
        &[("out", 27)],
        &[("x", 3)],
        "assert_eq(x ^ 3, out)",
    );
}

// ============================================================================
// Let bindings
// ============================================================================

#[test]
fn ir_let_binding() {
    ir_pipeline_verify(
        &[("out", 50)],
        &[("x", 5), ("y", 10)],
        "let z = x * y\nassert_eq(z, out)",
    );
}

#[test]
fn ir_let_chain() {
    ir_pipeline_verify(
        &[("out", 50)],
        &[("x", 5)],
        "let y = x * x\nlet z = y + y\nassert_eq(z, out)",
    );
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn ir_constant_mul() {
    // x * 3 = out → x=7, out=21
    ir_pipeline_verify(
        &[("out", 21)],
        &[("x", 7)],
        "assert_eq(x * 3, out)",
    );
}

#[test]
fn ir_constant_add() {
    ir_pipeline_verify(
        &[("out", 15)],
        &[("x", 10)],
        "assert_eq(x + 5, out)",
    );
}

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
    ir_pipeline_verify(
        &[("out", 35)],
        &[("x", 5)],
        "assert_eq(x ^ 2 + x + 5, out)",
    );
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
    ir_pipeline_optimized_verify(
        &[("out", 15)],
        &[("x", 10)],
        "assert_eq(x + 2 + 3, out)",
    );
}

#[test]
fn ir_optimized_quadratic() {
    ir_pipeline_optimized_verify(
        &[("out", 35)],
        &[("x", 5)],
        "assert_eq(x ^ 2 + x + 5, out)",
    );
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

    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("out".into(), expected);
    inputs.insert("l".into(), left);
    inputs.insert("r".into(), right);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).unwrap();
}

// ============================================================================
// Boolean / comparison operators — IR → R1CS E2E
// ============================================================================

#[test]
fn ir_is_eq_true() {
    // x == y where x=5, y=5 → result=1, assert that
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 1)],
        &[("x", 5), ("y", 5)],
        source,
    );
}

#[test]
fn ir_is_eq_false() {
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 0)],
        &[("x", 5), ("y", 10)],
        source,
    );
}

#[test]
fn ir_is_neq() {
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 1)],
        &[("x", 5), ("y", 10)],
        source,
    );
}

#[test]
fn ir_is_neq_false() {
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 0)],
        &[("x", 7), ("y", 7)],
        source,
    );
}

#[test]
fn ir_not_false() {
    let source = "let r = !x\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 1)],
        &[("x", 0)],
        source,
    );
}

#[test]
fn ir_not_true() {
    let source = "let r = !x\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 0)],
        &[("x", 1)],
        source,
    );
}

#[test]
fn ir_and_true() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 1)],
        &[("a", 1), ("b", 1)],
        source,
    );
}

#[test]
fn ir_and_false() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 0)],
        &[("a", 1), ("b", 0)],
        source,
    );
}

#[test]
fn ir_or_true() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 1)],
        &[("a", 0), ("b", 1)],
        source,
    );
}

#[test]
fn ir_or_false() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(
        &[("expected", 0)],
        &[("a", 0), ("b", 0)],
        source,
    );
}

#[test]
fn ir_assert_pass() {
    // assert(true) should produce constraints that verify
    let source = "assert(flag)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["flag"];
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("flag".into(), FieldElement::ONE);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(1) should verify");
}

#[test]
fn ir_assert_eq_via_operators() {
    // assert(x == y) should work as a constraint
    let source = "assert(x == y)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["x", "y"];
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), FieldElement::from_u64(42));
    inputs.insert("y".into(), FieldElement::from_u64(42));

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(42 == 42) should verify");
}

#[test]
fn ir_assert_not_false() {
    // assert(!flag) where flag=0 → should pass
    let source = "assert(!flag)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["flag"];
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("flag".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(!0) should verify");
}

#[test]
fn ir_assert_and() {
    // assert(a && b) where a=1, b=1
    let source = "assert(a && b)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["a", "b"];
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::ONE);
    inputs.insert("b".into(), FieldElement::ONE);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(1 && 1) should verify");
}

#[test]
fn ir_assert_or() {
    // assert(a || b) where a=0, b=1
    let source = "assert(a || b)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["a", "b"];
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::ZERO);
    inputs.insert("b".into(), FieldElement::ONE);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(0 || 1) should verify");
}

#[test]
fn ir_bool_true_false_in_circuit() {
    // true and false should be usable in circuits
    let source = "assert_eq(true, expected)";
    ir_pipeline_verify(
        &[("expected", 1)],
        &[],
        source,
    );
}

#[test]
fn ir_optimized_complex() {
    // Multi-step with constants that can fold
    ir_pipeline_optimized_verify(
        &[("out", 50)],
        &[("x", 5)],
        "let a = 2 * 5\nlet b = x * a\nassert_eq(b, out)",
    );
}

// ====================================================================
// Soundness tests — verify cheating prover cannot forge results
// ====================================================================

#[test]
fn ir_assert_false_fails_verification() {
    let source = "assert(flag)";
    let program = IrLowering::lower_circuit(source, &[], &["flag"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("flag".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "assert(0) must fail R1CS verification"
    );
}

#[test]
fn ir_is_eq_soundness_wrong_result_rejected() {
    // x == y where x=5, y=10 but we claim result=1 (forged equality)
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    let program = IrLowering::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), FieldElement::from_u64(5));
    inputs.insert("y".into(), FieldElement::from_u64(10));
    inputs.insert("expected".into(), FieldElement::ONE); // WRONG: 5 != 10

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "claiming 5 == 10 must fail verification (IsZero gadget soundness)"
    );
}

#[test]
fn ir_is_neq_soundness_wrong_result_rejected() {
    // x != y where x=7, y=7 but we claim result=1 (forged inequality)
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    let program = IrLowering::lower_circuit(source, &["expected"], &["x", "y"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), FieldElement::from_u64(7));
    inputs.insert("y".into(), FieldElement::from_u64(7));
    inputs.insert("expected".into(), FieldElement::ONE); // WRONG: 7 == 7

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "claiming 7 != 7 must fail verification"
    );
}

#[test]
fn ir_is_lt_soundness_wrong_result_rejected() {
    let source = "let lt = a < b\nassert_eq(lt, expected)";
    let program = IrLowering::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(10));
    inputs.insert("b".into(), FieldElement::from_u64(3));
    inputs.insert("expected".into(), FieldElement::ONE); // WRONG: 10 >= 3

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "claiming 10 < 3 must fail verification"
    );
}

#[test]
fn ir_and_non_boolean_input_fails() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    let program = IrLowering::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(2)); // NOT boolean
    inputs.insert("b".into(), FieldElement::ONE);
    inputs.insert("expected".into(), FieldElement::from_u64(2));

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "a=2 should fail boolean enforcement in And operator"
    );
}

#[test]
fn ir_or_non_boolean_input_fails() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    let program = IrLowering::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(3)); // NOT boolean
    inputs.insert("b".into(), FieldElement::ZERO);
    inputs.insert("expected".into(), FieldElement::from_u64(3));

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "a=3 should fail boolean enforcement in Or operator"
    );
}

// ============================================================================
// T1: IsLt/IsLe boundary tests near 2^252
// ============================================================================

/// Compute 2^n as a FieldElement.
fn pow2(n: u32) -> FieldElement {
    let mut v = FieldElement::ONE;
    for _ in 0..n {
        v = v.add(&v);
    }
    v
}

#[test]
fn ir_is_lt_boundary_adjacent_at_max() {
    // a = 2^252 - 2, b = 2^252 - 1 → a < b = true
    let max = pow2(252).sub(&FieldElement::ONE); // 2^252 - 1
    let almost = max.sub(&FieldElement::ONE); // 2^252 - 2
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", almost), ("b", max)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_equal_values() {
    // a = 0, b = 0 → a < b = false (diff = 2^252 - 1, bit 252 = 0)
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", FieldElement::ZERO), ("b", FieldElement::ZERO)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_zero_vs_max() {
    // a = 0, b = 2^252 - 1 → a < b = true (maximum valid diff)
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", FieldElement::ZERO), ("b", max)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_max_vs_zero() {
    // a = 2^252 - 1, b = 0 → a < b = false
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", max), ("b", FieldElement::ZERO)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_max_equal() {
    // a = 2^252 - 1, b = 2^252 - 1 → a < b = false
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", max), ("b", max)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_boundary_max_equal() {
    // a = 2^252 - 1, b = 2^252 - 1 → a <= b = true
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", max), ("b", max)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_boundary_max_vs_zero() {
    // a = 2^252 - 1, b = 0 → a <= b = false
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", max), ("b", FieldElement::ZERO)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_boundary_zero_vs_max() {
    // a = 0, b = 2^252 - 1 → a <= b = true
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", FieldElement::ZERO), ("b", max)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

// ============================================================================
// T2: Division constraint soundness vs malicious prover
// ============================================================================

#[test]
fn ir_division_malicious_witness_divisor_zero_rejected() {
    // Compile a/b, then craft a witness where b=0 and a=0, claiming result=42.
    // The constraint den * inv = 1 cannot be satisfied when den=0.
    let source = "assert_eq(a / b, out)";
    let program = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    // Build witness from honest generator with valid inputs to get correct size
    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut honest_inputs = HashMap::new();
    honest_inputs.insert("a".into(), FieldElement::from_u64(42));
    honest_inputs.insert("b".into(), FieldElement::from_u64(7));
    honest_inputs.insert("out".into(), FieldElement::from_u64(6));
    let mut w = gen.generate(&honest_inputs).unwrap();

    // Now corrupt: set b=0 in the witness (wire index for b)
    // Wire layout: [ONE, pub(out), wit(a), wit(b), intermediates...]
    // b is the 4th wire (index 3)
    w[3] = FieldElement::ZERO;

    assert!(
        compiler.cs.verify(&w).is_err(),
        "division with divisor=0 in witness must fail constraint verification"
    );
}

#[test]
fn ir_division_malicious_witness_forged_result_rejected() {
    // Honest computation: 42/7=6. Prover claims result=99.
    let source = "assert_eq(a / b, out)";
    let program = IrLowering::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(42));
    inputs.insert("b".into(), FieldElement::from_u64(7));
    inputs.insert("out".into(), FieldElement::from_u64(99)); // WRONG result

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "forged division result must fail verification"
    );
}

// ============================================================================
// M1: IsLt/IsLe bounded-input optimization tests
// ============================================================================

/// Helper: compile source with given pub/wit names and return constraint count.
fn compile_constraint_count(source: &str, public: &[&str], witness: &[&str]) -> usize {
    let program = IrLowering::lower_circuit(source, public, witness).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();
    compiler.cs.num_constraints()
}

#[test]
fn is_lt_fewer_constraints_with_prior_range_check() {
    // Unbounded: 760 (2×253 range + 254 decomp) + 2 (assert) = 762
    let full = compile_constraint_count("assert(a < b)", &["a"], &["b"]);

    // Bounded to 8 bits: 9+9 (range_check) + 10 (9-bit decomp) + 2 (assert) = 30
    let opt = compile_constraint_count(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
        &["a"],
        &["b"],
    );

    assert!(
        opt < full,
        "bounded should use fewer constraints: {opt} vs {full}"
    );
    assert!(opt <= 32, "expected ≤32 constraints with 8-bit bounds, got {opt}");
    assert!(full >= 760, "unbounded should use ~762 constraints, got {full}");
}

#[test]
fn is_le_fewer_constraints_with_prior_range_check() {
    let full = compile_constraint_count("assert(a <= b)", &["a"], &["b"]);
    let opt = compile_constraint_count(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a <= b)",
        &["a"],
        &["b"],
    );

    assert!(opt < full, "bounded should use fewer: {opt} vs {full}");
    assert!(opt <= 32, "expected ≤32 with 8-bit bounds, got {opt}");
}

#[test]
fn is_lt_asymmetric_bounds_uses_max() {
    // range_check(a, 8) + range_check(b, 16) → effective_bits = 16
    // Cost: 9 + 17 + 18 + 2 = 46
    let count = compile_constraint_count(
        "range_check(a, 8)\nrange_check(b, 16)\nassert(a < b)",
        &["a"],
        &["b"],
    );
    assert!(count <= 48, "expected ≤48 with asymmetric bounds, got {count}");
}

#[test]
fn is_lt_one_bounded_falls_back_to_full() {
    // Only a is range-checked → b needs full 252-bit range check
    // Cost: 9 (range_check a) + 253 (enforce_252 b) + 254 (decomp) + 2 = 518
    let count = compile_constraint_count(
        "range_check(a, 8)\nassert(a < b)",
        &["a"],
        &["b"],
    );
    // Should be less than full (saves one 252-bit range check = 253 constraints)
    let full = compile_constraint_count("assert(a < b)", &["a"], &["b"]);
    assert!(
        count < full,
        "one bounded should save one range check: {count} vs {full}"
    );
}

#[test]
fn is_lt_bounded_correct_values() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(100))],
        &[("b", FieldElement::from_u64(200))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
    );
}

#[test]
fn is_le_bounded_equal_values() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(42))],
        &[("b", FieldElement::from_u64(42))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a <= b)",
    );
}

#[test]
fn is_lt_bounded_max_values_for_bits() {
    // Both at max of 8-bit range: 254 < 255
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(254))],
        &[("b", FieldElement::from_u64(255))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
    );
}

#[test]
fn is_lt_bounded_zero_values() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(0))],
        &[("b", FieldElement::from_u64(1))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
    );
}

#[test]
fn is_lt_bounded_asymmetric_correct() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(200))],
        &[("b", FieldElement::from_u64(50000))],
        "range_check(a, 8)\nrange_check(b, 16)\nassert(a < b)",
    );
}
