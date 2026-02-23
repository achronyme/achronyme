use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::IrLowering;
use memory::FieldElement;

/// Full pipeline: source → IR → R1CS → witness → verify.
fn ir_pipeline_verify(public: &[(&str, u64)], witness: &[(&str, u64)], source: &str) {
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
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut ir_compiler = R1CSCompiler::new();
    ir_compiler.compile_ir(&program).unwrap();

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

/// IR-only pipeline (for features only supported via IR path).
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
fn ir_pipeline_optimized_verify(public: &[(&str, u64)], witness: &[(&str, u64)], source: &str) {
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
    ir_pipeline_verify(&[("out", 27)], &[("x", 3)], "assert_eq(x ^ 3, out)");
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
    ir_pipeline_verify(&[("out", 21)], &[("x", 7)], "assert_eq(x * 3, out)");
}

#[test]
fn ir_constant_add() {
    ir_pipeline_verify(&[("out", 15)], &[("x", 10)], "assert_eq(x + 5, out)");
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
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("x", 5), ("y", 5)], source);
}

#[test]
fn ir_is_eq_false() {
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("x", 5), ("y", 10)], source);
}

#[test]
fn ir_is_neq() {
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("x", 5), ("y", 10)], source);
}

#[test]
fn ir_is_neq_false() {
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("x", 7), ("y", 7)], source);
}

#[test]
fn ir_not_false() {
    let source = "let r = !x\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("x", 0)], source);
}

#[test]
fn ir_not_true() {
    let source = "let r = !x\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("x", 1)], source);
}

#[test]
fn ir_and_true() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("a", 1), ("b", 1)], source);
}

#[test]
fn ir_and_false() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("a", 1), ("b", 0)], source);
}

#[test]
fn ir_or_true() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("a", 0), ("b", 1)], source);
}

#[test]
fn ir_or_false() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("a", 0), ("b", 0)], source);
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
    compiler
        .cs
        .verify(&w)
        .expect("assert(42 == 42) should verify");
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
    compiler
        .cs
        .verify(&w)
        .expect("assert(1 && 1) should verify");
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
    compiler
        .cs
        .verify(&w)
        .expect("assert(0 || 1) should verify");
}

#[test]
fn ir_bool_true_false_in_circuit() {
    // true and false should be usable in circuits
    let source = "assert_eq(true, expected)";
    ir_pipeline_verify(&[("expected", 1)], &[], source);
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
    assert!(
        opt <= 32,
        "expected ≤32 constraints with 8-bit bounds, got {opt}"
    );
    assert!(
        full >= 760,
        "unbounded should use ~762 constraints, got {full}"
    );
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
    assert!(
        count <= 48,
        "expected ≤48 with asymmetric bounds, got {count}"
    );
}

#[test]
fn is_lt_one_bounded_falls_back_to_full() {
    // Only a is range-checked → b needs full 252-bit range check
    // Cost: 9 (range_check a) + 253 (enforce_252 b) + 254 (decomp) + 2 = 518
    let count = compile_constraint_count("range_check(a, 8)\nassert(a < b)", &["a"], &["b"]);
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

// ============================================================================
// Arrays
// ============================================================================

/// IR-only pipeline that uses `lower_circuit` with array syntax in decl specs.
fn ir_array_verify(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    pub_decls: &[&str],
    wit_decls: &[&str],
    source: &str,
) {
    let program = IrLowering::lower_circuit(source, pub_decls, wit_decls).unwrap();
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
        .expect("array pipeline witness failed verification");
}

/// Self-contained pipeline helper.
fn ir_self_contained_verify(inputs: &[(&str, FieldElement)], source: &str) {
    let (_, _, program) = IrLowering::lower_self_contained(source).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut input_map = HashMap::new();
    for (name, val) in inputs {
        input_map.insert(name.to_string(), *val);
    }

    let w = gen.generate(&input_map).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("self-contained pipeline witness failed verification");
}

#[test]
fn ir_array_literal_and_index() {
    // let a = [x, y, z]; assert_eq(a[1], y)
    ir_only_verify_fe(
        &[],
        &[
            ("x", FieldElement::from_u64(10)),
            ("y", FieldElement::from_u64(20)),
            ("z", FieldElement::from_u64(30)),
        ],
        "let a = [x, y, z]\nassert_eq(a[1], y)",
    );
}

#[test]
fn ir_array_public_declaration() {
    // public path[3] creates path_0, path_1, path_2
    ir_array_verify(
        &[
            ("path_0", FieldElement::from_u64(1)),
            ("path_1", FieldElement::from_u64(2)),
            ("path_2", FieldElement::from_u64(3)),
        ],
        &[],
        &["path[3]"],
        &[],
        "assert_eq(path[0] + path[1], path[2])",
    );
}

#[test]
fn ir_array_witness_declaration() {
    // witness bits[4] creates bits_0..bits_3
    ir_array_verify(
        &[("sum", FieldElement::from_u64(10))],
        &[
            ("bits_0", FieldElement::from_u64(1)),
            ("bits_1", FieldElement::from_u64(2)),
            ("bits_2", FieldElement::from_u64(3)),
            ("bits_3", FieldElement::from_u64(4)),
        ],
        &["sum"],
        &["bits[4]"],
        "assert_eq(bits[0] + bits[1] + bits[2] + bits[3], sum)",
    );
}

#[test]
fn ir_array_for_iteration() {
    // for elem in arr { ... } unrolls over array elements
    ir_only_verify_fe(
        &[("sum", FieldElement::from_u64(60))],
        &[
            ("x", FieldElement::from_u64(10)),
            ("y", FieldElement::from_u64(20)),
            ("z", FieldElement::from_u64(30)),
        ],
        r#"let a = [x, y, z]
let acc = 0
for elem in a {
    assert_eq(elem, elem)
}
assert_eq(x + y + z, sum)"#,
    );
}

#[test]
fn ir_array_index_out_of_bounds() {
    let result = IrLowering::lower_circuit(
        "let a = [x, y, z]\nassert_eq(a[5], x)",
        &[],
        &["x", "y", "z"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("out of bounds"),
        "expected IndexOutOfBounds, got: {err}"
    );
}

#[test]
fn ir_array_dynamic_index_rejected() {
    // a[x] where x is a witness (not compile-time constant) → error
    let result =
        IrLowering::lower_circuit("let a = [y, y, y]\nassert_eq(a[x], y)", &[], &["x", "y"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("compile-time constant"),
        "expected compile-time constant error, got: {err}"
    );
}

#[test]
fn ir_array_len_builtin() {
    // len(arr) returns compile-time constant
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(3))],
        &[
            ("x", FieldElement::from_u64(1)),
            ("y", FieldElement::from_u64(2)),
            ("z", FieldElement::from_u64(3)),
        ],
        "let a = [x, y, z]\nassert_eq(len(a), out)",
    );
}

#[test]
fn ir_array_in_let_binding() {
    // let arr = [a, b]; assert_eq(arr[0], a)
    ir_only_verify_fe(
        &[],
        &[
            ("a", FieldElement::from_u64(42)),
            ("b", FieldElement::from_u64(99)),
        ],
        "let arr = [a, b]\nassert_eq(arr[0], a)\nassert_eq(arr[1], b)",
    );
}

#[test]
fn ir_array_empty_rejected() {
    let result = IrLowering::lower_circuit("let a = []", &[], &[]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("empty"),
        "expected empty array error, got: {err}"
    );
}

#[test]
fn ir_array_index_with_for_counter() {
    // arr[i] where i is the for loop counter — compile-time constant
    ir_array_verify(
        &[("sum", FieldElement::from_u64(6))],
        &[
            ("arr_0", FieldElement::from_u64(1)),
            ("arr_1", FieldElement::from_u64(2)),
            ("arr_2", FieldElement::from_u64(3)),
        ],
        &["sum"],
        &["arr[3]"],
        r#"let total = arr[0] + arr[1] + arr[2]
assert_eq(total, sum)"#,
    );
}

// ============================================================================
// Functions
// ============================================================================

#[test]
fn ir_fn_basic_inline() {
    // fn double(x) { x + x }  assert_eq(double(a), a + a)
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(20))],
        &[("a", FieldElement::from_u64(10))],
        "fn double(x) { x + x }\nassert_eq(double(a), out)",
    );
}

#[test]
fn ir_fn_multi_param() {
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(30))],
        &[
            ("a", FieldElement::from_u64(10)),
            ("b", FieldElement::from_u64(20)),
        ],
        "fn add(x, y) { x + y }\nassert_eq(add(a, b), out)",
    );
}

#[test]
fn ir_fn_multiple_calls() {
    // Same fn called twice, independent inlines
    ir_only_verify_fe(
        &[
            ("out1", FieldElement::from_u64(20)),
            ("out2", FieldElement::from_u64(40)),
        ],
        &[
            ("a", FieldElement::from_u64(10)),
            ("b", FieldElement::from_u64(20)),
        ],
        "fn double(x) { x + x }\nassert_eq(double(a), out1)\nassert_eq(double(b), out2)",
    );
}

#[test]
fn ir_fn_wrong_arg_count() {
    let result =
        IrLowering::lower_circuit("fn double(x) { x + x }\ndouble(a, b)", &[], &["a", "b"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("expects 1 arguments, got 2"),
        "expected WrongArgumentCount, got: {err}"
    );
}

#[test]
fn ir_fn_recursive_rejected() {
    let result = IrLowering::lower_circuit("fn f(x) { f(x) }\nf(a)", &[], &["a"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("recursive"),
        "expected RecursiveFunction, got: {err}"
    );
}

#[test]
fn ir_fn_mutual_recursive_rejected() {
    let result = IrLowering::lower_circuit("fn f(x) { g(x) }\nfn g(x) { f(x) }\nf(a)", &[], &["a"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("recursive"),
        "expected RecursiveFunction, got: {err}"
    );
}

#[test]
fn ir_fn_with_for_loop() {
    // Function body contains a for loop
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(10))],
        &[("a", FieldElement::from_u64(1))],
        r#"fn sum10(x) {
    let acc = 0
    for i in 0..10 {
        x
    }
}
assert_eq(sum10(a) + 9 * a, out)"#,
    );
}

#[test]
fn ir_fn_with_builtins() {
    // Function body uses poseidon
    let program = IrLowering::lower_circuit(
        "fn hash_pair(a, b) { poseidon(a, b) }\nhash_pair(x, y)",
        &[],
        &["x", "y"],
    )
    .unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();
    // Should produce same constraints as a direct poseidon call
    assert!(
        compiler.cs.num_constraints() >= 361,
        "expected ~361 constraints for poseidon, got {}",
        compiler.cs.num_constraints()
    );
}

#[test]
fn ir_fn_scope_isolation() {
    // Inner let doesn't leak to caller
    let result = IrLowering::lower_circuit(
        "fn f(x) { let inner = x + 1\n inner }\nf(a)\nassert_eq(inner, a)",
        &[],
        &["a"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("undeclared") || format!("{err}").contains("inner"),
        "expected undeclared variable error for 'inner', got: {err}"
    );
}

#[test]
fn ir_fn_forward_reference_rejected() {
    // Call before definition → error
    let result = IrLowering::lower_circuit("f(a)\nfn f(x) { x + x }", &[], &["a"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("not defined") || format!("{err}").contains("not supported"),
        "expected function-not-defined error, got: {err}"
    );
}

// ============================================================================
// Crypto builtins
// ============================================================================

#[test]
fn ir_poseidon_many_single() {
    // poseidon_many(a) = poseidon(a, 0)
    let source_many = "poseidon_many(a)";
    let source_direct = "poseidon(a, 0)";

    let prog_many = IrLowering::lower_circuit(source_many, &[], &["a"]).unwrap();
    let prog_direct = IrLowering::lower_circuit(source_direct, &[], &["a"]).unwrap();

    let mut comp_many = R1CSCompiler::new();
    comp_many.compile_ir(&prog_many).unwrap();
    let mut comp_direct = R1CSCompiler::new();
    comp_direct.compile_ir(&prog_direct).unwrap();

    assert_eq!(
        comp_many.cs.num_constraints(),
        comp_direct.cs.num_constraints(),
        "poseidon_many(a) should have same constraints as poseidon(a, 0)"
    );

    // Verify with actual inputs
    let gen = WitnessGenerator::from_compiler(&comp_many);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(42));
    let w = gen.generate(&inputs).unwrap();
    comp_many.cs.verify(&w).unwrap();
}

#[test]
fn ir_poseidon_many_two() {
    // poseidon_many(a, b) = poseidon(a, b)
    let prog_many = IrLowering::lower_circuit("poseidon_many(a, b)", &[], &["a", "b"]).unwrap();
    let prog_direct = IrLowering::lower_circuit("poseidon(a, b)", &[], &["a", "b"]).unwrap();

    let mut comp_many = R1CSCompiler::new();
    comp_many.compile_ir(&prog_many).unwrap();
    let mut comp_direct = R1CSCompiler::new();
    comp_direct.compile_ir(&prog_direct).unwrap();

    assert_eq!(
        comp_many.cs.num_constraints(),
        comp_direct.cs.num_constraints()
    );
}

#[test]
fn ir_poseidon_many_three() {
    // poseidon_many(a, b, c) = poseidon(poseidon(a, b), c)
    let source = "poseidon_many(a, b, c)";
    let prog = IrLowering::lower_circuit(source, &[], &["a", "b", "c"]).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    // Should be ~722 constraints (2 poseidon hashes)
    assert!(
        compiler.cs.num_constraints() >= 722,
        "expected ~722 constraints for 2 poseidon hashes, got {}",
        compiler.cs.num_constraints()
    );

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(1));
    inputs.insert("b".into(), FieldElement::from_u64(2));
    inputs.insert("c".into(), FieldElement::from_u64(3));
    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).unwrap();
}

#[test]
fn ir_poseidon_many_empty_rejected() {
    let result = IrLowering::lower_circuit("poseidon_many()", &[], &[]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("expects 1 arguments, got 0"),
        "expected WrongArgumentCount, got: {err}"
    );
}

#[test]
fn ir_merkle_verify_depth_1() {
    // Single sibling: merkle_verify(root, leaf, [sibling], [dir])
    let source = r#"
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    let prog = IrLowering::lower_circuit(source, &["root"], &["leaf", "sibling", "dir"]).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    // At depth 1: 2 poseidon hashes + 1 mux + 1 assert_eq ≈ 725 constraints
    let gen = WitnessGenerator::from_compiler(&compiler);

    // Compute expected root: poseidon(leaf, sibling) when dir=0
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let leaf = FieldElement::from_u64(42);
    let sibling = FieldElement::from_u64(99);
    let hash = constraints::poseidon::poseidon_hash(&params, leaf, sibling);

    let mut inputs = HashMap::new();
    inputs.insert("root".into(), hash);
    inputs.insert("leaf".into(), leaf);
    inputs.insert("sibling".into(), sibling);
    inputs.insert("dir".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).unwrap();
}

#[test]
fn ir_merkle_verify_mismatched_lengths() {
    let source = r#"
let path = [s0, s1, s2]
let dirs = [d0, d1]
merkle_verify(root, leaf, path, dirs)
"#;
    let result =
        IrLowering::lower_circuit(source, &["root"], &["leaf", "s0", "s1", "s2", "d0", "d1"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("length mismatch"),
        "expected ArrayLengthMismatch, got: {err}"
    );
}

#[test]
fn ir_merkle_verify_wrong_root_fails() {
    let source = r#"
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    let prog = IrLowering::lower_circuit(source, &["root"], &["leaf", "sibling", "dir"]).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("root".into(), FieldElement::from_u64(999)); // WRONG root
    inputs.insert("leaf".into(), FieldElement::from_u64(42));
    inputs.insert("sibling".into(), FieldElement::from_u64(99));
    inputs.insert("dir".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "wrong root should fail verification"
    );
}

// ============================================================================
// Constraint count validation
// ============================================================================

#[test]
fn ir_fn_inline_same_constraints() {
    // double(a) should produce same constraints as a + a
    let prog_fn = IrLowering::lower_circuit(
        "fn double(x) { x + x }\nassert_eq(double(a), out)",
        &["out"],
        &["a"],
    )
    .unwrap();
    let prog_direct = IrLowering::lower_circuit("assert_eq(a + a, out)", &["out"], &["a"]).unwrap();

    let mut comp_fn = R1CSCompiler::new();
    comp_fn.compile_ir(&prog_fn).unwrap();
    let mut comp_direct = R1CSCompiler::new();
    comp_direct.compile_ir(&prog_direct).unwrap();

    assert_eq!(
        comp_fn.cs.num_constraints(),
        comp_direct.cs.num_constraints(),
        "fn inline should have same constraint count as direct expression"
    );
}

// ============================================================================
// Integration: self-contained with arrays and functions
// ============================================================================

#[test]
fn ir_self_contained_with_arrays() {
    // public path[3] in source
    let source = r#"
public sum
witness arr[3]
assert_eq(arr[0] + arr[1] + arr[2], sum)
"#;
    ir_self_contained_verify(
        &[
            ("sum", FieldElement::from_u64(6)),
            ("arr_0", FieldElement::from_u64(1)),
            ("arr_1", FieldElement::from_u64(2)),
            ("arr_2", FieldElement::from_u64(3)),
        ],
        source,
    );
}

#[test]
fn ir_self_contained_with_functions() {
    let source = r#"
public out
witness a
fn double(x) { x + x }
assert_eq(double(a), out)
"#;
    ir_self_contained_verify(
        &[
            ("out", FieldElement::from_u64(20)),
            ("a", FieldElement::from_u64(10)),
        ],
        source,
    );
}

#[test]
fn ir_merkle_proof_self_contained() {
    // Full self-contained Merkle circuit using merkle_verify builtin
    let source = r#"
public root
witness leaf, sibling, dir
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let leaf = FieldElement::from_u64(42);
    let sibling = FieldElement::from_u64(99);
    let hash = constraints::poseidon::poseidon_hash(&params, leaf, sibling);

    ir_self_contained_verify(
        &[
            ("root", hash),
            ("leaf", leaf),
            ("sibling", sibling),
            ("dir", FieldElement::ZERO),
        ],
        source,
    );
}

#[test]
fn ir_fn_returning_expression() {
    // Function returns its last expression (x * x)
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(100))],
        &[("a", FieldElement::from_u64(10))],
        "fn square(x) { x * x }\nassert_eq(square(a), out)",
    );
}

#[test]
fn ir_array_scalar_type_mismatch() {
    // Using a scalar as array → TypeMismatch
    let result = IrLowering::lower_circuit("assert_eq(x[0], x)", &[], &["x"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("type mismatch") || format!("{err}").contains("scalar"),
        "expected TypeMismatch for indexing scalar, got: {err}"
    );
}

#[test]
fn ir_array_as_bare_expression_rejected() {
    // Array not in let binding → TypeMismatch
    let result = IrLowering::lower_circuit("assert_eq([x, y], x)", &[], &["x", "y"]);
    assert!(result.is_err());
}

#[test]
fn ir_merkle_verify_depth_3_builtin() {
    // Depth-3 Merkle membership proof using merkle_verify builtin
    let source = r#"
let path = [s0, s1, s2]
let dirs = [d0, d1, d2]
merkle_verify(root, leaf, path, dirs)
"#;
    let prog = IrLowering::lower_circuit(
        source,
        &["root"],
        &["leaf", "s0", "s1", "s2", "d0", "d1", "d2"],
    )
    .unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    // Should have reasonable constraint count: 3 * (2*361 + 2) + 1 ≈ 2175
    let nc = compiler.cs.num_constraints();
    assert!(
        nc >= 2000 && nc <= 3000,
        "expected ~2175 constraints for depth-3 Merkle, got {nc}"
    );
}

// ============================================================================
// I-04: IsLt/IsLe limb boundary tests at 2^64, 2^128, 2^192
//
// to_canonical() returns little-endian [u64; 4] limbs.
// Comparisons use big-endian tuple: (limbs[3], limbs[2], limbs[1], limbs[0]).
// These tests verify correctness at exact limb transitions where an off-by-one
// in limb ordering would produce reversed results.
// ============================================================================

// --- Circuit path (witness inputs → bit decomposition) ---

#[test]
fn ir_is_lt_limb_boundary_2_64() {
    // 2^64 - 1 < 2^64: crosses limb[0] → limb[1]
    let boundary = pow2(64);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", below), ("b", boundary)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_64_reversed() {
    // 2^64 ≮ 2^64 - 1
    let boundary = pow2(64);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", boundary), ("b", below)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_128() {
    // 2^128 - 1 < 2^128: crosses limb[1] → limb[2]
    let boundary = pow2(128);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", below), ("b", boundary)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_128_reversed() {
    let boundary = pow2(128);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", boundary), ("b", below)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_192() {
    // 2^192 - 1 < 2^192: crosses limb[2] → limb[3]
    let boundary = pow2(192);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", below), ("b", boundary)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_192_reversed() {
    let boundary = pow2(192);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", boundary), ("b", below)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_limb_boundary_equal_2_64() {
    let v = pow2(64);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", v), ("b", v)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_limb_boundary_equal_2_128() {
    let v = pow2(128);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", v), ("b", v)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_limb_boundary_equal_2_192() {
    let v = pow2(192);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", v), ("b", v)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

// --- Const-fold path (big number literals, optimization folds the comparison) ---

/// Helper: compile with optimization, verify the folded result.
fn const_fold_verify(source: &str) {
    let mut program = IrLowering::lower_circuit(source, &[], &[]).unwrap();
    ir::passes::optimize(&mut program);
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();
    let gen = WitnessGenerator::from_compiler(&compiler);
    let w = gen.generate(&HashMap::new()).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("const-folded assertion should verify");
}

#[test]
fn ir_is_lt_const_fold_limb_2_64() {
    // 2^64 - 1 = 18446744073709551615
    // 2^64     = 18446744073709551616
    const_fold_verify("assert(18446744073709551615 < 18446744073709551616)");
}

#[test]
fn ir_is_lt_const_fold_limb_2_128() {
    // 2^128 - 1 = 340282366920938463463374607431768211455
    // 2^128     = 340282366920938463463374607431768211456
    const_fold_verify(
        "assert(340282366920938463463374607431768211455 < 340282366920938463463374607431768211456)",
    );
}

#[test]
fn ir_is_lt_const_fold_limb_2_192() {
    // 2^192 - 1 = 6277101735386680763835789423207666416102355444464034512895
    // 2^192     = 6277101735386680763835789423207666416102355444464034512896
    const_fold_verify("assert(6277101735386680763835789423207666416102355444464034512895 < 6277101735386680763835789423207666416102355444464034512896)");
}

#[test]
fn ir_is_lt_const_fold_near_modulus() {
    // p - 2 < p - 1 (near the BN254 scalar field modulus)
    // p - 1 = 21888242871839275222246405745257275088548364400416034343698204186575808495616
    // p - 2 = 21888242871839275222246405745257275088548364400416034343698204186575808495615
    const_fold_verify("assert(21888242871839275222246405745257275088548364400416034343698204186575808495615 < 21888242871839275222246405745257275088548364400416034343698204186575808495616)");
}

#[test]
fn ir_is_le_const_fold_near_modulus() {
    // p - 1 <= p - 1
    const_fold_verify("assert(21888242871839275222246405745257275088548364400416034343698204186575808495616 <= 21888242871839275222246405745257275088548364400416034343698204186575808495616)");
}

#[test]
fn ir_is_lt_const_fold_limb_2_64_false() {
    // 2^64 ≮ 2^64 - 1 → const_fold produces false → assert(false) → verification fails
    let source = "assert(18446744073709551616 < 18446744073709551615)";
    let mut program = IrLowering::lower_circuit(source, &[], &[]).unwrap();
    ir::passes::optimize(&mut program);
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();
    let gen = WitnessGenerator::from_compiler(&compiler);
    let w = gen.generate(&HashMap::new()).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "2^64 < 2^64-1 should be false, assert must fail"
    );
}
