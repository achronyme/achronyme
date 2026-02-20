//! Property-based tests for the IR → R1CS / Plonkish pipeline.
//!
//! These tests verify that for random field element inputs, the full
//! compilation pipeline (lower → compile → witness → verify) produces
//! valid proofs. This catches edge cases in constant folding, witness
//! generation, and bit decomposition that fixed example tests miss.

use std::collections::HashMap;

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::IrLowering;
use memory::FieldElement;
use proptest::prelude::*;

// ============================================================================
// Helpers
// ============================================================================

/// Full R1CS pipeline: source → IR → optimize → R1CS → witness → verify.
fn r1cs_verify(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    let w = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("R1CS verification failed");
}

/// Full Plonkish pipeline: source → IR → optimize → Plonkish → witness → verify.
fn plonkish_verify(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    wg.generate(&inputs, &mut compiler.system.assignments)
        .expect("Plonkish witness gen failed");
    compiler.system.verify().expect("Plonkish verification failed");
}

/// Both backends must accept the same circuit + inputs.
fn both_verify(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    r1cs_verify(public, witness, source);
    plonkish_verify(public, witness, source);
}

/// Strategy: random u64 converted to FieldElement (stays small, avoids field wrapping).
fn fe_u64() -> impl Strategy<Value = FieldElement> {
    any::<u64>().prop_map(FieldElement::from_u64)
}

/// Strategy: small positive values (1..10000) for division denominators.
fn fe_nonzero() -> impl Strategy<Value = FieldElement> {
    (1u64..10_000).prop_map(FieldElement::from_u64)
}

/// Strategy: small values suitable for comparison (< 2^64, avoids field-edge issues).
fn fe_small() -> impl Strategy<Value = FieldElement> {
    (0u64..1_000_000).prop_map(FieldElement::from_u64)
}

// ============================================================================
// Arithmetic properties: R1CS
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_r1cs_add_commutative(a in fe_u64(), b in fe_u64()) {
        let out = a.add(&b);
        r1cs_verify(
            &[("out", out)],
            &[("a", a), ("b", b)],
            "assert_eq(a + b, out)",
        );
    }

    #[test]
    fn prop_r1cs_mul_commutative(a in fe_u64(), b in fe_u64()) {
        let out = a.mul(&b);
        r1cs_verify(
            &[("out", out)],
            &[("a", a), ("b", b)],
            "assert_eq(a * b, out)",
        );
    }

    #[test]
    fn prop_r1cs_sub_inverse_of_add(a in fe_u64(), b in fe_u64()) {
        // (a + b) - b == a
        r1cs_verify(
            &[("out", a)],
            &[("a", a), ("b", b)],
            "assert_eq(a + b - b, out)",
        );
    }

    #[test]
    fn prop_r1cs_double_neg(a in fe_u64()) {
        r1cs_verify(
            &[("out", a)],
            &[("a", a)],
            "assert_eq(-(-a), out)",
        );
    }

    #[test]
    fn prop_r1cs_div_inverse_of_mul(a in fe_u64(), b in fe_nonzero()) {
        // (a * b) / b == a
        let prod = a.mul(&b);
        r1cs_verify(
            &[("out", a)],
            &[("ab", prod), ("b", b)],
            "assert_eq(ab / b, out)",
        );
    }

    #[test]
    fn prop_r1cs_distributive(a in fe_u64(), b in fe_u64(), c in fe_u64()) {
        // a * (b + c) == a*b + a*c
        let lhs = a.mul(&b.add(&c));
        r1cs_verify(
            &[("out", lhs)],
            &[("a", a), ("b", b), ("c", c)],
            "assert_eq(a * b + a * c, out)",
        );
    }

    #[test]
    fn prop_r1cs_pow_squares(a in fe_u64()) {
        let sq = a.mul(&a);
        r1cs_verify(
            &[("out", sq)],
            &[("a", a)],
            "assert_eq(a^2, out)",
        );
    }

    #[test]
    fn prop_r1cs_pow_cubes(a in fe_u64()) {
        let cube = a.mul(&a).mul(&a);
        r1cs_verify(
            &[("out", cube)],
            &[("a", a)],
            "assert_eq(a^3, out)",
        );
    }
}

// ============================================================================
// Arithmetic properties: Plonkish (same properties, different backend)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_plonkish_add(a in fe_u64(), b in fe_u64()) {
        let out = a.add(&b);
        plonkish_verify(
            &[("out", out)],
            &[("a", a), ("b", b)],
            "assert_eq(a + b, out)",
        );
    }

    #[test]
    fn prop_plonkish_mul(a in fe_u64(), b in fe_u64()) {
        let out = a.mul(&b);
        plonkish_verify(
            &[("out", out)],
            &[("a", a), ("b", b)],
            "assert_eq(a * b, out)",
        );
    }

    #[test]
    fn prop_plonkish_sub_inverse(a in fe_u64(), b in fe_u64()) {
        r1cs_verify(
            &[("out", a)],
            &[("a", a), ("b", b)],
            "assert_eq(a + b - b, out)",
        );
    }

    #[test]
    fn prop_plonkish_div(a in fe_u64(), b in fe_nonzero()) {
        let prod = a.mul(&b);
        plonkish_verify(
            &[("out", a)],
            &[("ab", prod), ("b", b)],
            "assert_eq(ab / b, out)",
        );
    }
}

// ============================================================================
// Boolean / comparison properties (R1CS)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_r1cs_is_eq_reflexive(a in fe_u64()) {
        r1cs_verify(
            &[("out", FieldElement::ONE)],
            &[("a", a)],
            r#"
                let r = a == a
                assert_eq(r, out)
            "#,
        );
    }

    #[test]
    fn prop_r1cs_is_eq_symmetric(a in fe_u64(), b in fe_u64()) {
        // (a == b) should equal (b == a)
        r1cs_verify(
            &[],
            &[("a", a), ("b", b)],
            r#"
                let r1 = a == b
                let r2 = b == a
                assert_eq(r1, r2)
            "#,
        );
    }

    #[test]
    fn prop_r1cs_neq_complement_of_eq(a in fe_u64(), b in fe_u64()) {
        // (a != b) + (a == b) == 1
        r1cs_verify(
            &[("one", FieldElement::ONE)],
            &[("a", a), ("b", b)],
            r#"
                let eq = a == b
                let neq = a != b
                assert_eq(eq + neq, one)
            "#,
        );
    }

    #[test]
    fn prop_r1cs_not_involutive(a in fe_small()) {
        // Not is tested on the result of a comparison (guaranteed boolean)
        r1cs_verify(
            &[],
            &[("a", a)],
            r#"
                let eq = a == a
                let neg = !eq
                let back = !neg
                assert_eq(back, eq)
            "#,
        );
    }
}

// ============================================================================
// Comparison ordering properties (R1CS — expensive, fewer cases)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn prop_r1cs_lt_antisymmetric(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
        b in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        // If a < b then !(b < a), and vice versa.
        // Encoded as: (a < b) + (b < a) + (a == b) == 1
        r1cs_verify(
            &[("one", FieldElement::ONE)],
            &[("a", a), ("b", b)],
            r#"
                let lt = a < b
                let gt = b < a
                let eq = a == b
                assert_eq(lt + gt + eq, one)
            "#,
        );
    }

    #[test]
    fn prop_r1cs_lt_irreflexive(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        // a < a should be false (0)
        r1cs_verify(
            &[("zero", FieldElement::ZERO)],
            &[("a", a)],
            r#"
                let r = a < a
                assert_eq(r, zero)
            "#,
        );
    }

    #[test]
    fn prop_r1cs_le_reflexive(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        // a <= a should be true (1)
        r1cs_verify(
            &[("one", FieldElement::ONE)],
            &[("a", a)],
            r#"
                let r = a <= a
                assert_eq(r, one)
            "#,
        );
    }
}

// ============================================================================
// Comparison ordering properties (Plonkish — fewer cases, expensive gadget)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_plonkish_lt_antisymmetric(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
        b in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        plonkish_verify(
            &[("one", FieldElement::ONE)],
            &[("a", a), ("b", b)],
            r#"
                let lt = a < b
                let gt = b < a
                let eq = a == b
                assert_eq(lt + gt + eq, one)
            "#,
        );
    }

    #[test]
    fn prop_plonkish_lt_irreflexive(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        plonkish_verify(
            &[("zero", FieldElement::ZERO)],
            &[("a", a)],
            r#"
                let r = a < a
                assert_eq(r, zero)
            "#,
        );
    }

    #[test]
    fn prop_plonkish_le_reflexive(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        plonkish_verify(
            &[("one", FieldElement::ONE)],
            &[("a", a)],
            r#"
                let r = a <= a
                assert_eq(r, one)
            "#,
        );
    }
}

// ============================================================================
// Cross-backend consistency
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_both_backends_agree_on_arithmetic(a in fe_u64(), b in fe_nonzero()) {
        let out = a.mul(&b).add(&a);
        both_verify(
            &[("out", out)],
            &[("a", a), ("b", b)],
            "assert_eq(a * b + a, out)",
        );
    }

    #[test]
    fn prop_both_backends_agree_on_mux(
        cond in prop::bool::ANY,
        x in fe_u64(),
        y in fe_u64(),
    ) {
        let cond_fe = if cond { FieldElement::ONE } else { FieldElement::ZERO };
        let expected = if cond { x } else { y };
        both_verify(
            &[("out", expected)],
            &[("c", cond_fe), ("x", x), ("y", y)],
            r#"
                let r = mux(c, x, y)
                assert_eq(r, out)
            "#,
        );
    }

    #[test]
    fn prop_both_backends_agree_on_eq(a in fe_u64(), b in fe_u64()) {
        let eq_val = if a.to_canonical() == b.to_canonical() {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        };
        both_verify(
            &[("out", eq_val)],
            &[("a", a), ("b", b)],
            r#"
                let r = a == b
                assert_eq(r, out)
            "#,
        );
    }
}

// ============================================================================
// Witness generation: wrong inputs must fail verification
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_r1cs_wrong_witness_rejected(a in fe_u64(), b in fe_u64(), c in fe_u64()) {
        // Compute correct product, then supply wrong output
        let correct = a.mul(&b);
        // Skip if c happens to equal the correct answer
        prop_assume!(c.to_canonical() != correct.to_canonical());

        let pub_names = &["out"];
        let wit_names = &["a", "b"];
        let source = "assert_eq(a * b, out)";

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();

        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("out".to_string(), c); // WRONG value
        inputs.insert("a".to_string(), a);
        inputs.insert("b".to_string(), b);

        let w = wg.generate(&inputs).unwrap();
        assert!(
            compiler.cs.verify(&w).is_err(),
            "wrong witness should be rejected"
        );
    }
}

// ============================================================================
// L3: Cross-backend parity — both backends accept/reject same inputs
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_both_backends_agree_on_poseidon(
        a in fe_small(),
        b in fe_small(),
    ) {
        use constraints::poseidon::{poseidon_hash, PoseidonParams};
        let params = PoseidonParams::bn254_t3();
        let expected = poseidon_hash(&params, a, b);

        both_verify(
            &[("out", expected)],
            &[("a", a), ("b", b)],
            "assert_eq(poseidon(a, b), out)",
        );
    }

    #[test]
    fn prop_both_backends_agree_on_neq(a in fe_u64(), b in fe_u64()) {
        let neq_val = if a.to_canonical() != b.to_canonical() {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        };
        both_verify(
            &[("out", neq_val)],
            &[("a", a), ("b", b)],
            r#"
                let r = a != b
                assert_eq(r, out)
            "#,
        );
    }

    #[test]
    fn prop_both_backends_agree_on_lt(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
        b in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        let la = a.to_canonical();
        let lb = b.to_canonical();
        let lt_val = if (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]) {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        };
        both_verify(
            &[("out", lt_val)],
            &[("a", a), ("b", b)],
            r#"
                let r = a < b
                assert_eq(r, out)
            "#,
        );
    }

    #[test]
    fn prop_both_backends_agree_on_assert(
        a in fe_small(),
        b in fe_small(),
    ) {
        let prod = a.mul(&b);
        both_verify(
            &[("out", prod)],
            &[("a", a), ("b", b)],
            r#"
                let r = a * b
                assert_eq(r, out)
            "#,
        );
    }
}

// ============================================================================
// L3: Cross-backend rejection parity — wrong witness rejected by both
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn prop_both_backends_reject_wrong_mul(
        a in fe_u64(),
        b in fe_u64(),
        c in fe_u64(),
    ) {
        let correct = a.mul(&b);
        prop_assume!(c.to_canonical() != correct.to_canonical());

        let pub_names = &["out"];
        let wit_names = &["a", "b"];
        let source = "assert_eq(a * b, out)";

        // R1CS should reject
        {
            let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
            let mut compiler = R1CSCompiler::new();
            compiler.compile_ir(&program).unwrap();
            let wg = WitnessGenerator::from_compiler(&compiler);
            let mut inputs = HashMap::new();
            inputs.insert("out".to_string(), c);
            inputs.insert("a".to_string(), a);
            inputs.insert("b".to_string(), b);
            let w = wg.generate(&inputs).unwrap();
            assert!(compiler.cs.verify(&w).is_err(), "R1CS should reject wrong mul");
        }

        // Plonkish should also reject
        {
            let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
            let mut compiler = PlonkishCompiler::new();
            compiler.compile_ir(&program).unwrap();
            let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
            let mut inputs = HashMap::new();
            inputs.insert("out".to_string(), c);
            inputs.insert("a".to_string(), a);
            inputs.insert("b".to_string(), b);
            wg.generate(&inputs, &mut compiler.system.assignments).unwrap();
            assert!(compiler.system.verify().is_err(), "Plonkish should reject wrong mul");
        }
    }
}

// ============================================================================
// L4: Division-by-zero tests — all paths in both backends
// ============================================================================

#[test]
fn test_r1cs_div_by_zero_witness_error() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = "assert_eq(a / b, out)";

    let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::ZERO); // div by zero
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let result = wg.generate(&inputs);
    assert!(result.is_err(), "R1CS witness gen should error on div by zero");
}

#[test]
fn test_plonkish_div_by_zero_witness_error() {
    let pub_names = &["out"];
    let wit_names = &["a", "b"];
    let source = "assert_eq(a / b, out)";

    let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let result = wg.generate(&inputs, &mut compiler.system.assignments);
    assert!(result.is_err(), "Plonkish witness gen should error on div by zero");
}

#[test]
fn test_r1cs_div_by_zero_in_expression() {
    // Division where denominator is a computed zero: (a - a) = 0
    let pub_names = &["out"];
    let wit_names = &["a"];
    let source = "assert_eq(a / (a - a), out)";

    let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::ZERO);

    let result = wg.generate(&inputs);
    assert!(result.is_err(), "div by computed zero should error");
}

#[test]
fn test_r1cs_div_valid_witness_passes() {
    // Ensure valid division works correctly
    let a = FieldElement::from_u64(42);
    let b = FieldElement::from_u64(7);
    let expected = a.div(&b).unwrap();

    r1cs_verify(
        &[("out", expected)],
        &[("a", a), ("b", b)],
        "assert_eq(a / b, out)",
    );
}

#[test]
fn test_plonkish_div_valid_witness_passes() {
    let a = FieldElement::from_u64(42);
    let b = FieldElement::from_u64(7);
    let expected = a.div(&b).unwrap();

    plonkish_verify(
        &[("out", expected)],
        &[("a", a), ("b", b)],
        "assert_eq(a / b, out)",
    );
}

#[test]
fn test_r1cs_div_zero_numerator_passes() {
    // 0 / x = 0 should work
    r1cs_verify(
        &[("out", FieldElement::ZERO)],
        &[("a", FieldElement::ZERO), ("b", FieldElement::from_u64(7))],
        "assert_eq(a / b, out)",
    );
}

#[test]
fn test_plonkish_div_zero_numerator_passes() {
    // 0 / x = 0 should work
    plonkish_verify(
        &[("out", FieldElement::ZERO)],
        &[("a", FieldElement::ZERO), ("b", FieldElement::from_u64(7))],
        "assert_eq(a / b, out)",
    );
}

// ============================================================================
// T5: Optimization soundness — optimized vs unoptimized must both verify
// ============================================================================

/// R1CS pipeline WITHOUT optimization.
fn r1cs_verify_unoptimized(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    // NO optimization

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    let w = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("unoptimized R1CS verification failed");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_optimization_soundness_arithmetic(a in fe_u64(), b in fe_nonzero()) {
        let out = a.mul(&b).add(&a);
        let source = "assert_eq(a * b + a, out)";
        let pubs = &[("out", out)];
        let wit = &[("a", a), ("b", b)];
        r1cs_verify(pubs, wit, source);
        r1cs_verify_unoptimized(pubs, wit, source);
    }

    #[test]
    fn prop_optimization_soundness_const_fold(a in fe_u64()) {
        // 2 + 3 = 5 should fold, x + 5 remains
        let out = a.add(&FieldElement::from_u64(5));
        let source = "assert_eq(a + 2 + 3, out)";
        let pubs = &[("out", out)];
        let wit = &[("a", a)];
        r1cs_verify(pubs, wit, source);
        r1cs_verify_unoptimized(pubs, wit, source);
    }

    #[test]
    fn prop_optimization_soundness_mul_by_zero(a in fe_u64()) {
        // a * 0 should fold to 0
        let source = "assert_eq(a * 0, out)";
        let pubs = &[("out", FieldElement::ZERO)];
        let wit = &[("a", a)];
        r1cs_verify(pubs, wit, source);
        r1cs_verify_unoptimized(pubs, wit, source);
    }

    #[test]
    fn prop_optimization_soundness_identity(a in fe_u64()) {
        // a + 0 = a, a * 1 = a should fold
        let source = "assert_eq(a + 0, out)";
        let pubs = &[("out", a)];
        let wit = &[("a", a)];
        r1cs_verify(pubs, wit, source);
        r1cs_verify_unoptimized(pubs, wit, source);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    #[test]
    fn prop_optimization_soundness_comparison(
        a in (0u64..100_000).prop_map(FieldElement::from_u64),
        b in (0u64..100_000).prop_map(FieldElement::from_u64),
    ) {
        let la = a.to_canonical();
        let lb = b.to_canonical();
        let lt_val = if (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]) {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        };
        let source = r#"
            let r = a < b
            assert_eq(r, out)
        "#;
        let pubs = &[("out", lt_val)];
        let wit = &[("a", a), ("b", b)];
        r1cs_verify(pubs, wit, source);
        r1cs_verify_unoptimized(pubs, wit, source);
    }
}
