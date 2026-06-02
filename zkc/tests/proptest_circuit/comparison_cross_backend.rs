use super::*;

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
