use super::*;

// ============================================================================
// Adversarial witness: wrong mux output rejected
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Wrong mux output must be rejected.
    #[test]
    fn prop_wrong_mux_rejected(
        cond in prop::bool::ANY,
        a in fe_u64(),
        b in fe_u64(),
        wrong in fe_u64(),
    ) {
        let c = if cond { FieldElement::ONE } else { FieldElement::ZERO };
        let correct = if cond { a } else { b };
        prop_assume!(wrong.to_canonical() != correct.to_canonical());

        let pub_names = &["out"];
        let wit_names = &["c", "a", "b"];
        let source = "assert_eq(mux(c, a, b), out)";

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();
        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("out".to_string(), wrong);
        inputs.insert("c".to_string(), c);
        inputs.insert("a".to_string(), a);
        inputs.insert("b".to_string(), b);
        let w = wg.generate(&inputs).unwrap();
        prop_assert!(compiler.cs.verify(&w).is_err(), "wrong mux output must be rejected");
    }

    /// Wrong division result must be rejected.
    #[test]
    fn prop_wrong_div_rejected(a in fe_u64(), b in fe_nonzero(), wrong in fe_u64()) {
        let correct = a.div(&b).unwrap();
        prop_assume!(wrong.to_canonical() != correct.to_canonical());

        let pub_names = &["out"];
        let wit_names = &["a", "b"];
        let source = "assert_eq(a / b, out)";

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();
        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("out".to_string(), wrong);
        inputs.insert("a".to_string(), a);
        inputs.insert("b".to_string(), b);
        let w = wg.generate(&inputs).unwrap();
        prop_assert!(compiler.cs.verify(&w).is_err(), "wrong division result must be rejected");
    }

    /// Non-boolean condition in mux must be rejected.
    #[test]
    fn prop_non_boolean_mux_cond_rejected(
        c_raw in (2u64..1_000_000).prop_map(FieldElement::from_u64),
        a in fe_u64(),
        b in fe_u64(),
    ) {
        let pub_names = &["out"];
        let wit_names = &["c", "a", "b"];
        let source = "assert_eq(mux(c, a, b), out)";

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();
        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("out".to_string(), a); // doesn't matter
        inputs.insert("c".to_string(), c_raw); // NOT boolean
        inputs.insert("a".to_string(), a);
        inputs.insert("b".to_string(), b);
        let w = wg.generate(&inputs).unwrap();
        prop_assert!(
            compiler.cs.verify(&w).is_err(),
            "non-boolean mux condition must be rejected"
        );
    }
}

// ============================================================================
// Adversarial witness: range_check overflow attacks
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Value exceeding range_check limit must be rejected.
    /// This is the Dark Forest class of vulnerability — overflow via large values.
    #[test]
    fn prop_range_check_overflow_rejected(
        bits in 1u32..32,
        offset in 0u64..100,
    ) {
        // 2^bits + offset should exceed the range check
        let overflow_val: FieldElement = FieldElement::from_u64((1u64 << bits) + offset);
        let pub_names: &[&str] = &[];
        let wit_names = &["x"];
        let source = &format!("range_check(x, {bits})");

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();
        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("x".to_string(), overflow_val);
        let w = wg.generate(&inputs).unwrap();
        prop_assert!(
            compiler.cs.verify(&w).is_err(),
            "value 2^{bits}+{offset} must fail range_check({bits})"
        );
    }

    /// Value within range_check limit must be accepted.
    #[test]
    fn prop_range_check_valid_accepted(
        bits in 1u32..32,
        val in 0u64..1_000_000,
    ) {
        // Ensure val fits in bits
        let max = 1u64 << bits;
        prop_assume!(val < max);
        let fe_val: FieldElement = FieldElement::from_u64(val);
        let pub_names: &[&str] = &[];
        let wit_names = &["x"];
        let source = &format!("range_check(x, {bits})");

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();
        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("x".to_string(), fe_val);
        let w = wg.generate(&inputs).unwrap();
        prop_assert!(
            compiler.cs.verify(&w).is_ok(),
            "value {val} must pass range_check({bits})"
        );
    }
}

// ============================================================================
// Adversarial: combined circuit attacks
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Wrong Poseidon hash must be rejected even with correct inputs.
    #[test]
    fn prop_wrong_poseidon_output_rejected(
        a in fe_small(),
        b in fe_small(),
        wrong in fe_u64(),
    ) {
        use constraints::poseidon::{poseidon_hash, PoseidonParams};
        let params = PoseidonParams::bn254_t3();
        let correct = poseidon_hash(&params, a, b);
        prop_assume!(wrong.to_canonical() != correct.to_canonical());

        let pub_names = &["out"];
        let wit_names = &["a", "b"];
        let source = "assert_eq(poseidon(a, b), out)";

        let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();
        let wg = WitnessGenerator::from_compiler(&compiler);
        let mut inputs = HashMap::new();
        inputs.insert("out".to_string(), wrong);
        inputs.insert("a".to_string(), a);
        inputs.insert("b".to_string(), b);
        let w = wg.generate(&inputs).unwrap();
        prop_assert!(
            compiler.cs.verify(&w).is_err(),
            "wrong Poseidon output must be rejected"
        );
    }
}
