use super::*;

// ============================================================================
// T5: Optimization soundness — optimized vs unoptimized must both verify
// ============================================================================

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
