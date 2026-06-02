use super::*;

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
