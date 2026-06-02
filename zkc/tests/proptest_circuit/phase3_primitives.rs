use super::*;

// ============================================================================
// Phase III primitives: Mux properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Mux idempotence: mux(c, x, x) = x for any condition.
    #[test]
    fn prop_mux_idempotent(cond in prop::bool::ANY, x in fe_u64()) {
        let c = if cond { FieldElement::ONE } else { FieldElement::ZERO };
        both_verify(
            &[("out", x)],
            &[("c", c), ("x", x)],
            "let y = x\nassert_eq(mux(c, x, y), out)",
        );
    }

    /// Mux complement: mux(c, a, b) gives a when c=1, b when c=0.
    #[test]
    fn prop_mux_select_correct(cond in prop::bool::ANY, a in fe_u64(), b in fe_u64()) {
        let c = if cond { FieldElement::ONE } else { FieldElement::ZERO };
        let expected = if cond { a } else { b };
        both_verify(
            &[("out", expected)],
            &[("c", c), ("a", a), ("b", b)],
            "assert_eq(mux(c, a, b), out)",
        );
    }

    /// Mux in arithmetic context: mux result used in addition.
    #[test]
    fn prop_mux_then_add(cond in prop::bool::ANY, a in fe_u64(), b in fe_u64(), d in fe_u64()) {
        let c = if cond { FieldElement::ONE } else { FieldElement::ZERO };
        let selected = if cond { a } else { b };
        let expected = selected.add(&d);
        both_verify(
            &[("out", expected)],
            &[("c", c), ("a", a), ("b", b), ("d", d)],
            "assert_eq(mux(c, a, b) + d, out)",
        );
    }
}

// ============================================================================
// Phase III primitives: Division properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Division roundtrip: (a / b) * b = a.
    #[test]
    fn prop_div_roundtrip(a in fe_u64(), b in fe_nonzero()) {
        r1cs_verify(
            &[("out", a)],
            &[("a", a), ("b", b)],
            "let q = a / b\nassert_eq(q * b, out)",
        );
    }

    /// Division identity: a / 1 = a.
    #[test]
    fn prop_div_by_one(a in fe_u64()) {
        r1cs_verify(
            &[("out", a)],
            &[("a", a)],
            "assert_eq(a / 1, out)",
        );
    }

    /// Self-division: a / a = 1 (for a ≠ 0).
    #[test]
    fn prop_div_self(a in fe_nonzero()) {
        both_verify(
            &[("out", FieldElement::ONE)],
            &[("a", a)],
            "assert_eq(a / a, out)",
        );
    }

    /// Double inverse: 1 / (1 / a) = a.
    #[test]
    fn prop_double_inverse(a in fe_nonzero()) {
        r1cs_verify(
            &[("out", a)],
            &[("a", a)],
            "let inv = 1 / a\nassert_eq(1 / inv, out)",
        );
    }
}

// ============================================================================
// Phase III primitives: IsLtBounded (D7 optimization)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Bounded comparison matches unbounded for small values.
    /// range_check(a, 32) + range_check(b, 32) + (a < b) = native comparison.
    #[test]
    fn prop_islt_bounded_correct(
        a in (0u64..1_000_000).prop_map(FieldElement::from_u64),
        b in (0u64..1_000_000).prop_map(FieldElement::from_u64),
    ) {
        let la = a.to_canonical();
        let lb = b.to_canonical();
        let lt_val = if (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]) {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        };
        r1cs_verify(
            &[("out", lt_val)],
            &[("a", a), ("b", b)],
            "range_check(a, 32)\nrange_check(b, 32)\nassert_eq(a < b, out)",
        );
    }

    /// Bounded IsLe matches native for small values.
    #[test]
    fn prop_isle_bounded_correct(
        a in (0u64..1_000_000).prop_map(FieldElement::from_u64),
        b in (0u64..1_000_000).prop_map(FieldElement::from_u64),
    ) {
        let la = a.to_canonical();
        let lb = b.to_canonical();
        let le_val = if (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0]) {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        };
        r1cs_verify(
            &[("out", le_val)],
            &[("a", a), ("b", b)],
            "range_check(a, 32)\nrange_check(b, 32)\nassert_eq(a <= b, out)",
        );
    }

    /// Bounded and unbounded IsLt give the same result.
    #[test]
    fn prop_islt_bounded_matches_unbounded(
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
        // Unbounded
        r1cs_verify(
            &[("out", lt_val)],
            &[("a", a), ("b", b)],
            "assert_eq(a < b, out)",
        );
        // Bounded (same result expected)
        r1cs_verify(
            &[("out", lt_val)],
            &[("a", a), ("b", b)],
            "range_check(a, 32)\nrange_check(b, 32)\nassert_eq(a < b, out)",
        );
    }
}

// ============================================================================
// Phase III primitives: Poseidon with random inputs
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Poseidon circuit output matches native hash for random inputs.
    #[test]
    fn prop_poseidon_circuit_matches_native(a in fe_u64(), b in fe_u64()) {
        use constraints::poseidon::{poseidon_hash, PoseidonParams};
        let params = PoseidonParams::bn254_t3();
        let expected = poseidon_hash(&params, a, b);
        r1cs_verify(
            &[("out", expected)],
            &[("a", a), ("b", b)],
            "assert_eq(poseidon(a, b), out)",
        );
    }

    /// Poseidon is deterministic: same inputs → same hash.
    #[test]
    fn prop_poseidon_deterministic(a in fe_u64(), b in fe_u64()) {
        use constraints::poseidon::{poseidon_hash, PoseidonParams};
        let params = PoseidonParams::bn254_t3();
        let h1 = poseidon_hash(&params, a, b);
        let h2 = poseidon_hash(&params, a, b);
        prop_assert_eq!(h1, h2);
    }

    /// Poseidon is non-commutative: poseidon(a, b) ≠ poseidon(b, a) (usually).
    #[test]
    fn prop_poseidon_non_commutative(a in fe_u64(), b in fe_u64()) {
        use constraints::poseidon::{poseidon_hash, PoseidonParams};
        prop_assume!(a.to_canonical() != b.to_canonical());
        let params = PoseidonParams::bn254_t3();
        let h_ab = poseidon_hash(&params, a, b);
        let h_ba = poseidon_hash(&params, b, a);
        prop_assert_ne!(h_ab, h_ba);
    }
}
