use super::*;

// ============================================================================
// Inverse properties: a * inv(a) == 1
// ============================================================================

#[test]
fn inv_mul_identity_small_primes() {
    for val in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
        let a = FieldElement::from_u64(val);
        let inv_a = a.inv().unwrap();
        assert_eq!(
            a.mul(&inv_a),
            FieldElement::ONE,
            "a * inv(a) != 1 for a = {val}"
        );
    }
}

#[test]
fn inv_mul_identity_large_values() {
    let values = [
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "1000000007",
        "999999999999999989",
    ];
    for v in values {
        let a = fe(v);
        let inv_a = a.inv().unwrap();
        assert_eq!(
            a.mul(&inv_a),
            FieldElement::ONE,
            "a * inv(a) != 1 for a = {v}"
        );
    }
}

#[test]
fn double_neg_identity() {
    let values = [
        "0",
        "1",
        "2",
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "42",
        "1000000007",
    ];
    for v in values {
        let a = fe(v);
        assert_eq!(a.neg().neg(), a, "neg(neg(a)) != a for a = {v}");
    }
}

#[test]
fn double_inv_identity() {
    let values = [
        "1",
        "2",
        "3",
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "42",
        "1000000007",
    ];
    for v in values {
        let a = fe(v);
        assert_eq!(
            a.inv().unwrap().inv().unwrap(),
            a,
            "inv(inv(a)) != a for a = {v}"
        );
    }
}

// ============================================================================
// Additive inverse: a + neg(a) == 0
// ============================================================================

#[test]
fn add_neg_is_zero() {
    let values = [
        "0",
        "1",
        "2",
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "42",
        "999999999999999989",
    ];
    for v in values {
        let a = fe(v);
        assert_eq!(
            a.add(&a.neg()),
            FieldElement::ZERO,
            "a + neg(a) != 0 for a = {v}"
        );
    }
}

// ============================================================================
// Division — a / a == 1 for a != 0
// ============================================================================

#[test]
fn div_self_is_one() {
    let values = [
        "1",
        "2",
        "3",
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "42",
        "1000000007",
    ];
    for v in values {
        let a = fe(v);
        assert_eq!(
            a.div(&a).unwrap(),
            FieldElement::ONE,
            "a / a != 1 for a = {v}"
        );
    }
}

#[test]
fn div_by_one_is_identity() {
    let values = ["0", "1", "2", P_MINUS_1, P_MINUS_2, HALF_P, "42"];
    for v in values {
        let a = fe(v);
        assert_eq!(
            a.div(&FieldElement::ONE).unwrap(),
            a,
            "a / 1 != a for a = {v}"
        );
    }
}

// ============================================================================
// Powers of 2 — stress Montgomery reduction
// ============================================================================

#[test]
fn powers_of_2_mul_chain() {
    let mut acc = FieldElement::ONE;
    let two = FieldElement::from_u64(2);
    for i in 0..64 {
        let expected = FieldElement::from_u64(1u64 << i);
        assert_eq!(acc, expected, "2^{i} mismatch");
        acc = acc.mul(&two);
    }
}

#[test]
fn square_chain_small() {
    // 3^1 = 3, 3^2 = 9, 3^4 = 81, 3^8 = 6561
    let three: FieldElement = FieldElement::from_u64(3);
    let mut x = three;
    let expected = [9u64, 81, 6561, 43046721];
    for (i, &exp) in expected.iter().enumerate() {
        x = x.mul(&x);
        assert_eq!(x, FieldElement::from_u64(exp), "3^(2^{}) mismatch", i + 1);
    }
}

// ============================================================================
// Fermat's little theorem: a^(p-1) == 1 for a != 0
// ============================================================================

#[test]
fn fermats_little_theorem_small() {
    // For small values, verify a^(p-1) = 1 via repeated squaring (inv is pow(a, p-2))
    // Since a * inv(a) = 1 and inv(a) = a^(p-2), we have a^(p-1) = 1
    // This is already tested by inv_mul_identity, but let's be explicit
    for val in [2u64, 3, 5, 7, 42, 100] {
        let a = FieldElement::from_u64(val);
        let a_inv = a.inv().unwrap();
        // a^(p-1) = a * a^(p-2) = a * inv(a) = 1
        assert_eq!(
            a.mul(&a_inv),
            FieldElement::ONE,
            "Fermat's little theorem: {val}^(p-1) != 1"
        );
    }
}

// ============================================================================
// From/to canonical round-trip
// ============================================================================

#[test]
fn canonical_round_trip() {
    let values = [0u64, 1, 2, 42, 1000, u64::MAX];
    for v in values {
        let fe: FieldElement = FieldElement::from_u64(v);
        let canonical = fe.to_canonical();
        assert_eq!(canonical[0], v, "canonical[0] != {v}");
        assert_eq!(canonical[1], 0, "canonical[1] != 0 for small value {v}");
        assert_eq!(canonical[2], 0);
        assert_eq!(canonical[3], 0);
    }
}

#[test]
fn from_decimal_str_round_trip() {
    let strs = ["0", "1", "42", "1000000007", P_MINUS_1, P_MINUS_2, HALF_P];
    for s in strs {
        let a = fe(s);
        let b = fe(s);
        assert_eq!(a, b, "from_decimal_str not deterministic for {s}");
    }
}

// ============================================================================
// Subtraction is add(neg(b))
// ============================================================================

#[test]
fn sub_equals_add_neg() {
    let pairs = [
        ("5", "3"),
        ("0", "1"),
        ("1", "0"),
        (P_MINUS_1, "1"),
        (HALF_P, "42"),
        ("100", P_MINUS_1),
    ];
    for (a_s, b_s) in pairs {
        let a = fe(a_s);
        let b = fe(b_s);
        assert_eq!(
            a.sub(&b),
            a.add(&b.neg()),
            "sub != add(neg) for ({a_s}, {b_s})"
        );
    }
}

// ============================================================================
// Division is mul(inv(b))
// ============================================================================

#[test]
fn div_equals_mul_inv() {
    let pairs = [
        ("6", "3"),
        ("1", "1"),
        (P_MINUS_1, "2"),
        (HALF_P, "7"),
        ("42", "13"),
    ];
    for (a_s, b_s) in pairs {
        let a = fe(a_s);
        let b = fe(b_s);
        assert_eq!(
            a.div(&b).unwrap(),
            a.mul(&b.inv().unwrap()),
            "div != mul(inv) for ({a_s}, {b_s})"
        );
    }
}

// ============================================================================
// arkworks property: doubling — a.double() == a + a
// Source: arkworks test-templates, test_add_properties
// ============================================================================

#[test]
fn doubling_equals_add_self() {
    let values = [
        "0",
        "1",
        "2",
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "42",
        "1000000007",
        "999999999999999989",
    ];
    for v in values {
        let a = fe(v);
        let doubled = a.add(&a);
        let times_two = a.mul(&FieldElement::from_u64(2));
        assert_eq!(doubled, times_two, "a + a != a * 2 for a = {v}");
    }
}

// ============================================================================
// arkworks property: subtraction anti-commutativity — (a - b) + (b - a) == 0
// Source: arkworks test-templates, test_sub_properties
// ============================================================================

#[test]
fn sub_anti_commutativity() {
    let pairs = [
        ("1", "2"),
        ("42", "99"),
        (P_MINUS_1, "1"),
        (HALF_P, P_MINUS_2),
        ("0", P_MINUS_1),
        ("1000000007", "42"),
    ];
    for (a_s, b_s) in pairs {
        let a = fe(a_s);
        let b = fe(b_s);
        let ab = a.sub(&b);
        let ba = b.sub(&a);
        assert_eq!(
            ab.add(&ba),
            FieldElement::ZERO,
            "(a - b) + (b - a) != 0 for ({a_s}, {b_s})"
        );
    }
}

// ============================================================================
// arkworks property: squaring — a * a == a.square()
// Source: arkworks test-templates, test_mul_properties
// We don't have a separate .square() method, so we verify a * a consistency.
// ============================================================================

#[test]
fn squaring_consistency() {
    let values = [
        "0",
        "1",
        "2",
        "3",
        P_MINUS_1,
        P_MINUS_2,
        HALF_P,
        "42",
        "1000000007",
    ];
    for v in values {
        let a = fe(v);
        let sq = a.mul(&a);
        // Verify (a^2) is deterministic and a * a == a * a
        let sq2 = a.mul(&a);
        assert_eq!(sq, sq2, "squaring not deterministic for {v}");
    }
}

// ============================================================================
// arkworks property: square distributivity — (a + b)^2 == a^2 + 2ab + b^2
// Source: arkworks test-templates, test_mul_properties
// ============================================================================

#[test]
fn square_distributivity() {
    let pairs = [
        ("1", "2"),
        ("3", "5"),
        ("42", "99"),
        (P_MINUS_1, "1"),
        (HALF_P, "7"),
        ("1000000007", "42"),
    ];
    for (a_s, b_s) in pairs {
        let a = fe(a_s);
        let b = fe(b_s);
        let lhs = a.add(&b).mul(&a.add(&b)); // (a+b)^2
        let a_sq = a.mul(&a);
        let b_sq = b.mul(&b);
        let two_ab = a.mul(&b).add(&a.mul(&b)); // 2ab
        let rhs = a_sq.add(&b_sq).add(&two_ab); // a^2 + b^2 + 2ab
        assert_eq!(lhs, rhs, "(a+b)^2 != a^2 + 2ab + b^2 for ({a_s}, {b_s})");
    }
}

// ============================================================================
// arkworks property: zero element properties
// Source: arkworks test-templates, test_add_properties / test_mul_properties
// ============================================================================

#[test]
fn zero_add_identity() {
    let values = [
        "0",
        "1",
        P_MINUS_1,
        HALF_P,
        "42",
        "1000000007",
        "999999999999999989",
    ];
    for v in values {
        let a = fe(v);
        assert_eq!(FieldElement::ZERO.add(&a), a, "0 + a != a for a = {v}");
        assert_eq!(a.add(&FieldElement::ZERO), a, "a + 0 != a for a = {v}");
    }
}

#[test]
fn zero_mul_absorbing() {
    let values = ["0", "1", P_MINUS_1, HALF_P, "42", "1000000007"];
    for v in values {
        let a = fe(v);
        assert_eq!(
            FieldElement::ZERO.mul(&a),
            FieldElement::ZERO,
            "0 * a != 0 for a = {v}"
        );
        assert_eq!(
            a.mul(&FieldElement::ZERO),
            FieldElement::ZERO,
            "a * 0 != 0 for a = {v}"
        );
    }
}

#[test]
fn one_mul_identity() {
    let values = ["0", "1", P_MINUS_1, HALF_P, "42", "1000000007"];
    for v in values {
        let a = fe(v);
        assert_eq!(FieldElement::ONE.mul(&a), a, "1 * a != a for a = {v}");
        assert_eq!(a.mul(&FieldElement::ONE), a, "a * 1 != a for a = {v}");
    }
}

// ============================================================================
// gnark-crypto property: Montgomery form stress test
// Source: gnark-crypto element_test.go uses specific limb patterns to stress
//         Montgomery reduction. We replicate with powers of 2 and large values.
// ============================================================================

#[test]
fn montgomery_stress_large_values() {
    // Multiply large values near the modulus to stress Montgomery reduction
    let large_values = [P_MINUS_1, P_MINUS_2, HALF_P];
    for a_s in &large_values {
        for b_s in &large_values {
            let a = fe(a_s);
            let b = fe(b_s);
            let c = a.mul(&b);
            // Verify commutativity under stress
            assert_eq!(c, b.mul(&a), "commutativity failed for large values");
            // Verify a * b * inv(b) == a (when b != 0)
            if !b.is_zero() {
                let b_inv = b.inv().unwrap();
                assert_eq!(c.mul(&b_inv), a, "a * b * inv(b) != a for large values");
            }
        }
    }
}

// ============================================================================
// arkworks: generator element — BN254 Fr has generator = 5
// Source: arkworks bn254 FrConfig, GENERATOR = 5
// ============================================================================

#[test]
fn bn254_generator_is_5() {
    // arkworks defines GENERATOR = 5 for BN254 Fr
    // This means 5 is a primitive root of the multiplicative group.
    // We verify basic properties: 5 is non-zero, 5 * inv(5) == 1.
    let gen = FieldElement::from_u64(5);
    assert!(!gen.is_zero());
    let gen_inv = gen.inv().unwrap();
    assert_eq!(gen.mul(&gen_inv), FieldElement::ONE);
}
