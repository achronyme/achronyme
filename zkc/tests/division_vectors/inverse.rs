use super::*;

// ============================================================================
// 6. Modular inverse properties
// Source: gnark-crypto field element tests — Fermat's little theorem: a^{-1} = a^{p-2}.
// Key identities:
//   inv(1) = 1
//   inv(p-1) = p-1  (because (p-1)*(p-1) = p^2-2p+1 ≡ 1 mod p)
//   inv(2) = (p+1)/2
// ============================================================================

#[test]
fn inv_one_is_one() {
    // 1 / 1 = 1
    compile_and_verify(DIV_SOURCE, &[("a", fe(1)), ("b", fe(1)), ("out", fe(1))]);
}

#[test]
fn inv_pminus1_is_pminus1() {
    // (p-1) * (p-1) = p^2 - 2p + 1 ≡ 1 mod p
    // So 1 / (p-1) = p-1
    compile_and_verify(
        DIV_SOURCE,
        &[("a", fe(1)), ("b", p_minus_1()), ("out", p_minus_1())],
    );
}

#[test]
fn inv_2_is_half_p_plus_1() {
    // inv(2) = (p+1)/2
    let inv2 =
        fe_str("10944121435919637611123202872628637544274182200208017171849102093287904247809");
    compile_and_verify(DIV_SOURCE, &[("a", fe(1)), ("b", fe(2)), ("out", inv2)]);
}

#[test]
fn inv_3() {
    // Verify 1/3 by checking 3 * (1/3) = 1
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", fe(3)), ("out", fe(1))],
    );
}

#[test]
fn inv_7() {
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", fe(7)), ("out", fe(1))],
    );
}

#[test]
fn inv_pminus2() {
    // Verify 1/(p-2) by roundtrip
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", p_minus_2()), ("out", fe(1))],
    );
}

// ============================================================================
// 7. Roundtrip property: (a / b) * b = a
// Source: field axiom — a * b^{-1} * b = a for b ≠ 0.
// gnark std — Div + Mul roundtrip verification.
// ============================================================================

const ROUNDTRIP_SOURCE: &str =
    "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)";

div_property_tests! {
    (roundtrip_42_7, ROUNDTRIP_SOURCE, [("a", fe(42)), ("b", fe(7)), ("expected", fe(42))]),
    (roundtrip_1_1, ROUNDTRIP_SOURCE, [("a", fe(1)), ("b", fe(1)), ("expected", fe(1))]),
    (roundtrip_100_10, ROUNDTRIP_SOURCE, [("a", fe(100)), ("b", fe(10)), ("expected", fe(100))]),
    (roundtrip_0_5, ROUNDTRIP_SOURCE, [("a", fe(0)), ("b", fe(5)), ("expected", fe(0))]),
    (roundtrip_pminus1_1, ROUNDTRIP_SOURCE, [("a", p_minus_1()), ("b", fe(1)), ("expected", p_minus_1())]),
    (roundtrip_pminus1_pminus1, ROUNDTRIP_SOURCE, [("a", p_minus_1()), ("b", p_minus_1()), ("expected", p_minus_1())]),
    (roundtrip_pminus2_2, ROUNDTRIP_SOURCE, [("a", p_minus_2()), ("b", fe(2)), ("expected", p_minus_2())]),
    (roundtrip_1_pminus1, ROUNDTRIP_SOURCE, [("a", fe(1)), ("b", p_minus_1()), ("expected", fe(1))]),
}

#[test]
fn roundtrip_exhaustive() {
    let numerators = [
        fe(0),
        fe(1),
        fe(2),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        p_minus_1(),
    ];
    let denominators = [
        fe(1),
        fe(2),
        fe(3),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        p_minus_1(),
        p_minus_2(),
    ];
    for &a in &numerators {
        for &b in &denominators {
            compile_and_verify(ROUNDTRIP_SOURCE, &[("a", a), ("b", b), ("expected", a)]);
        }
    }
}

// ============================================================================
// 8. Inverse roundtrip: b * (1 / b) = 1
// Source: field axiom — multiplicative inverse.
// ============================================================================

const INV_ROUNDTRIP_SOURCE: &str = "witness b\npublic out\nassert_eq(b * (1 / b), out)";

div_property_tests! {
    (inv_roundtrip_1, INV_ROUNDTRIP_SOURCE, [("b", fe(1)), ("out", fe(1))]),
    (inv_roundtrip_2, INV_ROUNDTRIP_SOURCE, [("b", fe(2)), ("out", fe(1))]),
    (inv_roundtrip_3, INV_ROUNDTRIP_SOURCE, [("b", fe(3)), ("out", fe(1))]),
    (inv_roundtrip_7, INV_ROUNDTRIP_SOURCE, [("b", fe(7)), ("out", fe(1))]),
    (inv_roundtrip_42, INV_ROUNDTRIP_SOURCE, [("b", fe(42)), ("out", fe(1))]),
    (inv_roundtrip_255, INV_ROUNDTRIP_SOURCE, [("b", fe(255)), ("out", fe(1))]),
    (inv_roundtrip_u32max, INV_ROUNDTRIP_SOURCE, [("b", fe(u32::MAX as u64)), ("out", fe(1))]),
    (inv_roundtrip_u64max, INV_ROUNDTRIP_SOURCE, [("b", fe(u64::MAX)), ("out", fe(1))]),
    (inv_roundtrip_pminus1, INV_ROUNDTRIP_SOURCE, [("b", p_minus_1()), ("out", fe(1))]),
    (inv_roundtrip_pminus2, INV_ROUNDTRIP_SOURCE, [("b", p_minus_2()), ("out", fe(1))]),
}

#[test]
fn inv_roundtrip_exhaustive() {
    let values = [
        fe(1),
        fe(2),
        fe(3),
        fe(5),
        fe(7),
        fe(11),
        fe(13),
        fe(17),
        fe(19),
        fe(23),
        fe(42),
        fe(100),
        fe(255),
        fe(256),
        fe(1000),
        fe(65535),
        fe(65536),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &v in &values {
        compile_and_verify(INV_ROUNDTRIP_SOURCE, &[("b", v), ("out", fe(1))]);
    }
}

// ============================================================================
// 9. Double inverse: 1 / (1 / a) = a
// Source: field axiom — (a^{-1})^{-1} = a.
// ============================================================================

const DOUBLE_INV_SOURCE: &str = "witness a\npublic out\nlet inv = 1 / a\nassert_eq(1 / inv, out)";

div_property_tests! {
    (double_inv_1, DOUBLE_INV_SOURCE, [("a", fe(1)), ("out", fe(1))]),
    (double_inv_2, DOUBLE_INV_SOURCE, [("a", fe(2)), ("out", fe(2))]),
    (double_inv_42, DOUBLE_INV_SOURCE, [("a", fe(42)), ("out", fe(42))]),
    (double_inv_pminus1, DOUBLE_INV_SOURCE, [("a", p_minus_1()), ("out", p_minus_1())]),
    (double_inv_pminus2, DOUBLE_INV_SOURCE, [("a", p_minus_2()), ("out", p_minus_2())]),
    (double_inv_u64max, DOUBLE_INV_SOURCE, [("a", fe(u64::MAX)), ("out", fe(u64::MAX))]),
}

#[test]
fn double_inv_exhaustive() {
    let values = [
        fe(1),
        fe(2),
        fe(3),
        fe(7),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        p_minus_1(),
    ];
    for &v in &values {
        compile_and_verify(DOUBLE_INV_SOURCE, &[("a", v), ("out", v)]);
    }
}

// ============================================================================
// 10. Distributive property: (a + b) / c = a/c + b/c
// Source: field axiom — distributivity of multiplication over addition.
// ============================================================================

const DISTRIBUTIVE_SOURCE: &str = "\
witness a\nwitness b\nwitness c\n\
assert_eq((a + b) / c, a / c + b / c)";

div_property_tests! {
    (distributive_6_4_2, DISTRIBUTIVE_SOURCE, [("a", fe(6)), ("b", fe(4)), ("c", fe(2))]),
    (distributive_10_20_5, DISTRIBUTIVE_SOURCE, [("a", fe(10)), ("b", fe(20)), ("c", fe(5))]),
    (distributive_100_200_10, DISTRIBUTIVE_SOURCE, [("a", fe(100)), ("b", fe(200)), ("c", fe(10))]),
    (distributive_1_pminus1_2, DISTRIBUTIVE_SOURCE, [("a", fe(1)), ("b", p_minus_1()), ("c", fe(2))]),
    (distributive_42_0_7, DISTRIBUTIVE_SOURCE, [("a", fe(42)), ("b", fe(0)), ("c", fe(7))]),
    (distributive_pminus1_1_pminus1, DISTRIBUTIVE_SOURCE, [("a", p_minus_1()), ("b", fe(1)), ("c", p_minus_1())]),
}

#[test]
fn distributive_exhaustive() {
    let values = [fe(1), fe(2), fe(3), fe(7), fe(42), fe(100), p_minus_1()];
    let divisors = [fe(1), fe(2), fe(3), fe(7), fe(42), p_minus_1()];
    for &a in &values {
        for &b in &values {
            for &c in &divisors {
                compile_and_verify(DISTRIBUTIVE_SOURCE, &[("a", a), ("b", b), ("c", c)]);
            }
        }
    }
}

// ============================================================================
// 11. Non-trivial modular results (a / b where result is not a small integer)
// Source: gnark-crypto field element tests — verifying modular arithmetic.
// ============================================================================
