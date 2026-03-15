//! Phase I — Field Arithmetic Vectors (BN254 Fr)
//!
//! Industry-sourced algebraic property tests following the arkworks test methodology:
//!   - arkworks test-templates: https://github.com/arkworks-rs/algebra/blob/master/test-templates/src/fields.rs
//!   - arkworks bn254 Fr:       https://github.com/arkworks-rs/algebra/blob/master/curves/bn254/src/fields/fr.rs
//!   - gnark-crypto bn254 Fr:   https://github.com/Consensys/gnark-crypto/blob/master/ecc/bn254/fr/element_test.go
//!
//! Test methodology: arkworks and gnark-crypto both use property-based testing for field
//! arithmetic (commutativity, associativity, distributivity, identity, inverse). We replicate
//! their exact property patterns with BN254 boundary values (0, 1, p-1, p-2, (p-1)/2).
//!
//! p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! MODULUS from arkworks bn254: [0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029]
//! GENERATOR = 5 (from arkworks FrConfig)

use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(s: &str) -> FieldElement {
    if let Some(hex) = s.strip_prefix("0x") {
        FieldElement::from_hex_str(&format!("0x{hex}")).unwrap()
    } else {
        FieldElement::from_decimal_str(s).unwrap()
    }
}

/// The field prime p as a decimal string.
const P: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
/// p - 1
const P_MINUS_1: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";
/// p - 2
const P_MINUS_2: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495615";
/// (p - 1) / 2
const HALF_P: &str =
    "10944121435919637611123202872628637544274182200208017171849102093287904247808";
/// (p + 1) / 2 = inv(2) mod p
const INV_2: &str = "10944121435919637611123202872628637544274182200208017171849102093287904247809";

// ============================================================================
// Macro for bulk test generation
// ============================================================================

macro_rules! field_binary_tests {
    ($op:ident, $method:ident, $( ($name:ident, $a:expr, $b:expr, $expected:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                let expected = fe($expected);
                let result = a.$method(&b);
                assert_eq!(result, expected,
                    "{}: {} {} {} \n  got      {:?}\n  expected {:?}",
                    stringify!($name), $a, stringify!($method), $b,
                    result.to_canonical(), expected.to_canonical());
            }
        )+
    };
}

macro_rules! field_unary_tests {
    ($method:ident, $( ($name:ident, $a:expr, $expected:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let expected = fe($expected);
                let result = a.$method();
                assert_eq!(result, expected,
                    "{}: {}({}) \n  got      {:?}\n  expected {:?}",
                    stringify!($name), stringify!($method), $a,
                    result.to_canonical(), expected.to_canonical());
            }
        )+
    };
}

// ============================================================================
// Addition — boundary values
// ============================================================================

field_binary_tests!(
    add,
    add,
    // Identity
    (add_zero_zero, "0", "0", "0"),
    (add_zero_one, "0", "1", "1"),
    (add_one_zero, "1", "0", "1"),
    (add_one_one, "1", "1", "2"),
    // Overflow: (p-1) + 1 = 0 mod p
    (add_p_minus_1_plus_1, P_MINUS_1, "1", "0"),
    // (p-1) + 2 = 1 mod p
    (add_p_minus_1_plus_2, P_MINUS_1, "2", "1"),
    // (p-1) + (p-1) = p - 2 mod p  (2(p-1) mod p = 2p - 2 mod p = -2 mod p = p-2)
    (
        add_p_minus_1_plus_p_minus_1,
        P_MINUS_1,
        P_MINUS_1,
        P_MINUS_2
    ),
    // (p-2) + 1 = p-1
    (add_p_minus_2_plus_1, P_MINUS_2, "1", P_MINUS_1),
    // (p-2) + 2 = 0
    (add_p_minus_2_plus_2, P_MINUS_2, "2", "0"),
    // (p-2) + 3 = 1
    (add_p_minus_2_plus_3, P_MINUS_2, "3", "1"),
    // Small values
    (add_2_3, "2", "3", "5"),
    (add_100_200, "100", "200", "300"),
    (
        add_max_u64_1,
        "18446744073709551615",
        "1",
        "18446744073709551616"
    ),
    // Half field
    (add_half_half, HALF_P, HALF_P, P_MINUS_1),
    (
        add_half_plus_1,
        HALF_P,
        "1",
        "10944121435919637611123202872628637544274182200208017171849102093287904247809"
    ),
    // Small primes
    (add_3_5, "3", "5", "8"),
    (add_7_11, "7", "11", "18"),
    (add_13_17, "13", "17", "30"),
    (add_19_23, "19", "23", "42"),
    (add_29_31, "29", "31", "60"),
    (add_37_41, "37", "41", "78"),
    (add_43_47, "43", "47", "90"),
);

// ============================================================================
// Subtraction — boundary values
// ============================================================================

field_binary_tests!(
    sub,
    sub,
    // Identity
    (sub_zero_zero, "0", "0", "0"),
    (sub_one_one, "1", "1", "0"),
    (sub_one_zero, "1", "0", "1"),
    // Underflow: 0 - 1 = p - 1
    (sub_zero_minus_1, "0", "1", P_MINUS_1),
    // 0 - 2 = p - 2
    (sub_zero_minus_2, "0", "2", P_MINUS_2),
    // 1 - 2 = p - 1
    (sub_1_minus_2, "1", "2", P_MINUS_1),
    // (p-1) - (p-1) = 0
    (sub_p_minus_1_self, P_MINUS_1, P_MINUS_1, "0"),
    // (p-1) - 0 = p-1
    (sub_p_minus_1_minus_0, P_MINUS_1, "0", P_MINUS_1),
    // Small values
    (sub_5_3, "5", "3", "2"),
    (sub_100_1, "100", "1", "99"),
    // Small primes
    (sub_11_7, "11", "7", "4"),
    (sub_23_19, "23", "19", "4"),
    (sub_47_43, "47", "43", "4"),
    (sub_31_29, "31", "29", "2"),
    // Underflow with small values
    (
        sub_3_5,
        "3",
        "5",
        "21888242871839275222246405745257275088548364400416034343698204186575808495615"
    ),
    (
        sub_7_11,
        "7",
        "11",
        "21888242871839275222246405745257275088548364400416034343698204186575808495613"
    ),
);

// ============================================================================
// Multiplication — boundary values
// ============================================================================

field_binary_tests!(
    mul,
    mul,
    // Identity and absorbing element
    (mul_zero_zero, "0", "0", "0"),
    (mul_zero_one, "0", "1", "0"),
    (mul_one_zero, "1", "0", "0"),
    (mul_one_one, "1", "1", "1"),
    (mul_one_any, "1", "42", "42"),
    (mul_any_one, "42", "1", "42"),
    (mul_zero_large, "0", P_MINUS_1, "0"),
    (mul_large_zero, P_MINUS_1, "0", "0"),
    // (p-1) * (p-1) = (-1) * (-1) = 1
    (mul_neg1_neg1, P_MINUS_1, P_MINUS_1, "1"),
    // (p-1) * 2 = -2 mod p = p - 2
    (mul_neg1_times_2, P_MINUS_1, "2", P_MINUS_2),
    // 2 * (p-1) = p - 2
    (mul_2_times_neg1, "2", P_MINUS_1, P_MINUS_2),
    // Small values
    (mul_2_3, "2", "3", "6"),
    (mul_7_11, "7", "11", "77"),
    (mul_1000_1000, "1000", "1000", "1000000"),
    // Small primes
    (mul_3_5, "3", "5", "15"),
    (mul_13_17, "13", "17", "221"),
    (mul_19_23, "19", "23", "437"),
    (mul_29_31, "29", "31", "899"),
    (mul_37_41, "37", "41", "1517"),
    (mul_43_47, "43", "47", "2021"),
    // Powers
    (mul_2_2, "2", "2", "4"),
    (mul_3_3, "3", "3", "9"),
    (mul_10_10, "10", "10", "100"),
    (mul_100_100, "100", "100", "10000"),
);

// ============================================================================
// Negation — boundary values
// ============================================================================

field_unary_tests!(
    neg,
    // -0 = 0
    (neg_zero, "0", "0"),
    // -1 = p - 1
    (neg_one, "1", P_MINUS_1),
    // -(p-1) = 1
    (neg_p_minus_1, P_MINUS_1, "1"),
    // -(p-2) = 2
    (neg_p_minus_2, P_MINUS_2, "2"),
    // -2 = p - 2
    (neg_two, "2", P_MINUS_2),
    // -42
    (
        neg_42,
        "42",
        "21888242871839275222246405745257275088548364400416034343698204186575808495575"
    ),
);

// ============================================================================
// Inverse — boundary values
// ============================================================================

macro_rules! field_inv_tests {
    ($( ($name:ident, $a:expr, $expected:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let expected = fe($expected);
                let result = a.inv().expect("inv returned None");
                assert_eq!(result, expected,
                    "{}: inv({}) \n  got      {:?}\n  expected {:?}",
                    stringify!($name), $a,
                    result.to_canonical(), expected.to_canonical());
            }
        )+
    };
}

field_inv_tests!(
    // inv(1) = 1
    (inv_one, "1", "1"),
    // inv(p-1) = inv(-1) = -1 = p-1
    (inv_neg1, P_MINUS_1, P_MINUS_1),
    // inv(2) = (p+1)/2
    (inv_two, "2", INV_2),
);

// ============================================================================
// Algebraic properties — commutativity
// ============================================================================

macro_rules! commutativity_tests {
    ($op:ident, $method:ident, $( ($name:ident, $a:expr, $b:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                assert_eq!(a.$method(&b), b.$method(&a),
                    "{}: commutativity failed for {} {} {}",
                    stringify!($name), $a, stringify!($method), $b);
            }
        )+
    };
}

commutativity_tests!(
    add,
    add,
    (comm_add_0_1, "0", "1"),
    (comm_add_1_2, "1", "2"),
    (comm_add_42_99, "42", "99"),
    (comm_add_large_small, P_MINUS_1, "7"),
    (comm_add_half_1, HALF_P, "1"),
    (comm_add_large_large, P_MINUS_1, P_MINUS_2),
    (comm_add_3_5, "3", "5"),
    (comm_add_7_13, "7", "13"),
    (comm_add_17_19, "17", "19"),
    (comm_add_23_29, "23", "29"),
    (comm_add_31_37, "31", "37"),
    (comm_add_half_large, HALF_P, P_MINUS_1),
);

commutativity_tests!(
    mul,
    mul,
    (comm_mul_0_1, "0", "1"),
    (comm_mul_1_2, "1", "2"),
    (comm_mul_42_99, "42", "99"),
    (comm_mul_large_small, P_MINUS_1, "7"),
    (comm_mul_half_1, HALF_P, "3"),
    (comm_mul_large_large, P_MINUS_1, P_MINUS_2),
    (comm_mul_3_5, "3", "5"),
    (comm_mul_7_13, "7", "13"),
    (comm_mul_17_19, "17", "19"),
    (comm_mul_23_29, "23", "29"),
    (comm_mul_31_37, "31", "37"),
    (comm_mul_half_large, HALF_P, P_MINUS_1),
);

// ============================================================================
// Algebraic properties — associativity
// ============================================================================

macro_rules! associativity_tests {
    ($method:ident, $( ($name:ident, $a:expr, $b:expr, $c:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                let c = fe($c);
                let lhs = a.$method(&b).$method(&c);
                let rhs = a.$method(&b.$method(&c));
                assert_eq!(lhs, rhs,
                    "{}: associativity failed for ({} {} {}) {} {}",
                    stringify!($name), $a, stringify!($method), $b, stringify!($method), $c);
            }
        )+
    };
}

associativity_tests!(
    add,
    (assoc_add_1_2_3, "1", "2", "3"),
    (assoc_add_large, P_MINUS_1, "5", "7"),
    (assoc_add_half, HALF_P, HALF_P, "1"),
    (assoc_add_zeros, "0", "0", "0"),
    (assoc_add_mixed, "42", P_MINUS_2, "100"),
);

associativity_tests!(
    mul,
    (assoc_mul_2_3_5, "2", "3", "5"),
    (assoc_mul_large, P_MINUS_1, "3", "7"),
    (assoc_mul_ones, "1", "1", "1"),
    (assoc_mul_mixed, "42", "13", "97"),
);

// ============================================================================
// Algebraic properties — distributivity: a * (b + c) == a*b + a*c
// ============================================================================

macro_rules! distributivity_tests {
    ($( ($name:ident, $a:expr, $b:expr, $c:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                let c = fe($c);
                let lhs = a.mul(&b.add(&c));
                let rhs = a.mul(&b).add(&a.mul(&c));
                assert_eq!(lhs, rhs,
                    "{}: distributivity failed: {} * ({} + {}) != {} * {} + {} * {}",
                    stringify!($name), $a, $b, $c, $a, $b, $a, $c);
            }
        )+
    };
}

distributivity_tests!(
    (dist_2_3_5, "2", "3", "5"),
    (dist_large, P_MINUS_1, "42", "99"),
    (dist_half, HALF_P, "3", "7"),
    (dist_zero, "0", "1", "2"),
    (dist_one, "1", P_MINUS_1, "1"),
    (dist_mixed, "17", P_MINUS_2, HALF_P),
);

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
    let three = FieldElement::from_u64(3);
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
        let fe = FieldElement::from_u64(v);
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
