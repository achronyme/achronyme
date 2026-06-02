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
#[allow(dead_code)]
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

#[path = "field_arithmetic_vectors/algebra.rs"]
mod algebra;
#[path = "field_arithmetic_vectors/boundary.rs"]
mod boundary;
#[path = "field_arithmetic_vectors/identities_stress.rs"]
mod identities_stress;
