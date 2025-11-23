//! Predefined mathematical constants for the VM

use achronyme_types::complex::Complex;
use achronyme_types::value::Value;
use std::f64::consts;

/// Get a predefined constant by name (case-sensitive)
pub(crate) fn get_constant(name: &str) -> Option<Value> {
    match name {
        // Mathematical constants
        "pi" => Some(Value::Number(consts::PI)),
        "e" => Some(Value::Number(consts::E)),
        "phi" => Some(Value::Number(1.618033988749895)), // Golden ratio
        "sqrt2" => Some(Value::Number(consts::SQRT_2)),
        "sqrt3" => Some(Value::Number(1.7320508075688772)),
        "ln2" => Some(Value::Number(consts::LN_2)),
        "ln10" => Some(Value::Number(consts::LN_10)),

        // Complex number constant
        "i" => Some(Value::Complex(Complex::new(0.0, 1.0))),

        // IEEE 754 special values
        "Infinity" => Some(Value::Number(f64::INFINITY)),
        "NaN" => Some(Value::Number(f64::NAN)),

        _ => None,
    }
}

/// Check if a name is a predefined constant
#[allow(dead_code)]
pub(crate) fn is_constant(name: &str) -> bool {
    matches!(
        name,
        "pi" | "e" | "phi" | "sqrt2" | "sqrt3" | "ln2" | "ln10" | "i" | "Infinity" | "NaN"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pi_constant() {
        let pi = get_constant("pi").unwrap();
        match pi {
            Value::Number(n) => assert_eq!(n, consts::PI),
            _ => panic!("Expected Number"),
        }
    }

    #[test]
    fn test_i_constant() {
        let i = get_constant("i").unwrap();
        match i {
            Value::Complex(c) => {
                assert_eq!(c.re, 0.0);
                assert_eq!(c.im, 1.0);
            }
            _ => panic!("Expected Complex"),
        }
    }

    #[test]
    fn test_is_constant() {
        assert!(is_constant("pi"));
        assert!(is_constant("e"));
        assert!(is_constant("i"));
        assert!(!is_constant("x"));
        assert!(!is_constant("foo"));
    }

    #[test]
    fn test_unknown_constant() {
        assert!(get_constant("unknown").is_none());
    }
}
