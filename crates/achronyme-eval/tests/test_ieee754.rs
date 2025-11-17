/// Tests for IEEE 754 Compliance (Infinity, NaN)
///
/// This module tests:
/// - Infinity and NaN literals
/// - Division by zero behavior
/// - NaN comparisons
/// - Infinity arithmetic
/// - isnan, isinf, isfinite builtins

#[path = "test_common.rs"]
mod test_common;

use test_common::eval;
use achronyme_types::value::Value;

// ============================================================================
// Literal Parsing Tests
// ============================================================================

#[test]
fn test_infinity_literal() {
    let result = eval("Infinity").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_positive());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_negative_infinity_literal() {
    let result = eval("-Infinity").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_negative());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_nan_literal() {
    let result = eval("NaN").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_nan());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

// ============================================================================
// Division by Zero Tests
// ============================================================================

#[test]
fn test_division_positive_by_zero() {
    // 1/0 should give Infinity
    let result = eval("1/0").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_positive());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_division_negative_by_zero() {
    // -1/0 should give -Infinity
    let result = eval("-1/0").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_negative());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_division_zero_by_zero() {
    // 0/0 should give NaN
    let result = eval("0/0").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_nan());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

// ============================================================================
// NaN Comparison Tests
// ============================================================================

#[test]
fn test_nan_not_equal_to_itself() {
    // NaN != NaN (IEEE 754 behavior)
    let result = eval("NaN == NaN").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_nan_not_equal_to_number() {
    let result = eval("NaN == 42").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_nan_comparisons() {
    // All comparisons with NaN should return false
    assert_eq!(eval("NaN > 0").unwrap(), Value::Boolean(false));
    assert_eq!(eval("NaN < 0").unwrap(), Value::Boolean(false));
    assert_eq!(eval("NaN >= 0").unwrap(), Value::Boolean(false));
    assert_eq!(eval("NaN <= 0").unwrap(), Value::Boolean(false));
}

// ============================================================================
// Infinity Arithmetic Tests
// ============================================================================

#[test]
fn test_infinity_plus_number() {
    let result = eval("Infinity + 100").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_positive());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_infinity_minus_infinity() {
    // Infinity - Infinity = NaN (indeterminate form)
    let result = eval("Infinity - Infinity").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_nan());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_infinity_times_zero() {
    // Infinity * 0 = NaN (indeterminate form)
    let result = eval("Infinity * 0").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_nan());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_negative_infinity_operations() {
    let result = eval("-Infinity * 2").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_negative());
        }
        _ => panic!("Expected Number, got {:?}", result),
    }
}

#[test]
fn test_infinity_comparison() {
    assert_eq!(eval("Infinity > 1000000").unwrap(), Value::Boolean(true));
    assert_eq!(eval("-Infinity < -1000000").unwrap(), Value::Boolean(true));
    assert_eq!(eval("Infinity == Infinity").unwrap(), Value::Boolean(true));
}

// ============================================================================
// isnan() Tests
// ============================================================================

#[test]
fn test_isnan_with_nan() {
    let result = eval("isnan(NaN)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isnan_with_zero_div_zero() {
    let result = eval("isnan(0/0)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isnan_with_number() {
    let result = eval("isnan(42)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isnan_with_infinity() {
    let result = eval("isnan(Infinity)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isnan_with_vector() {
    let result = eval("isnan([1, NaN, 3])").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Boolean(false));
            assert_eq!(v[1], Value::Boolean(true));
            assert_eq!(v[2], Value::Boolean(false));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ============================================================================
// isinf() Tests
// ============================================================================

#[test]
fn test_isinf_with_positive_infinity() {
    let result = eval("isinf(Infinity)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isinf_with_negative_infinity() {
    let result = eval("isinf(-Infinity)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isinf_with_division_by_zero() {
    let result = eval("isinf(1/0)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isinf_with_number() {
    let result = eval("isinf(42)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isinf_with_nan() {
    let result = eval("isinf(NaN)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isinf_with_vector() {
    let result = eval("isinf([1, Infinity, -Infinity])").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Boolean(false));
            assert_eq!(v[1], Value::Boolean(true));
            assert_eq!(v[2], Value::Boolean(true));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ============================================================================
// isfinite() Tests
// ============================================================================

#[test]
fn test_isfinite_with_number() {
    let result = eval("isfinite(42)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isfinite_with_float() {
    let result = eval("isfinite(3.14)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_isfinite_with_infinity() {
    let result = eval("isfinite(Infinity)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isfinite_with_negative_infinity() {
    let result = eval("isfinite(-Infinity)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isfinite_with_nan() {
    let result = eval("isfinite(NaN)").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_isfinite_with_vector() {
    let result = eval("isfinite([1, Infinity, NaN])").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Boolean(true));
            assert_eq!(v[1], Value::Boolean(false));
            assert_eq!(v[2], Value::Boolean(false));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ============================================================================
// Display/Formatting Tests
// ============================================================================

#[test]
fn test_str_infinity() {
    let result = eval("str(Infinity)").unwrap();
    assert_eq!(result, Value::String("Infinity".to_string()));
}

#[test]
fn test_str_negative_infinity() {
    let result = eval("str(-Infinity)").unwrap();
    assert_eq!(result, Value::String("-Infinity".to_string()));
}

#[test]
fn test_str_nan() {
    let result = eval("str(NaN)").unwrap();
    assert_eq!(result, Value::String("NaN".to_string()));
}

// ============================================================================
// Edge Cases and Complex Expressions
// ============================================================================

#[test]
fn test_complex_sqrt_negative_gives_nan() {
    // NOTE: Currently sqrt(-1) returns NaN because the builtin sqrt
    // uses f64::sqrt which returns NaN for negative inputs.
    // Ideally, this should return a complex number (0+1i),
    // but that would require extending the sqrt builtin to handle
    // complex results. For now, we test the current IEEE 754 behavior.
    let result = eval("sqrt(-1)").unwrap();
    match result {
        Value::Number(n) => {
            // Currently returns NaN (IEEE 754 behavior for real sqrt)
            assert!(n.is_nan());
        }
        Value::Complex(c) => {
            // If complex support is added later, this is the expected result
            assert!(c.re.abs() < 1e-10);
            assert!((c.im - 1.0).abs() < 1e-10);
        }
        _ => panic!("sqrt(-1) should return Number(NaN) or Complex, got {:?}", result),
    }
}

#[test]
fn test_infinity_in_array() {
    let result = eval("[1, Infinity, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Number(1.0));
            match v[1] {
                Value::Number(n) => assert!(n.is_infinite() && n.is_sign_positive()),
                _ => panic!("Expected Infinity"),
            }
            assert_eq!(v[2], Value::Number(3.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_nan_in_array() {
    let result = eval("[1, NaN, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Number(1.0));
            match v[1] {
                Value::Number(n) => assert!(n.is_nan()),
                _ => panic!("Expected NaN"),
            }
            assert_eq!(v[2], Value::Number(3.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_infinity_variable_assignment() {
    let result = eval("let x = Infinity; x").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_infinite());
            assert!(n.is_sign_positive());
        }
        _ => panic!("Expected Number"),
    }
}

#[test]
fn test_nan_variable_assignment() {
    let result = eval("let x = NaN; x").unwrap();
    match result {
        Value::Number(n) => {
            assert!(n.is_nan());
        }
        _ => panic!("Expected Number"),
    }
}

#[test]
fn test_infinity_as_function_argument() {
    let result = eval("isinf(Infinity + 1)").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_typeof_infinity() {
    let result = eval("typeof(Infinity)").unwrap();
    assert_eq!(result, Value::String("Number".to_string()));
}

#[test]
fn test_typeof_nan() {
    let result = eval("typeof(NaN)").unwrap();
    assert_eq!(result, Value::String("Number".to_string()));
}
