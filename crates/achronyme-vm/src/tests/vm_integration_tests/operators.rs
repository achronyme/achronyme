use super::helpers::execute;
use crate::value::Value;

// ============================================================================
// POW Operator Tests
// ============================================================================

#[test]
fn test_pow_basic() {
    let result = execute("2 ^ 10").unwrap();
    assert_eq!(result, Value::Number(1024.0));
}

#[test]
fn test_pow_cube() {
    let result = execute("3 ^ 3").unwrap();
    assert_eq!(result, Value::Number(27.0));
}

#[test]
fn test_pow_square() {
    let result = execute("5 ^ 2").unwrap();
    assert_eq!(result, Value::Number(25.0));
}

#[test]
fn test_pow_fractional() {
    // 10 ^ 0.5 = sqrt(10)
    let result = execute("10 ^ 0.5").unwrap();
    match result {
        Value::Number(n) => {
            assert!(
                (n - 3.16227766).abs() < 0.0001,
                "Expected ~3.16227766, got {}",
                n
            );
        }
        _ => panic!("Expected Number"),
    }
}

#[test]
fn test_pow_negative_base() {
    let result = execute("(-2) ^ 3").unwrap();
    assert_eq!(result, Value::Number(-8.0));
}

#[test]
fn test_pow_zero_exponent() {
    let result = execute("5 ^ 0").unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_pow_with_map() {
    let source = r#"map((x) => x ^ 2, [1, 2, 3, 4, 5])"#;
    let result = execute(source).unwrap();
    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(4.0));
            assert_eq!(vec[2], Value::Number(9.0));
            assert_eq!(vec[3], Value::Number(16.0));
            assert_eq!(vec[4], Value::Number(25.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_pow_in_expression() {
    let result = execute("2 ^ 3 + 1").unwrap();
    assert_eq!(result, Value::Number(9.0)); // 8 + 1
}

#[test]
fn test_pow_chained() {
    // Right associative: 2 ^ (3 ^ 2) = 2 ^ 9 = 512
    let result = execute("2 ^ 3 ^ 2").unwrap();
    assert_eq!(result, Value::Number(512.0));
}

// ===== Range Expression Tests =====

#[test]
fn test_range_exclusive() {
    let result = execute("0..5").unwrap();
    match result {
        Value::Vector(vec) => {
            let vec_borrow = vec.borrow();
            assert_eq!(vec_borrow.len(), 5);
            assert_eq!(vec_borrow[0], Value::Number(0.0));
            assert_eq!(vec_borrow[4], Value::Number(4.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_inclusive() {
    let result = execute("0..=5").unwrap();
    match result {
        Value::Vector(vec) => {
            let vec_borrow = vec.borrow();
            assert_eq!(vec_borrow.len(), 6);
            assert_eq!(vec_borrow[0], Value::Number(0.0));
            assert_eq!(vec_borrow[5], Value::Number(5.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_with_map() {
    let result = execute("map((x) => x * 2, 1..4)").unwrap();
    match result {
        Value::Vector(vec) => {
            let vec_borrow = vec.borrow();
            assert_eq!(vec_borrow.len(), 3);
            assert_eq!(vec_borrow[0], Value::Number(2.0));
            assert_eq!(vec_borrow[1], Value::Number(4.0));
            assert_eq!(vec_borrow[2], Value::Number(6.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_negative() {
    let result = execute("-5..-1").unwrap();
    match result {
        Value::Vector(vec) => {
            let vec_borrow = vec.borrow();
            assert_eq!(vec_borrow.len(), 4);
            assert_eq!(vec_borrow[0], Value::Number(-5.0));
            assert_eq!(vec_borrow[3], Value::Number(-2.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_with_reduce() {
    // Sum of 1..=10 = 55
    let result = execute("reduce((acc, x) => acc + x, 0, 1..=10)").unwrap();
    assert_eq!(result, Value::Number(55.0));
}

// ===== IEEE 754 Special Values Tests =====

#[test]
fn test_ieee754_division_by_zero_positive() {
    let result = execute("1 / 0").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_infinite() && n.is_sign_positive()),
        _ => panic!("Expected Number(Infinity)"),
    }
}

#[test]
fn test_ieee754_division_by_zero_negative() {
    let result = execute("(-1) / 0").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_infinite() && n.is_sign_negative()),
        _ => panic!("Expected Number(-Infinity)"),
    }
}

#[test]
fn test_ieee754_zero_divided_by_zero() {
    let result = execute("0 / 0").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_nan()),
        _ => panic!("Expected Number(NaN)"),
    }
}

#[test]
fn test_ieee754_infinity_plus_one() {
    let result = execute("Infinity + 1").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_infinite() && n.is_sign_positive()),
        _ => panic!("Expected Number(Infinity)"),
    }
}

#[test]
fn test_ieee754_infinity_minus_infinity() {
    let result = execute("Infinity - Infinity").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_nan()),
        _ => panic!("Expected Number(NaN)"),
    }
}

#[test]
fn test_ieee754_infinity_times_zero() {
    let result = execute("Infinity * 0").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_nan()),
        _ => panic!("Expected Number(NaN)"),
    }
}

#[test]
fn test_ieee754_infinity_divided_by_infinity() {
    let result = execute("Infinity / Infinity").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_nan()),
        _ => panic!("Expected Number(NaN)"),
    }
}

#[test]
fn test_ieee754_nan_propagation() {
    let result = execute("NaN + 42").unwrap();
    match result {
        Value::Number(n) => assert!(n.is_nan()),
        _ => panic!("Expected Number(NaN)"),
    }
}

#[test]
fn test_ieee754_finite_divided_by_infinity() {
    let result = execute("42 / Infinity").unwrap();
    match result {
        Value::Number(n) => assert_eq!(n, 0.0),
        _ => panic!("Expected Number(0)"),
    }
}
