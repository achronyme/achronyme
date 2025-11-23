use super::helpers::execute;
use crate::value::Value;

// ===== Complex Number Tests =====

#[test]
fn test_complex_literal() {
    use achronyme_types::complex::Complex;

    let result = execute("1i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, 1.0)));

    let result = execute("2i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, 2.0)));

    let result = execute("3+4i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(3.0, 4.0)));
}

#[test]
fn test_complex_constant_i() {
    use achronyme_types::complex::Complex;

    let result = execute("i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, 1.0)));
}

#[test]
fn test_complex_addition() {
    use achronyme_types::complex::Complex;

    let result = execute("1i + 2i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, 3.0)));

    let result = execute("(1+2i) + (3+4i)").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(4.0, 6.0)));

    let result = execute("5 + 2i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(5.0, 2.0)));

    let result = execute("2i + 5").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(5.0, 2.0)));
}

#[test]
fn test_complex_subtraction() {
    use achronyme_types::complex::Complex;

    let result = execute("5i - 2i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, 3.0)));

    let result = execute("(5+6i) - (2+3i)").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(3.0, 3.0)));

    let result = execute("10 - 2i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(10.0, -2.0)));

    let result = execute("2i - 5").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(-5.0, 2.0)));
}

#[test]
fn test_complex_multiplication() {
    use achronyme_types::complex::Complex;

    let result = execute("1i * 1i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(-1.0, 0.0)));

    let result = execute("2i * 3i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(-6.0, 0.0)));

    let result = execute("(2+3i) * (1-2i)").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(8.0, -1.0)));

    let result = execute("2 * 3i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, 6.0)));
}

#[test]
fn test_complex_division() {
    use achronyme_types::complex::Complex;

    let result = execute("(4+2i) / 2").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(2.0, 1.0)));

    let result = execute("1i / 1i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(1.0, 0.0)));
}

#[test]
fn test_complex_negation() {
    use achronyme_types::complex::Complex;

    let result = execute("-i").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(0.0, -1.0)));

    let result = execute("-(3+4i)").unwrap();
    assert_eq!(result, Value::Complex(Complex::new(-3.0, -4.0)));
}

#[test]
fn test_complex_power() {
    // i^i ≈ 0.2079 (famous mathematical result)
    let result = execute("i ^ i").unwrap();
    match result {
        Value::Complex(c) => {
            assert!(
                (c.re - 0.2078795).abs() < 0.0001,
                "Expected i^i ≈ 0.2079, got {}",
                c.re
            );
            assert!(
                c.im.abs() < 0.0001,
                "Expected imaginary part ≈ 0, got {}",
                c.im
            );
        }
        _ => panic!("Expected Complex value"),
    }
}

#[test]
fn test_complex_power_real_exponent() {
    use achronyme_types::complex::Complex;

    let result = execute("(1+1i) ^ 2").unwrap();
    match result {
        Value::Complex(c) => {
            assert!((c.re - 0.0).abs() < 0.0001);
            assert!((c.im - 2.0).abs() < 0.0001);
        }
        _ => panic!("Expected Complex value"),
    }
}

#[test]
fn test_math_constants() {
    // Test pi
    let pi_result = execute("pi").unwrap();
    match pi_result {
        Value::Number(n) => assert!((n - std::f64::consts::PI).abs() < 0.0001),
        _ => panic!("Expected Number"),
    }

    // Test e
    let e_result = execute("e").unwrap();
    match e_result {
        Value::Number(n) => assert!((n - std::f64::consts::E).abs() < 0.0001),
        _ => panic!("Expected Number"),
    }

    // Test phi (golden ratio)
    let phi_result = execute("phi").unwrap();
    match phi_result {
        Value::Number(n) => assert!((n - 1.618033988749895).abs() < 0.0001),
        _ => panic!("Expected Number"),
    }
}

#[test]
fn test_complex_with_map() {
    use achronyme_types::complex::Complex;

    let result = execute("map((x) => x * i, [1, 2, 3])").unwrap();
    match result {
        Value::Vector(vec) => {
            let vec_borrow = vec.borrow();
            assert_eq!(vec_borrow.len(), 3);

            // Check first element
            match &vec_borrow[0] {
                Value::Complex(c) => {
                    assert_eq!(c.re, 0.0);
                    assert_eq!(c.im, 1.0);
                }
                _ => panic!("Expected Complex"),
            }

            // Check second element
            match &vec_borrow[1] {
                Value::Complex(c) => {
                    assert_eq!(c.re, 0.0);
                    assert_eq!(c.im, 2.0);
                }
                _ => panic!("Expected Complex"),
            }
        }
        _ => panic!("Expected Vector"),
    }
}
