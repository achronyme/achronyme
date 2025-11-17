use achronyme_eval::Evaluator;
use achronyme_parser::parse;
use achronyme_types::complex::Complex;
use achronyme_types::value::Value;

fn eval(source: &str) -> Result<Value, String> {
    let statements = parse(source)?;
    let mut evaluator = Evaluator::new();

    let mut result = Value::Number(0.0);
    for stmt in &statements {
        result = evaluator.evaluate(stmt)?;
    }

    Ok(result)
}

fn eval_with_evaluator(evaluator: &mut Evaluator, source: &str) -> Result<Value, String> {
    let statements = parse(source)?;

    let mut result = Value::Number(0.0);
    for stmt in &statements {
        result = evaluator.evaluate(stmt)?;
    }

    Ok(result)
}

// ========================================================================
// Broadcasting Tests: Scalar + Vector
// ========================================================================

#[test]
fn test_scalar_add_vector() {
    let result = eval("3 + [1, 2, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(4.0), Value::Number(5.0), Value::Number(6.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_add_scalar() {
    let result = eval("[1, 2, 3] + 3").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(4.0), Value::Number(5.0), Value::Number(6.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_scalar_multiply_vector() {
    let result = eval("2 * [1, 2, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(2.0), Value::Number(4.0), Value::Number(6.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_multiply_scalar() {
    let result = eval("[1, 2, 3] * 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(2.0), Value::Number(4.0), Value::Number(6.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_divide_scalar() {
    let result = eval("[2, 4, 6] / 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_scalar_divide_vector() {
    let result = eval("12 / [2, 3, 4]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(6.0), Value::Number(4.0), Value::Number(3.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_subtract_scalar() {
    let result = eval("[5, 4, 3] - 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(3.0), Value::Number(2.0), Value::Number(1.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_scalar_subtract_vector() {
    let result = eval("10 - [1, 2, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(9.0), Value::Number(8.0), Value::Number(7.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_power_scalar() {
    let result = eval("[1, 2, 3] ^ 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(1.0), Value::Number(4.0), Value::Number(9.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_scalar_power_vector() {
    let result = eval("2 ^ [1, 2, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v, vec![Value::Number(2.0), Value::Number(4.0), Value::Number(8.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ========================================================================
// Broadcasting Tests: Complex + Vector → Vector of Complex
// ========================================================================

#[test]
fn test_complex_add_vector() {
    let result = eval("(1+i) + [1, 2, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Complex(Complex::new(2.0, 1.0)));
            assert_eq!(v[1], Value::Complex(Complex::new(3.0, 1.0)));
            assert_eq!(v[2], Value::Complex(Complex::new(4.0, 1.0)));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_add_complex() {
    let result = eval("[1, 2, 3] + (2+i)").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Complex(Complex::new(3.0, 1.0)));
            assert_eq!(v[1], Value::Complex(Complex::new(4.0, 1.0)));
            assert_eq!(v[2], Value::Complex(Complex::new(5.0, 1.0)));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_complex_multiply_vector() {
    let result = eval("(2+i) * [1, 2, 3]").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            assert_eq!(v[0], Value::Complex(Complex::new(2.0, 1.0)));  // (2+i) * 1
            assert_eq!(v[1], Value::Complex(Complex::new(4.0, 2.0)));  // (2+i) * 2
            assert_eq!(v[2], Value::Complex(Complex::new(6.0, 3.0)));  // (2+i) * 3
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ========================================================================
// Broadcasting Tests: Scalar + Vector of Complex
// ========================================================================

#[test]
fn test_scalar_add_complex_vector() {
    let mut evaluator = Evaluator::new();
    eval_with_evaluator(&mut evaluator, "let cv = [1+i, 2+2i]").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "3 + cv").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], Value::Complex(Complex::new(4.0, 1.0)));
            assert_eq!(v[1], Value::Complex(Complex::new(5.0, 2.0)));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_complex_vector_multiply_scalar() {
    let mut evaluator = Evaluator::new();
    eval_with_evaluator(&mut evaluator, "let cv = [1+i, 2+2i]").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "cv * 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], Value::Complex(Complex::new(2.0, 2.0)));
            assert_eq!(v[1], Value::Complex(Complex::new(4.0, 4.0)));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_complex_vector_divide_scalar() {
    let mut evaluator = Evaluator::new();
    eval_with_evaluator(&mut evaluator, "let cv = [2+2i, 4+4i]").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "cv / 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], Value::Complex(Complex::new(1.0, 1.0)));
            assert_eq!(v[1], Value::Complex(Complex::new(2.0, 2.0)));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ========================================================================
// Broadcasting Tests: Complex + Vector of Complex
// ========================================================================

#[test]
fn test_complex_add_complex_vector() {
    let mut evaluator = Evaluator::new();
    eval_with_evaluator(&mut evaluator, "let cv = [1+i, 2+2i]").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "(1+i) + cv").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0], Value::Complex(Complex::new(2.0, 2.0)));
            assert_eq!(v[1], Value::Complex(Complex::new(3.0, 3.0)));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_complex_vector_power_scalar() {
    let mut evaluator = Evaluator::new();
    eval_with_evaluator(&mut evaluator, "let cv = [1+i, 2+2i]").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "cv ^ 2").unwrap();
    match result {
        Value::Vector(v) => {
            assert_eq!(v.len(), 2);
            // (1+i)^2 = 1 + 2i - 1 = 0 + 2i
            let c1 = v[0].as_complex().unwrap();
            assert!((c1.re - 0.0).abs() < 1e-10);
            assert!((c1.im - 2.0).abs() < 1e-10);
            // (2+2i)^2 = 4 + 8i - 4 = 0 + 8i
            let c2 = v[1].as_complex().unwrap();
            assert!((c2.re - 0.0).abs() < 1e-10);
            assert!((c2.im - 8.0).abs() < 1e-10);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ========================================================================
// Broadcasting Tests: With Variables
// ========================================================================

#[test]
fn test_broadcasting_with_variables() {
    let mut evaluator = Evaluator::new();

    eval_with_evaluator(&mut evaluator, "let v = [1, 2, 3]").unwrap();
    eval_with_evaluator(&mut evaluator, "let scale = 5").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "v * scale").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec, vec![Value::Number(5.0), Value::Number(10.0), Value::Number(15.0)]);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_broadcasting_in_pipeline() {
    let mut evaluator = Evaluator::new();

    eval_with_evaluator(&mut evaluator, "let v = [1, 2, 3]").unwrap();
    eval_with_evaluator(&mut evaluator, "let v = v * 2").unwrap();
    eval_with_evaluator(&mut evaluator, "let v = v + 1").unwrap();

    let result = eval_with_evaluator(&mut evaluator, "v").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec, vec![Value::Number(3.0), Value::Number(5.0), Value::Number(7.0)]);  // (v * 2) + 1
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

// ========================================================================
// Broadcasting Tests: Error Cases
// ========================================================================

#[test]
fn test_vector_dimension_mismatch() {
    // Vector-to-vector operations with different dimensions should fail
    let result = eval("[1, 2, 3] + [1, 2]");
    assert!(result.is_err(), "Expected error for dimension mismatch");
    // Just verify it's an error - the exact message depends on Vector implementation
}

#[test]
fn test_division_by_zero_scalar() {
    // IEEE 754 compliant: division by zero returns Infinity, not an error
    let result = eval("[1, 2, 3] / 0");
    assert!(result.is_ok(), "Division by zero should return Infinity (IEEE 754)");

    // Each element should be Infinity
    match result.unwrap() {
        achronyme_types::value::Value::Vector(v) => {
            assert_eq!(v.len(), 3);
            for val in v {
                match val {
                    achronyme_types::value::Value::Number(n) => {
                        assert!(n.is_infinite(), "Expected Infinity for division by zero");
                    }
                    _ => panic!("Expected Number"),
                }
            }
        }
        _ => panic!("Expected Vector"),
    }
}
