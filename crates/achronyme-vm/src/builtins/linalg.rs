//! Linear algebra functions
//!
//! This module provides linear algebra operations for the VM:
//! - dot: Dot product of two vectors
//! - cross: Cross product of two 3D vectors
//! - norm: Euclidean norm (magnitude) of a vector
//! - normalize: Normalize a vector to unit length
//! - transpose: Transpose a 2D matrix
//! - det: Determinant of a square matrix
//! - trace: Trace (sum of diagonal elements) of a square matrix

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::complex::Complex;
use achronyme_types::sync::shared;
use achronyme_types::tensor::RealTensor;

/// Calculate dot product of two vectors
pub fn vm_dot(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "dot() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(rc1), Value::Vector(rc2)) => {
            let v1 = rc1.read();
            let v2 = rc2.read();

            if v1.len() != v2.len() {
                return Err(VmError::Runtime(format!(
                    "dot() requires vectors of same length, got {} and {}",
                    v1.len(),
                    v2.len()
                )));
            }

            let mut sum = Value::Number(0.0);
            for (val1, val2) in v1.iter().zip(v2.iter()) {
                // Calculate product
                let product = match (val1, val2) {
                    (Value::Number(n1), Value::Number(n2)) => Value::Number(n1 * n2),
                    (Value::Number(n1), Value::Complex(c2)) => {
                        Value::Complex(Complex::from_real(*n1) * *c2)
                    }
                    (Value::Complex(c1), Value::Number(n2)) => {
                        Value::Complex(*c1 * Complex::from_real(*n2))
                    }
                    (Value::Complex(c1), Value::Complex(c2)) => Value::Complex(*c1 * *c2),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "dot".to_string(),
                            expected: "numeric or complex vectors".to_string(),
                            got: format!("{:?}, {:?}", val1, val2),
                        })
                    }
                };

                // Add to sum
                match (sum, product) {
                    (Value::Number(s), Value::Number(p)) => sum = Value::Number(s + p),
                    (Value::Number(s), Value::Complex(p)) => {
                        sum = Value::Complex(Complex::from_real(s) + p)
                    }
                    (Value::Complex(s), Value::Number(p)) => {
                        sum = Value::Complex(s + Complex::from_real(p))
                    }
                    (Value::Complex(s), Value::Complex(p)) => sum = Value::Complex(s + p),
                    _ => unreachable!(),
                }
            }
            Ok(sum)
        }
        _ => Err(VmError::TypeError {
            operation: "dot".to_string(),
            expected: "two Vectors".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Calculate cross product of two 3D vectors
pub fn vm_cross(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "cross() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(rc1), Value::Vector(rc2)) => {
            let v1 = rc1.read();
            let v2 = rc2.read();

            if v1.len() != 3 || v2.len() != 3 {
                return Err(VmError::Runtime("cross() requires 3D vectors".to_string()));
            }

            let (x1, y1, z1) = match (&v1[0], &v1[1], &v1[2]) {
                (Value::Number(x), Value::Number(y), Value::Number(z)) => (*x, *y, *z),
                _ => {
                    return Err(VmError::TypeError {
                        operation: "cross".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?}", v1),
                    })
                }
            };

            let (x2, y2, z2) = match (&v2[0], &v2[1], &v2[2]) {
                (Value::Number(x), Value::Number(y), Value::Number(z)) => (*x, *y, *z),
                _ => {
                    return Err(VmError::TypeError {
                        operation: "cross".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?}", v2),
                    })
                }
            };

            let result = vec![
                Value::Number(y1 * z2 - z1 * y2),
                Value::Number(z1 * x2 - x1 * z2),
                Value::Number(x1 * y2 - y1 * x2),
            ];

            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "cross".to_string(),
            expected: "two Vectors".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Calculate Euclidean norm (magnitude) of a vector
pub fn vm_norm(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "norm() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.read();
            let mut sum_sq = 0.0;
            for val in vec.iter() {
                match val {
                    Value::Number(n) => sum_sq += n * n,
                    Value::Complex(c) => sum_sq += c.magnitude() * c.magnitude(),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "norm".to_string(),
                            expected: "numeric or complex vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Number(sum_sq.sqrt()))
        }
        _ => Err(VmError::TypeError {
            operation: "norm".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Normalize a vector to unit length
pub fn vm_normalize(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "normalize() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            // Calculate norm
            let norm_result = vm_norm(_vm, args)?;
            let norm = match norm_result {
                Value::Number(n) => n,
                _ => {
                    return Err(VmError::Runtime(
                        "norm() returned non-numeric value".to_string(),
                    ))
                }
            };

            if norm == 0.0 {
                return Err(VmError::Runtime("Cannot normalize zero vector".to_string()));
            }

            // Divide each element by norm
            let vec = rc.read();
            let mut normalized = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => normalized.push(Value::Number(n / norm)),
                    Value::Complex(c) => {
                        normalized.push(Value::Complex(*c / Complex::from_real(norm)))
                    }
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "normalize".to_string(),
                            expected: "numeric or complex vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }

            Ok(Value::Vector(shared(normalized)))
        }
        _ => Err(VmError::TypeError {
            operation: "normalize".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Transpose a 2D matrix
pub fn vm_transpose(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "transpose() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Tensor(tensor) => {
            // Validate tensor is 2D
            if tensor.shape().len() != 2 {
                return Err(VmError::Runtime(format!(
                    "transpose() requires 2D tensor, got {}D",
                    tensor.shape().len()
                )));
            }

            let rows = tensor.shape()[0];
            let cols = tensor.shape()[1];
            let data = tensor.data();

            // Create transposed data
            let mut transposed = Vec::with_capacity(rows * cols);
            for j in 0..cols {
                for i in 0..rows {
                    transposed.push(data[i * cols + j]);
                }
            }

            // Create new tensor with swapped dimensions
            match RealTensor::new(transposed, vec![cols, rows]) {
                Ok(result) => Ok(Value::Tensor(result)),
                Err(e) => Err(VmError::Runtime(format!(
                    "Failed to create transposed tensor: {}",
                    e
                ))),
            }
        }
        _ => Err(VmError::TypeError {
            operation: "transpose".to_string(),
            expected: "Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate determinant of a square matrix
pub fn vm_det(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "det() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Tensor(tensor) => {
            // Validate tensor is 2D
            if tensor.shape().len() != 2 {
                return Err(VmError::Runtime(format!(
                    "det() requires 2D tensor, got {}D",
                    tensor.shape().len()
                )));
            }

            let rows = tensor.shape()[0];
            let cols = tensor.shape()[1];

            // Validate square matrix
            if rows != cols {
                return Err(VmError::Runtime(format!(
                    "det() requires square matrix, got {}x{}",
                    rows, cols
                )));
            }

            let data = tensor.data();
            let n = rows;

            // Calculate determinant based on size
            let det = match n {
                0 => {
                    return Err(VmError::Runtime(
                        "det() cannot compute determinant of 0x0 matrix".to_string(),
                    ));
                }
                1 => data[0],
                2 => {
                    // For 2x2: ad - bc
                    let a = data[0];
                    let b = data[1];
                    let c = data[2];
                    let d = data[3];
                    a * d - b * c
                }
                3 => {
                    // For 3x3: use rule of Sarrus
                    // det = a(ei-fh) - b(di-fg) + c(dh-eg)
                    let a = data[0];
                    let b = data[1];
                    let c = data[2];
                    let d = data[3];
                    let e = data[4];
                    let f = data[5];
                    let g = data[6];
                    let h = data[7];
                    let i = data[8];

                    a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)
                }
                _ => {
                    // For larger matrices, use recursive cofactor expansion
                    return Err(VmError::Runtime(format!(
                        "det() for {}x{} matrices not yet implemented",
                        n, n
                    )));
                }
            };

            Ok(Value::Number(det))
        }
        _ => Err(VmError::TypeError {
            operation: "det".to_string(),
            expected: "Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Calculate trace (sum of diagonal elements) of a square matrix
pub fn vm_trace(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "trace() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Tensor(tensor) => {
            // Validate tensor is 2D
            if tensor.shape().len() != 2 {
                return Err(VmError::Runtime(format!(
                    "trace() requires 2D tensor, got {}D",
                    tensor.shape().len()
                )));
            }

            let rows = tensor.shape()[0];
            let cols = tensor.shape()[1];

            // Validate square matrix
            if rows != cols {
                return Err(VmError::Runtime(format!(
                    "trace() requires square matrix, got {}x{}",
                    rows, cols
                )));
            }

            let data = tensor.data();
            let n = rows;

            // Sum diagonal elements: data[i * n + i] for i in 0..n
            let mut sum = 0.0;
            for i in 0..n {
                sum += data[i * n + i];
            }

            Ok(Value::Number(sum))
        }
        _ => Err(VmError::TypeError {
            operation: "trace".to_string(),
            expected: "Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use achronyme_types::sync::shared;

    fn setup_vm() -> VM {
        VM::new()
    }

    #[test]
    fn test_dot_basic() {
        let mut vm = setup_vm();
        let v1 = vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)];
        let v2 = vec![Value::Number(4.0), Value::Number(5.0), Value::Number(6.0)];
        let result = vm_dot(
            &mut vm,
            &[Value::Vector(shared(v1)), Value::Vector(shared(v2))],
        )
        .unwrap();
        // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
        assert_eq!(result, Value::Number(32.0));
    }

    #[test]
    fn test_cross_basic() {
        let mut vm = setup_vm();
        let v1 = vec![Value::Number(1.0), Value::Number(0.0), Value::Number(0.0)];
        let v2 = vec![Value::Number(0.0), Value::Number(1.0), Value::Number(0.0)];
        let result = vm_cross(
            &mut vm,
            &[Value::Vector(shared(v1)), Value::Vector(shared(v2))],
        )
        .unwrap();
        // i × j = k = [0, 0, 1]
        match result {
            Value::Vector(rc) => {
                let v = rc.read();
                assert_eq!(v.len(), 3);
                assert_eq!(v[0], Value::Number(0.0));
                assert_eq!(v[1], Value::Number(0.0));
                assert_eq!(v[2], Value::Number(1.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_norm_basic() {
        let mut vm = setup_vm();
        let v = vec![Value::Number(3.0), Value::Number(4.0)];
        let result = vm_norm(&mut vm, &[Value::Vector(shared(v))]).unwrap();
        // sqrt(3^2 + 4^2) = sqrt(9 + 16) = sqrt(25) = 5
        assert_eq!(result, Value::Number(5.0));
    }

    #[test]
    fn test_normalize_basic() {
        let mut vm = setup_vm();
        let v = vec![Value::Number(3.0), Value::Number(4.0)];
        let result = vm_normalize(&mut vm, &[Value::Vector(shared(v))]).unwrap();
        match result {
            Value::Vector(rc) => {
                let normalized = rc.read();
                assert_eq!(normalized.len(), 2);
                // Should be [3/5, 4/5] = [0.6, 0.8]
                if let Value::Number(n) = normalized[0] {
                    assert!((n - 0.6).abs() < 0.001);
                }
                if let Value::Number(n) = normalized[1] {
                    assert!((n - 0.8).abs() < 0.001);
                }
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_transpose_2x2() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 2], [3, 4]]
        let data = vec![1.0, 2.0, 3.0, 4.0];
        let tensor = RealTensor::new(data, vec![2, 2]).unwrap();
        let result = vm_transpose(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        match result {
            Value::Tensor(t) => {
                // Should be [[1, 3], [2, 4]]
                assert_eq!(t.shape(), &[2, 2]);
                assert_eq!(t.data()[0], 1.0);
                assert_eq!(t.data()[1], 3.0);
                assert_eq!(t.data()[2], 2.0);
                assert_eq!(t.data()[3], 4.0);
            }
            _ => panic!("Expected Tensor"),
        }
    }

    #[test]
    fn test_transpose_2x3() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 2, 3], [4, 5, 6]]
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let tensor = RealTensor::new(data, vec![2, 3]).unwrap();
        let result = vm_transpose(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        match result {
            Value::Tensor(t) => {
                // Should be [[1, 4], [2, 5], [3, 6]]
                assert_eq!(t.shape(), &[3, 2]);
                assert_eq!(t.data()[0], 1.0);
                assert_eq!(t.data()[1], 4.0);
                assert_eq!(t.data()[2], 2.0);
                assert_eq!(t.data()[3], 5.0);
                assert_eq!(t.data()[4], 3.0);
                assert_eq!(t.data()[5], 6.0);
            }
            _ => panic!("Expected Tensor"),
        }
    }

    #[test]
    fn test_det_2x2() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 2], [3, 4]]
        let data = vec![1.0, 2.0, 3.0, 4.0];
        let tensor = RealTensor::new(data, vec![2, 2]).unwrap();
        let result = vm_det(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // det = 1*4 - 2*3 = 4 - 6 = -2
        assert_eq!(result, Value::Number(-2.0));
    }

    #[test]
    fn test_det_2x2_diagonal() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[2, 0], [0, 3]]
        let data = vec![2.0, 0.0, 0.0, 3.0];
        let tensor = RealTensor::new(data, vec![2, 2]).unwrap();
        let result = vm_det(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // det = 2*3 - 0*0 = 6
        assert_eq!(result, Value::Number(6.0));
    }

    #[test]
    fn test_det_3x3_identity() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
        let data = vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];
        let tensor = RealTensor::new(data, vec![3, 3]).unwrap();
        let result = vm_det(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // det of identity matrix is 1
        assert_eq!(result, Value::Number(1.0));
    }

    #[test]
    fn test_det_3x3() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 2, 3], [0, 1, 4], [5, 6, 0]]
        let data = vec![1.0, 2.0, 3.0, 0.0, 1.0, 4.0, 5.0, 6.0, 0.0];
        let tensor = RealTensor::new(data, vec![3, 3]).unwrap();
        let result = vm_det(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // det = 1*(1*0 - 4*6) - 2*(0*0 - 4*5) + 3*(0*6 - 1*5)
        //     = 1*(-24) - 2*(-20) + 3*(-5)
        //     = -24 + 40 - 15
        //     = 1
        assert_eq!(result, Value::Number(1.0));
    }

    #[test]
    fn test_trace_2x2() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 2], [3, 4]]
        let data = vec![1.0, 2.0, 3.0, 4.0];
        let tensor = RealTensor::new(data, vec![2, 2]).unwrap();
        let result = vm_trace(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // trace = 1 + 4 = 5
        assert_eq!(result, Value::Number(5.0));
    }

    #[test]
    fn test_trace_3x3_diagonal() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[5, 0, 0], [0, 3, 0], [0, 0, 2]]
        let data = vec![5.0, 0.0, 0.0, 0.0, 3.0, 0.0, 0.0, 0.0, 2.0];
        let tensor = RealTensor::new(data, vec![3, 3]).unwrap();
        let result = vm_trace(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // trace = 5 + 3 + 2 = 10
        assert_eq!(result, Value::Number(10.0));
    }

    #[test]
    fn test_trace_3x3() {
        use achronyme_types::tensor::RealTensor;
        let mut vm = setup_vm();
        // Create [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0];
        let tensor = RealTensor::new(data, vec![3, 3]).unwrap();
        let result = vm_trace(&mut vm, &[Value::Tensor(tensor)]).unwrap();

        // trace = 1 + 5 + 9 = 15
        assert_eq!(result, Value::Number(15.0));
    }

    #[test]
    fn test_dot_complex() {
        let mut vm = setup_vm();
        let v1 = vec![
            Value::Complex(Complex::new(1.0, 1.0)),
            Value::Complex(Complex::new(2.0, 2.0)),
        ];
        let v2 = vec![Value::Number(2.0), Value::Complex(Complex::new(0.0, 1.0))];
        // (1+i)*2 + (2+2i)*i = 2+2i + 2i-2 = 4i
        let result = vm_dot(
            &mut vm,
            &[Value::Vector(shared(v1)), Value::Vector(shared(v2))],
        )
        .unwrap();

        match result {
            Value::Complex(c) => {
                assert!((c.re).abs() < 1e-10);
                assert!((c.im - 4.0).abs() < 1e-10);
            }
            _ => panic!("Expected Complex"),
        }
    }

    #[test]
    fn test_norm_complex() {
        let mut vm = setup_vm();
        let v = vec![Value::Number(3.0), Value::Complex(Complex::new(0.0, 4.0))];
        // sqrt(3^2 + |4i|^2) = sqrt(9 + 16) = 5
        let result = vm_norm(&mut vm, &[Value::Vector(shared(v))]).unwrap();
        assert_eq!(result, Value::Number(5.0));
    }

    #[test]
    fn test_normalize_complex() {
        let mut vm = setup_vm();
        let v = vec![
            Value::Complex(Complex::new(3.0, 0.0)),
            Value::Complex(Complex::new(0.0, 4.0)),
        ];
        let result = vm_normalize(&mut vm, &[Value::Vector(shared(v))]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 2);
                // [3/5, 4i/5] = [0.6, 0.8i]
                if let Value::Complex(c) = vec[0] {
                    assert!((c.re - 0.6).abs() < 1e-10);
                    assert!((c.im).abs() < 1e-10);
                } else {
                    panic!("Expected Complex");
                }

                if let Value::Complex(c) = vec[1] {
                    assert!((c.re).abs() < 1e-10);
                    assert!((c.im - 0.8).abs() < 1e-10);
                } else {
                    panic!("Expected Complex");
                }
            }
            _ => panic!("Expected Vector"),
        }
    }
}
