use achronyme_types::complex::Complex;
use achronyme_types::value::Value;
use achronyme_types::tensor::{RealTensor, ComplexTensor};

pub fn apply_divide(left: Value, right: Value) -> Result<Value, String> {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => {
            // IEEE 754 compliant division:
            // x / 0 where x > 0 -> Infinity
            // x / 0 where x < 0 -> -Infinity
            // 0 / 0 -> NaN
            // All these are handled naturally by f64 division
            Ok(Value::Number(a / b))
        }
        (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(a / b)),

        // Tensor support (optimized path)
        (Value::Tensor(a), Value::Tensor(b)) => {
            a.div(&b).map(Value::Tensor).map_err(|e| e.to_string())
        }
        (Value::ComplexTensor(a), Value::ComplexTensor(b)) => {
            a.div(&b).map(Value::ComplexTensor).map_err(|e| e.to_string())
        }

        // Type promotion: Number → Complex
        (Value::Number(a), Value::Complex(b)) => {
            Ok(Value::Complex(Complex::from_real(a) / b))
        }
        (Value::Complex(a), Value::Number(b)) => {
            Ok(Value::Complex(a / Complex::from_real(b)))
        }

        // Legacy Vector / Vector
        (Value::Vector(ref a), Value::Vector(ref b)) => {
            // Check if both vectors are numeric
            if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                // Check if any element is complex
                let has_complex_a = a.iter().any(|v| matches!(v, Value::Complex(_)));
                let has_complex_b = b.iter().any(|v| matches!(v, Value::Complex(_)));

                if has_complex_a || has_complex_b {
                    // Complex tensor division
                    let tensor_a = Value::to_complex_tensor(a).map_err(|_| "Type conversion error")?;
                    let tensor_b = Value::to_complex_tensor(b).map_err(|_| "Type conversion error")?;
                    let result = tensor_a.div(&tensor_b).map_err(|e| e.to_string())?;
                    Ok(Value::ComplexTensor(result))
                } else {
                    // Real tensor division
                    let tensor_a = Value::to_real_tensor(a).map_err(|_| "Type conversion error")?;
                    let tensor_b = Value::to_real_tensor(b).map_err(|_| "Type conversion error")?;
                    let result = tensor_a.div(&tensor_b).map_err(|e| e.to_string())?;
                    Ok(Value::Tensor(result))
                }
            } else {
                Err("Vector division requires numeric vectors".to_string())
            }
        }

        // Broadcasting: Scalar / Vector
        // IEEE 754: division by zero elements produces Infinity/NaN
        (Value::Number(scalar), Value::Vector(ref vec)) => {
            if Value::is_numeric_vector(vec) {
                let result: Vec<Value> = vec.iter().map(|v| match v {
                    Value::Number(n) => Value::Number(scalar / n),
                    Value::Complex(c) => Value::Complex(Complex::from_real(scalar) / *c),
                    _ => unreachable!(),
                }).collect();
                Ok(Value::Vector(result))
            } else {
                Err("Broadcasting requires numeric vector".to_string())
            }
        }
        (Value::Vector(ref vec), Value::Number(scalar)) => {
            // IEEE 754: division by zero scalar produces Infinity/NaN
            if Value::is_numeric_vector(vec) {
                let result: Vec<Value> = vec.iter().map(|v| match v {
                    Value::Number(n) => Value::Number(n / scalar),
                    Value::Complex(c) => Value::Complex(*c / Complex::from_real(scalar)),
                    _ => unreachable!(),
                }).collect();
                Ok(Value::Vector(result))
            } else {
                Err("Broadcasting requires numeric vector".to_string())
            }
        }

        // Broadcasting: Complex / Vector
        (Value::Complex(c), Value::Vector(ref vec)) => {
            if Value::is_numeric_vector(vec) {
                let result: Vec<Value> = vec.iter().map(|v| match v {
                    Value::Number(n) => Value::Complex(c / Complex::from_real(*n)),
                    Value::Complex(cv) => Value::Complex(c / *cv),
                    _ => unreachable!(),
                }).collect();
                Ok(Value::Vector(result))
            } else {
                Err("Broadcasting requires numeric vector".to_string())
            }
        }
        (Value::Vector(ref vec), Value::Complex(c)) => {
            if Value::is_numeric_vector(vec) {
                let result: Vec<Value> = vec.iter().map(|v| match v {
                    Value::Number(n) => Value::Complex(Complex::from_real(*n) / c),
                    Value::Complex(cv) => Value::Complex(*cv / c),
                    _ => unreachable!(),
                }).collect();
                Ok(Value::Vector(result))
            } else {
                Err("Broadcasting requires numeric vector".to_string())
            }
        }

        // Broadcasting: Tensor / Scalar
        (Value::Tensor(t), Value::Number(scalar)) => {
            t.div_scalar(scalar).map(Value::Tensor)
        }
        (Value::Number(scalar), Value::Tensor(t)) => {
            // scalar / tensor = scalar * (1 / tensor)
            // We need to compute element-wise: scalar / each_element
            let data: Vec<f64> = t.data().iter().map(|&x| {
                if x == 0.0 {
                    f64::INFINITY // Or could return error
                } else {
                    scalar / x
                }
            }).collect();
            RealTensor::new(data, t.shape().to_vec())
                .map(Value::Tensor)
                .map_err(|e| e.to_string())
        }

        // Broadcasting: Tensor / Complex
        (Value::Tensor(t), Value::Complex(c)) => {
            let ct = t.to_complex();
            ct.div_scalar(c).map(Value::ComplexTensor)
        }
        (Value::Complex(c), Value::Tensor(t)) => {
            // c / tensor: element-wise c / each_element
            let data: Vec<Complex> = t.data().iter().map(|&x| {
                if x == 0.0 {
                    Complex::new(f64::INFINITY, 0.0)
                } else {
                    c / Complex::from_real(x)
                }
            }).collect();
            ComplexTensor::new(data, t.shape().to_vec())
                .map(Value::ComplexTensor)
                .map_err(|e| e.to_string())
        }

        // Broadcasting: ComplexTensor / Scalar
        (Value::ComplexTensor(ct), Value::Number(scalar)) => {
            ct.div_scalar(Complex::from_real(scalar)).map(Value::ComplexTensor)
        }
        (Value::Number(scalar), Value::ComplexTensor(ct)) => {
            // scalar / tensor: element-wise scalar / each_element
            let data: Vec<Complex> = ct.data().iter().map(|c| {
                if c.re == 0.0 && c.im == 0.0 {
                    Complex::new(f64::INFINITY, 0.0)
                } else {
                    Complex::from_real(scalar) / *c
                }
            }).collect();
            ComplexTensor::new(data, ct.shape().to_vec())
                .map(Value::ComplexTensor)
                .map_err(|e| e.to_string())
        }

        // Broadcasting: ComplexTensor / Complex
        (Value::ComplexTensor(ct), Value::Complex(c)) => {
            ct.div_scalar(c).map(Value::ComplexTensor)
        }
        (Value::Complex(c), Value::ComplexTensor(ct)) => {
            // c / tensor: element-wise c / each_element
            let data: Vec<Complex> = ct.data().iter().map(|elem| {
                if elem.re == 0.0 && elem.im == 0.0 {
                    Complex::new(f64::INFINITY, 0.0)
                } else {
                    c / *elem
                }
            }).collect();
            ComplexTensor::new(data, ct.shape().to_vec())
                .map(Value::ComplexTensor)
                .map_err(|e| e.to_string())
        }

        _ => Err("Incompatible types for division".to_string()),
    }
}
