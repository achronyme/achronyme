//! Value operation helpers

use crate::error::VmError;
use crate::value::Value;

/// Value operation methods
pub(crate) trait ValueOps {
    fn add_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn sub_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn mul_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn div_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn neg_value(&self, value: &Value) -> Result<Value, VmError>;
    fn lt_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn le_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn gt_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn ge_values(&self, left: &Value, right: &Value) -> Result<Value, VmError>;
    fn is_truthy(&self, value: &Value) -> bool;
}

/// Implementation of value operations for the VM
pub(crate) struct ValueOperations;

impl ValueOperations {
    pub(crate) fn add_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a + b)),
            (Value::String(a), Value::String(b)) => Ok(Value::String(format!("{}{}", a, b))),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a + *b)),
            (Value::Number(a), Value::Complex(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(Complex::new(*a, 0.0) + *b))
            }
            (Value::Complex(a), Value::Number(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(*a + Complex::new(*b, 0.0)))
            }
            // String concatenation with automatic conversion
            (Value::String(s), other) => {
                let other_str = Self::value_to_string(other);
                Ok(Value::String(format!("{}{}", s, other_str)))
            }
            (other, Value::String(s)) => {
                let other_str = Self::value_to_string(other);
                Ok(Value::String(format!("{}{}", other_str, s)))
            }
            _ => Err(VmError::TypeError {
                operation: "addition".to_string(),
                expected: "Number, Complex, or String".to_string(),
                got: format!("{:?} + {:?}", left, right),
            }),
        }
    }

    pub(crate) fn sub_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a - b)),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a - *b)),
            (Value::Number(a), Value::Complex(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(Complex::new(*a, 0.0) - *b))
            }
            (Value::Complex(a), Value::Number(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(*a - Complex::new(*b, 0.0)))
            }
            _ => Err(VmError::TypeError {
                operation: "subtraction".to_string(),
                expected: "Number or Complex".to_string(),
                got: format!("{:?} - {:?}", left, right),
            }),
        }
    }

    pub(crate) fn mul_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a * b)),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a * *b)),
            (Value::Number(a), Value::Complex(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(Complex::new(*a, 0.0) * *b))
            }
            (Value::Complex(a), Value::Number(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(*a * Complex::new(*b, 0.0)))
            }
            _ => Err(VmError::TypeError {
                operation: "multiplication".to_string(),
                expected: "Number or Complex".to_string(),
                got: format!("{:?} * {:?}", left, right),
            }),
        }
    }

    pub(crate) fn div_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                // IEEE 754 semantics: division by zero produces Infinity or NaN
                // a / 0 = Infinity (if a > 0)
                // a / 0 = -Infinity (if a < 0)
                // 0 / 0 = NaN
                Ok(Value::Number(a / b))
            }
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a / *b)),
            (Value::Number(a), Value::Complex(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(Complex::new(*a, 0.0) / *b))
            }
            (Value::Complex(a), Value::Number(b)) => {
                use achronyme_types::complex::Complex;
                // IEEE 754: division by zero is allowed, produces Infinity/NaN components
                Ok(Value::Complex(*a / Complex::new(*b, 0.0)))
            }
            _ => Err(VmError::TypeError {
                operation: "division".to_string(),
                expected: "Number or Complex".to_string(),
                got: format!("{:?} / {:?}", left, right),
            }),
        }
    }

    pub(crate) fn pow_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a.powf(*b))),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(a.pow_complex(b))),
            (Value::Number(a), Value::Complex(b)) => {
                use achronyme_types::complex::Complex;
                Ok(Value::Complex(Complex::new(*a, 0.0).pow_complex(b)))
            }
            (Value::Complex(a), Value::Number(b)) => {
                Ok(Value::Complex(a.pow(*b)))
            }
            _ => Err(VmError::TypeError {
                operation: "exponentiation".to_string(),
                expected: "Number or Complex".to_string(),
                got: format!("{:?} ^ {:?}", left, right),
            }),
        }
    }

    pub(crate) fn neg_value(value: &Value) -> Result<Value, VmError> {
        match value {
            Value::Number(n) => Ok(Value::Number(-n)),
            Value::Complex(c) => Ok(Value::Complex(-*c)),
            _ => Err(VmError::TypeError {
                operation: "negation".to_string(),
                expected: "Number or Complex".to_string(),
                got: format!("-{:?}", value),
            }),
        }
    }

    pub(crate) fn lt_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a < b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} < {:?}", left, right),
            }),
        }
    }

    pub(crate) fn le_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a <= b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} <= {:?}", left, right),
            }),
        }
    }

    pub(crate) fn gt_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a > b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} > {:?}", left, right),
            }),
        }
    }

    pub(crate) fn ge_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a >= b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} >= {:?}", left, right),
            }),
        }
    }

    pub(crate) fn is_truthy(value: &Value) -> bool {
        match value {
            Value::Boolean(b) => *b,
            Value::Null => false,
            Value::Number(n) => *n != 0.0,
            _ => true,
        }
    }

    pub(crate) fn not_value(value: &Value) -> Result<Value, VmError> {
        Ok(Value::Boolean(!Self::is_truthy(value)))
    }

    /// Convert a value to its string representation (for interpolated strings)
    pub(crate) fn value_to_string(value: &Value) -> String {
        match value {
            Value::Number(n) => {
                // Format number without unnecessary trailing zeros
                if n.fract() == 0.0 && n.is_finite() {
                    format!("{}", *n as i64)
                } else {
                    format!("{}", n)
                }
            }
            Value::Boolean(b) => b.to_string(),
            Value::String(s) => s.clone(),
            Value::Null => "null".to_string(),
            Value::Complex(c) => {
                let re = c.re;
                let im = c.im;
                if re == 0.0 {
                    format!("{}i", im)
                } else if im >= 0.0 {
                    format!("{}+{}i", re, im)
                } else {
                    format!("{}{}i", re, im)
                }
            }
            Value::Vector(vec) => {
                let vec_borrow = vec.borrow();
                let elements: Vec<String> = vec_borrow
                    .iter()
                    .map(|v| Self::value_to_string(v))
                    .collect();
                format!("[{}]", elements.join(", "))
            }
            Value::Record(map) => {
                let map_borrow = map.borrow();
                let fields: Vec<String> = map_borrow
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, Self::value_to_string(v)))
                    .collect();
                format!("{{{}}}", fields.join(", "))
            }
            Value::Function(_) => "[Function]".to_string(),
            Value::Generator(_) => "[Generator]".to_string(),
            Value::Error { message, kind, .. } => {
                if let Some(k) = kind {
                    format!("Error({}): {}", k, message)
                } else {
                    format!("Error: {}", message)
                }
            }
            _ => format!("{:?}", value),
        }
    }
}
