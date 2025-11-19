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
            _ => Err(VmError::TypeError {
                operation: "addition".to_string(),
                expected: "Number or String".to_string(),
                got: format!("{:?} + {:?}", left, right),
            }),
        }
    }

    pub(crate) fn sub_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a - b)),
            _ => Err(VmError::TypeError {
                operation: "subtraction".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} - {:?}", left, right),
            }),
        }
    }

    pub(crate) fn mul_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a * b)),
            _ => Err(VmError::TypeError {
                operation: "multiplication".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} * {:?}", left, right),
            }),
        }
    }

    pub(crate) fn div_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                if *b == 0.0 {
                    Err(VmError::DivisionByZero)
                } else {
                    Ok(Value::Number(a / b))
                }
            }
            _ => Err(VmError::TypeError {
                operation: "division".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} / {:?}", left, right),
            }),
        }
    }

    pub(crate) fn neg_value(value: &Value) -> Result<Value, VmError> {
        match value {
            Value::Number(n) => Ok(Value::Number(-n)),
            _ => Err(VmError::TypeError {
                operation: "negation".to_string(),
                expected: "Number".to_string(),
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
}
