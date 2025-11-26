//! Utility functions
//!
//! This module provides utility operations for the VM:
//! - typeof: Get type name of a value
//! - str: Convert value to string representation
//! - isnan: Check if value is NaN
//! - isinf: Check if value is infinite
//! - isfinite: Check if value is finite

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::sync::shared;

/// Get the type name of a value
pub fn vm_typeof(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "typeof() expects 1 argument, got {}",
            args.len()
        )));
    }

    let type_name = match &args[0] {
        Value::Number(_) => "Number",
        Value::Boolean(_) => "Boolean",
        Value::String(_) => "String",
        Value::Vector(_) => "Vector",
        Value::Complex(_) => "Complex",
        Value::Function(_) => "Function",
        Value::Null => "Null",
        Value::Tensor(_) => "Tensor",
        Value::ComplexTensor(_) => "ComplexTensor",
        Value::Record(_) => "Record",
        Value::TailCall(_) => "TailCall",
        Value::EarlyReturn(_) => "EarlyReturn",
        Value::MutableRef(_) => "MutableRef",
        Value::Generator(_) => "Generator",
        Value::Future(_) => "Future",
        Value::Error { .. } => "Error",
        Value::BoundMethod { .. } => "BoundMethod",
        Value::Sender(_) => "Sender",
        Value::Receiver(_) => "Receiver",
        Value::AsyncMutex(_) => "AsyncMutex",
        Value::MutexGuard(_) => "MutexGuard",
        Value::Signal(_) => "Signal",
        _ => "Internal",
    };

    Ok(Value::String(type_name.to_string()))
}

/// Convert a value to its string representation
pub fn vm_str(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "str() expects 1 argument, got {}",
            args.len()
        )));
    }

    let string_repr = format_value(&args[0]);
    Ok(Value::String(string_repr))
}

/// Check if a value is NaN
pub fn vm_isnan(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "isnan() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Boolean(n.is_nan())),
        Value::Vector(rc) => {
            let vec = rc.read();
            let mut results = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => results.push(Value::Boolean(n.is_nan())),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "isnan".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(shared(results)))
        }
        _ => Err(VmError::TypeError {
            operation: "isnan".to_string(),
            expected: "Number or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Check if a value is infinite
pub fn vm_isinf(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "isinf() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Boolean(n.is_infinite())),
        Value::Vector(rc) => {
            let vec = rc.read();
            let mut results = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => results.push(Value::Boolean(n.is_infinite())),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "isinf".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(shared(results)))
        }
        _ => Err(VmError::TypeError {
            operation: "isinf".to_string(),
            expected: "Number or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Check if a value is finite
pub fn vm_isfinite(_vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "isfinite() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Boolean(n.is_finite())),
        Value::Vector(rc) => {
            let vec = rc.read();
            let mut results = Vec::new();
            for val in vec.iter() {
                match val {
                    Value::Number(n) => results.push(Value::Boolean(n.is_finite())),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "isfinite".to_string(),
                            expected: "numeric vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(Value::Vector(shared(results)))
        }
        _ => Err(VmError::TypeError {
            operation: "isfinite".to_string(),
            expected: "Number or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Format a value for display
fn format_value(value: &Value) -> String {
    match value {
        Value::Number(n) => {
            if n.is_nan() {
                "NaN".to_string()
            } else if n.is_infinite() {
                if n.is_sign_positive() {
                    "Infinity".to_string()
                } else {
                    "-Infinity".to_string()
                }
            } else if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        Value::Boolean(b) => format!("{}", b),
        Value::String(s) => s.clone(),
        Value::Vector(rc) => {
            let vec = rc.read();
            let elements: Vec<String> = vec.iter().map(format_value).collect();
            format!("[{}]", elements.join(", "))
        }
        Value::Complex(c) => {
            if c.im >= 0.0 {
                format!("{}+{}i", c.re, c.im)
            } else {
                format!("{}{}i", c.re, c.im)
            }
        }
        Value::Function(_) => "<function>".to_string(),
        Value::Null => "null".to_string(),
        Value::Tensor(_) => "<tensor>".to_string(),
        Value::ComplexTensor(_) => "<complex-tensor>".to_string(),
        Value::Record(rc) => {
            let map = rc.read();
            if map.is_empty() {
                "{}".to_string()
            } else {
                let pairs: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
        }
        Value::TailCall(_) => "<tail-call>".to_string(),
        Value::EarlyReturn(_) => "<early-return>".to_string(),
        Value::MutableRef(_) => "<mutable-ref>".to_string(),
        Value::Generator(_) => "<generator>".to_string(),
        Value::Future(_) => "<future>".to_string(),
        Value::Error { .. } => "Error".to_string(),
        Value::BoundMethod { method_name, .. } => format!("<method {}>", method_name),
        Value::Sender(_) => "<sender>".to_string(),
        Value::Receiver(_) => "<receiver>".to_string(),
        Value::AsyncMutex(_) => "<mutex>".to_string(),
        Value::MutexGuard(_) => "<mutex-guard>".to_string(),
        Value::Signal(rc) => {
            let state = rc.read();
            format!("Signal({})", format_value(&state.value))
        }
        _ => format!("{:?}", value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_vm() -> VM {
        VM::new()
    }

    #[test]
    fn test_typeof_number() {
        let vm = setup_vm();
        let result = vm_typeof(&vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::String("Number".to_string()));
    }

    #[test]
    fn test_typeof_string() {
        let vm = setup_vm();
        let result = vm_typeof(&vm, &[Value::String("hello".to_string())]).unwrap();
        assert_eq!(result, Value::String("String".to_string()));
    }

    #[test]
    fn test_typeof_boolean() {
        let vm = setup_vm();
        let result = vm_typeof(&vm, &[Value::Boolean(true)]).unwrap();
        assert_eq!(result, Value::String("Boolean".to_string()));
    }

    #[test]
    fn test_str_number() {
        let vm = setup_vm();
        let result = vm_str(&vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::String("42".to_string()));
    }

    #[test]
    fn test_str_string() {
        let vm = setup_vm();
        let result = vm_str(&vm, &[Value::String("hello".to_string())]).unwrap();
        assert_eq!(result, Value::String("hello".to_string()));
    }

    #[test]
    fn test_str_boolean() {
        let vm = setup_vm();
        let result = vm_str(&vm, &[Value::Boolean(true)]).unwrap();
        assert_eq!(result, Value::String("true".to_string()));
    }

    #[test]
    fn test_isnan_true() {
        let vm = setup_vm();
        let result = vm_isnan(&vm, &[Value::Number(f64::NAN)]).unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_isnan_false() {
        let vm = setup_vm();
        let result = vm_isnan(&vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::Boolean(false));
    }

    #[test]
    fn test_isinf_positive() {
        let vm = setup_vm();
        let result = vm_isinf(&vm, &[Value::Number(f64::INFINITY)]).unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_isinf_negative() {
        let vm = setup_vm();
        let result = vm_isinf(&vm, &[Value::Number(f64::NEG_INFINITY)]).unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_isinf_false() {
        let vm = setup_vm();
        let result = vm_isinf(&vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::Boolean(false));
    }

    #[test]
    fn test_isfinite_true() {
        let vm = setup_vm();
        let result = vm_isfinite(&vm, &[Value::Number(42.0)]).unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_isfinite_false_nan() {
        let vm = setup_vm();
        let result = vm_isfinite(&vm, &[Value::Number(f64::NAN)]).unwrap();
        assert_eq!(result, Value::Boolean(false));
    }

    #[test]
    fn test_isfinite_false_inf() {
        let vm = setup_vm();
        let result = vm_isfinite(&vm, &[Value::Number(f64::INFINITY)]).unwrap();
        assert_eq!(result, Value::Boolean(false));
    }
}
