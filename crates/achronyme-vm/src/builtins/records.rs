//! Record (object/map) functions
//!
//! This module provides operations for working with records:
//! - keys: Get all keys from a record
//! - values: Get all values from a record
//! - has_field: Check if a record has a specific field

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;

/// Get all keys from a record as a vector of strings
pub fn vm_keys(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "keys() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Record(rc) => {
            let map = rc.borrow();
            let keys: Vec<Value> = map.keys().map(|k| Value::String(k.clone())).collect();
            Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(
                keys,
            ))))
        }
        _ => Err(VmError::TypeError {
            operation: "keys".to_string(),
            expected: "Record".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Get all values from a record as a vector
pub fn vm_values(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "values() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Record(rc) => {
            let map = rc.borrow();
            let values: Vec<Value> = map.values().cloned().collect();
            Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(
                values,
            ))))
        }
        _ => Err(VmError::TypeError {
            operation: "values".to_string(),
            expected: "Record".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Check if a record has a specific field
pub fn vm_has_field(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "has_field() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Record(rc), Value::String(field_name)) => {
            let map = rc.borrow();
            Ok(Value::Boolean(map.contains_key(field_name)))
        }
        (Value::Record(_), _) => Err(VmError::TypeError {
            operation: "has_field".to_string(),
            expected: "String as second argument".to_string(),
            got: format!("{:?}", args[1]),
        }),
        _ => Err(VmError::TypeError {
            operation: "has_field".to_string(),
            expected: "Record as first argument".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    fn setup_vm() -> VM {
        VM::new()
    }

    fn create_test_record() -> Value {
        let mut map = HashMap::new();
        map.insert("name".to_string(), Value::String("Alice".to_string()));
        map.insert("age".to_string(), Value::Number(30.0));
        map.insert("active".to_string(), Value::Boolean(true));
        Value::Record(Rc::new(RefCell::new(map)))
    }

    #[test]
    fn test_keys_basic() {
        let mut vm = setup_vm();
        let record = create_test_record();
        let result = vm_keys(&mut vm, &[record]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.borrow();
                assert_eq!(vec.len(), 3);
                // Keys should be strings
                for val in vec.iter() {
                    assert!(matches!(val, Value::String(_)));
                }
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_values_basic() {
        let mut vm = setup_vm();
        let record = create_test_record();
        let result = vm_values(&mut vm, &[record]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.borrow();
                assert_eq!(vec.len(), 3);
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_has_field_true() {
        let mut vm = setup_vm();
        let record = create_test_record();
        let result = vm_has_field(&mut vm, &[record, Value::String("name".to_string())]).unwrap();
        assert_eq!(result, Value::Boolean(true));
    }

    #[test]
    fn test_has_field_false() {
        let mut vm = setup_vm();
        let record = create_test_record();
        let result =
            vm_has_field(&mut vm, &[record, Value::String("missing".to_string())]).unwrap();
        assert_eq!(result, Value::Boolean(false));
    }
}
