//! Vector/Array built-in functions
//!
//! This module provides vector operations including:
//! - Modification: push, pop, insert, remove
//! - Slicing: slice, concat
//! - Transformation: reverse, sort
//! - Info: len (also in string module)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::cell::RefCell;
use std::rc::Rc;

// ============================================================================
// Modification Functions
// ============================================================================

pub fn vm_push(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "push() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => {
            let mut new_vec = vec.borrow().clone();
            new_vec.push(args[1].clone());
            Ok(Value::Vector(Rc::new(RefCell::new(new_vec))))
        }
        _ => Err(VmError::TypeError {
            operation: "push".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_pop(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "pop() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => {
            let borrowed = vec.borrow();
            if borrowed.is_empty() {
                return Err(VmError::Runtime(
                    "pop(): cannot pop from empty vector".to_string(),
                ));
            }
            let mut new_vec = borrowed.clone();
            drop(borrowed);
            new_vec.pop();
            Ok(Value::Vector(Rc::new(RefCell::new(new_vec))))
        }
        _ => Err(VmError::TypeError {
            operation: "pop".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_insert(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(format!(
            "insert() expects 3 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1], &args[2]) {
        (Value::Vector(vec), Value::Number(idx), value) => {
            let idx = *idx as usize;
            let borrowed = vec.borrow();
            if idx > borrowed.len() {
                return Err(VmError::Runtime(format!(
                    "insert(): index {} out of bounds for vector of length {}",
                    idx,
                    borrowed.len()
                )));
            }
            let mut new_vec = borrowed.clone();
            drop(borrowed);
            new_vec.insert(idx, value.clone());
            Ok(Value::Vector(Rc::new(RefCell::new(new_vec))))
        }
        _ => Err(VmError::TypeError {
            operation: "insert".to_string(),
            expected: "Vector, Number, Any".to_string(),
            got: format!("{:?}, {:?}, {:?}", args[0], args[1], args[2]),
        }),
    }
}

pub fn vm_remove(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "remove() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(vec), Value::Number(idx)) => {
            let idx = *idx as usize;
            let borrowed = vec.borrow();
            if idx >= borrowed.len() {
                return Err(VmError::Runtime(format!(
                    "remove(): index {} out of bounds for vector of length {}",
                    idx,
                    borrowed.len()
                )));
            }
            let mut new_vec = borrowed.clone();
            drop(borrowed);
            new_vec.remove(idx);
            Ok(Value::Vector(Rc::new(RefCell::new(new_vec))))
        }
        _ => Err(VmError::TypeError {
            operation: "remove".to_string(),
            expected: "Vector, Number".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

// ============================================================================
// Slicing and Concatenation
// ============================================================================

pub fn vm_slice(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(format!(
            "slice() expects 3 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1], &args[2]) {
        (Value::Vector(vec), Value::Number(start), Value::Number(end)) => {
            let start = *start as usize;
            let end = *end as usize;
            let borrowed = vec.borrow();

            if start > borrowed.len() || end > borrowed.len() || start > end {
                return Err(VmError::Runtime(format!(
                    "slice(): invalid range [{}..{}] for vector of length {}",
                    start,
                    end,
                    borrowed.len()
                )));
            }

            let result = borrowed[start..end].to_vec();
            drop(borrowed);
            Ok(Value::Vector(Rc::new(RefCell::new(result))))
        }
        _ => Err(VmError::TypeError {
            operation: "slice".to_string(),
            expected: "Vector, Number, Number".to_string(),
            got: format!("{:?}, {:?}, {:?}", args[0], args[1], args[2]),
        }),
    }
}

pub fn vm_concat_vec(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "concat() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(v1), Value::Vector(v2)) => {
            let mut result = v1.borrow().clone();
            result.extend(v2.borrow().clone());
            Ok(Value::Vector(Rc::new(RefCell::new(result))))
        }
        _ => Err(VmError::TypeError {
            operation: "concat".to_string(),
            expected: "Vector, Vector".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

// ============================================================================
// Transformation Functions
// ============================================================================

pub fn vm_reverse(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "reverse() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => {
            let mut reversed = vec.borrow().clone();
            reversed.reverse();
            Ok(Value::Vector(Rc::new(RefCell::new(reversed))))
        }
        _ => Err(VmError::TypeError {
            operation: "reverse".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_sort(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "sort() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => {
            let mut sorted = vec.borrow().clone();

            // Simple sort for numbers and strings
            sorted.sort_by(|a, b| match (a, b) {
                (Value::Number(n1), Value::Number(n2)) => {
                    n1.partial_cmp(n2).unwrap_or(std::cmp::Ordering::Equal)
                }
                (Value::String(s1), Value::String(s2)) => s1.cmp(s2),
                _ => std::cmp::Ordering::Equal,
            });

            Ok(Value::Vector(Rc::new(RefCell::new(sorted))))
        }
        _ => Err(VmError::TypeError {
            operation: "sort".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

// ============================================================================
// Query Functions
// ============================================================================

pub fn vm_first(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "first() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => {
            let borrowed = vec.borrow();
            if borrowed.is_empty() {
                Ok(Value::Null)
            } else {
                Ok(borrowed[0].clone())
            }
        }
        _ => Err(VmError::TypeError {
            operation: "first".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_last(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "last() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => {
            let borrowed = vec.borrow();
            if borrowed.is_empty() {
                Ok(Value::Null)
            } else {
                let len = borrowed.len();
                Ok(borrowed[len - 1].clone())
            }
        }
        _ => Err(VmError::TypeError {
            operation: "last".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

pub fn vm_is_empty(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "is_empty() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec) => Ok(Value::Boolean(vec.borrow().is_empty())),
        Value::String(s) => Ok(Value::Boolean(s.is_empty())),
        _ => Err(VmError::TypeError {
            operation: "is_empty".to_string(),
            expected: "Vector or String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
