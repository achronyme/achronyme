//! Advanced array/vector functions (Phase 4E)
//!
//! This module provides advanced array operations:
//! - product: Product of all elements
//! - zip: Combine two arrays element-wise
//! - flatten: Flatten nested arrays
//! - take: Take first n elements
//! - drop: Drop first n elements
//! - unique: Remove duplicate elements
//! - chunk: Split array into chunks of size n
//! - range: Generate numeric range (Phase 4A function)

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::complex::Complex;
use achronyme_types::sync::shared;
use std::collections::HashSet;

// ============================================================================
// Phase 4E: Advanced Array Functions
// ============================================================================

/// Calculate the product of all elements in an array
///
/// Example: product([2, 3, 4]) -> 24
pub fn vm_product(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "product() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.read();
            if vec.is_empty() {
                return Ok(Value::Number(1.0));
            }

            let mut product = Value::Number(1.0);

            for val in vec.iter() {
                match (&product, val) {
                    (Value::Number(acc), Value::Number(n)) => {
                        product = Value::Number(acc * n);
                    }
                    (Value::Number(acc), Value::Complex(c)) => {
                        let acc_complex = Complex::from_real(*acc);
                        product = Value::Complex(acc_complex * *c);
                    }
                    (Value::Complex(acc), Value::Number(n)) => {
                        let n_complex = Complex::from_real(*n);
                        product = Value::Complex(*acc * n_complex);
                    }
                    (Value::Complex(acc), Value::Complex(c)) => {
                        product = Value::Complex(*acc * *c);
                    }
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "product".to_string(),
                            expected: "numeric or complex vector".to_string(),
                            got: format!("{:?}", val),
                        })
                    }
                }
            }
            Ok(product)
        }
        _ => Err(VmError::TypeError {
            operation: "product".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Combine two arrays element-wise into pairs
///
/// Example: zip([1, 2, 3], [4, 5, 6]) -> [[1, 4], [2, 5], [3, 6]]
pub fn vm_zip(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "zip() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(v1), Value::Vector(v2)) => {
            let vec1 = v1.read();
            let vec2 = v2.read();
            let min_len = vec1.len().min(vec2.len());

            let mut result = Vec::new();
            for i in 0..min_len {
                let pair = vec![vec1[i].clone(), vec2[i].clone()];
                result.push(Value::Vector(shared(pair)));
            }

            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "zip".to_string(),
            expected: "Vector, Vector".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Flatten nested arrays up to a specified depth (default: 1)
///
/// Example: flatten([[1, 2], [3, 4]]) -> [1, 2, 3, 4]
/// Example: flatten([[[1]], [[2]]], 2) -> [1, 2]
pub fn vm_flatten(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() || args.len() > 2 {
        return Err(VmError::Runtime(format!(
            "flatten() expects 1 or 2 arguments, got {}",
            args.len()
        )));
    }

    let depth = if args.len() == 2 {
        match &args[1] {
            Value::Number(n) => *n as usize,
            _ => {
                return Err(VmError::TypeError {
                    operation: "flatten".to_string(),
                    expected: "Number for depth".to_string(),
                    got: format!("{:?}", args[1]),
                })
            }
        }
    } else {
        1
    };

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.read().clone();
            // No need to drop rc - it's just a reference
            let result = flatten_recursive(&vec, depth);
            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "flatten".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Recursive helper for flatten
fn flatten_recursive(vec: &[Value], depth: usize) -> Vec<Value> {
    if depth == 0 {
        return vec.to_vec();
    }

    let mut result = Vec::new();
    for val in vec {
        match val {
            Value::Vector(inner_rc) => {
                let inner = inner_rc.read();
                let flattened = flatten_recursive(&inner, depth - 1);
                result.extend(flattened);
            }
            other => result.push(other.clone()),
        }
    }
    result
}

/// Take the first n elements from an array
///
/// Example: take([1, 2, 3, 4, 5], 3) -> [1, 2, 3]
pub fn vm_take(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "take() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(rc), Value::Number(n)) => {
            let n = (*n as usize).max(0);
            let vec = rc.read();
            let result = vec.iter().take(n).cloned().collect();
            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "take".to_string(),
            expected: "Vector, Number".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Drop the first n elements from an array
///
/// Example: drop([1, 2, 3, 4, 5], 2) -> [3, 4, 5]
pub fn vm_drop(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "drop() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(rc), Value::Number(n)) => {
            let n = (*n as usize).max(0);
            let vec = rc.read();
            let result = vec.iter().skip(n).cloned().collect();
            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "drop".to_string(),
            expected: "Vector, Number".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

/// Remove duplicate elements from an array (preserves first occurrence order)
///
/// Example: unique([1, 2, 2, 3, 1, 4]) -> [1, 2, 3, 4]
pub fn vm_unique(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "unique() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(rc) => {
            let vec = rc.read();
            let mut seen = HashSet::new();
            let mut result = Vec::new();

            for val in vec.iter() {
                // Create a simple hash key based on value type and content
                let key = value_hash_key(val);
                if seen.insert(key) {
                    result.push(val.clone());
                }
            }

            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "unique".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Create a simple hash key for values
fn value_hash_key(val: &Value) -> String {
    match val {
        Value::Number(n) => format!("n:{}", n),
        Value::Boolean(b) => format!("b:{}", b),
        Value::String(s) => format!("s:{}", s),
        Value::Null => "null".to_string(),
        _ => format!("{:?}", val), // Fallback for complex types
    }
}

/// Split an array into chunks of specified size
///
/// Example: chunk([1, 2, 3, 4, 5], 2) -> [[1, 2], [3, 4], [5]]
pub fn vm_chunk(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "chunk() expects 2 arguments, got {}",
            args.len()
        )));
    }

    match (&args[0], &args[1]) {
        (Value::Vector(rc), Value::Number(size)) => {
            let size = *size as usize;
            if size == 0 {
                return Err(VmError::Runtime(
                    "chunk() size must be greater than 0".to_string(),
                ));
            }

            let vec = rc.read();
            let mut result = Vec::new();

            for chunk in vec.chunks(size) {
                result.push(Value::Vector(shared(chunk.to_vec())));
            }

            Ok(Value::Vector(shared(result)))
        }
        _ => Err(VmError::TypeError {
            operation: "chunk".to_string(),
            expected: "Vector, Number".to_string(),
            got: format!("{:?}, {:?}", args[0], args[1]),
        }),
    }
}

// ============================================================================
// Phase 4A: Core Essential - range function
// ============================================================================

/// Generate a numeric range from start to end (exclusive) with optional step
///
/// Example: range(0, 5) -> [0, 1, 2, 3, 4]
/// Example: range(1, 10, 2) -> [1, 3, 5, 7, 9]
/// Example: range(5, 0, -1) -> [5, 4, 3, 2, 1]
pub fn vm_range(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime(format!(
            "range() expects 2 or 3 arguments, got {}",
            args.len()
        )));
    }

    let start = match &args[0] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "range".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let end = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "range".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let step = if args.len() == 3 {
        match &args[2] {
            Value::Number(n) => *n,
            _ => {
                return Err(VmError::TypeError {
                    operation: "range".to_string(),
                    expected: "Number".to_string(),
                    got: format!("{:?}", args[2]),
                })
            }
        }
    } else {
        1.0
    };

    if step == 0.0 {
        return Err(VmError::Runtime("range() step cannot be zero".to_string()));
    }

    let mut result = Vec::new();
    if step > 0.0 {
        let mut current = start;
        while current < end {
            result.push(Value::Number(current));
            current += step;
        }
    } else {
        let mut current = start;
        while current > end {
            result.push(Value::Number(current));
            current += step;
        }
    }

    Ok(Value::Vector(shared(result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_vm() -> VM {
        VM::new()
    }

    // ========================================================================
    // Product Tests
    // ========================================================================

    #[test]
    fn test_product_basic() {
        let vm = setup_vm();
        let vec = vec![Value::Number(2.0), Value::Number(3.0), Value::Number(4.0)];
        let result = vm_product(&vm, &[Value::Vector(shared(vec))]).unwrap();
        assert_eq!(result, Value::Number(24.0));
    }

    #[test]
    fn test_product_empty() {
        let vm = setup_vm();
        let vec: Vec<Value> = vec![];
        let result = vm_product(&vm, &[Value::Vector(shared(vec))]).unwrap();
        assert_eq!(result, Value::Number(1.0));
    }

    #[test]
    fn test_product_with_zero() {
        let vm = setup_vm();
        let vec = vec![Value::Number(5.0), Value::Number(0.0), Value::Number(3.0)];
        let result = vm_product(&vm, &[Value::Vector(shared(vec))]).unwrap();
        assert_eq!(result, Value::Number(0.0));
    }

    // ========================================================================
    // Zip Tests
    // ========================================================================

    #[test]
    fn test_zip_basic() {
        let vm = setup_vm();
        let v1 = vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)];
        let v2 = vec![Value::Number(4.0), Value::Number(5.0), Value::Number(6.0)];
        let result = vm_zip(
            &vm,
            &[Value::Vector(shared(v1)), Value::Vector(shared(v2))],
        )
        .unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 3);
                // Check first pair
                if let Value::Vector(pair) = &vec[0] {
                    let p = pair.read();
                    assert_eq!(p[0], Value::Number(1.0));
                    assert_eq!(p[1], Value::Number(4.0));
                }
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_zip_different_lengths() {
        let vm = setup_vm();
        let v1 = vec![Value::Number(1.0), Value::Number(2.0)];
        let v2 = vec![Value::Number(4.0), Value::Number(5.0), Value::Number(6.0)];
        let result = vm_zip(
            &vm,
            &[Value::Vector(shared(v1)), Value::Vector(shared(v2))],
        )
        .unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 2); // Should zip to length of shorter array
            }
            _ => panic!("Expected Vector"),
        }
    }

    // ========================================================================
    // Flatten Tests
    // ========================================================================

    #[test]
    fn test_flatten_basic() {
        let vm = setup_vm();
        let inner1 = Value::Vector(shared(vec![Value::Number(1.0), Value::Number(2.0)]));
        let inner2 = Value::Vector(shared(vec![Value::Number(3.0), Value::Number(4.0)]));
        let outer = vec![inner1, inner2];
        let result = vm_flatten(&vm, &[Value::Vector(shared(outer))]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 4);
                assert_eq!(vec[0], Value::Number(1.0));
                assert_eq!(vec[3], Value::Number(4.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_flatten_depth() {
        let vm = setup_vm();
        let innermost = Value::Vector(shared(vec![Value::Number(1.0)]));
        let middle = Value::Vector(shared(vec![innermost]));
        let outer = vec![middle];
        let result =
            vm_flatten(&vm, &[Value::Vector(shared(outer)), Value::Number(2.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 1);
                assert_eq!(vec[0], Value::Number(1.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    // ========================================================================
    // Take Tests
    // ========================================================================

    #[test]
    fn test_take_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_take(&vm, &[Value::Vector(shared(vec)), Value::Number(3.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 3);
                assert_eq!(vec[0], Value::Number(1.0));
                assert_eq!(vec[2], Value::Number(3.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_take_more_than_length() {
        let vm = setup_vm();
        let vec = vec![Value::Number(1.0), Value::Number(2.0)];
        let result = vm_take(&vm, &[Value::Vector(shared(vec)), Value::Number(10.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 2);
            }
            _ => panic!("Expected Vector"),
        }
    }

    // ========================================================================
    // Drop Tests
    // ========================================================================

    #[test]
    fn test_drop_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_drop(&vm, &[Value::Vector(shared(vec)), Value::Number(2.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 3);
                assert_eq!(vec[0], Value::Number(3.0));
                assert_eq!(vec[2], Value::Number(5.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_drop_all() {
        let vm = setup_vm();
        let vec = vec![Value::Number(1.0), Value::Number(2.0)];
        let result = vm_drop(&vm, &[Value::Vector(shared(vec)), Value::Number(10.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 0);
            }
            _ => panic!("Expected Vector"),
        }
    }

    // ========================================================================
    // Unique Tests
    // ========================================================================

    #[test]
    fn test_unique_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(1.0),
            Value::Number(4.0),
        ];
        let result = vm_unique(&vm, &[Value::Vector(shared(vec))]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 4);
                assert_eq!(vec[0], Value::Number(1.0));
                assert_eq!(vec[1], Value::Number(2.0));
                assert_eq!(vec[2], Value::Number(3.0));
                assert_eq!(vec[3], Value::Number(4.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_unique_strings() {
        let vm = setup_vm();
        let vec = vec![
            Value::String("a".to_string()),
            Value::String("b".to_string()),
            Value::String("a".to_string()),
            Value::String("c".to_string()),
        ];
        let result = vm_unique(&vm, &[Value::Vector(shared(vec))]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 3);
            }
            _ => panic!("Expected Vector"),
        }
    }

    // ========================================================================
    // Chunk Tests
    // ========================================================================

    #[test]
    fn test_chunk_basic() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
            Value::Number(5.0),
        ];
        let result = vm_chunk(&vm, &[Value::Vector(shared(vec)), Value::Number(2.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 3); // [1,2], [3,4], [5]
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_chunk_exact() {
        let vm = setup_vm();
        let vec = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
        ];
        let result = vm_chunk(&vm, &[Value::Vector(shared(vec)), Value::Number(2.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 2);
            }
            _ => panic!("Expected Vector"),
        }
    }

    // ========================================================================
    // Range Tests
    // ========================================================================

    #[test]
    fn test_range_basic() {
        let vm = setup_vm();
        let result = vm_range(&vm, &[Value::Number(0.0), Value::Number(5.0)]).unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 5);
                assert_eq!(vec[0], Value::Number(0.0));
                assert_eq!(vec[4], Value::Number(4.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_range_step() {
        let vm = setup_vm();
        let result = vm_range(
            &vm,
            &[Value::Number(1.0), Value::Number(10.0), Value::Number(2.0)],
        )
        .unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 5); // [1, 3, 5, 7, 9]
                assert_eq!(vec[0], Value::Number(1.0));
                assert_eq!(vec[4], Value::Number(9.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_range_negative_step() {
        let vm = setup_vm();
        let result = vm_range(
            &vm,
            &[Value::Number(5.0), Value::Number(0.0), Value::Number(-1.0)],
        )
        .unwrap();

        match result {
            Value::Vector(rc) => {
                let vec = rc.read();
                assert_eq!(vec.len(), 5); // [5, 4, 3, 2, 1]
                assert_eq!(vec[0], Value::Number(5.0));
                assert_eq!(vec[4], Value::Number(1.0));
            }
            _ => panic!("Expected Vector"),
        }
    }

    #[test]
    fn test_range_zero_step_error() {
        let vm = setup_vm();
        let result = vm_range(
            &vm,
            &[Value::Number(0.0), Value::Number(5.0), Value::Number(0.0)],
        );
        assert!(result.is_err());
    }
}
