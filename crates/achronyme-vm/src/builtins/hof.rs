//! Higher-Order Function (HOF) Built-ins
//!
//! This module implements built-in higher-order functions that operate on collections:
//! - map: Transform each element
//! - filter: Select elements matching predicate
//! - reduce: Fold collection to single value
//! - pipe: Compose functions left-to-right
//! - any: Test if any element matches predicate
//! - all: Test if all elements match predicate
//! - find: Find first matching element
//! - findIndex: Find index of first matching element
//! - count: Count elements matching predicate

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use crate::vm::{VmBuilder, VmIterator};

/// Helper function to check if a value is truthy
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Boolean(b) => *b,
        Value::Null => false,
        Value::Number(n) => *n != 0.0,
        Value::String(s) => !s.is_empty(),
        Value::Vector(v) => !v.read().is_empty(),
        _ => true,
    }
}

/// map(callback, collection) -> collection
///
/// Transforms each element of the collection using the callback function.
/// Type preservation: Tensor -> Tensor (if all results are numbers), else Vector.
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 2, 3];
/// let doubled = map(x => x * 2, numbers);  // [2, 4, 6]
/// ```
pub fn vm_map(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "map() expects 2 arguments (callback, collection), got {}",
            args.len()
        )));
    }

    let callback = &args[0];
    let collection = &args[1];

    // Create iterator
    let mut iter = VmIterator::from_value(collection)?;

    // Create builder (try to preserve type)
    let mut builder = VmBuilder::from_hint(collection);

    // Iterate and transform
    while let Some(item) = iter.next() {
        // Call the callback function
        let result = vm.call_value(callback, &[item])?;
        builder.push(result)?;
    }

    builder.finalize()
}

/// filter(predicate, collection) -> Vector
///
/// Selects elements from the collection that match the predicate.
/// Always returns a Vector (type cannot be preserved due to filtering).
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 2, 3, 4, 5];
/// let evens = filter(x => x % 2 == 0, numbers);  // [2, 4]
/// ```
pub fn vm_filter(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "filter() expects 2 arguments (predicate, collection), got {}",
            args.len()
        )));
    }

    let predicate = &args[0];
    let collection = &args[1];

    let mut iter = VmIterator::from_value(collection)?;
    let mut builder = VmBuilder::new_vector(); // Always returns vector

    while let Some(item) = iter.next() {
        let matches = vm.call_value(predicate, std::slice::from_ref(&item))?;

        // Check if truthy
        if is_truthy(&matches) {
            builder.push(item)?;
        }
    }

    builder.finalize()
}

/// reduce(callback, initial, collection) -> Any
///
/// Reduces the collection to a single value by repeatedly applying the callback.
/// The callback receives (accumulator, current_element) and returns the new accumulator.
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 2, 3, 4];
/// let sum = reduce((acc, x) => acc + x, 0, numbers);  // 10
/// ```
pub fn vm_reduce(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(format!(
            "reduce() expects 3 arguments (callback, initial, collection), got {}",
            args.len()
        )));
    }

    let callback = &args[0];
    let mut accumulator = args[1].clone();
    let collection = &args[2];

    let mut iter = VmIterator::from_value(collection)?;

    while let Some(item) = iter.next() {
        accumulator = vm.call_value(callback, &[accumulator, item])?;
    }

    Ok(accumulator)
}

/// pipe(value, ...functions) -> Any
///
/// Passes the value through a pipeline of functions left-to-right.
/// Each function receives the output of the previous function.
///
/// # Examples
/// ```achronyme
/// let result = pipe(5, x => x * 2, x => x + 1);  // 11
/// ```
pub fn vm_pipe(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime(
            "pipe() expects at least 1 argument (initial value)".into(),
        ));
    }

    let mut value = args[0].clone();

    // Apply each function in sequence
    for func in &args[1..] {
        value = vm.call_value(func, &[value])?;
    }

    Ok(value)
}

/// any(predicate, collection) -> Boolean
///
/// Returns true if any element in the collection matches the predicate.
/// Short-circuits on the first match.
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 2, 3, 4, 5];
/// let has_even = any(x => x % 2 == 0, numbers);  // true
/// ```
pub fn vm_any(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "any() expects 2 arguments (predicate, collection), got {}",
            args.len()
        )));
    }

    let predicate = &args[0];
    let collection = &args[1];

    let mut iter = VmIterator::from_value(collection)?;

    while let Some(item) = iter.next() {
        let matches = vm.call_value(predicate, &[item])?;

        if is_truthy(&matches) {
            return Ok(Value::Boolean(true));
        }
    }

    Ok(Value::Boolean(false))
}

/// all(predicate, collection) -> Boolean
///
/// Returns true if all elements in the collection match the predicate.
/// Short-circuits on the first non-match.
///
/// # Examples
/// ```achronyme
/// let numbers = [2, 4, 6, 8];
/// let all_even = all(x => x % 2 == 0, numbers);  // true
/// ```
pub fn vm_all(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "all() expects 2 arguments (predicate, collection), got {}",
            args.len()
        )));
    }

    let predicate = &args[0];
    let collection = &args[1];

    let mut iter = VmIterator::from_value(collection)?;

    while let Some(item) = iter.next() {
        let matches = vm.call_value(predicate, &[item])?;

        if !is_truthy(&matches) {
            return Ok(Value::Boolean(false));
        }
    }

    Ok(Value::Boolean(true))
}

/// find(predicate, collection) -> Any | Null
///
/// Returns the first element that matches the predicate, or null if none match.
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 2, 3, 4, 5];
/// let first_even = find(x => x % 2 == 0, numbers);  // 2
/// ```
pub fn vm_find(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "find() expects 2 arguments (predicate, collection), got {}",
            args.len()
        )));
    }

    let predicate = &args[0];
    let collection = &args[1];

    let mut iter = VmIterator::from_value(collection)?;

    while let Some(item) = iter.next() {
        let matches = vm.call_value(predicate, std::slice::from_ref(&item))?;

        if is_truthy(&matches) {
            return Ok(item);
        }
    }

    Ok(Value::Null)
}

/// findIndex(predicate, collection) -> Number | Null
///
/// Returns the index of the first element that matches the predicate,
/// or null if none match.
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 3, 4, 5];
/// let index = findIndex(x => x % 2 == 0, numbers);  // 2
/// ```
pub fn vm_find_index(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "findIndex() expects 2 arguments (predicate, collection), got {}",
            args.len()
        )));
    }

    let predicate = &args[0];
    let collection = &args[1];

    let mut iter = VmIterator::from_value(collection)?;
    let mut index = 0;

    while let Some(item) = iter.next() {
        let matches = vm.call_value(predicate, &[item])?;

        if is_truthy(&matches) {
            return Ok(Value::Number(index as f64));
        }

        index += 1;
    }

    Ok(Value::Null)
}

/// count(predicate, collection) -> Number
///
/// Counts the number of elements that match the predicate.
///
/// # Examples
/// ```achronyme
/// let numbers = [1, 2, 3, 4, 5, 6];
/// let even_count = count(x => x % 2 == 0, numbers);  // 3
/// ```
pub fn vm_count(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "count() expects 2 arguments (predicate, collection), got {}",
            args.len()
        )));
    }

    let predicate = &args[0];
    let collection = &args[1];

    let mut iter = VmIterator::from_value(collection)?;
    let mut count = 0;

    while let Some(item) = iter.next() {
        let matches = vm.call_value(predicate, &[item])?;

        if is_truthy(&matches) {
            count += 1;
        }
    }

    Ok(Value::Number(count as f64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_truthy() {
        assert!(is_truthy(&Value::Boolean(true)));
        assert!(!is_truthy(&Value::Boolean(false)));
        assert!(!is_truthy(&Value::Null));
        assert!(is_truthy(&Value::Number(1.0)));
        assert!(!is_truthy(&Value::Number(0.0)));
        assert!(is_truthy(&Value::String("hello".to_string())));
        assert!(!is_truthy(&Value::String("".to_string())));
    }

    // Integration tests with actual VM would go here
    // For now, these are just structure tests
}
