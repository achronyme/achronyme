//! Tests for for-in loop iteration over Vectors and Tensors
//!
//! This module tests the new iteration capabilities:
//! - Iterating over Vector elements directly
//! - Iterating over Tensor elements (RealTensor and ComplexTensor)
//! - Control flow (break, continue) within vector/tensor loops
//! - Return statements from within loops
//! - Nested iteration over vectors
//! - Backward compatibility with generators

use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

/// Helper function to create evaluator with standard imports
fn eval_with_imports() -> Evaluator {
    Evaluator::new()
}

// ============================================================================
// Basic Vector Iteration
// ============================================================================

#[test]
fn test_for_in_vector_basic_sum() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut sum = 0
        let numbers = [1, 2, 3, 4, 5]
        for(x in numbers) {
            sum = sum + x
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_for_in_vector_inline_array() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut product = 1
        for(x in [2, 3, 4]) {
            product = product * x
        }
        product
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(24.0));
}

#[test]
fn test_for_in_vector_empty() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut count = 0
        for(x in []) {
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_for_in_vector_single_element() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut result = 0
        for(x in [42]) {
            result = x
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_for_in_vector_heterogeneous() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut count = 0
        for(item in [1, "two", true, null]) {
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(4.0));
}

#[test]
fn test_for_in_vector_strings() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut result = ""
        for(s in ["hello", " ", "world"]) {
            result = concat(result, s)
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::String("hello world".to_string()));
}

#[test]
fn test_for_in_vector_loop_returns_last_value() {
    let mut eval = Evaluator::new();
    let code = r#"
        let doubled = for(x in [1, 2, 3]) {
            x * 2
        }
        doubled
    "#;
    let result = eval.eval_str(code).unwrap();
    // Last value is 3 * 2 = 6
    assert_eq!(result, Value::Number(6.0));
}

// ============================================================================
// Vector Iteration with Break
// ============================================================================

#[test]
fn test_for_in_vector_break_basic() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut found = -1
        for(x in [1, 2, 3, 4, 5]) {
            if(x == 3) {
                found = x
                break
            }
        }
        found
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_for_in_vector_break_with_value() {
    let mut eval = Evaluator::new();
    let code = r#"
        let result = for(x in [1, 2, 3, 4, 5]) {
            if(x == 3) { break x * 10 }
            x
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_for_in_vector_break_first_element() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut count = 0
        for(x in [1, 2, 3]) {
            break
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_for_in_vector_break_last_element() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut sum = 0
        for(x in [1, 2, 3]) {
            sum = sum + x
            if(x == 3) { break }
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(6.0));
}

// ============================================================================
// Vector Iteration with Continue
// ============================================================================

#[test]
fn test_for_in_vector_continue_basic() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut sum = 0
        for(x in [1, 2, 3, 4, 5]) {
            if(x == 3) { continue }
            sum = sum + x
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // sum = 1 + 2 + 4 + 5 = 12 (skips 3)
    assert_eq!(result, Value::Number(12.0));
}

#[test]
fn test_for_in_vector_continue_skip_evens() {
    let mut eval = eval_with_imports();
    let code = r#"
        mut odd_count = 0
        mut odd_sum = 0
        for(x in [1, 2, 3, 4, 5, 6]) {
            if(x % 2 == 0) { continue }
            odd_count = odd_count + 1
            odd_sum = odd_sum + x
        }
        odd_sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // odd numbers: 1, 3, 5 -> sum = 9
    assert_eq!(result, Value::Number(9.0));
}

#[test]
fn test_for_in_vector_continue_all_elements() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut count = 0
        for(x in [1, 2, 3]) {
            count = count + 1
            continue
            // This should never execute
            count = count + 100
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

// ============================================================================
// Vector Iteration with Return
// ============================================================================

#[test]
fn test_for_in_vector_return_from_function() {
    let mut eval = Evaluator::new();
    let code = r#"
        let findFirst = (arr, target) => do {
            for(x in arr) {
                if(x == target) { return x }
            }
            null
        }
        findFirst([1, 2, 3, 4], 3)
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_for_in_vector_return_not_found() {
    let mut eval = Evaluator::new();
    let code = r#"
        let findFirst = (arr, target) => do {
            for(x in arr) {
                if(x == target) { return x }
            }
            -1
        }
        findFirst([1, 2, 3, 4], 10)
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(-1.0));
}

#[test]
fn test_for_in_vector_return_with_computation() {
    let mut eval = Evaluator::new();
    let code = r#"
        let sumUntil = (arr, limit) => do {
            mut total = 0
            for(x in arr) {
                total = total + x
                if(total >= limit) { return total }
            }
            total
        }
        sumUntil([5, 10, 15, 20], 25)
    "#;
    let result = eval.eval_str(code).unwrap();
    // 5 + 10 + 15 = 30 >= 25, returns 30
    assert_eq!(result, Value::Number(30.0));
}

// ============================================================================
// Nested Vector Iteration
// ============================================================================

#[test]
fn test_for_in_vector_nested_basic() {
    let mut eval = eval_with_imports();
    // Use vectors of different types to avoid auto-tensor conversion
    let code = r#"
        mut total_count = 0
        mut num_sum = 0
        let matrix = [[1, "a"], [2, "b"]]
        for(row in matrix) {
            for(elem in row) {
                total_count = total_count + 1
                if(typeof(elem) == "Number") {
                    num_sum = num_sum + elem
                }
            }
        }
        { count: total_count, sum: num_sum }
    "#;
    let result = eval.eval_str(code).unwrap();
    match result {
        Value::Record(map) => {
            assert_eq!(map.get("count"), Some(&Value::Number(4.0)));
            assert_eq!(map.get("sum"), Some(&Value::Number(3.0))); // 1 + 2 = 3
        }
        _ => panic!("Expected Record"),
    }
}

#[test]
fn test_for_in_vector_nested_with_break() {
    let mut eval = eval_with_imports();
    // Use mixed-type vectors to prevent tensor conversion
    let code = r#"
        mut sum = 0
        let matrix = [[1, "x", 2], [3, "y", 4], [5, "z", 6]]
        for(row in matrix) {
            for(elem in row) {
                if(typeof(elem) == "Number") {
                    if(elem == 4) { break }
                    sum = sum + elem
                }
            }
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // First row: 1 + 2 = 3
    // Second row: 3 (break at 4)
    // Third row: 5 + 6 = 11
    // Total: 3 + 3 + 11 = 17
    assert_eq!(result, Value::Number(17.0));
}

#[test]
fn test_for_in_vector_nested_outer_break() {
    let mut eval = eval_with_imports();
    // Use mixed-type vectors to prevent tensor conversion
    let code = r#"
        mut count = 0
        let matrix = [[1, "a"], [3, "b"], [5, "c"]]
        for(row in matrix) {
            if(count >= 3) { break }
            for(elem in row) {
                count = count + 1
            }
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    // First row: count = 2
    // Second row: count = 4, but condition check happens at start of outer loop
    // So both rows complete: count = 4
    assert_eq!(result, Value::Number(4.0));
}

// ============================================================================
// Tensor Iteration (RealTensor)
// ============================================================================

#[test]
fn test_for_in_tensor_linspace() {
    let mut eval = Evaluator::new();
    let code = r#"
        let tensor = linspace(0, 4, 5)
        mut sum = 0
        for(val in tensor) {
            sum = sum + val
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // linspace(0, 4, 5) = [0, 1, 2, 3, 4]
    // sum = 0 + 1 + 2 + 3 + 4 = 10
    assert_eq!(result, Value::Number(10.0));
}

#[test]
fn test_for_in_tensor_zeros() {
    let mut eval = eval_with_imports();
    // Use linspace to create a tensor
    let code = r#"
        let tensor = linspace(0, 0, 5)
        mut count = 0
        for(val in tensor) {
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_for_in_tensor_ones() {
    let mut eval = eval_with_imports();
    // Use linspace to create a tensor of ones
    let code = r#"
        let tensor = linspace(1, 1, 3)
        mut product = 1
        for(val in tensor) {
            product = product * val
        }
        product
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_for_in_tensor_with_break() {
    let mut eval = Evaluator::new();
    let code = r#"
        let tensor = linspace(1, 10, 10)
        mut sum = 0
        for(val in tensor) {
            if(val > 5) { break }
            sum = sum + val
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // 1 + 2 + 3 + 4 + 5 = 15
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_for_in_tensor_with_continue() {
    let mut eval = Evaluator::new();
    let code = r#"
        let tensor = linspace(1, 5, 5)
        mut sum = 0
        for(val in tensor) {
            if(val == 3) { continue }
            sum = sum + val
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // 1 + 2 + 4 + 5 = 12 (skips 3)
    assert_eq!(result, Value::Number(12.0));
}

#[test]
fn test_for_in_tensor_returns_last_value() {
    let mut eval = Evaluator::new();
    let code = r#"
        let tensor = linspace(2, 6, 3)
        let last = for(val in tensor) {
            val * 2
        }
        last
    "#;
    let result = eval.eval_str(code).unwrap();
    // linspace(2, 6, 3) = [2, 4, 6]
    // Last value: 6 * 2 = 12
    assert_eq!(result, Value::Number(12.0));
}

// ============================================================================
// ComplexTensor Iteration
// ============================================================================

#[test]
fn test_for_in_complex_tensor_basic() {
    let mut eval = Evaluator::new();
    let code = r#"
        let tensor = [1+2i, 3+4i, 5+6i]
        mut count = 0
        for(val in tensor) {
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_for_in_complex_tensor_operations() {
    let mut eval = eval_with_imports();
    let code = r#"
        let tensor = [1+0i, 0+1i, 1+1i]
        mut count = 0
        for(c in tensor) {
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    // Just count the elements
    assert_eq!(result, Value::Number(3.0));
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[test]
fn test_for_in_non_iterable_error() {
    let mut eval = Evaluator::new();
    let code = r#"
        for(x in 42) { x }
    "#;
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot iterate over"));
}

#[test]
fn test_for_in_string_error() {
    let mut eval = Evaluator::new();
    let code = r#"
        for(c in "hello") { c }
    "#;
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot iterate over"));
}

#[test]
fn test_for_in_boolean_error() {
    let mut eval = Evaluator::new();
    let code = r#"
        for(x in true) { x }
    "#;
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot iterate over"));
}

#[test]
fn test_for_in_null_error() {
    let mut eval = Evaluator::new();
    let code = r#"
        for(x in null) { x }
    "#;
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot iterate over"));
}

// ============================================================================
// Backward Compatibility with Generators
// ============================================================================

#[test]
fn test_for_in_generator_still_works() {
    let mut eval = eval_with_imports();
    let code = r#"
        mut sum = 0
        for(i in range(1, 6)) {
            sum = sum + i
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // range(1, 6) = [1, 2, 3, 4, 5] (end is exclusive)
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_for_in_generator_with_break() {
    let mut eval = eval_with_imports();
    let code = r#"
        mut count = 0
        for(i in range(1, 100)) {
            if(i > 3) { break }
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_for_in_generator_with_continue() {
    let mut eval = eval_with_imports();
    let code = r#"
        mut sum = 0
        for(i in range(1, 6)) {
            if(i == 3) { continue }
            sum = sum + i
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // range(1, 6) = [1, 2, 3, 4, 5], skips 3: 1 + 2 + 4 + 5 = 12
    assert_eq!(result, Value::Number(12.0));
}

// ============================================================================
// Advanced Use Cases
// ============================================================================

#[test]
fn test_for_in_vector_filter_transform() {
    let mut eval = eval_with_imports();
    let code = r#"
        let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        mut evens_sum = 0
        mut evens_count = 0
        for(n in numbers) {
            if(n % 2 == 0) {
                evens_sum = evens_sum + n * 2
                evens_count = evens_count + 1
            }
        }
        { sum: evens_sum, count: evens_count }
    "#;
    let result = eval.eval_str(code).unwrap();
    match result {
        Value::Record(map) => {
            // evens: 2, 4, 6, 8, 10
            // doubled: 4, 8, 12, 16, 20
            // sum: 4 + 8 + 12 + 16 + 20 = 60
            assert_eq!(map.get("sum"), Some(&Value::Number(60.0)));
            assert_eq!(map.get("count"), Some(&Value::Number(5.0)));
        }
        _ => panic!("Expected Record"),
    }
}

#[test]
fn test_for_in_vector_find_max() {
    let mut eval = Evaluator::new();
    let code = r#"
        let findMax = (arr) => do {
            mut maximum = arr[0]
            for(x in arr) {
                if(x > maximum) {
                    maximum = x
                }
            }
            maximum
        }
        findMax([3, 1, 4, 1, 5, 9, 2, 6])
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(9.0));
}

#[test]
fn test_for_in_vector_index_simulation() {
    let mut eval = eval_with_imports();
    let code = r#"
        let arr = ["a", "b", "c", "d"]
        mut idx = 0
        mut last_index = -1
        for(elem in arr) {
            last_index = idx
            idx = idx + 1
        }
        last_index
    "#;
    let result = eval.eval_str(code).unwrap();
    // Last index should be 3 (for "d")
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_for_in_vector_accumulator_pattern() {
    let mut eval = Evaluator::new();
    let code = r#"
        let reduce = (arr, initial, fn) => do {
            mut acc = initial
            for(x in arr) {
                acc = fn(acc, x)
            }
            acc
        }
        reduce([1, 2, 3, 4, 5], 0, (a, b) => a + b)
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_for_in_vector_with_records() {
    let mut eval = Evaluator::new();
    let code = r#"
        let people = [
            { name: "Alice", age: 30 },
            { name: "Bob", age: 25 },
            { name: "Charlie", age: 35 }
        ]
        mut total_age = 0
        for(person in people) {
            total_age = total_age + person.age
        }
        total_age
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(90.0));
}

#[test]
fn test_for_in_tensor_statistical_operations() {
    let mut eval = Evaluator::new();
    let code = r#"
        let data = linspace(1, 5, 5)
        mut sum = 0
        mut count = 0
        for(val in data) {
            sum = sum + val
            count = count + 1
        }
        let mean = sum / count
        mean
    "#;
    let result = eval.eval_str(code).unwrap();
    // mean of [1, 2, 3, 4, 5] = 15 / 5 = 3
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_for_in_mixed_iteration() {
    let mut eval = eval_with_imports();
    // Use heterogeneous vectors to prevent auto-tensor conversion
    let code = r#"
        let vectors = [[1, "a", 2], [3, "b", 4], [5, "c", 6]]
        mut grand_total = 0
        for(vec in vectors) {
            mut subtotal = 0
            for(x in vec) {
                if(typeof(x) == "Number") {
                    subtotal = subtotal + x
                }
            }
            grand_total = grand_total + subtotal
        }
        grand_total
    "#;
    let result = eval.eval_str(code).unwrap();
    // (1+2) + (3+4) + (5+6) = 3 + 7 + 11 = 21
    assert_eq!(result, Value::Number(21.0));
}
