//! Tests for break and continue statements in loops
//!
//! This module tests the implementation of loop control flow statements:
//! - `break` - Exit the current loop immediately
//! - `break expr` - Exit the loop and return a value
//! - `continue` - Skip to the next iteration
//! - Validation that both only work inside loops

use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

mod test_common;
use test_common::*;

// ============================================================================
// Basic Break Tests
// ============================================================================

#[test]
fn test_break_basic_while() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        while(i < 10) {
            if(i == 3) { break }
            i = i + 1
        }
        i
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_break_at_start_of_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut count = 0
        while(true) {
            break
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_break_with_value() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        let result = while(i < 100) {
            i = i + 1
            if(i == 5) { break i * 2 }
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(10.0));
}

#[test]
fn test_break_with_complex_expression() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut sum = 0
        mut i = 0
        let result = while(i < 100) {
            sum = sum + i
            i = i + 1
            if(i == 5) { break { value: sum, count: i } }
        }
        result.value
    "#;
    let result = eval.eval_str(code).unwrap();
    // sum = 0 + 1 + 2 + 3 + 4 = 10
    assert_eq!(result, Value::Number(10.0));
}

// ============================================================================
// Basic Continue Tests
// ============================================================================

#[test]
fn test_continue_basic_while() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut sum = 0
        mut i = 0
        while(i < 5) {
            i = i + 1
            if(i == 3) { continue }
            sum = sum + i
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // sum = 1 + 2 + 4 + 5 = 12 (skips 3)
    assert_eq!(result, Value::Number(12.0));
}

#[test]
fn test_continue_skips_rest_of_body() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut result = ""
        mut i = 0
        while(i < 5) {
            i = i + 1
            if(i % 2 == 0) { continue }
            result = concat(result, concat(str(i), ","))
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    // Only odd numbers: "1,3,5,"
    match result {
        Value::String(s) => {
            assert_eq!(s, "1,3,5,");
        }
        _ => panic!("Expected String"),
    }
}

#[test]
fn test_continue_multiple_times() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut count = 0
        mut i = 0
        while(i < 10) {
            i = i + 1
            if(i % 2 == 0) { continue }
            if(i % 3 == 0) { continue }
            count = count + 1
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    // Only numbers not divisible by 2 or 3: 1, 5, 7 = 3 numbers
    assert_eq!(result, Value::Number(3.0));
}

// ============================================================================
// For-In Loop Tests
// NOTE: For-in tests with generators that have yields inside while loops are
// ignored because this is a known limitation (see test_generators.rs)
// ============================================================================

#[test]
#[ignore = "yields inside while loops not yet supported - needs continuation-based execution"]
fn test_break_in_for_loop() {
    let mut eval = Evaluator::new();
    // Test with generator instead of range
    let code = r#"
        let make_range = (start, end) => generate {
            mut i = start
            while(i < end) {
                yield i
                i = i + 1
            }
        }
        mut found = -1
        for(x in make_range(1, 10)) {
            if(x == 5) {
                found = x
                break
            }
        }
        found
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
#[ignore = "yields inside while loops not yet supported - needs continuation-based execution"]
fn test_continue_in_for_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        let make_range = (start, end) => generate {
            mut i = start
            while(i < end) {
                yield i
                i = i + 1
            }
        }
        mut evens = ""
        for(x in make_range(1, 10)) {
            if(x % 2 != 0) { continue }
            evens = concat(evens, concat(str(x), ","))
        }
        evens
    "#;
    let result = eval.eval_str(code).unwrap();
    match result {
        Value::String(s) => {
            assert_eq!(s, "2,4,6,8,");
        }
        _ => panic!("Expected String"),
    }
}

#[test]
#[ignore = "yields inside while loops not yet supported - needs continuation-based execution"]
fn test_break_with_value_in_for_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        let make_range = (start, end) => generate {
            mut i = start
            while(i < end) {
                yield i
                i = i + 1
            }
        }
        let result = for(x in make_range(1, 100)) {
            if(x * x > 50) { break x }
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    // 7 * 7 = 49 (not > 50), 8 * 8 = 64 (> 50), so result = 8
    assert_eq!(result, Value::Number(8.0));
}

// ============================================================================
// Nested Loop Tests
// ============================================================================

#[test]
fn test_break_only_affects_inner_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut outer_count = 0
        while(outer_count < 3) {
            mut inner_count = 0
            while(inner_count < 5) {
                if(inner_count == 2) { break }
                inner_count = inner_count + 1
            }
            outer_count = outer_count + 1
        }
        outer_count
    "#;
    let result = eval.eval_str(code).unwrap();
    // Outer loop completes all 3 iterations
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_continue_only_affects_inner_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut total = 0
        mut outer = 0
        while(outer < 3) {
            mut inner = 0
            while(inner < 3) {
                inner = inner + 1
                if(inner == 2) { continue }
                total = total + 1
            }
            outer = outer + 1
        }
        total
    "#;
    let result = eval.eval_str(code).unwrap();
    // Each outer iteration: inner adds 2 to total (skips when inner == 2)
    // 3 outer iterations * 2 = 6
    assert_eq!(result, Value::Number(6.0));
}

#[test]
#[ignore = "yields inside while loops not yet supported - needs continuation-based execution"]
fn test_nested_for_with_break() {
    let mut eval = Evaluator::new();
    let code = r#"
        let make_range = (start, end) => generate {
            mut i = start
            while(i < end) {
                yield i
                i = i + 1
            }
        }
        mut count = 0
        for(i in make_range(1, 4)) {
            for(j in make_range(1, 4)) {
                if(j == 2) { break }
                count = count + 1
            }
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    // For each i (1,2,3), only j=1 gets counted before break
    // So 3 counts
    assert_eq!(result, Value::Number(3.0));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_break_outside_loop_is_error() {
    let mut eval = Evaluator::new();
    let code = "break";
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("loop"));
}

#[test]
fn test_break_with_value_outside_loop_is_error() {
    let mut eval = Evaluator::new();
    let code = "break 42";
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("loop"));
}

#[test]
fn test_continue_outside_loop_is_error() {
    let mut eval = Evaluator::new();
    let code = "continue";
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("loop"));
}

#[test]
fn test_break_in_function_without_loop_is_error() {
    let mut eval = Evaluator::new();
    let code = r#"
        let f = () => do { break }
        f()
    "#;
    let result = eval.eval_str(code);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("loop") || err_msg.contains("break"), "Error should mention loop or break: {}", err_msg);
}

#[test]
fn test_continue_in_if_outside_loop_is_error() {
    let mut eval = Evaluator::new();
    let code = r#"
        if(true) { continue }
    "#;
    let result = eval.eval_str(code);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("loop"));
}

// ============================================================================
// Complex Control Flow Tests
// ============================================================================

#[test]
fn test_break_inside_if_in_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        while(i < 100) {
            i = i + 1
            if(i > 5) {
                if(i % 2 == 0) {
                    break
                }
            }
        }
        i
    "#;
    let result = eval.eval_str(code).unwrap();
    // i becomes 6 (first even > 5)
    assert_eq!(result, Value::Number(6.0));
}

#[test]
#[ignore = "yields inside while loops not yet supported - needs continuation-based execution"]
fn test_continue_inside_nested_if() {
    let mut eval = Evaluator::new();
    let code = r#"
        let make_range = (start, end) => generate {
            mut i = start
            while(i < end) {
                yield i
                i = i + 1
            }
        }
        mut sum = 0
        for(x in make_range(1, 10)) {
            if(x > 2) {
                if(x < 8) {
                    if(x % 2 == 0) {
                        continue
                    }
                }
            }
            sum = sum + x
        }
        sum
    "#;
    let result = eval.eval_str(code).unwrap();
    // Sum includes: 1, 2, 3, 5, 7, 8, 9
    // (skips 4 and 6 which are even and between 2 and 8)
    // 1+2+3+5+7+8+9 = 35
    assert_eq!(result, Value::Number(35.0));
}

#[test]
fn test_break_and_continue_together() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut results = ""
        mut i = 0
        while(i < 20) {
            i = i + 1
            if(i % 2 == 0) { continue }
            if(i > 10) { break }
            results = concat(results, concat(str(i), ","))
        }
        results
    "#;
    let result = eval.eval_str(code).unwrap();
    // Odd numbers from 1-9: "1,3,5,7,9,"
    match result {
        Value::String(s) => {
            assert_eq!(s, "1,3,5,7,9,");
        }
        _ => panic!("Expected String"),
    }
}

#[test]
fn test_early_termination_search() {
    let mut eval = Evaluator::new();
    let code = r#"
        let data = [1, 3, 5, 7, 9, 11, 13, 15]
        mut found_index = -1
        mut i = 0
        while(i < len(data)) {
            if(data[i] == 9) {
                found_index = i
                break
            }
            i = i + 1
        }
        found_index
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(4.0));
}

// ============================================================================
// Loop Return Value Tests
// ============================================================================

#[test]
fn test_while_returns_last_value_without_break() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        let result = while(i < 3) {
            i = i + 1
            i * 10
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    // Last iteration: i becomes 3, returns 30
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_break_value_overrides_loop_result() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        let result = while(i < 100) {
            i = i + 1
            if(i == 2) { break 999 }
            i * 10
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(999.0));
}

#[test]
#[ignore = "yields inside while loops not yet supported - needs continuation-based execution"]
fn test_for_loop_returns_last_value() {
    let mut eval = Evaluator::new();
    let code = r#"
        let make_range = (start, end) => generate {
            mut i = start
            while(i < end) {
                yield i
                i = i + 1
            }
        }
        let result = for(x in make_range(1, 4)) {
            x * x
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    // Last value: 3 * 3 = 9
    assert_eq!(result, Value::Number(9.0));
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_break_in_empty_while_body() {
    let mut eval = Evaluator::new();
    let code = r#"
        while(true) { break }
        42
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_continue_with_only_increment() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        mut count = 0
        while(i < 10) {
            i = i + 1
            continue
            count = count + 1  // This should never execute
        }
        count
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_break_preserves_scope() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut x = 0
        while(true) {
            let y = 10
            x = y
            break
        }
        x
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(10.0));
}

// ============================================================================
// Integration with Other Features
// ============================================================================

#[test]
fn test_break_with_record_value() {
    let mut eval = Evaluator::new();
    let code = r#"
        mut i = 0
        let result = while(i < 100) {
            i = i + 1
            if(i == 3) {
                break { index: i, doubled: i * 2, squared: i * i }
            }
        }
        result.squared
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(9.0));
}

#[test]
fn test_break_in_match_inside_loop() {
    let mut eval = Evaluator::new();
    let code = r#"
        let data = ["a", "b", "STOP", "c", "d"]
        mut result = ""
        mut i = 0
        while(i < len(data)) {
            let should_break = match(data[i]) {
                "STOP" => true,
                x => do {
                    result = concat(result, concat(x, ","))
                    false
                }
            }
            if(should_break) { break }
            i = i + 1
        }
        result
    "#;
    let result = eval.eval_str(code).unwrap();
    match result {
        Value::String(s) => {
            assert_eq!(s, "a,b,");
        }
        _ => panic!("Expected String"),
    }
}

#[test]
fn test_return_takes_precedence_over_break() {
    let mut eval = Evaluator::new();
    let code = r#"
        let find_first_even = (arr) => do {
            mut i = 0
            while(i < len(arr)) {
                if(arr[i] % 2 == 0) {
                    return arr[i]
                }
                i = i + 1
            }
            -1
        }
        find_first_even([1, 3, 5, 8, 9])
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Number(8.0));
}

#[test]
fn test_early_return_from_loop_inside_function() {
    let mut eval = Evaluator::new();
    let code = r#"
        let search = (target) => do {
            mut i = 0
            while(i < 100) {
                i = i + 1
                if(i == target) {
                    return true
                }
            }
            false
        }
        search(50)
    "#;
    let result = eval.eval_str(code).unwrap();
    assert_eq!(result, Value::Boolean(true));
}
