//! Compatibility tests for the Achronyme VM
//!
//! These tests ensure that the VM produces correct results for all valid
//! Achronyme programs by comparing against expected values.
//!
//! Note: Direct comparison with tree-walker evaluator is temporarily disabled
//! due to API changes in the Value type (Vector/Record now use Rc<RefCell<>>).

use achronyme_parser;
use achronyme_vm::{VM, Compiler};
use achronyme_types::value::Value;
use std::rc::Rc;
use std::cell::RefCell;

/// Run source code with VM and assert it produces the expected result
fn test_compatibility(source: &str, expected: Value) {
    // Parse
    let ast = achronyme_parser::parse(source)
        .unwrap_or_else(|e| panic!("Failed to parse source '{}': {:?}", source, e));

    // Execute with VM
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler.compile(&ast)
        .unwrap_or_else(|e| panic!("Compilation failed for '{}': {}", source, e));

    let mut vm = VM::new();
    let vm_result = vm.execute(module)
        .unwrap_or_else(|e| panic!("VM execution failed for '{}': {}", source, e));

    // Compare results
    assert_values_equal(&expected, &vm_result, source);
}

/// Helper to create a vector Value
fn vec_value(items: Vec<Value>) -> Value {
    Value::Vector(Rc::new(RefCell::new(items)))
}

/// Helper to create a record Value
fn rec_value(items: Vec<(&str, Value)>) -> Value {
    use std::collections::HashMap;
    let map: HashMap<String, Value> = items.into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    Value::Record(Rc::new(RefCell::new(map)))
}

/// Compare two Values for equality, handling floating point imprecision
fn assert_values_equal(tree_val: &Value, vm_val: &Value, source: &str) {
    match (tree_val, vm_val) {
        (Value::Number(a), Value::Number(b)) => {
            // Handle NaN specially
            if a.is_nan() && b.is_nan() {
                return; // Both NaN is ok
            }
            // Handle infinity
            if a.is_infinite() && b.is_infinite() {
                assert_eq!(
                    a.is_sign_positive(),
                    b.is_sign_positive(),
                    "Infinity sign mismatch for '{}': tree={}, vm={}",
                    source, a, b
                );
                return;
            }
            assert!(
                (a - b).abs() < 1e-10,
                "Number mismatch for '{}': tree={}, vm={}",
                source, a, b
            );
        }
        (Value::Boolean(a), Value::Boolean(b)) => {
            assert_eq!(a, b, "Boolean mismatch for '{}'", source);
        }
        (Value::String(a), Value::String(b)) => {
            assert_eq!(a, b, "String mismatch for '{}'", source);
        }
        (Value::Null, Value::Null) => {},
        (Value::Vector(a), Value::Vector(b)) => {
            assert_eq!(
                a.len(),
                b.len(),
                "Vector length mismatch for '{}': tree={}, vm={}",
                source, a.len(), b.len()
            );
            for (i, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
                assert_values_equal(av, bv, &format!("{}[{}]", source, i));
            }
        }
        (Value::Record(a), Value::Record(b)) => {
            assert_eq!(
                a.len(),
                b.len(),
                "Record size mismatch for '{}': tree={}, vm={}",
                source, a.len(), b.len()
            );
            for (key, aval) in a.iter() {
                let bval = b.get(key)
                    .unwrap_or_else(|| panic!("Key '{}' missing in VM result for '{}'", key, source));
                assert_values_equal(aval, bval, &format!("{}.{}", source, key));
            }
        }
        // Functions are not directly comparable
        (Value::Function(_), Value::Function(_)) => {
            // Both are functions, that's good enough
        }
        (Value::MutableRef(a), Value::MutableRef(b)) => {
            // Compare the dereferenced values
            assert_values_equal(&a.borrow(), &b.borrow(), source);
        }
        _ => {
            panic!(
                "Type mismatch for '{}': tree={:?}, vm={:?}",
                source, tree_val, vm_val
            );
        }
    }
}

// ============================================================================
// BASIC TESTS
// ============================================================================

#[test]
fn test_arithmetic_add() {
    test_compatibility("2 + 2", Value::Number(4.0));
}

#[test]
fn test_arithmetic_subtract() {
    test_compatibility("10 - 3", Value::Number(7.0));
}

#[test]
fn test_arithmetic_multiply() {
    test_compatibility("4 * 5", Value::Number(20.0));
}

#[test]
fn test_arithmetic_divide() {
    test_compatibility("20 / 4", Value::Number(5.0));
}

#[test]
fn test_arithmetic_power() {
    test_compatibility("2 ^ 10", Value::Number(1024.0));
}

#[test]
fn test_arithmetic_complex() {
    test_compatibility("2 + 3 * 4", Value::Number(14.0));
    test_compatibility("(2 + 3) * 4", Value::Number(20.0));
    test_compatibility("10 / 2 - 3", Value::Number(2.0));
}

#[test]
fn test_negative_numbers() {
    test_compatibility("-5", Value::Number(-5.0));
    test_compatibility("-5 + 10", Value::Number(5.0));
}

#[test]
fn test_variables() {
    test_compatibility("let x = 5; x", Value::Number(5.0));
    test_compatibility("let x = 10; let y = 20; x + y", Value::Number(30.0));
    test_compatibility("let x = 5; x * 2", Value::Number(10.0));
}

#[test]
fn test_variable_reassignment() {
    test_compatibility("let x = 5; x = 10; x", Value::Number(10.0));
}

#[test]
fn test_functions() {
    test_compatibility("let f = (x) => x * 2; f(5)", Value::Number(10.0));
    test_compatibility("let add = (a, b) => a + b; add(3, 4)", Value::Number(7.0));
}

#[test]
fn test_function_closure() {
    test_compatibility("let make_adder = (n) => (x) => x + n; let add5 = make_adder(5); add5(10)", Value::Number(15.0));
}

#[test]
fn test_arrays() {
    test_compatibility("[1, 2, 3]", vec_value(vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]));
    test_compatibility("let arr = [1, 2, 3]; arr[0]", Value::Number(1.0));
    test_compatibility("let arr = [1, 2, 3]; arr[1]", Value::Number(2.0));
    test_compatibility("let arr = [1, 2, 3]; arr[2]", Value::Number(3.0));
}

#[test]
fn test_array_length() {
    test_compatibility("len([1, 2, 3, 4, 5])", Value::Number(5.0));
    test_compatibility("let arr = [1, 2, 3]; len(arr)", Value::Number(3.0));
}

// ============================================================================
// BUILT-IN FUNCTION TESTS
// ============================================================================

#[test]
fn test_builtin_sin() {
    test_compatibility("sin(0)");
}

#[test]
fn test_builtin_cos() {
    test_compatibility("cos(0)");
}

#[test]
fn test_builtin_sqrt() {
    test_compatibility("sqrt(16)");
}

#[test]
fn test_builtin_abs() {
    test_compatibility("abs(-5)");
}

#[test]
fn test_builtin_max() {
    test_compatibility("max(1, 2, 3, 4, 5)");
}

#[test]
fn test_builtin_min() {
    test_compatibility("min(5, 4, 3, 2, 1)");
}

#[test]
fn test_builtin_floor() {
    test_compatibility("floor(3.7)");
}

#[test]
fn test_builtin_ceil() {
    test_compatibility("ceil(3.2)");
}

#[test]
fn test_builtin_round() {
    test_compatibility("round(3.5)");
}

// ============================================================================
// HIGHER-ORDER FUNCTION TESTS
// ============================================================================

#[test]
fn test_hof_map() {
    test_compatibility("map((x) => x * 2, [1, 2, 3])");
    test_compatibility("map((x) => x + 1, [0, 1, 2])");
}

#[test]
fn test_hof_filter() {
    test_compatibility("filter((x) => x > 2, [1, 2, 3, 4, 5])");
    test_compatibility("filter((x) => x % 2 == 0, [1, 2, 3, 4, 5, 6])");
}

#[test]
fn test_hof_reduce() {
    test_compatibility("reduce((acc, x) => acc + x, 0, [1, 2, 3, 4])");
    test_compatibility("reduce((acc, x) => acc * x, 1, [1, 2, 3, 4])");
}

// ============================================================================
// CONDITIONAL TESTS
// ============================================================================

#[test]
fn test_if_true() {
    test_compatibility("if (true) 1 else 2");
}

#[test]
fn test_if_false() {
    test_compatibility("if (false) 1 else 2");
}

#[test]
fn test_if_comparison() {
    test_compatibility("if (5 > 3) 10 else 20");
    test_compatibility("if (2 > 5) 10 else 20");
}

#[test]
fn test_nested_if() {
    test_compatibility("if (true) if (false) 1 else 2 else 3");
}

// ============================================================================
// COMPARISON TESTS
// ============================================================================

#[test]
fn test_comparison_eq() {
    test_compatibility("5 == 5");
    test_compatibility("5 == 3");
}

#[test]
fn test_comparison_ne() {
    test_compatibility("5 != 3");
    test_compatibility("5 != 5");
}

#[test]
fn test_comparison_lt() {
    test_compatibility("3 < 5");
    test_compatibility("5 < 3");
}

#[test]
fn test_comparison_gt() {
    test_compatibility("5 > 3");
    test_compatibility("3 > 5");
}

#[test]
fn test_comparison_le() {
    test_compatibility("3 <= 5");
    test_compatibility("5 <= 5");
    test_compatibility("5 <= 3");
}

#[test]
fn test_comparison_ge() {
    test_compatibility("5 >= 3");
    test_compatibility("5 >= 5");
    test_compatibility("3 >= 5");
}

// ============================================================================
// LOGICAL OPERATOR TESTS
// ============================================================================

#[test]
fn test_logical_and() {
    test_compatibility("true && true");
    test_compatibility("true && false");
    test_compatibility("false && true");
    test_compatibility("false && false");
}

#[test]
fn test_logical_or() {
    test_compatibility("true || true");
    test_compatibility("true || false");
    test_compatibility("false || true");
    test_compatibility("false || false");
}

#[test]
fn test_logical_not() {
    test_compatibility("!true");
    test_compatibility("!false");
}

// ============================================================================
// LOOP TESTS
// ============================================================================

#[test]
fn test_for_in_loop() {
    test_compatibility("let sum = 0; for i in [1, 2, 3] { sum = sum + i }; sum");
}

#[test]
fn test_for_in_loop_range() {
    test_compatibility("let sum = 0; for i in range(1, 5) { sum = sum + i }; sum");
}

// ============================================================================
// RECURSION TESTS
// ============================================================================

#[test]
fn test_factorial() {
    test_compatibility("let fact = (n) => if (n <= 1) 1 else n * fact(n - 1); fact(5)");
}

#[test]
fn test_fibonacci() {
    test_compatibility("let fib = (n) => if (n <= 1) n else fib(n - 1) + fib(n - 2); fib(10)");
}

#[test]
fn test_tail_recursion() {
    test_compatibility(
        "let sum_tail = (n, acc) => if (n == 0) acc else sum_tail(n - 1, acc + n); sum_tail(100, 0)"
    );
}

// ============================================================================
// STRING TESTS
// ============================================================================

#[test]
fn test_string_literal() {
    test_compatibility("\"hello\"");
}

#[test]
fn test_string_concatenation() {
    test_compatibility("\"hello\" + \" \" + \"world\"");
}

// ============================================================================
// RECORD TESTS
// ============================================================================

#[test]
fn test_record_literal() {
    test_compatibility("{ x: 5, y: 10 }");
}

#[test]
fn test_record_access() {
    test_compatibility("let p = { x: 5, y: 10 }; p.x");
    test_compatibility("let p = { x: 5, y: 10 }; p.y");
}

// ============================================================================
// BLOCK TESTS
// ============================================================================

#[test]
fn test_block_expression() {
    test_compatibility("{ let x = 5; x * 2 }");
}

#[test]
fn test_block_multiple_statements() {
    test_compatibility("{ let x = 5; let y = 10; x + y }");
}

// ============================================================================
// COMPLEX EXPRESSIONS
// ============================================================================

#[test]
fn test_complex_expression_1() {
    test_compatibility("let x = 5; let f = (n) => n * 2; f(x) + 10");
}

#[test]
fn test_complex_expression_2() {
    test_compatibility("reduce((acc, x) => acc + x, 0, map((x) => x * 2, [1, 2, 3, 4]))");
}

#[test]
fn test_complex_expression_3() {
    test_compatibility(
        "let nums = [1, 2, 3, 4, 5]; \
         let evens = filter((x) => x % 2 == 0, nums); \
         reduce((acc, x) => acc + x, 0, evens)"
    );
}
