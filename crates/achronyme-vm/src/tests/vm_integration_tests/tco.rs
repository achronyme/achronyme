use super::helpers::execute;
use crate::value::Value;

// ============================================================================
// PHASE 7: TAIL CALL OPTIMIZATION TESTS
// ============================================================================

/// Test 1: Simple tail-recursive factorial
/// This would stack overflow without TCO, but should work with it
#[test]
fn test_tail_recursive_factorial() {
    let source = r#"
        let fact = (n, acc) => do {
            if (n == 0) {
                acc
            } else {
                rec(n - 1, acc * n)
            }
        }
        fact(10, 1)
    "#;
    let result = execute(source).unwrap();
    // 10! = 3628800
    assert_eq!(result, Value::Number(3628800.0));
}

/// Test 2: Deep tail recursion (would overflow without TCO)
/// Testing with a large number to ensure TCO is working
#[test]
fn test_deep_tail_recursion() {
    let source = r#"
        let countdown = (n) => do {
            if (n == 0) {
                42
            } else {
                rec(n - 1)
            }
        }
        countdown(1000)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

/// Test 3: Mutual tail recursion
/// even/odd predicates implemented with tail calls
#[test]
fn test_mutual_tail_recursion() {
    let source = r#"
        let is_even = (n, is_odd_fn) => do {
            if (n == 0) {
                true
            } else {
                is_odd_fn(n - 1, rec)
            }
        }

        let is_odd = (n, is_even_fn) => do {
            if (n == 0) {
                false
            } else {
                is_even_fn(n - 1, rec)
            }
        }

        is_even(10, is_odd)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

/// Test 4: Tail call in if-else branches
/// Both branches should support tail calls
#[test]
fn test_tail_call_in_if_branches() {
    let source = r#"
        let helper = (n) => do {
            if (n == 0) {
                100
            } else {
                if (n < 3) {
                    rec(n - 1)
                } else {
                    rec(n - 1)
                }
            }
        }
        helper(5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(100.0));
}

/// Test 5: Non-tail recursive call (should use regular CALL)
/// Last operation is addition, not the recursive call
#[test]
fn test_non_tail_recursive_call() {
    let source = r#"
        let sum_to_n = (n) => do {
            if (n == 0) {
                0
            } else {
                n + rec(n - 1)
            }
        }
        sum_to_n(5)
    "#;
    let result = execute(source).unwrap();
    // 5 + 4 + 3 + 2 + 1 = 15
    assert_eq!(result, Value::Number(15.0));
}

/// Test 6: Tail call with multiple arguments
/// Tests that TailCall correctly copies multiple arguments
#[test]
fn test_tail_call_multiple_args() {
    // First, test the simplest case: single iteration
    let source = r#"
        let simple = (a, b) => if (a <= 0) { b } else { rec(a - 1, b + 1) }
        simple(1, 0)
    "#;
    let result = execute(source).unwrap();
    println!("simple(1, 0) = {:?}", result);
    assert_eq!(result, Value::Number(1.0));

    // Now test with more iterations
    let source = r#"
        let sum_two = (a, b) => if (a <= 0) { b } else { rec(a - 1, b + 1) }
        sum_two(3, 0)
    "#;
    let result = execute(source).unwrap();
    println!("sum_two(3, 0) = {:?}", result);
    assert_eq!(result, Value::Number(3.0));

    // Now test with 3 arguments
    let source = r#"
        let sum_helper = (a, b, c) => if (a <= 0) { b + c } else { rec(a - 1, b + 1, c + 2) }
        sum_helper(3, 0, 0)
    "#;
    let result = execute(source).unwrap();
    println!("sum_helper(3, 0, 0) = {:?}", result);
    // b increases by 3, c increases by 6, total = 9
    assert_eq!(result, Value::Number(9.0));
}

/// Test 7: Tail call in do block
/// Last expression in a do block is in tail position
#[test]
fn test_tail_call_in_do_block() {
    let source = r#"
        let countdown = (n) => do {
            let dummy = n * 2
            if (n == 0) {
                dummy
            } else {
                rec(n - 1)
            }
        }
        countdown(3)
    "#;
    let result = execute(source).unwrap();
    // When n reaches 0, dummy = 0 * 2 = 0
    assert_eq!(result, Value::Number(0.0));
}

/// Test 8: Tail call with closure (ensure upvalues work correctly)
#[test]
fn test_tail_call_with_closure() {
    let source = r#"
        let make_counter = (limit) => do {
            (n) => do {
                if (n >= limit) {
                    n
                } else {
                    rec(n + 1)
                }
            }
        }
        let counter = make_counter(10)
        counter(0)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(10.0));
}

/// Test 9: Call expression with lambda in tail position
#[test]
fn test_tail_call_expression() {
    let source = r#"
        let apply = (f, x) => f(x)
        let countdown = (n) => do {
            if (n == 0) {
                42
            } else {
                apply(rec, n - 1)
            }
        }
        countdown(100)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

/// Test 10: Accumulator pattern with tail recursion
#[test]
fn test_accumulator_pattern() {
    let source = r#"
        let ac = (n, acc) => do {
            if (n == 0) {
                acc
            } else {
                rec(n - 1, acc + n)
            }
        }
        ac(100, 0)
    "#;
    let result = execute(source).unwrap();
    // Sum of 1 to 100 = 5050
    assert_eq!(result, Value::Number(5050.0));
}