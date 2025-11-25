//! Built-in function tests

use crate::compiler::Compiler;
use crate::value::Value;
use crate::vm::VM;

/// Helper to compile and execute source code
fn execute(source: &str) -> Result<Value, String> {
    // Parse
    let ast = achronyme_parser::parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

    // Compile
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler
        .compile(&ast)
        .map_err(|e| format!("Compile error: {}", e))?;

    // Execute
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let local = tokio::task::LocalSet::new();

    local
        .block_on(&rt, async {
            let mut vm = VM::new();
            vm.execute(module).await
        })
        .map_err(|e| format!("Runtime error: {}", e))
}

// ============================================================================
// Debug Test
// ============================================================================

#[test]
fn test_builtin_registry_debug() {
    use crate::compiler::Compiler;

    let compiler = Compiler::new("<test>".to_string());
    println!("Total builtins registered: {}", compiler.builtins.len());
    println!("sin ID: {:?}", compiler.builtins.get_id("sin"));
    println!("cos ID: {:?}", compiler.builtins.get_id("cos"));
    println!("print ID: {:?}", compiler.builtins.get_id("print"));

    assert!(compiler.builtins.get_id("sin").is_some());
}

// ============================================================================
// Math Functions
// ============================================================================

#[test]
fn test_builtin_sin() {
    let result = execute("sin(0)").unwrap();
    assert_eq!(result, Value::Number(0.0));

    let source = "sin(1.5707963267948966)"; // PI/2
    let result = execute(source).unwrap();
    match result {
        Value::Number(n) => assert!((n - 1.0).abs() < 0.0001),
        _ => panic!("Expected number"),
    }
}

#[test]
fn test_builtin_cos() {
    let result = execute("cos(0)").unwrap();
    assert_eq!(result, Value::Number(1.0));

    let source = "cos(3.14159265359)"; // PI
    let result = execute(source).unwrap();
    match result {
        Value::Number(n) => assert!((n + 1.0).abs() < 0.0001),
        _ => panic!("Expected number"),
    }
}

#[test]
fn test_builtin_sqrt() {
    let result = execute("sqrt(16)").unwrap();
    assert_eq!(result, Value::Number(4.0));

    let result = execute("sqrt(2)").unwrap();
    match result {
        Value::Number(n) => assert!((n - std::f64::consts::SQRT_2).abs() < 0.0001),
        _ => panic!("Expected number"),
    }
}

#[test]
fn test_builtin_abs() {
    let result = execute("abs(-42)").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = execute("abs(3.5)").unwrap();
    assert_eq!(result, Value::Number(3.5));
}

#[test]
fn test_builtin_floor() {
    let result = execute("floor(3.14)").unwrap();
    assert_eq!(result, Value::Number(3.0));

    let result = execute("floor(-2.7)").unwrap();
    assert_eq!(result, Value::Number(-3.0));
}

#[test]
fn test_builtin_ceil() {
    let result = execute("ceil(3.14)").unwrap();
    assert_eq!(result, Value::Number(4.0));

    let result = execute("ceil(-2.7)").unwrap();
    assert_eq!(result, Value::Number(-2.0));
}

#[test]
fn test_builtin_round() {
    let result = execute("round(3.14)").unwrap();
    assert_eq!(result, Value::Number(3.0));

    let result = execute("round(3.7)").unwrap();
    assert_eq!(result, Value::Number(4.0));
}

#[test]
fn test_builtin_min_max() {
    let result = execute("min(5, 2, 8, 1)").unwrap();
    assert_eq!(result, Value::Number(1.0));

    let result = execute("max(5, 2, 8, 1)").unwrap();
    assert_eq!(result, Value::Number(8.0));
}

#[test]
fn test_builtin_pow() {
    let result = execute("pow(2, 10)").unwrap();
    assert_eq!(result, Value::Number(1024.0));

    let result = execute("pow(5, 3)").unwrap();
    assert_eq!(result, Value::Number(125.0));
}

// ============================================================================
// String Functions
// ============================================================================

#[test]
fn test_builtin_len_string() {
    let result = execute(r#"len("hello")"#).unwrap();
    assert_eq!(result, Value::Number(5.0));

    let result = execute(r#"len("")"#).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_builtin_upper_lower() {
    let result = execute(r#"upper("hello")"#).unwrap();
    assert_eq!(result, Value::String("HELLO".to_string()));

    let result = execute(r#"lower("WORLD")"#).unwrap();
    assert_eq!(result, Value::String("world".to_string()));
}

#[test]
fn test_builtin_trim() {
    let result = execute(r#"trim("  hello  ")"#).unwrap();
    assert_eq!(result, Value::String("hello".to_string()));
}

#[test]
fn test_builtin_split_join() {
    let result = execute(r#"split("a,b,c", ",")"#).unwrap();
    match result {
        Value::Vector(v) => {
            let vec = v.read();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::String("a".to_string()));
            assert_eq!(vec[1], Value::String("b".to_string()));
            assert_eq!(vec[2], Value::String("c".to_string()));
        }
        _ => panic!("Expected vector"),
    }

    let result = execute(r#"join(["a", "b", "c"], "-")"#).unwrap();
    assert_eq!(result, Value::String("a-b-c".to_string()));
}

#[test]
fn test_builtin_replace() {
    let result = execute(r#"replace("hello world", "world", "there")"#).unwrap();
    assert_eq!(result, Value::String("hello there".to_string()));
}

#[test]
fn test_builtin_contains() {
    let result = execute(r#"contains("hello world", "world")"#).unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute(r#"contains("hello", "xyz")"#).unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_builtin_starts_with_ends_with() {
    let result = execute(r#"starts_with("hello", "he")"#).unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute(r#"ends_with("hello", "lo")"#).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

// ============================================================================
// Vector Functions
// ============================================================================

#[test]
fn test_builtin_len_vector() {
    let result = execute(r#"len([1, 2, 3])"#).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_builtin_push() {
    let result = execute(r#"push([1, 2], 3)"#).unwrap();
    match result {
        Value::Vector(v) => {
            let vec = v.read();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[2], Value::Number(3.0));
        }
        _ => panic!("Expected vector"),
    }
}

#[test]
fn test_builtin_pop() {
    let result = execute(r#"pop([1, 2, 3])"#).unwrap();
    // pop returns the removed element
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_builtin_first_last() {
    let result = execute(r#"first([1, 2, 3])"#).unwrap();
    assert_eq!(result, Value::Number(1.0));

    let result = execute(r#"last([1, 2, 3])"#).unwrap();
    assert_eq!(result, Value::Number(3.0));

    let result = execute(r#"first([])"#).unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn test_builtin_reverse() {
    let result = execute(r#"reverse([1, 2, 3])"#).unwrap();
    match result {
        Value::Vector(v) => {
            let vec = v.read();
            assert_eq!(vec[0], Value::Number(3.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(1.0));
        }
        _ => panic!("Expected vector"),
    }
}

#[test]
fn test_builtin_sort() {
    let result = execute(r#"sort([3, 1, 2])"#).unwrap();
    match result {
        Value::Vector(v) => {
            let vec = v.read();
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
        }
        _ => panic!("Expected vector"),
    }
}

#[test]
fn test_builtin_slice() {
    let result = execute(r#"slice([1, 2, 3, 4, 5], 1, 4)"#).unwrap();
    match result {
        Value::Vector(v) => {
            let vec = v.read();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(2.0));
            assert_eq!(vec[1], Value::Number(3.0));
            assert_eq!(vec[2], Value::Number(4.0));
        }
        _ => panic!("Expected vector"),
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_builtin_chained_operations() {
    let source = r#"
        let numbers = [3, 1, 4, 1, 5]
        let sorted = sort(numbers)
        first(sorted)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_builtin_in_function() {
    let source = r#"
        let hypotenuse = (a, b) => sqrt(pow(a, 2) + pow(b, 2))
        hypotenuse(3, 4)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_builtin_string_processing() {
    let source = r#"
        let text = "  HELLO WORLD  "
        let cleaned = trim(text)
        let lower_text = lower(cleaned)
        let words = split(lower_text, " ")
        len(words)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(2.0));
}

#[test]
fn test_builtin_vector_math() {
    let source = r#"
        let numbers = [1, 2, 3, 4, 5]
        let doubled = push(numbers, 6)
        let last_val = last(doubled)
        last_val * 2
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(12.0));
}
