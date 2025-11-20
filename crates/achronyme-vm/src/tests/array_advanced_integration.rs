//! Integration tests for Phase 4E Advanced Array functions
//!
//! These tests verify that the advanced array functions work correctly
//! when called through the full VM compilation and execution pipeline.

use crate::compiler::Compiler;
use crate::value::Value;
use crate::vm::VM;

fn compile_and_run(source: &str) -> Result<Value, String> {
    // Parse
    let ast = achronyme_parser::parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

    // Compile
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler
        .compile(&ast)
        .map_err(|e| format!("Compile error: {}", e))?;

    // Execute
    let mut vm = VM::new();
    vm.execute(module)
        .map_err(|e| format!("Runtime error: {}", e))
}

// ============================================================================
// Range Tests (Phase 4A)
// ============================================================================

#[test]
fn test_range_basic() {
    let result = compile_and_run("range(0, 5)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(0.0));
            assert_eq!(vec[4], Value::Number(4.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_with_step() {
    let result = compile_and_run("range(1, 10, 2)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[4], Value::Number(9.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_negative_step() {
    let result = compile_and_run("range(5, 0, -1)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(5.0));
            assert_eq!(vec[4], Value::Number(1.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_in_expression() {
    let result = compile_and_run("len(range(0, 10))").unwrap();
    assert_eq!(result, Value::Number(10.0));
}

// ============================================================================
// Product Tests
// ============================================================================

#[test]
fn test_product_basic() {
    let result = compile_and_run("product([2, 3, 4])").unwrap();
    assert_eq!(result, Value::Number(24.0));
}

#[test]
fn test_product_empty() {
    let result = compile_and_run("product([])").unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_product_with_range() {
    let result = compile_and_run("product(range(1, 5))").unwrap();
    assert_eq!(result, Value::Number(24.0)); // 1 * 2 * 3 * 4 = 24
}

// ============================================================================
// Zip Tests
// ============================================================================

#[test]
fn test_zip_basic() {
    let result = compile_and_run("zip([1, 2, 3], [4, 5, 6])").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 3);
            // Check first pair
            if let Value::Vector(pair) = &vec[0] {
                let p = pair.borrow();
                assert_eq!(p[0], Value::Number(1.0));
                assert_eq!(p[1], Value::Number(4.0));
            } else {
                panic!("Expected pair to be Vector");
            }
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_zip_different_lengths() {
    let result = compile_and_run("len(zip([1, 2], [3, 4, 5, 6]))").unwrap();
    assert_eq!(result, Value::Number(2.0)); // Should zip to length of shorter
}

// ============================================================================
// Flatten Tests
// ============================================================================

#[test]
fn test_flatten_basic() {
    let result = compile_and_run("flatten([[1, 2], [3, 4]])").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 4);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[3], Value::Number(4.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_flatten_with_depth() {
    let result = compile_and_run("flatten([[[1]], [[2]]], 2)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 2);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_flatten_mixed() {
    let result = compile_and_run("flatten([1, [2, 3], 4])").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 4);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
            assert_eq!(vec[3], Value::Number(4.0));
        }
        _ => panic!("Expected Vector"),
    }
}

// ============================================================================
// Take Tests
// ============================================================================

#[test]
fn test_take_basic() {
    let result = compile_and_run("take([1, 2, 3, 4, 5], 3)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[2], Value::Number(3.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_take_with_range() {
    let result = compile_and_run("take(range(0, 100), 5)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 5);
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_take_more_than_length() {
    let result = compile_and_run("len(take([1, 2], 10))").unwrap();
    assert_eq!(result, Value::Number(2.0));
}

// ============================================================================
// Drop Tests
// ============================================================================

#[test]
fn test_drop_basic() {
    let result = compile_and_run("drop([1, 2, 3, 4, 5], 2)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(3.0));
            assert_eq!(vec[2], Value::Number(5.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_drop_all() {
    let result = compile_and_run("len(drop([1, 2, 3], 10))").unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_take_and_drop_combined() {
    // Take middle elements: drop first 2, then take 3
    let result = compile_and_run("take(drop([1, 2, 3, 4, 5, 6, 7], 2), 3)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(3.0)); // [3, 4, 5]
            assert_eq!(vec[2], Value::Number(5.0));
        }
        _ => panic!("Expected Vector"),
    }
}

// ============================================================================
// Unique Tests
// ============================================================================

#[test]
fn test_unique_basic() {
    let result = compile_and_run("unique([1, 2, 2, 3, 1, 4])").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
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
fn test_unique_already_unique() {
    let result = compile_and_run("len(unique([1, 2, 3, 4]))").unwrap();
    assert_eq!(result, Value::Number(4.0));
}

#[test]
fn test_unique_all_same() {
    let result = compile_and_run("len(unique([5, 5, 5, 5]))").unwrap();
    assert_eq!(result, Value::Number(1.0));
}

// ============================================================================
// Chunk Tests
// ============================================================================

#[test]
fn test_chunk_basic() {
    let result = compile_and_run("chunk([1, 2, 3, 4, 5], 2)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 3); // [1,2], [3,4], [5]
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_chunk_exact() {
    let result = compile_and_run("chunk([1, 2, 3, 4], 2)").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 2); // [1,2], [3,4]
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_chunk_with_range() {
    let result = compile_and_run("len(chunk(range(0, 10), 3))").unwrap();
    assert_eq!(result, Value::Number(4.0)); // 10 elements / 3 = 4 chunks
}

// ============================================================================
// Complex Integration Tests
// ============================================================================

#[test]
fn test_pipeline_operations() {
    // Create range, take subset, get product
    let result = compile_and_run("product(take(range(1, 6), 4))").unwrap();
    assert_eq!(result, Value::Number(24.0)); // 1 * 2 * 3 * 4 = 24
}

#[test]
fn test_nested_array_operations() {
    // Chunk a range, then flatten it back
    let result = compile_and_run("flatten(chunk(range(0, 6), 2))").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 6);
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_array_manipulation_chain() {
    // Complex chain: range -> drop first 2 -> take next 3 -> product
    let result = compile_and_run("product(take(drop(range(1, 10), 2), 3))").unwrap();
    assert_eq!(result, Value::Number(60.0)); // 3 * 4 * 5 = 60
}

#[test]
fn test_zip_with_range() {
    let result = compile_and_run("zip([\"a\", \"b\", \"c\"], range(1, 4))").unwrap();
    match result {
        Value::Vector(rc) => {
            let vec = rc.borrow();
            assert_eq!(vec.len(), 3);
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_unique_with_sum() {
    // Remove duplicates then sum
    let result = compile_and_run("sum(unique([1, 2, 2, 3, 3, 3, 4]))").unwrap();
    assert_eq!(result, Value::Number(10.0)); // 1 + 2 + 3 + 4 = 10
}

#[test]
fn test_chunked_sums() {
    // Chunk array and check we got the right number of chunks
    let result = compile_and_run("len(chunk(range(1, 11), 3))").unwrap();
    assert_eq!(result, Value::Number(4.0)); // [1,2,3], [4,5,6], [7,8,9], [10]
}
