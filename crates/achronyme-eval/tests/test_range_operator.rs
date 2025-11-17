//! Tests for the range operator (..) and inclusive range operator (..=)
//! Range expressions generate vectors of integers.

mod test_common;
use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

#[test]
fn test_simple_exclusive_range() {
    // 1..5 -> [1, 2, 3, 4]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("1..5").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 4);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
            assert_eq!(vec[3], Value::Number(4.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_simple_inclusive_range() {
    // 1..=5 -> [1, 2, 3, 4, 5]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("1..=5").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
            assert_eq!(vec[3], Value::Number(4.0));
            assert_eq!(vec[4], Value::Number(5.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_from_zero() {
    // 0..5 -> [0, 1, 2, 3, 4]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("0..5").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(0.0));
            assert_eq!(vec[4], Value::Number(4.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_negative_range() {
    // 0-5..0 -> [-5, -4, -3, -2, -1]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("0-5..0").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(-5.0));
            assert_eq!(vec[1], Value::Number(-4.0));
            assert_eq!(vec[2], Value::Number(-3.0));
            assert_eq!(vec[3], Value::Number(-2.0));
            assert_eq!(vec[4], Value::Number(-1.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_empty_exclusive_range() {
    // 5..5 -> [] (start == end, exclusive)
    let mut eval = Evaluator::new();
    let result = eval.eval_str("5..5").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 0);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_empty_reverse_range() {
    // 5..3 -> [] (start > end)
    let mut eval = Evaluator::new();
    let result = eval.eval_str("5..3").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 0);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_single_element_inclusive_range() {
    // 5..=5 -> [5]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("5..=5").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 1);
            assert_eq!(vec[0], Value::Number(5.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_with_variables() {
    // let n = 10; 0..n
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let n = 10; 0..n").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 10);
            assert_eq!(vec[0], Value::Number(0.0));
            assert_eq!(vec[9], Value::Number(9.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_with_expressions() {
    // 1+2..10-3 -> 3..7 -> [3, 4, 5, 6]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("1+2..10-3").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 4);
            assert_eq!(vec[0], Value::Number(3.0));
            assert_eq!(vec[1], Value::Number(4.0));
            assert_eq!(vec[2], Value::Number(5.0));
            assert_eq!(vec[3], Value::Number(6.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_precedence_lower_than_arithmetic() {
    // 1+2..5 should be (1+2)..5 = 3..5, not 1+(2..5)
    let mut eval = Evaluator::new();
    let result = eval.eval_str("1+2..5").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 2);
            assert_eq!(vec[0], Value::Number(3.0));
            assert_eq!(vec[1], Value::Number(4.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_with_function_calls() {
    // 0..len([1,2,3,4,5]) -> 0..5 -> [0, 1, 2, 3, 4]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("0..len([1,2,3,4,5])").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(0.0));
            assert_eq!(vec[4], Value::Number(4.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_in_for_loop() {
    // for(i in 0..5) { sum += i } -> sum = 0+1+2+3+4 = 10
    let mut eval = Evaluator::new();
    let result = eval.eval_str("do { mut sum = 0; for(i in 0..5) { sum += i }; sum }").unwrap();
    assert_eq!(result, Value::Number(10.0));
}

#[test]
fn test_range_in_for_loop_inclusive() {
    // for(i in 1..=5) { sum += i } -> sum = 1+2+3+4+5 = 15
    let mut eval = Evaluator::new();
    let result = eval.eval_str("do { mut sum = 0; for(i in 1..=5) { sum += i }; sum }").unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_range_can_be_indexed() {
    // (1..5)[2] -> [1,2,3,4][2] -> 3
    let mut eval = Evaluator::new();
    let result = eval.eval_str("(1..5)[2]").unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_range_with_map() {
    // map((x) => x*2, 1..4) -> [2, 4, 6]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("map((x) => x*2, 1..4)").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(2.0));
            assert_eq!(vec[1], Value::Number(4.0));
            assert_eq!(vec[2], Value::Number(6.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_with_filter() {
    // filter((x) => x % 2 == 0, 1..=10) -> [2, 4, 6, 8, 10]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("filter((x) => x % 2 == 0, 1..=10)").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(2.0));
            assert_eq!(vec[1], Value::Number(4.0));
            assert_eq!(vec[2], Value::Number(6.0));
            assert_eq!(vec[3], Value::Number(8.0));
            assert_eq!(vec[4], Value::Number(10.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_with_reduce() {
    // reduce((acc, x) => acc + x, 0, 1..=100) -> sum of 1 to 100 = 5050
    let mut eval = Evaluator::new();
    let result = eval.eval_str("reduce((acc, x) => acc + x, 0, 1..=100)").unwrap();
    assert_eq!(result, Value::Number(5050.0));
}

#[test]
fn test_existing_slice_still_works() {
    // arr[1..3] should still work for slicing
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let arr = [1,2,3,4,5]; arr[1..3]").unwrap();
    // Slicing returns Tensor or Vector depending on input type
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 2);
            assert_eq!(vec[0], Value::Number(2.0));
            assert_eq!(vec[1], Value::Number(3.0));
        }
        Value::Tensor(tensor) => {
            let data = tensor.data();
            assert_eq!(data.len(), 2);
            assert_eq!(data[0], 2.0);
            assert_eq!(data[1], 3.0);
        }
        _ => panic!("Expected Vector or Tensor, got {:?}", result),
    }
}

#[test]
fn test_slice_open_end_still_works() {
    // arr[2..] should still work
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let arr = [1,2,3,4,5]; arr[2..]").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(3.0));
            assert_eq!(vec[1], Value::Number(4.0));
            assert_eq!(vec[2], Value::Number(5.0));
        }
        Value::Tensor(tensor) => {
            let data = tensor.data();
            assert_eq!(data.len(), 3);
            assert_eq!(data[0], 3.0);
            assert_eq!(data[1], 4.0);
            assert_eq!(data[2], 5.0);
        }
        _ => panic!("Expected Vector or Tensor, got {:?}", result),
    }
}

#[test]
fn test_slice_open_start_still_works() {
    // arr[..3] should still work
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let arr = [1,2,3,4,5]; arr[..3]").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
        }
        Value::Tensor(tensor) => {
            let data = tensor.data();
            assert_eq!(data.len(), 3);
            assert_eq!(data[0], 1.0);
            assert_eq!(data[1], 2.0);
            assert_eq!(data[2], 3.0);
        }
        _ => panic!("Expected Vector or Tensor, got {:?}", result),
    }
}

#[test]
fn test_slice_full_range_still_works() {
    // arr[..] should still work (copy entire array)
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let arr = [1,2,3,4,5]; arr[..]").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 5);
        }
        Value::Tensor(tensor) => {
            assert_eq!(tensor.data().len(), 5);
        }
        _ => panic!("Expected Vector or Tensor, got {:?}", result),
    }
}

#[test]
fn test_range_with_large_numbers() {
    // 100..110 -> [100, 101, 102, 103, 104, 105, 106, 107, 108, 109]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("100..110").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 10);
            assert_eq!(vec[0], Value::Number(100.0));
            assert_eq!(vec[9], Value::Number(109.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_spread_operator_still_works() {
    // Ensure ... (spread) is not confused with .. (range)
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let a = [1,2]; let b = [3,4]; [...a, ...b]").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 4);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
            assert_eq!(vec[3], Value::Number(4.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_assigned_to_variable() {
    // let r = 1..5; r
    let mut eval = Evaluator::new();
    let result = eval.eval_str("let r = 1..5; r").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 4);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_in_array_literal() {
    // [1..3, 10..12] -> nested array of ranges
    // Note: Achronyme may coerce this to a 2D Tensor if dimensions match
    let mut eval = Evaluator::new();
    let result = eval.eval_str("[1..3, 10..12]").unwrap();
    match result {
        Value::Vector(outer) => {
            assert_eq!(outer.len(), 2);
            match &outer[0] {
                Value::Vector(inner) => {
                    assert_eq!(inner.len(), 2);
                    assert_eq!(inner[0], Value::Number(1.0));
                    assert_eq!(inner[1], Value::Number(2.0));
                }
                _ => panic!("Expected inner Vector"),
            }
            match &outer[1] {
                Value::Vector(inner) => {
                    assert_eq!(inner.len(), 2);
                    assert_eq!(inner[0], Value::Number(10.0));
                    assert_eq!(inner[1], Value::Number(11.0));
                }
                _ => panic!("Expected inner Vector"),
            }
        }
        Value::Tensor(tensor) => {
            // May be coerced to 2D tensor
            let data = tensor.data();
            assert_eq!(data.len(), 4);
            assert_eq!(data[0], 1.0);
            assert_eq!(data[1], 2.0);
            assert_eq!(data[2], 10.0);
            assert_eq!(data[3], 11.0);
        }
        _ => panic!("Expected Vector or Tensor, got {:?}", result),
    }
}

#[test]
fn test_float_truncation() {
    // Floats are truncated to integers: 1.9..5.1 -> 1..5 -> [1, 2, 3, 4]
    let mut eval = Evaluator::new();
    let result = eval.eval_str("1.9..5.1").unwrap();
    match result {
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 4);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[3], Value::Number(4.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_range_error_with_boolean() {
    // Boolean in range should error
    let mut eval = Evaluator::new();
    let result = eval.eval_str("true..5");
    assert!(result.is_err());
}

#[test]
fn test_range_error_with_string() {
    // String in range should error
    let mut eval = Evaluator::new();
    let result = eval.eval_str("\"a\"..\"z\"");
    assert!(result.is_err());
}
