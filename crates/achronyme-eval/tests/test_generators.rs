/// Integration tests for generators and for-in loops
///
/// Tests the generator and iterator functionality:
/// - generate { statements } - Create a generator function
/// - yield expr - Suspend generator and return value
/// - for(x in iterator) { body } - Iterate over an iterator
/// - generator.next() - Resume generator and get next value
/// - Iterator protocol: {value: T, done: Boolean}
///
/// NESTED CONTROL FLOW SUPPORT: Yields inside nested control structures (while, if, for)
/// are now fully supported. The implementation uses a yield-counting approach that
/// re-executes the generator from the beginning while skipping already-processed yields.
/// This enables proper state preservation across suspensions within nested structures.

use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

fn eval(source: &str) -> Result<Value, String> {
    let mut evaluator = Evaluator::new();
    evaluator.eval_str(source)
}

// ============================================================================
// Basic Generator Tests
// ============================================================================

#[test]
fn test_simple_generator() {
    let result = eval(r#"
        let gen = () => generate {
            yield 1
            yield 2
            yield 3
        }

        let g = gen()
        let a = g.next()
        let b = g.next()
        let c = g.next()
        [a.value, b.value, c.value]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], Value::Number(1.0));
        assert_eq!(values[1], Value::Number(2.0));
        assert_eq!(values[2], Value::Number(3.0));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

#[test]
fn test_generator_done_state() {
    let result = eval(r#"
        let gen = () => generate {
            yield 1
        }

        let g = gen()
        let a = g.next()
        let b = g.next()
        [a.done, b.done]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Boolean(false));
        assert_eq!(values[1], Value::Boolean(true));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

#[test]
fn test_generator_sticky_done() {
    let result = eval(r#"
        let gen = () => generate {
            yield 42
        }

        let g = gen()
        g.next()
        g.next()
        let third = g.next()
        third.done
    "#).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

// ============================================================================
// Generator with State
// ============================================================================

#[test]
fn test_generator_with_mutable_state() {
    let result = eval(r#"
        let countdown = (n) => generate {
            mut i = n
            while(i > 0) {
                yield i
                i = i - 1
            }
        }

        let gen = countdown(3)
        let a = gen.next().value
        let b = gen.next().value
        let c = gen.next().value
        [a, b, c]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], Value::Number(3.0));
        assert_eq!(values[1], Value::Number(2.0));
        assert_eq!(values[2], Value::Number(1.0));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

#[test]
fn test_generator_preserves_state() {
    let result = eval(r#"
        let counter = () => generate {
            mut count = 0
            while(count < 100) {
                count = count + 1
                yield count
            }
        }

        let gen = counter()
        let first = gen.next().value
        let second = gen.next().value
        let third = gen.next().value
        third - first
    "#).unwrap();
    assert_eq!(result, Value::Number(2.0));  // 3 - 1
}

// ============================================================================
// Generator with Return
// ============================================================================

#[test]
fn test_generator_with_return() {
    let result = eval(r#"
        let gen = () => generate {
            yield 1
            yield 2
            return 42
        }

        let g = gen()
        g.next()
        g.next()
        let final_result = g.next()
        [final_result.value, final_result.done]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Number(42.0));
        assert_eq!(values[1], Value::Boolean(true));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

#[test]
fn test_generator_return_ends_iteration() {
    let result = eval(r#"
        let gen = () => generate {
            yield 1
            return 100
            yield 2
        }

        let g = gen()
        let a = g.next()
        let b = g.next()
        let c = g.next()
        [a.value, b.value, c.value, b.done, c.done]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 5);
        assert_eq!(values[0], Value::Number(1.0));
        assert_eq!(values[1], Value::Number(100.0));
        assert_eq!(values[2], Value::Number(100.0));  // Sticky return value
        assert_eq!(values[3], Value::Boolean(true));
        assert_eq!(values[4], Value::Boolean(true));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

// ============================================================================
// Fibonacci Generator
// ============================================================================

#[test]
fn test_fibonacci_generator() {
    let result = eval(r#"
        let fibonacci = () => generate {
            mut a = 0
            mut b = 1
            while(true) {
                yield a
                let temp = a
                a = b
                b = temp + b
            }
        }

        let fib = fibonacci()
        let values = [
            fib.next().value,
            fib.next().value,
            fib.next().value,
            fib.next().value,
            fib.next().value,
            fib.next().value,
            fib.next().value
        ]
        values
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 7);
        assert_eq!(values[0], Value::Number(0.0));
        assert_eq!(values[1], Value::Number(1.0));
        assert_eq!(values[2], Value::Number(1.0));
        assert_eq!(values[3], Value::Number(2.0));
        assert_eq!(values[4], Value::Number(3.0));
        assert_eq!(values[5], Value::Number(5.0));
        assert_eq!(values[6], Value::Number(8.0));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

// ============================================================================
// For-In Loop Tests
// ============================================================================

#[test]
fn test_for_in_with_generator() {
    let result = eval(r#"
        let range = (n) => generate {
            mut i = 0
            while(i < n) {
                yield i
                i = i + 1
            }
        }

        mut sum = 0
        for(x in range(5)) {
            sum = sum + x
        }
        sum
    "#).unwrap();
    assert_eq!(result, Value::Number(10.0));  // 0+1+2+3+4
}

#[test]
fn test_for_in_with_manual_iterator() {
    let result = eval(r#"
        mut state = {mut current: 0}
        let iterator = {
            next: () => do {
                if(state.current >= 3) {
                    {value: null, done: true}
                } else {
                    let value = state.current
                    state.current = state.current + 1
                    {value: value, done: false}
                }
            }
        }

        mut sum = 0
        for(x in iterator) {
            sum = sum + x
        }
        sum
    "#).unwrap();
    assert_eq!(result, Value::Number(3.0));  // 0+1+2
}

#[test]
fn test_for_in_empty_iterator() {
    let result = eval(r#"
        let empty = () => generate {
            return null
        }

        mut count = 0
        for(x in empty()) {
            count = count + 1
        }
        count
    "#).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_for_in_with_early_return() {
    let result = eval(r#"
        let range = (n) => generate {
            mut i = 0
            while(i < n) {
                yield i
                i = i + 1
            }
        }

        let findFirst = (pred) => do {
            for(x in range(10)) {
                if(pred(x)) {
                    return x
                }
            }
            -1
        }

        findFirst(x => x > 5)
    "#).unwrap();
    assert_eq!(result, Value::Number(6.0));
}

// ============================================================================
// Generator Composition
// ============================================================================

#[test]
fn test_map_over_generator() {
    let result = eval(r#"
        let range = (n) => generate {
            mut i = 0
            while(i < n) {
                yield i
                i = i + 1
            }
        }

        let mapIter = (f, iter) => {
            next: () => do {
                let item = iter.next()
                if(item.done) {
                    item
                } else {
                    {value: f(item.value), done: false}
                }
            }
        }

        let doubled = mapIter(x => x * 2, range(3))
        let a = doubled.next().value
        let b = doubled.next().value
        let c = doubled.next().value
        [a, b, c]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], Value::Number(0.0));
        assert_eq!(values[1], Value::Number(2.0));
        assert_eq!(values[2], Value::Number(4.0));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

#[test]
fn test_collect_generator() {
    let result = eval(r#"
        let range = (n) => generate {
            mut i = 0
            while(i < n) {
                yield i
                i = i + 1
            }
        }

        let collect = (iter) => do {
            mut result = []
            for(x in iter) {
                result = [...result, x]
            }
            result
        }

        collect(range(4))
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], Value::Number(0.0));
        assert_eq!(values[1], Value::Number(1.0));
        assert_eq!(values[2], Value::Number(2.0));
        assert_eq!(values[3], Value::Number(3.0));
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_yield_outside_generator_is_error() {
    let result = eval(r#"
        yield 42
    "#);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("yield"));
}

#[test]
fn test_generator_next_no_args() {
    // This should work - next() takes no args
    let result = eval(r#"
        let gen = () => generate {
            yield 1
        }
        let g = gen()
        g.next().value
    "#).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

// ============================================================================
// Multiple Independent Generators
// ============================================================================

#[test]
fn test_multiple_generator_instances() {
    let result = eval(r#"
        let counter = () => generate {
            mut i = 0
            while(i < 10) {
                i = i + 1
                yield i
            }
        }

        let g1 = counter()
        let g2 = counter()

        g1.next()
        g1.next()
        g2.next()

        let v1 = g1.next().value
        let v2 = g2.next().value
        [v1, v2]
    "#).unwrap();

    if let Value::Vector(values) = result {
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Number(3.0));  // g1 at 3rd call
        assert_eq!(values[1], Value::Number(2.0));  // g2 at 2nd call
    } else {
        panic!("Expected Vector, got {:?}", result);
    }
}

// ============================================================================
// Generator with Complex Yields
// ============================================================================

#[test]
fn test_generator_yields_records() {
    let result = eval(r#"
        let points = () => generate {
            yield {x: 0, y: 0}
            yield {x: 1, y: 2}
            yield {x: 3, y: 4}
        }

        let gen = points()
        let p1 = gen.next().value
        let p2 = gen.next().value
        p1.x + p2.y
    "#).unwrap();
    assert_eq!(result, Value::Number(2.0));  // 0 + 2
}

#[test]
fn test_generator_yields_vectors() {
    let result = eval(r#"
        let matrix_rows = () => generate {
            yield [1, 2, 3]
            yield [4, 5, 6]
        }

        let gen = matrix_rows()
        let row1 = gen.next().value
        let row2 = gen.next().value
        row1[0] + row2[2]
    "#).unwrap();
    assert_eq!(result, Value::Number(7.0));  // 1 + 6
}
