use super::helpers::execute;
use crate::value::Value;

#[test]
fn test_signal_basic() {
    let source = r#"
        let s = signal(10)
        let initial = s.value
        s.set(20)
        let updated = s.value
        [initial, updated]
    "#;
    let result = execute(source).unwrap();
    match result {
        Value::Vector(v) => {
            let vec = v.borrow();
            assert_eq!(vec[0], Value::Number(10.0));
            assert_eq!(vec[1], Value::Number(20.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_effect_reactivity() {
    let source = r#"
        let count = signal(0)
        let accumulator = signal(0) // Using signal as a mutable container for test

        effect(() => do {
            // This reads count.value, so it should subscribe
            let current = count.value
            // Update accumulator (side effect)
            // We use peek() here to read WITHOUT subscribing, avoiding infinite loop!
            accumulator.set(accumulator.peek() + 1)
        })

        // Effect runs once immediately -> acc = 1 (initial run)
        count.set(1) // Effect runs again -> acc = 2
        count.set(2) // Effect runs again -> acc = 3
        count.set(2) // Same value, should NOT run -> acc = 3

        accumulator.value
    "#;

    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_computed_simulation() {
    let source = r#"
        // We can simulate computed signals with effects
        let a = signal(2)
        let b = signal(3)
        let sum = signal(0)

        effect(() => do {
            sum.set(a.value + b.value)
        })

        let initial = sum.value
        a.set(5)
        let updated = sum.value

        // Check values explicitly since Vector equality is by reference
        if (initial == 5 && updated == 8) {
            true
        } else {
            false
        }
    "#;

    let result = execute(source).unwrap();
    assert_eq!(result, Value::Boolean(true));
}
