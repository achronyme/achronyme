use super::{result_int, result_int_list, run_stress};

// =============================================================================
// GC stress tests — verify HOFs survive aggressive garbage collection
// =============================================================================

#[test]
fn test_stress_map() {
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
let x = data.map(fn(n) { n * 2 })"#,
    )
    .unwrap();
    assert_eq!(
        result_int_list(&vm),
        vec![2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    );
}

#[test]
fn test_stress_filter() {
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
let x = data.filter(fn(n) { n % 3 == 0 })"#,
    )
    .unwrap();
    assert_eq!(result_int_list(&vm), vec![3, 6, 9]);
}

#[test]
fn test_stress_reduce() {
    let vm = run_stress("let x = [1, 2, 3, 4, 5].reduce(0, fn(acc, n) { acc + n })").unwrap();
    assert_eq!(result_int(&vm), 15);
}

#[test]
fn test_stress_sort() {
    let vm = run_stress("let x = [5, 3, 8, 1, 2].sort(fn(a, b) { a - b })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 2, 3, 5, 8]);
}

#[test]
fn test_stress_map_with_string_alloc() {
    // Each closure call allocates a new string — maximum GC pressure.
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5]
let strings = data.map(fn(n) { "item_" + n })
let x = strings.len()"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 5);
}

#[test]
fn test_stress_nested_hof() {
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5, 6]
let evens = data.filter(fn(n) { n % 2 == 0 })
let doubled = evens.map(fn(n) { n * 2 })
let x = doubled.reduce(0, fn(acc, n) { acc + n })"#,
    )
    .unwrap();
    // evens: [2, 4, 6], doubled: [4, 8, 12], sum: 24
    assert_eq!(result_int(&vm), 24);
}

#[test]
fn test_stress_flat_map() {
    let vm = run_stress("let x = [1, 2, 3].flat_map(fn(n) { [n, n * 10] })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 10, 2, 20, 3, 30]);
}

#[test]
fn test_stress_zip() {
    let vm = run_stress(
        r#"let pairs = [1, 2, 3].zip([10, 20, 30])
let x = pairs.len()"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 3);
}

#[test]
fn test_stress_for_each_with_upvalue() {
    let vm = run_stress(
        r#"mut sum = 0;
[10, 20, 30].for_each(fn(n) { sum = sum + n })
let x = sum"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 60);
}

#[test]
fn test_stress_find_any_all() {
    let vm = run_stress(
        r#"let found = [1, 2, 3, 4].find(fn(n) { n > 2 })
let has = [1, 2, 3].any(fn(n) { n == 2 })
let ok = [1, 2, 3].all(fn(n) { n > 0 })
let x = found"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 3);
}
