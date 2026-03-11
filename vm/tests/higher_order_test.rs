use compiler::Compiler;
use memory::Function;
use vm::{CallFrame, VM};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn run(source: &str) -> Result<VM, String> {
    run_inner(source, false)
}

fn run_stress(source: &str) -> Result<VM, String> {
    run_inner(source, true)
}

fn run_inner(source: &str, stress: bool) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.stress_mode = stress;
    vm.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone());
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    });

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("{e}"))?;
    Ok(vm)
}

fn result_int(vm: &VM) -> i64 {
    vm.stack[0].as_int().expect("expected int in R[0]")
}

fn result_int_list(vm: &VM) -> Vec<i64> {
    let val = vm.stack[0];
    assert!(val.is_list(), "expected list in R[0]");
    let handle = val.as_handle().unwrap();
    let list = vm.heap.get_list(handle).unwrap();
    list.iter()
        .map(|v| v.as_int().expect("expected int"))
        .collect()
}

fn result_bool(vm: &VM) -> bool {
    let val = vm.stack[0];
    if val == memory::Value::true_val() {
        true
    } else if val == memory::Value::false_val() {
        false
    } else {
        panic!("expected bool in R[0], got {:?}", val)
    }
}

// =============================================================================
// map
// =============================================================================

#[test]
fn test_map_basic() {
    let vm = run("let x = map([1, 2, 3], fn(n) { n * 2 })").unwrap();
    assert_eq!(result_int_list(&vm), vec![2, 4, 6]);
}

#[test]
fn test_map_empty_list() {
    let vm = run("let x = map([], fn(n) { n * 2 })").unwrap();
    assert_eq!(result_int_list(&vm), Vec::<i64>::new());
}

#[test]
fn test_map_with_closure_capture() {
    let vm = run(r#"let factor = 10
let x = map([1, 2, 3], fn(n) { n * factor })"#)
    .unwrap();
    assert_eq!(result_int_list(&vm), vec![10, 20, 30]);
}

#[test]
fn test_map_chained() {
    let vm = run(r#"let a = map([1, 2, 3], fn(n) { n + 1 })
let x = map(a, fn(n) { n * 2 })"#)
    .unwrap();
    assert_eq!(result_int_list(&vm), vec![4, 6, 8]);
}

// =============================================================================
// filter
// =============================================================================

#[test]
fn test_filter_basic() {
    let vm = run("let x = filter([1, 2, 3, 4, 5, 6], fn(n) { n % 2 == 0 })").unwrap();
    assert_eq!(result_int_list(&vm), vec![2, 4, 6]);
}

#[test]
fn test_filter_none_match() {
    let vm = run("let x = filter([1, 2, 3], fn(n) { n > 100 })").unwrap();
    assert_eq!(result_int_list(&vm), Vec::<i64>::new());
}

#[test]
fn test_filter_all_match() {
    let vm = run("let x = filter([1, 2, 3], fn(n) { n > 0 })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 2, 3]);
}

#[test]
fn test_filter_empty_list() {
    let vm = run("let x = filter([], fn(n) { true })").unwrap();
    assert_eq!(result_int_list(&vm), Vec::<i64>::new());
}

// =============================================================================
// reduce
// =============================================================================

#[test]
fn test_reduce_sum() {
    let vm = run("let x = reduce([1, 2, 3, 4], 0, fn(acc, n) { acc + n })").unwrap();
    assert_eq!(result_int(&vm), 10);
}

#[test]
fn test_reduce_product() {
    let vm = run("let x = reduce([1, 2, 3, 4], 1, fn(acc, n) { acc * n })").unwrap();
    assert_eq!(result_int(&vm), 24);
}

#[test]
fn test_reduce_empty_list() {
    let vm = run("let x = reduce([], 42, fn(acc, n) { acc + n })").unwrap();
    assert_eq!(result_int(&vm), 42);
}

#[test]
fn test_reduce_single_element() {
    let vm = run("let x = reduce([5], 0, fn(acc, n) { acc + n })").unwrap();
    assert_eq!(result_int(&vm), 5);
}

// =============================================================================
// for_each
// =============================================================================

#[test]
fn test_for_each_returns_nil() {
    let vm = run(r#"mut total = 0
for_each([1, 2, 3], fn(n) { total = total + n })
let x = total"#)
    .unwrap();
    // for_each mutates via upvalue; check that total accumulated
    assert_eq!(result_int(&vm), 6);
}

#[test]
fn test_for_each_empty_list() {
    let vm = run(r#"mut total = 0
for_each([], fn(n) { total = total + n })
let x = total"#)
    .unwrap();
    assert_eq!(result_int(&vm), 0);
}

// =============================================================================
// find
// =============================================================================

#[test]
fn test_find_found() {
    let vm = run("let x = find([1, 2, 3, 4], fn(n) { n > 2 })").unwrap();
    assert_eq!(result_int(&vm), 3);
}

#[test]
fn test_find_not_found() {
    let vm = run("let x = find([1, 2, 3], fn(n) { n > 100 })").unwrap();
    assert!(vm.stack[0].is_nil(), "expected nil when not found");
}

#[test]
fn test_find_empty_list() {
    let vm = run("let x = find([], fn(n) { true })").unwrap();
    assert!(vm.stack[0].is_nil());
}

// =============================================================================
// any / all
// =============================================================================

#[test]
fn test_any_true() {
    let vm = run("let x = any([1, 2, 3], fn(n) { n == 2 })").unwrap();
    assert!(result_bool(&vm));
}

#[test]
fn test_any_false() {
    let vm = run("let x = any([1, 2, 3], fn(n) { n > 10 })").unwrap();
    assert!(!result_bool(&vm));
}

#[test]
fn test_any_empty_list() {
    let vm = run("let x = any([], fn(n) { true })").unwrap();
    assert!(!result_bool(&vm));
}

#[test]
fn test_all_true() {
    let vm = run("let x = all([1, 2, 3], fn(n) { n > 0 })").unwrap();
    assert!(result_bool(&vm));
}

#[test]
fn test_all_false() {
    let vm = run("let x = all([1, 2, 3], fn(n) { n > 1 })").unwrap();
    assert!(!result_bool(&vm));
}

#[test]
fn test_all_empty_list() {
    let vm = run("let x = all([], fn(n) { false })").unwrap();
    // all([]) is vacuously true
    assert!(result_bool(&vm));
}

// =============================================================================
// sort
// =============================================================================

#[test]
fn test_sort_ascending() {
    let vm = run("let x = sort([3, 1, 4, 1, 5, 9], fn(a, b) { a - b })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 1, 3, 4, 5, 9]);
}

#[test]
fn test_sort_descending() {
    let vm = run("let x = sort([3, 1, 4], fn(a, b) { b - a })").unwrap();
    assert_eq!(result_int_list(&vm), vec![4, 3, 1]);
}

#[test]
fn test_sort_empty_list() {
    let vm = run("let x = sort([], fn(a, b) { a - b })").unwrap();
    assert_eq!(result_int_list(&vm), Vec::<i64>::new());
}

#[test]
fn test_sort_single_element() {
    let vm = run("let x = sort([42], fn(a, b) { a - b })").unwrap();
    assert_eq!(result_int_list(&vm), vec![42]);
}

#[test]
fn test_sort_already_sorted() {
    let vm = run("let x = sort([1, 2, 3], fn(a, b) { a - b })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 2, 3]);
}

// =============================================================================
// flat_map
// =============================================================================

#[test]
fn test_flat_map_basic() {
    let vm = run("let x = flat_map([1, 2, 3], fn(n) { [n, n * 10] })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 10, 2, 20, 3, 30]);
}

#[test]
fn test_flat_map_identity() {
    let vm = run("let x = flat_map([[1, 2], [3, 4]], fn(l) { l })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 2, 3, 4]);
}

#[test]
fn test_flat_map_non_list_passthrough() {
    let vm = run("let x = flat_map([1, 2, 3], fn(n) { n * 2 })").unwrap();
    assert_eq!(result_int_list(&vm), vec![2, 4, 6]);
}

#[test]
fn test_flat_map_empty_list() {
    let vm = run("let x = flat_map([], fn(n) { [n] })").unwrap();
    assert_eq!(result_int_list(&vm), Vec::<i64>::new());
}

// =============================================================================
// zip
// =============================================================================

#[test]
fn test_zip_equal_lengths() {
    let vm = run(r#"let pairs = zip([1, 2, 3], [10, 20, 30])
let x = reduce(pairs, 0, fn(acc, pair) { acc + pair[0] + pair[1] })"#)
    .unwrap();
    // (1+10) + (2+20) + (3+30) = 66
    assert_eq!(result_int(&vm), 66);
}

#[test]
fn test_zip_different_lengths() {
    let vm = run(r#"let pairs = zip([1, 2, 3], [10, 20])
let x = len(pairs)"#)
    .unwrap();
    // Truncated to shorter: 2 pairs
    assert_eq!(result_int(&vm), 2);
}

#[test]
fn test_zip_empty() {
    let vm = run("let x = zip([], [1, 2, 3])").unwrap();
    assert_eq!(result_int_list(&vm), Vec::<i64>::new());
}

// =============================================================================
// Composition — chaining HOFs together
// =============================================================================

#[test]
fn test_map_then_filter() {
    let vm = run(r#"let doubled = map([1, 2, 3, 4, 5], fn(n) { n * 2 })
let x = filter(doubled, fn(n) { n > 4 })"#)
    .unwrap();
    assert_eq!(result_int_list(&vm), vec![6, 8, 10]);
}

#[test]
fn test_filter_then_reduce() {
    let vm = run(
        r#"let evens = filter([1, 2, 3, 4, 5, 6], fn(n) { n % 2 == 0 })
let x = reduce(evens, 0, fn(acc, n) { acc + n })"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 12);
}

#[test]
fn test_map_filter_reduce_pipeline() {
    let vm = run(r#"let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
let result = map(data, fn(n) { n * n })
let big = filter(result, fn(n) { n > 20 })
let x = reduce(big, 0, fn(acc, n) { acc + n })"#)
    .unwrap();
    // Squares > 20: 25, 36, 49, 64, 81, 100 → sum = 355
    assert_eq!(result_int(&vm), 355);
}

// =============================================================================
// Error handling
// =============================================================================

fn expect_err(source: &str) -> String {
    match run(source) {
        Err(e) => e,
        Ok(_) => panic!("Expected an error for: {source}"),
    }
}

#[test]
fn test_map_non_list_error() {
    let err = expect_err("let x = map(42, fn(n) { n })");
    assert!(err.contains("must be a List"), "got: {err}");
}

#[test]
fn test_map_non_function_error() {
    let err = expect_err("let x = map([1, 2], 42)");
    assert!(err.contains("must be a Function"), "got: {err}");
}

#[test]
fn test_reduce_non_list_error() {
    let err = expect_err("let x = reduce(42, 0, fn(a, n) { a })");
    assert!(err.contains("must be a List"), "got: {err}");
}

#[test]
fn test_sort_bad_comparator_return() {
    let err = expect_err(r#"let x = sort([1, 2], fn(a, b) { "not a number" })"#);
    assert!(err.contains("must return a Number"), "got: {err}");
}

#[test]
fn test_closure_error_propagates() {
    let err = expect_err(
        r#"let x = map([1, 2, 3], fn(n) {
    assert(n < 3)
    return n
})"#,
    );
    assert!(err.contains("assertion failed"), "got: {err}");
}

// =============================================================================
// GC stress tests — verify HOFs survive aggressive garbage collection
// =============================================================================

#[test]
fn test_stress_map() {
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
let x = map(data, fn(n) { n * 2 })"#,
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
let x = filter(data, fn(n) { n % 3 == 0 })"#,
    )
    .unwrap();
    assert_eq!(result_int_list(&vm), vec![3, 6, 9]);
}

#[test]
fn test_stress_reduce() {
    let vm = run_stress("let x = reduce([1, 2, 3, 4, 5], 0, fn(acc, n) { acc + n })").unwrap();
    assert_eq!(result_int(&vm), 15);
}

#[test]
fn test_stress_sort() {
    let vm = run_stress("let x = sort([5, 3, 8, 1, 2], fn(a, b) { a - b })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 2, 3, 5, 8]);
}

#[test]
fn test_stress_map_with_string_alloc() {
    // Each closure call allocates a new string — maximum GC pressure.
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5]
let strings = map(data, fn(n) { "item_" + n })
let x = len(strings)"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 5);
}

#[test]
fn test_stress_nested_hof() {
    let vm = run_stress(
        r#"let data = [1, 2, 3, 4, 5, 6]
let evens = filter(data, fn(n) { n % 2 == 0 })
let doubled = map(evens, fn(n) { n * 2 })
let x = reduce(doubled, 0, fn(acc, n) { acc + n })"#,
    )
    .unwrap();
    // evens: [2, 4, 6], doubled: [4, 8, 12], sum: 24
    assert_eq!(result_int(&vm), 24);
}

#[test]
fn test_stress_flat_map() {
    let vm = run_stress("let x = flat_map([1, 2, 3], fn(n) { [n, n * 10] })").unwrap();
    assert_eq!(result_int_list(&vm), vec![1, 10, 2, 20, 3, 30]);
}

#[test]
fn test_stress_zip() {
    let vm = run_stress(
        r#"let pairs = zip([1, 2, 3], [10, 20, 30])
let x = len(pairs)"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 3);
}

#[test]
fn test_stress_for_each_with_upvalue() {
    let vm = run_stress(
        r#"mut sum = 0
for_each([10, 20, 30], fn(n) { sum = sum + n })
let x = sum"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 60);
}

#[test]
fn test_stress_find_any_all() {
    let vm = run_stress(
        r#"let found = find([1, 2, 3, 4], fn(n) { n > 2 })
let has = any([1, 2, 3], fn(n) { n == 2 })
let ok = all([1, 2, 3], fn(n) { n > 0 })
let x = found"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 3);
}
