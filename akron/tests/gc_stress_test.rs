use akron::{CallFrame, VM};
use compiler::Compiler;
use memory::Function;

/// Helper: compile and run Achronyme source with stress_mode enabled.
fn run_stress(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.stress_mode = true;
    vm.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
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
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

fn result_int(vm: &VM) -> i64 {
    vm.stack[0].as_int().expect("expected int in R[0]")
}

/// Helper: compile and run with a heap limit, returning error string on failure.
fn run_with_heap_limit(source: &str, max_heap_bytes: usize) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.heap.max_heap_bytes = max_heap_bytes;
    vm.instruction_budget = 200_000;
    vm.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
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
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("{e}"))?;
    Ok(vm)
}

fn result_string_list(vm: &VM) -> Vec<String> {
    let val = vm.stack[0];
    assert!(val.is_list(), "expected list in R[0]");
    let handle = val.as_handle().unwrap();
    let list = vm.heap.get_list(handle).unwrap();
    list.iter()
        .map(|v| {
            let h = v.as_handle().unwrap();
            vm.heap.get_string(h).unwrap().clone()
        })
        .collect()
}

// =============================================================================
// GC stress tests — verify multi-alloc natives survive aggressive GC
// =============================================================================

#[test]
fn test_stress_gc_keys() {
    let vm = run_stress(
        r#"let m = { "a": 1, "b": 2, "c": 3 }
let x = m.keys().len()"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 3);
}

#[test]
fn test_stress_gc_split() {
    let vm = run_stress(r#"let x = "a,b,c,d,e".split(",")"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["a", "b", "c", "d", "e"]);
}

#[test]
fn test_stress_gc_chars() {
    let vm = run_stress(r#"let x = "hello".chars()"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["h", "e", "l", "l", "o"]);
}

#[test]
fn test_stress_gc_for_in_map() {
    // Exercises the GetIter map path (N alloc_string + alloc_list + alloc_iterator)
    let vm = run_stress(
        r#"let m = { "x": 10, "y": 20, "z": 30 }
mut total = 0
for k in m {
    total = total + m[k]
}
let x = total"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 60);
}

#[test]
fn test_stress_gc_closure_capture() {
    // Exercises the Closure opcode path (N alloc_upvalue + alloc_closure)
    let vm = run_stress(
        r#"let a = 10
let b = 20
let c = 30
fn sum() {
    return a + b + c
}
let x = sum()"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 60);
}

#[test]
fn test_stress_gc_combined_natives() {
    // Chain multiple multi-alloc natives in one program
    let vm = run_stress(
        r#"let parts = "hello world foo".split(" ")
let k = { "a": 1, "b": 2 }.keys()
let c = "abc".chars()
let x = parts.len() + k.len() + c.len()"#,
    )
    .unwrap();
    assert_eq!(result_int(&vm), 8); // 3 + 2 + 3
}

// =============================================================================
// GcStats tests
// =============================================================================

#[test]
fn test_gc_stats_collections_increment() {
    let vm = run_stress(
        r#"mut i = 0
while i < 100 {
    let tmp = "garbage_" + i
    i = i + 1
}"#,
    )
    .unwrap();
    assert!(
        vm.heap.stats.collections > 0,
        "stress mode should trigger GC collections"
    );
    assert!(
        vm.heap.stats.total_gc_time_ns > 0,
        "GC timing should be recorded"
    );
}

#[test]
fn test_gc_stats_freed_bytes_after_stress() {
    let vm = run_stress(
        r#"mut i = 0
while i < 100 {
    let tmp = "garbage_" + i
    i = i + 1
}"#,
    )
    .unwrap();
    assert!(
        vm.heap.stats.total_freed_bytes > 0,
        "GC should free bytes during stress mode"
    );
}

#[test]
fn test_gc_stats_peak_heap_positive() {
    let vm = run_stress(r#"let x = [1, 2, 3]"#).unwrap();
    assert!(
        vm.heap.stats.peak_heap_bytes > 0,
        "peak_heap_bytes should be positive after allocations"
    );
}

#[test]
fn test_native_gc_stats_returns_map() {
    let vm = run_stress(
        r#"let s = gc_stats()
assert(typeof(s) == "Map")
let k = s.keys()
assert(k.len() == 5)"#,
    )
    .unwrap();
    // If we get here without error, the native returned a valid Map with 5 keys
    let _ = vm;
}

// =============================================================================
// Heap limit tests
// =============================================================================

#[test]
fn test_heap_limit_exceeded_error() {
    let source = r#"
mut list = []
mut i = 0
while i < 10000 {
    list.push("x")
    i = i + 1
}
"#;
    let result = run_with_heap_limit(source, 4096);
    match result {
        Ok(_) => panic!("Expected heap limit exceeded error"),
        Err(err) => assert!(
            err.contains("heap limit exceeded"),
            "Expected 'heap limit exceeded', got: {err}"
        ),
    }
}

#[test]
fn test_heap_limit_sufficient() {
    let source = r#"let x = 42"#;
    let result = run_with_heap_limit(source, 10 * 1024 * 1024);
    assert!(result.is_ok());
}

#[test]
fn test_heap_limit_gc_frees_enough() {
    // Each iteration creates a temporary string that becomes garbage.
    // GC should reclaim it, keeping the heap under the limit.
    let source = r#"
mut i = 0
while i < 500 {
    let tmp = "temp"
    i = i + 1
}
"#;
    let result = run_with_heap_limit(source, 1024 * 1024);
    assert!(result.is_ok());
}
