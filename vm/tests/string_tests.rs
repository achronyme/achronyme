use compiler::Compiler;
use memory::{Function, Value};
use vm::{CallFrame, VM};

/// Helper: compile and run Achronyme source, returning the VM after execution.
fn run_source(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.heap.import_strings(compiler.interner.strings);

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

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

/// Extract the integer result from R[0].
fn result_int(vm: &VM) -> i64 {
    vm.stack[0].as_int().expect("expected int in R[0]")
}

/// Extract the string result from R[0].
fn result_string(vm: &VM) -> String {
    let val = vm.stack[0];
    assert!(val.is_string(), "expected string in R[0], got {:?}", val);
    let handle = val.as_handle().unwrap();
    vm.heap.get_string(handle).unwrap().clone()
}

/// Extract the list of strings from R[0].
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
// len() — char count
// =============================================================================

#[test]
fn test_len_ascii() {
    let vm = run_source(r#"let x = len("hello")"#).unwrap();
    assert_eq!(result_int(&vm), 5);
}

#[test]
fn test_len_empty() {
    let vm = run_source(r#"let x = len("")"#).unwrap();
    assert_eq!(result_int(&vm), 0);
}

#[test]
fn test_len_multibyte() {
    // "café" is 4 chars but 5 bytes (é = 2 bytes in UTF-8)
    let vm = run_source(r#"let x = len("café")"#).unwrap();
    assert_eq!(result_int(&vm), 4);
}

#[test]
fn test_len_emoji() {
    // Each emoji is 1 codepoint (4 bytes)
    let vm = run_source(r#"let x = len("😀😀")"#).unwrap();
    assert_eq!(result_int(&vm), 2);
}

// =============================================================================
// String indexing: str[i]
// =============================================================================

#[test]
fn test_string_index_ascii() {
    let vm = run_source(
        r#"let s = "hello"
let x = s[0]"#,
    )
    .unwrap();
    assert_eq!(result_string(&vm), "h");
}

#[test]
fn test_string_index_last() {
    let vm = run_source(
        r#"let s = "hello"
let x = s[4]"#,
    )
    .unwrap();
    assert_eq!(result_string(&vm), "o");
}

#[test]
fn test_string_index_multibyte() {
    // "café"[3] should be "é"
    let vm = run_source(
        r#"let s = "café"
let x = s[3]"#,
    )
    .unwrap();
    assert_eq!(result_string(&vm), "é");
}

#[test]
fn test_string_index_out_of_bounds() {
    let result = run_source(
        r#"let s = "hi"
let x = s[5]"#,
    );
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        err.contains("out of bounds"),
        "expected 'out of bounds', got: {err}"
    );
}

#[test]
fn test_string_index_negative() {
    let result = run_source(
        r#"let s = "hi"
let x = s[-1]"#,
    );
    assert!(result.is_err());
}

// =============================================================================
// substring(str, start, end)
// =============================================================================

#[test]
fn test_substring_basic() {
    let vm = run_source(r#"let x = substring("hello world", 0, 5)"#).unwrap();
    assert_eq!(result_string(&vm), "hello");
}

#[test]
fn test_substring_middle() {
    let vm = run_source(r#"let x = substring("hello world", 6, 11)"#).unwrap();
    assert_eq!(result_string(&vm), "world");
}

#[test]
fn test_substring_clamp() {
    let vm = run_source(r#"let x = substring("hi", 0, 100)"#).unwrap();
    assert_eq!(result_string(&vm), "hi");
}

#[test]
fn test_substring_empty_range() {
    let vm = run_source(r#"let x = substring("hello", 3, 3)"#).unwrap();
    assert_eq!(result_string(&vm), "");
}

#[test]
fn test_substring_inverted_range() {
    let vm = run_source(r#"let x = substring("hello", 4, 2)"#).unwrap();
    assert_eq!(result_string(&vm), "");
}

#[test]
fn test_substring_multibyte() {
    let vm = run_source(r#"let x = substring("café latte", 0, 4)"#).unwrap();
    assert_eq!(result_string(&vm), "café");
}

// =============================================================================
// indexOf(str, substr)
// =============================================================================

#[test]
fn test_index_of_found() {
    let vm = run_source(r#"let x = indexOf("hello world", "world")"#).unwrap();
    assert_eq!(result_int(&vm), 6);
}

#[test]
fn test_index_of_not_found() {
    let vm = run_source(r#"let x = indexOf("hello", "xyz")"#).unwrap();
    assert_eq!(result_int(&vm), -1);
}

#[test]
fn test_index_of_beginning() {
    let vm = run_source(r#"let x = indexOf("hello", "hel")"#).unwrap();
    assert_eq!(result_int(&vm), 0);
}

#[test]
fn test_index_of_multibyte() {
    // "café latte" — "latte" starts at char index 5
    let vm = run_source(r#"let x = indexOf("café latte", "latte")"#).unwrap();
    assert_eq!(result_int(&vm), 5);
}

#[test]
fn test_index_of_empty_needle() {
    let vm = run_source(r#"let x = indexOf("hello", "")"#).unwrap();
    assert_eq!(result_int(&vm), 0);
}

// =============================================================================
// split(str, delim)
// =============================================================================

#[test]
fn test_split_basic() {
    let vm = run_source(r#"let x = split("a,b,c", ",")"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["a", "b", "c"]);
}

#[test]
fn test_split_no_match() {
    let vm = run_source(r#"let x = split("hello", ",")"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["hello"]);
}

#[test]
fn test_split_empty_parts() {
    let vm = run_source(r#"let x = split(",a,,b,", ",")"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["", "a", "", "b", ""]);
}

// =============================================================================
// trim(str)
// =============================================================================

#[test]
fn test_trim_basic() {
    let vm = run_source(r#"let x = trim("  hello  ")"#).unwrap();
    assert_eq!(result_string(&vm), "hello");
}

#[test]
fn test_trim_no_whitespace() {
    let vm = run_source(r#"let x = trim("hello")"#).unwrap();
    assert_eq!(result_string(&vm), "hello");
}

#[test]
fn test_trim_all_whitespace() {
    let vm = run_source(r#"let x = trim("   ")"#).unwrap();
    assert_eq!(result_string(&vm), "");
}

// =============================================================================
// replace(str, search, repl)
// =============================================================================

#[test]
fn test_replace_basic() {
    let vm = run_source(r#"let x = replace("hello world", "world", "rust")"#).unwrap();
    assert_eq!(result_string(&vm), "hello rust");
}

#[test]
fn test_replace_multiple() {
    let vm = run_source(r#"let x = replace("aaa", "a", "bb")"#).unwrap();
    assert_eq!(result_string(&vm), "bbbbbb");
}

#[test]
fn test_replace_no_match() {
    let vm = run_source(r#"let x = replace("hello", "xyz", "!")"#).unwrap();
    assert_eq!(result_string(&vm), "hello");
}

// =============================================================================
// toUpper(str) / toLower(str)
// =============================================================================

#[test]
fn test_to_upper() {
    let vm = run_source(r#"let x = toUpper("hello")"#).unwrap();
    assert_eq!(result_string(&vm), "HELLO");
}

#[test]
fn test_to_lower() {
    let vm = run_source(r#"let x = toLower("HELLO")"#).unwrap();
    assert_eq!(result_string(&vm), "hello");
}

#[test]
fn test_to_upper_mixed() {
    let vm = run_source(r#"let x = toUpper("Hello World 123!")"#).unwrap();
    assert_eq!(result_string(&vm), "HELLO WORLD 123!");
}

#[test]
fn test_to_lower_mixed() {
    let vm = run_source(r#"let x = toLower("Hello World 123!")"#).unwrap();
    assert_eq!(result_string(&vm), "hello world 123!");
}

// =============================================================================
// chars(str)
// =============================================================================

#[test]
fn test_chars_ascii() {
    let vm = run_source(r#"let x = chars("abc")"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["a", "b", "c"]);
}

#[test]
fn test_chars_empty() {
    let vm = run_source(r#"let x = chars("")"#).unwrap();
    assert_eq!(result_string_list(&vm), Vec::<String>::new());
}

#[test]
fn test_chars_multibyte() {
    let vm = run_source(r#"let x = chars("café")"#).unwrap();
    assert_eq!(result_string_list(&vm), vec!["c", "a", "f", "é"]);
}

// =============================================================================
// Integration: combining operations
// =============================================================================

#[test]
fn test_len_of_chars() {
    let vm = run_source(r#"let x = len(chars("hello"))"#).unwrap();
    assert_eq!(result_int(&vm), 5);
}

#[test]
fn test_index_after_split() {
    let vm = run_source(
        r#"let parts = split("a:b:c", ":")
let x = parts[1]"#,
    )
    .unwrap();
    assert_eq!(result_string(&vm), "b");
}

#[test]
fn test_trim_and_upper() {
    let vm = run_source(r#"let x = toUpper(trim("  hello  "))"#).unwrap();
    assert_eq!(result_string(&vm), "HELLO");
}

#[test]
fn test_replace_and_split() {
    let vm = run_source(
        r#"let s = replace("a.b.c", ".", ",")
let x = split(s, ",")"#,
    )
    .unwrap();
    assert_eq!(result_string_list(&vm), vec!["a", "b", "c"]);
}

#[test]
fn test_string_index_in_loop() {
    let vm = run_source(
        r#"let s = "abc"
mut result = ""
mut i = 0
while i < len(s) {
    result = result + s[i]
    i = i + 1
}
let x = result"#,
    )
    .unwrap();
    assert_eq!(result_string(&vm), "abc");
}

#[test]
fn test_substring_with_index_of() {
    let vm = run_source(
        r#"let s = "hello world"
let pos = indexOf(s, " ")
let x = substring(s, 0, pos)"#,
    )
    .unwrap();
    assert_eq!(result_string(&vm), "hello");
}
