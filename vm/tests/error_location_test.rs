use compiler::Compiler;
use memory::Function;
use vm::{CallFrame, VM};

/// Helper: compile source, run VM, return the VM (for inspecting error location).
fn run_program(source: &str) -> (VM, Result<(), vm::RuntimeError>) {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).expect("Compilation failed");
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
        max_slots: main_func.max_slots,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        upvalue_info: vec![],
        line_info: main_func.line_info.clone(),
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

    let result = vm.interpret();
    (vm, result)
}

#[test]
fn error_location_integer_overflow() {
    // Line 1 is fine, line 2 should overflow
    let source = "let x = 576460752303423487\nlet y = x + x";
    let (vm, result) = run_program(source);
    assert!(result.is_err(), "should overflow");
    let loc = vm
        .last_error_location
        .as_ref()
        .expect("should have location");
    assert_eq!(loc.0, "main", "function name should be 'main'");
    assert_eq!(loc.1, 2, "error should be on line 2");
}

#[test]
fn error_location_division_by_zero() {
    let source = "let a = 10\nlet b = 0\nlet c = a / b";
    let (vm, result) = run_program(source);
    assert!(result.is_err(), "should error on div by zero");
    let loc = vm
        .last_error_location
        .as_ref()
        .expect("should have location");
    assert_eq!(loc.0, "main");
    assert_eq!(loc.1, 3, "error should be on line 3");
}

#[test]
fn error_location_type_mismatch() {
    let source = "let x = 1\nlet y = \"hello\"\nlet z = x - y";
    let (vm, result) = run_program(source);
    assert!(result.is_err(), "should error on type mismatch");
    let loc = vm
        .last_error_location
        .as_ref()
        .expect("should have location");
    assert_eq!(loc.0, "main");
    assert_eq!(loc.1, 3, "error should be on line 3");
}

#[test]
fn error_location_assertion_failed() {
    let source = "let x = true\nassert(x)\nlet y = false\nassert(y)";
    let (vm, result) = run_program(source);
    assert!(result.is_err(), "should fail assertion");
    let loc = vm
        .last_error_location
        .as_ref()
        .expect("should have location");
    assert_eq!(loc.0, "main");
    assert_eq!(loc.1, 4, "error should be on line 4");
}

#[test]
fn no_error_location_on_success() {
    let source = "let x = 1 + 2";
    let (vm, result) = run_program(source);
    assert!(result.is_ok());
    assert!(
        vm.last_error_location.is_none(),
        "should have no error location on success"
    );
}
