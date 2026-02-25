use compiler::Compiler;
use memory::{Function, Value};
use vm::{CallFrame, VM};

/// Helper: compile source, run VM, return the last value on the stack.
fn run_program(source: &str) -> Result<Value, vm::RuntimeError> {
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

    vm.interpret()?;
    Ok(vm.stack[0])
}

/// Helper: compile, run, assert no error.
fn run_ok(source: &str) {
    run_program(source).expect("Runtime error");
}

/// Helper: compile, run, expect error.
fn run_err(source: &str) -> vm::RuntimeError {
    run_program(source).expect_err("Expected runtime error")
}

#[test]
fn test_poseidon_basic() {
    // poseidon(0, 0) should return a Field value
    let source = r#"
        let a = field(0)
        let b = field(0)
        let h = poseidon(a, b)
        assert(typeof(h) == "Field")
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_with_ints() {
    // poseidon should accept integers (auto-convert to FieldElement)
    let source = r#"
        let h = poseidon(1, 2)
        assert(typeof(h) == "Field")
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_deterministic() {
    // Same inputs → same output
    let source = r#"
        let h1 = poseidon(42, 99)
        let h2 = poseidon(42, 99)
        assert(h1 == h2)
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_different_inputs() {
    // Different inputs → different output
    let source = r#"
        let h1 = poseidon(1, 2)
        let h2 = poseidon(2, 1)
        assert(h1 != h2)
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_known_vector() {
    // poseidon(0, 0) should match the known circomlibjs result
    // This is the same reference vector used in constraints/src/poseidon.rs tests
    let source = r#"
        let h = poseidon(field(0), field(0))
        let expected = field("14744269619966411208579211824598458697587494354926760081771325075741142829156")
        assert(h == expected)
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_arity_error() {
    let err = run_err("poseidon(1)");
    match err {
        vm::RuntimeError::ArityMismatch(_) => {}
        other => panic!("Expected ArityMismatch, got {:?}", other),
    }
}

#[test]
fn test_poseidon_type_error() {
    let err = run_err(r#"poseidon("hello", 1)"#);
    match err {
        vm::RuntimeError::TypeMismatch(_) => {}
        other => panic!("Expected TypeMismatch, got {:?}", other),
    }
}

#[test]
fn test_poseidon_many_basic() {
    // poseidon_many(a, b, c) = poseidon(poseidon(a, b), c)
    let source = r#"
        let a = field(1)
        let b = field(2)
        let c = field(3)
        let h1 = poseidon_many(a, b, c)
        let h2 = poseidon(poseidon(a, b), c)
        assert(h1 == h2)
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_many_four_args() {
    // poseidon_many(a, b, c, d) = poseidon(poseidon(poseidon(a, b), c), d)
    let source = r#"
        let h1 = poseidon_many(1, 2, 3, 4)
        let h2 = poseidon(poseidon(poseidon(1, 2), 3), 4)
        assert(h1 == h2)
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_many_two_args_same_as_poseidon() {
    // poseidon_many(a, b) = poseidon(a, b)
    let source = r#"
        let h1 = poseidon_many(10, 20)
        let h2 = poseidon(10, 20)
        assert(h1 == h2)
    "#;
    run_ok(source);
}

#[test]
fn test_poseidon_many_arity_error() {
    let err = run_err("poseidon_many(1)");
    match err {
        vm::RuntimeError::ArityMismatch(_) => {}
        other => panic!("Expected ArityMismatch, got {:?}", other),
    }
}
