use compiler::Compiler;
use memory::{Function, Value};
use vm::{CallFrame, VM};

#[test]
fn test_execution_end_to_end() {
    let source = "1 + 2 * 3";

    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).expect("Compilation failed");
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        max_slots: main_func.max_slots,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        upvalue_info: Vec::new(),
    };

    let func_idx = vm.heap.alloc_function(func);

    let closure = memory::Closure {
        function: func_idx,
        upvalues: Vec::new(),
    };
    let closure_idx = vm.heap.alloc_closure(closure);

    let frame = CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    };
    vm.frames.push(frame);

    vm.interpret().expect("Runtime error");

    let result = vm.stack.get(0).cloned();
    if let Some(val) = result {
        if let Some(n) = val.as_int() {
            assert_eq!(n, 7);
        } else {
            panic!("Expected int 7, got {:?}", val);
        }
    } else {
        panic!("Stack too short to find result at R0");
    }
}

#[test]
fn test_mod_compilation() {
    let source = "7 % 2";
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).expect("Compilation failed");

    let main_func = compiler.compilers.last().expect("No main compiler");
    let mut vm = VM::new();

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        max_slots: main_func.max_slots,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        upvalue_info: Vec::new(),
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: Vec::new(),
    });

    let frame = CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    };
    vm.frames.push(frame);

    vm.interpret().expect("Runtime error");

    let result = vm.stack[0];
    if let Some(i) = result.as_int() {
        assert_eq!(i, 1);
    } else {
        panic!("Expected 1 result from 7 % 2, got {:?}", result);
    }
}
