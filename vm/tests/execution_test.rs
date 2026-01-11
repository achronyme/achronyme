use compiler::Compiler;
use memory::{Function, Value};
use vm::{CallFrame, VM};

#[test]
fn test_execution_end_to_end() {
    let source = "1 + 2 * 3";

    // 1. Compile
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).expect("Compilation failed");
    let main_func = compiler.compilers.last().expect("No main compiler");

    // 2. Setup VM
    let mut vm = VM::new();

    // 3. Create Function
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

    // 4. Create Call Frame
    let frame = CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    };
    vm.frames.push(frame);

    // 5. Run
    vm.interpret().expect("Runtime error");

    // Result should be in R0 due to accumulator pattern
    let result = vm.stack.get(0).cloned();
    if let Some(val) = result {
        if let Some(n) = val.as_number() {
            assert_eq!(n, 7.0);
        } else {
            panic!("Expected number 7.0, got {:?}", val);
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
    let closure_idx = vm.heap.alloc_closure(memory::Closure { function: func_idx, upvalues: Vec::new() });
    
    let frame = CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    };
    vm.frames.push(frame);
    
    vm.interpret().expect("Runtime error");
    
    let result = vm.stack[0];
    // Check value is 1 (Int) or 1.0 (Float)
    if let Some(i) = result.as_int() {
        assert_eq!(i, 1);
    } else if let Some(f) = result.as_number() {
         assert_eq!(f, 1.0);
    } else {
        panic!("Expected 1 or 1.0 result from 7 % 2");
    }
}
