use vm::{VM, CallFrame};
use memory::{Function, Value};
use compiler::Compiler;

#[test]
fn test_execution_end_to_end() {
    let source = "1 + 2 * 3";
    
    // 1. Compile
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).expect("Compilation failed");
    let constants = compiler.constants;
    
    // 2. Setup VM
    let mut vm = VM::new();
    
    // 3. Create Function
    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: constants,
    };
    
    let func_idx = vm.heap.alloc_function(func);
    
    // 4. Create Call Frame
    let frame = CallFrame {
        closure: func_idx,
        ip: 0,
        base: 0,
    };
    vm.frames.push(frame);
    
    // 5. Run
    vm.interpret().expect("Runtime error");
    
    // 6. Check Result (R3 or similar)
    // The compiler emits into registers. We need to know which one holds the final result.
    // In our rudimentary compiler, the last result is in the highest register returned by alloc_reg.
    // But since OpCode::Return was emitted with R[A] = result, we can't easily peek the transient stack.
    // However, the test "Result R7" implies we can look at the stack.
    // The specific registers depend on allocation order.
    // 1 -> R0
    // 2 -> R1
    // 3 -> R2
    // 2*3 -> R3
    // 1+R3 -> R4
    // Return R4
    
    let result = vm.stack.get(4).cloned();
    match result {
        Some(Value::Number(n)) => assert_eq!(n, 7.0),
        _ => panic!("Expected number 7.0, got {:?}", result)
    }
}
