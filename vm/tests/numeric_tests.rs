use memory::{Function, Value};
use vm::opcode::{instruction::*, OpCode};
use vm::{CallFrame, VM};

fn run_simple(chunk: Vec<u32>, constants: Vec<Value>) -> VM {
    let mut vm = VM::new();
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        max_slots: 255,
        chunk,
        constants,
        upvalue_info: Vec::new(),
        line_info: Vec::new(),
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure = memory::Closure {
        function: func_idx,
        upvalues: Vec::new(),
    };
    let closure_idx = vm.heap.alloc_closure(closure);

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });
    vm.interpret().expect("Runtime error");
    vm
}

#[test]
fn test_real_addition() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Add.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(1), Value::int(2)];
    let vm = run_simple(chunk, constants);
    assert_eq!(vm.stack[2].as_int(), Some(3));
}

#[test]
fn test_division_by_zero_integer() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Div.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(1), Value::int(0)];

    let mut vm = VM::new();
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        max_slots: 255,
        chunk,
        constants,
        upvalue_info: Vec::new(),
        line_info: Vec::new(),
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure = memory::Closure {
        function: func_idx,
        upvalues: Vec::new(),
    };
    let closure_idx = vm.heap.alloc_closure(closure);
    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    let result = vm.interpret();
    assert!(result.is_err(), "Division by zero should error");
}

#[test]
fn test_integer_multiplication() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Mul.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(6), Value::int(7)];
    let vm = run_simple(chunk, constants);
    assert_eq!(vm.stack[2].as_int(), Some(42));
}

#[test]
fn test_integer_subtraction() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Sub.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(10), Value::int(3)];
    let vm = run_simple(chunk, constants);
    assert_eq!(vm.stack[2].as_int(), Some(7));
}
