use memory::{Function, Value};
use vm::opcode::{instruction::*, OpCode};
use vm::{CallFrame, VM};

fn run_simple(chunk: Vec<u32>, constants: Vec<Value>) -> VM {
    let mut vm = VM::new();
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        max_slots: 255, // Safe default for manual bytecode tests
        chunk,
        constants,
        upvalue_info: Vec::new(),
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
    let constants = vec![Value::number(1.0), Value::number(2.0)];
    let vm = run_simple(chunk, constants);
    assert_eq!(vm.stack[2].as_number(), Some(3.0));
}

#[test]
fn test_ieee754_infinity() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Div.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::number(1.0), Value::number(0.0)];
    let vm = run_simple(chunk, constants);

    let val = vm.stack[2];
    if let Some(n) = val.as_number() {
        assert!(n.is_infinite() && n > 0.0);
    } else {
        panic!("Expected Number, got {:?}", val);
    }
}

#[test]
fn test_ieee754_nan() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 0),
        encode_abc(OpCode::Div.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::number(0.0)];
    let vm = run_simple(chunk, constants);

    let val = vm.stack[2];
    if let Some(n) = val.as_number() {
        assert!(n.is_nan());
    } else {
        panic!("Expected Number, got {:?}", val);
    }
}

#[test]
fn test_sqrt_negative_returns_nan() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abc(OpCode::Sqrt.as_u8(), 1, 0, 0),
        encode_abc(OpCode::Return.as_u8(), 1, 0, 0),
    ];
    let constants = vec![Value::number(-4.0)];
    let vm = run_simple(chunk, constants);

    let val = vm.stack[1];
    if let Some(n) = val.as_number() {
        assert!(n.is_nan(), "sqrt(-4) should be NaN without complex numbers");
    } else {
        panic!("Expected Number, got {:?}", val);
    }
}
