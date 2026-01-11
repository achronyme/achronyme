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
    };
    let func_idx = vm.heap.alloc_function(func);
    // Wrap in closure
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
fn test_int_storage() {
    // 50 (Int)
    let val = Value::int(50);
    assert!(val.is_int());
    assert!(!val.is_number()); // Should be false for our domain logic (distinct type)
    assert_eq!(val.as_int(), Some(50));
    
    // Negative
    let val_neg = Value::int(-42);
    assert_eq!(val_neg.as_int(), Some(-42));
}

#[test]
fn test_int_addition_wrapping() {
    // 2147483647 + 1 = -2147483648 (Wrapping)
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Add.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(i32::MAX), Value::int(1)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[2];
    assert!(res.is_int());
    assert_eq!(res.as_int(), Some(i32::MIN));
}

#[test]
fn test_int_subtraction() {
    // 10 - 20 = -10
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Sub.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(10), Value::int(20)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[2];
    assert!(res.is_int());
    assert_eq!(res.as_int(), Some(-10));
}

#[test]
fn test_int_division_truncating() {
    // 7 / 2 = 3
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Div.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(7), Value::int(2)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[2];
    assert!(res.is_int());
    assert_eq!(res.as_int(), Some(3));
}

#[test]
fn test_int_mod() {
    // 7 % 3 = 1
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Mod.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(7), Value::int(3)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[2];
    assert!(res.is_int());
    assert_eq!(res.as_int(), Some(1));
}

#[test]
fn test_int_mod_promotion() {
    // 5.5 % 2 = 1.5
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Mod.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::number(5.5), Value::int(2)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[2];
    assert!(res.is_number());
    assert_eq!(res.as_number(), Some(1.5));
}

#[test]
fn test_int_promotion_add() {
    // Int(5) + Float(2.5) = Float(7.5)
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Add.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(5), Value::number(2.5)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[2];
    assert!(res.is_number());
    assert_eq!(res.as_number(), Some(7.5));
}

#[test]
fn test_neg_int() {
    // -Int(10) = Int(-10)
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abc(OpCode::Neg.as_u8(), 1, 0, 0),
        encode_abc(OpCode::Return.as_u8(), 1, 0, 0),
    ];
    let constants = vec![Value::int(10)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[1];
    assert!(res.is_int());
    assert_eq!(res.as_int(), Some(-10));
}

#[test]
fn test_int_sqrt_promotion() {
    // Sqrt(Int(4)) = Float(2.0)
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abc(OpCode::Sqrt.as_u8(), 1, 0, 0),
        encode_abc(OpCode::Return.as_u8(), 1, 0, 0),
    ];
    let constants = vec![Value::int(4)];
    let vm = run_simple(chunk, constants);
    
    let res = vm.stack[1];
    assert!(res.is_number());
    assert_eq!(res.as_number(), Some(2.0));
}
