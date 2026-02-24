use memory::{Function, Value, I60_MAX, I60_MIN};
use vm::error::RuntimeError;
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

fn run_fallible(chunk: Vec<u32>, constants: Vec<Value>) -> Result<VM, RuntimeError> {
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
    vm.interpret().map(|_| vm)
}

#[test]
fn test_int_storage() {
    let val = Value::int(50);
    assert!(val.is_int());
    assert_eq!(val.as_int(), Some(50));

    let val_neg = Value::int(-42);
    assert_eq!(val_neg.as_int(), Some(-42));
}

#[test]
fn test_int_addition_overflow_errors() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Add.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(I60_MAX), Value::int(1)];
    let result = run_fallible(chunk, constants);
    assert!(matches!(result, Err(RuntimeError::IntegerOverflow)));
}

#[test]
fn test_int_subtraction_overflow_errors() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Sub.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(I60_MIN), Value::int(1)];
    let result = run_fallible(chunk, constants);
    assert!(matches!(result, Err(RuntimeError::IntegerOverflow)));
}

#[test]
fn test_int_multiplication_overflow_errors() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Mul.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(I60_MAX), Value::int(2)];
    let result = run_fallible(chunk, constants);
    assert!(matches!(result, Err(RuntimeError::IntegerOverflow)));
}

#[test]
fn test_neg_i60_min_overflow_errors() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abc(OpCode::Neg.as_u8(), 1, 0, 0),
        encode_abc(OpCode::Return.as_u8(), 1, 0, 0),
    ];
    let constants = vec![Value::int(I60_MIN)];
    let result = run_fallible(chunk, constants);
    assert!(matches!(result, Err(RuntimeError::IntegerOverflow)));
}

#[test]
fn test_pow_negative_exponent_errors() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Pow.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(2), Value::int(-3)];
    let result = run_fallible(chunk, constants);
    assert!(matches!(result, Err(RuntimeError::TypeMismatch(_))));
}

#[test]
fn test_pow_large_exponent_overflow_errors() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Pow.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(2), Value::int(100)];
    let result = run_fallible(chunk, constants);
    assert!(matches!(result, Err(RuntimeError::IntegerOverflow)));
}

#[test]
fn test_pow_trivial_bases_large_exponent_ok() {
    // 1 ^ 1000 = 1
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Pow.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(1), Value::int(1000)];
    let vm = run_simple(chunk, constants);
    assert!(vm.stack[2].is_int());
    assert_eq!(vm.stack[2].as_int(), Some(1));

    // 0 ^ 1000 = 0
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Pow.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(0), Value::int(1000)];
    let vm = run_simple(chunk, constants);
    assert!(vm.stack[2].is_int());
    assert_eq!(vm.stack[2].as_int(), Some(0));

    // (-1) ^ 1000 = 1
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Pow.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(-1), Value::int(1000)];
    let vm = run_simple(chunk, constants);
    assert!(vm.stack[2].is_int());
    assert_eq!(vm.stack[2].as_int(), Some(1));

    // (-1) ^ 999 = -1
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Pow.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    let constants = vec![Value::int(-1), Value::int(999)];
    let vm = run_simple(chunk, constants);
    assert!(vm.stack[2].is_int());
    assert_eq!(vm.stack[2].as_int(), Some(-1));
}

#[test]
fn test_int_subtraction() {
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
fn test_neg_int() {
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
