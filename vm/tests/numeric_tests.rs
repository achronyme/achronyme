use vm::{VM, CallFrame};
use memory::{Function, Value};
use vm::opcode::{OpCode, instruction::*};
use num_complex::Complex64;

fn run_simple(chunk: Vec<u32>, constants: Vec<Value>) -> VM {
    let mut vm = VM::new();
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        chunk,
        constants,
    };
    let func_idx = vm.heap.alloc_function(func);
    vm.frames.push(CallFrame { closure: func_idx, ip: 0, base: 0 });
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
fn test_real_complex_promotion() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 1),
        encode_abc(OpCode::Add.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    
    let mut vm = VM::new();
    let c_idx = vm.heap.alloc_complex(Complex64::new(0.0, 2.0));
    
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        chunk,
        constants: vec![Value::number(1.0), Value::complex(c_idx)],
    };
    let func_idx = vm.heap.alloc_function(func);
    vm.frames.push(CallFrame { closure: func_idx, ip: 0, base: 0 });
    vm.interpret().expect("Runtime error");
    
    let val = vm.stack[2];
    if val.is_complex() {
        let idx = val.as_handle().unwrap();
        let c = vm.heap.get_complex(idx).unwrap();
        assert!((c.re - 1.0).abs() < 1e-10);
        assert!((c.im - 2.0).abs() < 1e-10);
    } else {
        panic!("Expected Complex, got {:?}", val);
    }
}

#[test]
fn test_complex_times_complex_demote() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abx(OpCode::LoadConst.as_u8(), 1, 0),
        encode_abc(OpCode::Mul.as_u8(), 2, 0, 1),
        encode_abc(OpCode::Return.as_u8(), 2, 0, 0),
    ];
    
    let mut vm = VM::new();
    let c_idx = vm.heap.alloc_complex(Complex64::new(0.0, 1.0));
    
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        chunk,
        constants: vec![Value::complex(c_idx)],
    };
    let func_idx = vm.heap.alloc_function(func);
    vm.frames.push(CallFrame { closure: func_idx, ip: 0, base: 0 });
    vm.interpret().expect("Runtime error");
    
    assert_eq!(vm.stack[2].as_number(), Some(-1.0));
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
fn test_sqrt_negative_promotes() {
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abc(OpCode::Sqrt.as_u8(), 1, 0, 0),
        encode_abc(OpCode::Return.as_u8(), 1, 0, 0),
    ];
    let constants = vec![Value::number(-4.0)];
    let mut vm = VM::new();
    let func = Function {
        name: "test".to_string(),
        arity: 0,
        chunk,
        constants,
    };
    let func_idx = vm.heap.alloc_function(func);
    vm.frames.push(CallFrame { closure: func_idx, ip: 0, base: 0 });
    vm.interpret().expect("Runtime error");
    
    let val = vm.stack[1];
    if val.is_complex() {
        let idx = val.as_handle().unwrap();
        let c = vm.heap.get_complex(idx).unwrap();
        assert!((c.re).abs() < 1e-10);
        assert!((c.im - 2.0).abs() < 1e-10);
    } else {
        panic!("Expected Complex, got {:?}", val);
    }
}
