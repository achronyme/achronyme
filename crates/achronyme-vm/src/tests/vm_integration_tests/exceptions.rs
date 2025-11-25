use super::helpers::execute;
use crate::value::Value;

// ===== Phase 6 Week 15 Tests: Exception Runtime =====

/// Test throwing an uncaught exception
#[test]
fn test_throw_simple() {
    use crate::bytecode::{BytecodeModule, ConstantPool, FunctionPrototype};
    use crate::error::VmError;
    use crate::opcode::{instruction::*, OpCode};
    use achronyme_types::sync::Arc;

    // Build bytecode manually:
    // R[0] = "Error message"
    // THROW R[0]
    let mut constants = ConstantPool::new();
    let err_const_idx = constants.add_constant(Value::String("Test error".to_string()));
    let constants = Arc::new(constants);

    let mut main = FunctionPrototype::new("<main>".to_string(), constants.clone());
    main.register_count = 255;

    // LOAD_CONST R[0], K[err_const_idx]
    main.add_instruction(encode_abx(
        OpCode::LoadConst.as_u8(),
        0,
        err_const_idx as u16,
    ));
    // THROW R[0]
    main.add_instruction(encode_abc(OpCode::Throw.as_u8(), 0, 0, 0));

    let module = BytecodeModule {
        name: "test".to_string(),
        main,
        constants,
    };

    let result = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let mut vm = crate::vm::VM::new();
            vm.execute(module).await
        })
    };

    // Should return UncaughtException error
    assert!(result.is_err());
    match result.unwrap_err() {
        VmError::UncaughtException(val) => match val {
            Value::Error { message, .. } => assert_eq!(message, "Test error"),
            val => panic!("Expected Error value, got {:?}", val),
        },
        e => panic!("Expected UncaughtException, got {:?}", e),
    }
}

/// Test pushing and popping exception handlers
#[test]
fn test_push_pop_handler() {
    use crate::bytecode::{BytecodeModule, ConstantPool, FunctionPrototype};
    use crate::opcode::{instruction::*, OpCode};
    use achronyme_types::sync::Arc;

    // Build bytecode:
    // PUSH_HANDLER R[1], offset=5 (points to catch block)
    // R[0] = 42 (some safe code)
    // POP_HANDLER
    // RETURN R[0]
    let constants = Arc::new(ConstantPool::new());
    let mut main = FunctionPrototype::new("<main>".to_string(), constants.clone());
    main.register_count = 255;

    // PUSH_HANDLER R[1], offset=5
    main.add_instruction(encode_abx(OpCode::PushHandler.as_u8(), 1, 5));
    // LOAD_IMM_I8 R[0], 42
    main.add_instruction(encode_abx(OpCode::LoadImmI8.as_u8(), 0, 42));
    // POP_HANDLER
    main.add_instruction(encode_abc(OpCode::PopHandler.as_u8(), 0, 0, 0));
    // RETURN R[0]
    main.add_instruction(encode_abc(OpCode::Return.as_u8(), 0, 0, 0));

    let module = BytecodeModule {
        name: "test".to_string(),
        main,
        constants,
    };

    let result = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let mut vm = crate::vm::VM::new();
            vm.execute(module).await
        })
    };

    // Should succeed and return 42
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

/// Test catching an exception
#[test]
fn test_catch_exception() {
    use crate::bytecode::{BytecodeModule, ConstantPool, FunctionPrototype};
    use crate::opcode::{instruction::*, OpCode};
    use achronyme_types::sync::Arc;

    // Build bytecode:
    // PUSH_HANDLER R[1], offset=3 (points to catch block at IP 4)
    // R[0] = "Error"
    // THROW R[0]
    // POP_HANDLER  (skipped due to throw)
    // Catch block (IP 4):
    // RETURN R[1]  (error value stored in R[1])
    let mut constants = ConstantPool::new();
    let err_const_idx = constants.add_constant(Value::String("Caught!".to_string()));
    let constants = Arc::new(constants);

    let mut main = FunctionPrototype::new("<main>".to_string(), constants.clone());
    main.register_count = 255;

    // IP 0: PUSH_HANDLER R[1], offset=3 (catch block at IP 0 + 3 + 1 = 4)
    main.add_instruction(encode_abx(OpCode::PushHandler.as_u8(), 1, 3));
    // IP 1: LOAD_CONST R[0], K[err_const_idx]
    main.add_instruction(encode_abx(
        OpCode::LoadConst.as_u8(),
        0,
        err_const_idx as u16,
    ));
    // IP 2: THROW R[0]
    main.add_instruction(encode_abc(OpCode::Throw.as_u8(), 0, 0, 0));
    // IP 3: POP_HANDLER (never reached)
    main.add_instruction(encode_abc(OpCode::PopHandler.as_u8(), 0, 0, 0));
    // IP 4: Catch block - RETURN R[1]
    main.add_instruction(encode_abc(OpCode::Return.as_u8(), 1, 0, 0));

    let module = BytecodeModule {
        name: "test".to_string(),
        main,
        constants,
    };

    let result = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let mut vm = crate::vm::VM::new();
            vm.execute(module).await
        })
    };

    // Should return the caught error value
    assert!(result.is_ok());
    match result.unwrap() {
        Value::Error { message, .. } => assert_eq!(message, "Caught!"),
        val => panic!("Expected Error value, got {:?}", val),
    }
}

/// Test unwinding through multiple call frames
#[test]
fn test_unwinding_through_frames() {
    use crate::bytecode::{BytecodeModule, ConstantPool, FunctionPrototype};
    use crate::opcode::{instruction::*, OpCode};
    use achronyme_types::sync::Arc;

    // Setup: Main calls function A, A calls function B, B throws, A catches
    let mut constants = ConstantPool::new();
    let err_const = constants.add_constant(Value::String("B error".to_string()));
    let constants = Arc::new(constants);

    // Function B (throws error)
    let mut func_b = FunctionPrototype::new("func_b".to_string(), constants.clone());
    func_b.register_count = 255; // Use 256 registers for recursion support
    func_b.param_count = 0;
    // LOAD_CONST R[0], K[err_const]
    func_b.add_instruction(encode_abx(OpCode::LoadConst.as_u8(), 0, err_const as u16));
    // THROW R[0]
    func_b.add_instruction(encode_abc(OpCode::Throw.as_u8(), 0, 0, 0));

    // Function A (calls B with handler)
    let mut func_a = FunctionPrototype::new("func_a".to_string(), constants.clone());
    func_a.register_count = 255; // Use 256 registers for recursion support
    func_a.param_count = 0;
    // PUSH_HANDLER R[2], offset=4 (catch at IP 5)
    func_a.add_instruction(encode_abx(OpCode::PushHandler.as_u8(), 2, 4));
    // CLOSURE R[0], 0 (func_b is at index 0)
    func_a.add_instruction(encode_abx(OpCode::Closure.as_u8(), 0, 0));
    // CALL R[1] = R[0]() (0 args)
    func_a.add_instruction(encode_abc(OpCode::Call.as_u8(), 1, 0, 0));
    // POP_HANDLER (never reached)
    func_a.add_instruction(encode_abc(OpCode::PopHandler.as_u8(), 0, 0, 0));
    // RETURN_NULL (never reached)
    func_a.add_instruction(encode_abc(OpCode::ReturnNull.as_u8(), 0, 0, 0));
    // Catch block (IP 6): RETURN R[2]
    func_a.add_instruction(encode_abc(OpCode::Return.as_u8(), 2, 0, 0));
    // Add func_b as nested function
    func_a.functions.push(func_b);

    // Main (calls A)
    let mut main = FunctionPrototype::new("<main>".to_string(), constants.clone());
    main.register_count = 255; // Use 256 registers for recursion support
                               // CLOSURE R[0], 0 (func_a is at index 0)
    main.add_instruction(encode_abx(OpCode::Closure.as_u8(), 0, 0));
    // CALL R[1] = R[0]()
    main.add_instruction(encode_abc(OpCode::Call.as_u8(), 1, 0, 0));
    // RETURN R[1]
    main.add_instruction(encode_abc(OpCode::Return.as_u8(), 1, 0, 0));
    // Add func_a as nested function
    main.functions.push(func_a);

    let module = BytecodeModule {
        name: "test".to_string(),
        main,
        constants,
    };

    let result = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let mut vm = crate::vm::VM::new();
            vm.execute(module).await
        })
    };

    // Should return the caught error from function B
    assert!(result.is_ok());
    match result.unwrap() {
        Value::Error { message, .. } => assert_eq!(message, "B error"),
        val => panic!("Expected Error value, got {:?}", val),
    }
}

// ============================================================================
// WEEK 16: TRY-CATCH COMPILATION TESTS
// ============================================================================

#[test]
fn test_try_catch_basic() {
    let source = r#"
        try {
            throw "error"
        } catch(e) {
            e
        }
    "#;
    let result = execute(source).unwrap();
    match result {
        Value::Error { message, .. } => assert_eq!(message, "error"),
        val => panic!("Expected Error value, got {:?}", val),
    }
}

#[test]
fn test_try_catch_no_error() {
    let source = r#"
        try {
            42
        } catch(e) {
            0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_nested_try_catch() {
    let source = r#"
        try {
            try {
                throw "inner"
            } catch(e1) {
                throw "outer"
            }
        } catch(e2) {
            e2
        }
    "#;
    let result = execute(source).unwrap();
    match result {
        Value::Error { message, .. } => assert_eq!(message, "outer"),
        val => panic!("Expected Error value, got {:?}", val),
    }
}

#[test]
fn test_try_catch_in_function() {
    let source = r#"
        let f = () => do {
            try {
                throw "func_error"
            } catch(e) {
                e
            }
        }
        f()
    "#;
    let result = execute(source).unwrap();
    match result {
        Value::Error { message, .. } => assert_eq!(message, "func_error"),
        val => panic!("Expected Error value, got {:?}", val),
    }
}

#[test]
fn test_try_catch_with_computation() {
    let source = r#"
        let x = 10
        try {
            let y = x + 5
            throw y
        } catch(e) {
            30
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_throw_from_nested_call() {
    let source = r#"
        let inner = () => do {
            throw "deep_error"
        }
        let outer = () => do {
            inner()
        }
        try {
            outer()
        } catch(e) {
            e
        }
    "#;
    let result = execute(source).unwrap();
    match result {
        Value::Error { message, .. } => assert_eq!(message, "deep_error"),
        val => panic!("Expected Error value, got {:?}", val),
    }
}
