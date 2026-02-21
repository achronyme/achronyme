//! V-20: Edge case tests for VM robustness
//!
//! Covers: deep recursion stack overflow, GC stress, malicious bytecode
//! with raw instruction encoding, prove with empty scope.

use compiler::Compiler;
use memory::{Closure, Function, Value};
use vm::opcode::instruction::{encode_abc, encode_abx};
use vm::{CallFrame, OpCode, RuntimeError, VM};

// ======================================================================
// Helpers
// ======================================================================

/// Compile and run source, returning the VM or the RuntimeError.
fn run(source: &str) -> Result<VM, RuntimeError> {
    let mut compiler = Compiler::new();
    let bytecode = compiler
        .compile(source)
        .map_err(|e| RuntimeError::Unknown(format!("{e:?}")))?;
    let main_func = compiler.compilers.last().expect("no main compiler");

    let mut vm = VM::new();
    vm.heap.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone());
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(Closure {
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
    Ok(vm)
}

/// Build a VM with raw bytecode, constants, and max_slots, then interpret.
fn run_raw(
    chunk: Vec<u32>,
    constants: Vec<Value>,
    max_slots: u16,
) -> Result<VM, RuntimeError> {
    let mut vm = VM::new();
    let func = Function {
        name: "raw".to_string(),
        arity: 0,
        chunk,
        constants,
        max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(Closure {
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
    Ok(vm)
}

/// Extract error from Result<VM, RuntimeError>, panicking if Ok.
fn expect_err(result: Result<VM, RuntimeError>, msg: &str) -> RuntimeError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("{msg}"),
    }
}

// ======================================================================
// 1. Deep recursion → StackOverflow (raw bytecode: self-calling closure)
// ======================================================================

#[test]
fn deep_recursion_stack_overflow() {
    // Build a function that calls itself via a global.
    // Main: DefGlobalVar "recurse" = closure(proto 0), then GetGlobal + Call.
    // Proto 0: GetGlobal "recurse", Call it (infinite recursion).
    let mut vm = VM::new();

    // The user global index for "recurse" is USER_GLOBAL_START (12).
    let user_global_idx: u16 = vm::specs::USER_GLOBAL_START;

    // Proto 0 (recursive function): GetGlobal "recurse" into R[0], Call R[0]
    let recurse_chunk = vec![
        encode_abx(OpCode::GetGlobal.as_u8(), 0, user_global_idx),
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0),
    ];
    let recurse_func = Function {
        name: "recurse".to_string(),
        arity: 0,
        chunk: recurse_chunk,
        constants: vec![],
        max_slots: 4,
        upvalue_info: vec![],
    };
    let proto_handle = vm.heap.alloc_function(recurse_func);
    vm.prototypes.push(proto_handle);

    // Main: Closure R[0] = proto[0], DefGlobalVar Global[user_global_idx] = R[0],
    //       GetGlobal R[0] = Global[user_global_idx], Call R[0]
    let main_chunk = vec![
        encode_abx(OpCode::Closure.as_u8(), 0, 0),                     // R[0] = Closure(proto 0)
        encode_abx(OpCode::DefGlobalVar.as_u8(), 0, user_global_idx),  // Global["recurse"] = R[0]
        encode_abx(OpCode::GetGlobal.as_u8(), 0, user_global_idx),     // R[0] = Global["recurse"]
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0),                     // Call R[0]
    ];
    let main_func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: main_chunk,
        constants: vec![],
        max_slots: 4,
        upvalue_info: vec![],
    };
    let main_handle = vm.heap.alloc_function(main_func);
    let closure_handle = vm.heap.alloc_closure(Closure {
        function: main_handle,
        upvalues: vec![],
    });
    vm.frames.push(CallFrame {
        closure: closure_handle,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    let result = vm.interpret();
    let err = result.expect_err("deep recursion should cause StackOverflow");
    assert!(
        matches!(err, RuntimeError::StackOverflow),
        "expected StackOverflow, got {err:?}"
    );
}

// ======================================================================
// 2. GC stress — many allocations under stress mode
// ======================================================================

#[test]
fn gc_stress_many_allocations() {
    // Allocate many strings and lists under stress GC.
    // This exercises GC mark/sweep during every allocation.
    let source = r#"
        let a = "hello"
        let b = "world"
        let c = a
        let d = b
        let e = "test"
    "#;

    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).expect("compile failed");
    let main_func = compiler.compilers.last().expect("no main compiler");

    let mut vm = VM::new();
    vm.stress_mode = true;
    vm.heap.import_strings(compiler.interner.strings);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(Closure {
        function: func_idx,
        upvalues: vec![],
    });
    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().expect("GC stress should not crash");
}

// ======================================================================
// 3. Malicious bytecode — invalid opcode
// ======================================================================

#[test]
fn malicious_bytecode_invalid_opcode() {
    let chunk = vec![encode_abc(200, 0, 0, 0)];
    let err = expect_err(run_raw(chunk, vec![], 4), "invalid opcode should error");
    assert!(
        matches!(err, RuntimeError::InvalidOpcode(200)),
        "expected InvalidOpcode(200), got {err:?}"
    );
}

// ======================================================================
// 4. Malicious bytecode — LoadConst with out-of-bounds constant index
// ======================================================================

#[test]
fn malicious_bytecode_oob_constant_no_panic() {
    // LoadConst R[0] = K[9999] with only 1 constant.
    // VM uses .get().unwrap_or(nil) — gracefully returns nil, no panic.
    let chunk = vec![encode_abx(OpCode::LoadConst.as_u8(), 0, 9999)];
    let result = run_raw(chunk, vec![Value::number(1.0)], 4);
    assert!(result.is_ok(), "oob constant should not panic");
}

// ======================================================================
// 5. Malicious bytecode — register beyond stack (base + 255 in small frame)
// ======================================================================

#[test]
fn malicious_bytecode_register_oob() {
    // Move R[250] = R[251] with max_slots=4. The registers are within the
    // physical stack but outside this frame's allocation.
    let chunk = vec![encode_abc(OpCode::Move.as_u8(), 250, 251, 0)];
    let result = run_raw(chunk, vec![], 4);
    // The physical stack is large (65536), so this accesses uninitialized (nil)
    // slots. Move should succeed with nil. The key is it doesn't panic.
    // This verifies the VM doesn't crash on out-of-frame register access.
    assert!(result.is_ok(), "move from nil slots should not panic");
}

// ======================================================================
// 6. Malicious bytecode — arithmetic on nil values
// ======================================================================

#[test]
fn malicious_bytecode_arithmetic_on_nil() {
    // Add R[0] = R[1] + R[2] where R[1] and R[2] are nil (default stack).
    let chunk = vec![encode_abc(OpCode::Add.as_u8(), 0, 1, 2)];
    let err = expect_err(run_raw(chunk, vec![], 4), "add on nil should error");
    assert!(
        matches!(err, RuntimeError::TypeMismatch(_)),
        "expected TypeMismatch, got {err:?}"
    );
}

// ======================================================================
// 7. Prove with no handler configured
// ======================================================================

#[test]
fn prove_handler_not_configured_empty_scope() {
    let source = r#"
        prove {
            assert_eq(1, 1)
        }
    "#;
    let err = expect_err(run(source), "prove without handler should error");
    assert!(
        matches!(err, RuntimeError::ProveHandlerNotConfigured),
        "expected ProveHandlerNotConfigured, got {err:?}"
    );
}

// ======================================================================
// 8. Malicious bytecode — Jump to out-of-bounds IP
// ======================================================================

#[test]
fn malicious_bytecode_jump_oob() {
    // Jump past the end → ip >= chunk.len() → frame pops → clean exit.
    let chunk = vec![encode_abx(OpCode::Jump.as_u8(), 0, 9999)];
    let result = run_raw(chunk, vec![], 4);
    assert!(result.is_ok(), "jump past end should exit cleanly");
}

// ======================================================================
// 9. Malicious bytecode — Call with non-closure value
// ======================================================================

#[test]
fn malicious_bytecode_call_non_closure() {
    // R[0] = nil, then Call R[0].
    let chunk = vec![
        encode_abx(OpCode::LoadNil.as_u8(), 0, 0),
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0),
    ];
    let result = run_raw(chunk, vec![], 4);
    assert!(result.is_err(), "calling nil should error");
}

// ======================================================================
// 10. Malicious bytecode — Call with number value
// ======================================================================

#[test]
fn malicious_bytecode_call_number() {
    // R[0] = 42.0, then Call R[0].
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 0, 0),
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0),
    ];
    let result = run_raw(chunk, vec![Value::number(42.0)], 4);
    assert!(result.is_err(), "calling a number should error");
}

// ======================================================================
// 11. Malicious bytecode — GetGlobal with out-of-bounds index
// ======================================================================

#[test]
fn malicious_bytecode_get_global_oob() {
    // GetGlobal R[0] = Global[60000] — way beyond native count.
    let chunk = vec![encode_abx(OpCode::GetGlobal.as_u8(), 0, 60000)];
    let result = run_raw(chunk, vec![], 4);
    assert!(result.is_err(), "GetGlobal OOB should error, not panic");
}

// ======================================================================
// 12. Malicious bytecode — SetGlobal on immutable native
// ======================================================================

#[test]
fn malicious_bytecode_set_global_native() {
    // SetGlobal Global[0] = R[0] — index 0 is "print" (immutable native).
    let chunk = vec![
        encode_abx(OpCode::LoadNil.as_u8(), 0, 0),
        encode_abx(OpCode::SetGlobal.as_u8(), 0, 0),
    ];
    let result = run_raw(chunk, vec![], 4);
    // Should error because native globals are immutable.
    assert!(result.is_err(), "setting immutable native should error");
}

// ======================================================================
// 13. Malicious bytecode — BuildList with count exceeding registers
// ======================================================================

#[test]
fn malicious_bytecode_build_list_large_no_panic() {
    // BuildList R[0] = [R[1]..R[255]] — 255 elements starting at R[1].
    // Physical stack is large (65536), so bounds check passes (builds list of nils).
    // The key invariant is no panic — the V-11 fix prevents truly OOB access.
    let chunk = vec![encode_abc(OpCode::BuildList.as_u8(), 0, 1, 255)];
    let result = run_raw(chunk, vec![], 4);
    assert!(result.is_ok(), "BuildList within physical stack should not panic");
}

// ======================================================================
// 14. Malicious bytecode — Neg on non-numeric
// ======================================================================

#[test]
fn malicious_bytecode_neg_on_nil() {
    // Neg R[0] = -R[1] where R[1] is nil.
    let chunk = vec![encode_abc(OpCode::Neg.as_u8(), 0, 1, 0)];
    let err = expect_err(run_raw(chunk, vec![], 4), "neg on nil should error");
    assert!(
        matches!(err, RuntimeError::TypeMismatch(_)),
        "expected TypeMismatch, got {err:?}"
    );
}

// ======================================================================
// 15. Empty bytecode — clean exit
// ======================================================================

#[test]
fn empty_bytecode_clean_exit() {
    let result = run_raw(vec![], vec![], 4);
    assert!(result.is_ok(), "empty bytecode should exit cleanly");
}

// ======================================================================
// 16. Nop-only bytecode
// ======================================================================

#[test]
fn nop_only_bytecode() {
    let chunk = vec![
        encode_abc(OpCode::Nop.as_u8(), 0, 0, 0),
        encode_abc(OpCode::Nop.as_u8(), 0, 0, 0),
        encode_abc(OpCode::Nop.as_u8(), 0, 0, 0),
    ];
    let result = run_raw(chunk, vec![], 4);
    assert!(result.is_ok(), "nop-only bytecode should exit cleanly");
}

// ======================================================================
// 17. Division by zero (integer)
// ======================================================================

#[test]
fn division_by_zero_integer() {
    // Use raw bytecode with Value::int to test the integer div-by-zero path.
    // The bytecode compiler emits floats (10.0/0.0 = Inf), so we must use raw ints.
    let chunk = vec![
        encode_abx(OpCode::LoadConst.as_u8(), 1, 0), // R[1] = K[0] = int(10)
        encode_abx(OpCode::LoadConst.as_u8(), 2, 1), // R[2] = K[1] = int(0)
        encode_abc(OpCode::Div.as_u8(), 0, 1, 2),    // R[0] = R[1] / R[2]
    ];
    let constants = vec![Value::int(10), Value::int(0)];
    let err = expect_err(run_raw(chunk, constants, 4), "int div by zero should error");
    assert!(
        matches!(err, RuntimeError::DivisionByZero),
        "expected DivisionByZero, got {err:?}"
    );
}

// ======================================================================
// 18. Multiple sequential gaps in opcode numbering
// ======================================================================

#[test]
fn all_invalid_opcodes_rejected() {
    // Test a sampling of unassigned opcode values.
    for invalid_op in [4, 6, 7, 8, 9, 18, 19, 27, 30, 40, 50, 70, 80, 90, 200] {
        let chunk = vec![encode_abc(invalid_op, 0, 0, 0)];
        let result = run_raw(chunk, vec![], 4);
        let err = expect_err(result, &format!("opcode {invalid_op} should be invalid"));
        assert!(
            matches!(err, RuntimeError::InvalidOpcode(op) if op == invalid_op),
            "opcode {invalid_op}: expected InvalidOpcode, got {err:?}"
        );
    }
}
