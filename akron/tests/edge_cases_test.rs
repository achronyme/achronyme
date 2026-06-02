//! V-20: Edge case tests for VM robustness
//!
//! Covers: deep recursion stack overflow, GC stress, malicious bytecode
//! with raw instruction encoding, prove with empty scope.

use akron::opcode::instruction::{encode_abc, encode_abx};
use akron::{CallFrame, OpCode, RuntimeError, MAX_FRAMES, VM};
use akronc::Compiler;
use memory::{Closure, Function, Value};

// ======================================================================
// Helpers
// ======================================================================

/// Compile and run source, returning the VM or the RuntimeError.
fn run(source: &str) -> Result<VM, RuntimeError> {
    let mut compiler = Compiler::new();
    let bytecode = compiler
        .compile(source)
        .map_err(|e| RuntimeError::type_mismatch(format!("{e:?}")))?;
    let main_func = compiler.compilers.last().expect("no main compiler");

    let mut vm = VM::new();
    vm.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

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
fn run_raw(chunk: Vec<u32>, constants: Vec<Value>, max_slots: u16) -> Result<VM, RuntimeError> {
    let mut vm = VM::new();
    let func = Function {
        name: "raw".to_string(),
        arity: 0,
        chunk,
        constants,
        max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");
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

    let user_global_idx: u16 = resolve::BuiltinRegistry::default().vm_native_count() as u16;

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
        line_info: vec![],
    };
    let proto_handle = vm.heap.alloc_function(recurse_func).expect("alloc");
    vm.prototypes.push(proto_handle);

    // Main: Closure R[0] = proto[0], DefGlobalVar Global[user_global_idx] = R[0],
    //       GetGlobal R[0] = Global[user_global_idx], Call R[0]
    let main_chunk = vec![
        encode_abx(OpCode::Closure.as_u8(), 0, 0), // R[0] = Closure(proto 0)
        encode_abx(OpCode::DefGlobalVar.as_u8(), 0, user_global_idx), // Global["recurse"] = R[0]
        encode_abx(OpCode::GetGlobal.as_u8(), 0, user_global_idx), // R[0] = Global["recurse"]
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0), // Call R[0]
    ];
    let main_func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: main_chunk,
        constants: vec![],
        max_slots: 4,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let main_handle = vm.heap.alloc_function(main_func).expect("alloc");
    let closure_handle = vm
        .heap
        .alloc_closure(Closure {
            function: main_handle,
            upvalues: vec![],
        })
        .expect("alloc");
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
// 1b. Frame depth limit — max_slots=1 hits MAX_FRAMES before STACK_MAX
// ======================================================================

#[test]
fn frame_depth_limit_before_stack_max() {
    // With max_slots=1, STACK_MAX (65536) would allow ~65K frames.
    // MAX_FRAMES (4096) must trigger first.
    let mut vm = VM::new();
    let user_global_idx: u16 = resolve::BuiltinRegistry::default().vm_native_count() as u16;

    let recurse_chunk = vec![
        encode_abx(OpCode::GetGlobal.as_u8(), 0, user_global_idx),
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0),
    ];
    let recurse_func = Function {
        name: "recurse".to_string(),
        arity: 0,
        chunk: recurse_chunk,
        constants: vec![],
        max_slots: 1, // Minimal slots — won't hit STACK_MAX
        upvalue_info: vec![],
        line_info: vec![],
    };
    let proto_handle = vm.heap.alloc_function(recurse_func).expect("alloc");
    vm.prototypes.push(proto_handle);

    let main_chunk = vec![
        encode_abx(OpCode::Closure.as_u8(), 0, 0),
        encode_abx(OpCode::DefGlobalVar.as_u8(), 0, user_global_idx),
        encode_abx(OpCode::GetGlobal.as_u8(), 0, user_global_idx),
        encode_abc(OpCode::Call.as_u8(), 0, 0, 0),
    ];
    let main_func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: main_chunk,
        constants: vec![],
        max_slots: 1,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let main_handle = vm.heap.alloc_function(main_func).expect("alloc");
    let closure_handle = vm
        .heap
        .alloc_closure(Closure {
            function: main_handle,
            upvalues: vec![],
        })
        .expect("alloc");
    vm.frames.push(CallFrame {
        closure: closure_handle,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    let result = vm.interpret();
    let err = result.expect_err("deep recursion should hit frame limit");
    assert!(
        matches!(err, RuntimeError::StackOverflow),
        "expected StackOverflow from frame limit, got {err:?}"
    );
    // Verify it was the frame limit, not STACK_MAX
    assert!(
        vm.frames.len() <= MAX_FRAMES,
        "frames should be capped at MAX_FRAMES ({MAX_FRAMES}), got {}",
        vm.frames.len()
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
    vm.import_strings(compiler.interner.strings);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");
    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().expect("GC stress should not crash");
}

#[path = "edge_cases_test/raw_bytecode.rs"]
mod raw_bytecode;

// ======================================================================
// 19. Instruction budget — finite program completes within budget
// ======================================================================

#[test]
fn instruction_budget_sufficient() {
    // 3 nops = 3 instructions; budget of 10 is plenty.
    let chunk = vec![
        encode_abc(OpCode::Nop.as_u8(), 0, 0, 0),
        encode_abc(OpCode::Nop.as_u8(), 0, 0, 0),
        encode_abc(OpCode::Nop.as_u8(), 0, 0, 0),
    ];
    let mut vm = VM::new();
    let func = Function {
        name: "raw".to_string(),
        arity: 0,
        chunk,
        constants: vec![],
        max_slots: 4,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");
    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });
    vm.instruction_budget = 10;
    assert!(vm.interpret().is_ok(), "should complete within budget");
}

// ======================================================================
// 20. Instruction budget — exhausted returns error
// ======================================================================

#[test]
fn instruction_budget_exhausted() {
    // Infinite loop: Jump to self. Budget of 100 must stop it.
    let chunk = vec![encode_abx(OpCode::Jump.as_u8(), 0, 0)];
    let mut vm = VM::new();
    let func = Function {
        name: "raw".to_string(),
        arity: 0,
        chunk,
        constants: vec![],
        max_slots: 4,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");
    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });
    vm.instruction_budget = 100;
    let result = vm.interpret();
    let err = result.expect_err("infinite loop should exhaust budget");
    assert!(
        matches!(err, RuntimeError::InstructionBudgetExhausted),
        "expected InstructionBudgetExhausted, got {err:?}"
    );
}
