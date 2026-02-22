use compiler::Compiler;
use memory::{Function, Value};
use vm::{CallFrame, VM};

/// Helper: compile + run a source string and return the result value.
fn eval(source: &str) -> Value {
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
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: Vec::new(),
    });
    let frame = CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    };
    vm.frames.push(frame);
    vm.interpret().expect("Runtime error");
    vm.stack[0]
}

fn eval_bool(source: &str) -> bool {
    let val = eval(source);
    val.as_bool().unwrap_or_else(|| panic!("expected bool, got {:?}", val))
}

fn eval_int(source: &str) -> i64 {
    let val = eval(source);
    val.as_int().unwrap_or_else(|| panic!("expected int, got {:?}", val))
}

// ============================================================================
// != (NotEq)
// ============================================================================

#[test]
fn vm_neq_true() {
    assert!(eval_bool("3 != 4"));
}

#[test]
fn vm_neq_false() {
    assert!(!eval_bool("5 != 5"));
}

// ============================================================================
// <= (Le)
// ============================================================================

#[test]
fn vm_le_less() {
    assert!(eval_bool("3 <= 5"));
}

#[test]
fn vm_le_equal() {
    assert!(eval_bool("5 <= 5"));
}

#[test]
fn vm_le_greater() {
    assert!(!eval_bool("7 <= 5"));
}

// ============================================================================
// >= (Ge)
// ============================================================================

#[test]
fn vm_ge_greater() {
    assert!(eval_bool("7 >= 5"));
}

#[test]
fn vm_ge_equal() {
    assert!(eval_bool("5 >= 5"));
}

#[test]
fn vm_ge_less() {
    assert!(!eval_bool("3 >= 5"));
}

// ============================================================================
// ! (LogNot)
// ============================================================================

#[test]
fn vm_not_true() {
    assert!(!eval_bool("!true"));
}

#[test]
fn vm_not_false() {
    assert!(eval_bool("!false"));
}

#[test]
fn vm_not_nil() {
    assert!(eval_bool("!nil"));
}

#[test]
fn vm_not_zero() {
    // 0 is falsey in most languages; depends on VM semantics
    // Just verify it doesn't crash
    let _ = eval("!0");
}

// ============================================================================
// && (short-circuit And)
// ============================================================================

#[test]
fn vm_and_true_true() {
    assert!(eval_bool("true && true"));
}

#[test]
fn vm_and_true_false() {
    assert!(!eval_bool("true && false"));
}

#[test]
fn vm_and_false_true() {
    assert!(!eval_bool("false && true"));
}

#[test]
fn vm_and_false_false() {
    assert!(!eval_bool("false && false"));
}

// ============================================================================
// || (short-circuit Or)
// ============================================================================

#[test]
fn vm_or_true_false() {
    assert!(eval_bool("true || false"));
}

#[test]
fn vm_or_false_true() {
    assert!(eval_bool("false || true"));
}

#[test]
fn vm_or_false_false() {
    assert!(!eval_bool("false || false"));
}

#[test]
fn vm_or_true_true() {
    assert!(eval_bool("true || true"));
}

// ============================================================================
// Combined expressions
// ============================================================================

#[test]
fn vm_combined_comparison() {
    // (3 < 5) && (5 >= 5) → true
    assert!(eval_bool("3 < 5 && 5 >= 5"));
}

#[test]
fn vm_combined_not_eq() {
    // !(3 == 4) → true
    assert!(eval_bool("!(3 == 4)"));
}

#[test]
fn vm_chained_and() {
    assert!(eval_bool("true && true && true"));
    assert!(!eval_bool("true && false && true"));
}

#[test]
fn vm_chained_or() {
    assert!(eval_bool("false || false || true"));
    assert!(!eval_bool("false || false || false"));
}
