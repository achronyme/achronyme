use super::*;

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
fn malicious_bytecode_oob_constant_returns_error() {
    // LoadConst R[0] = K[9999] with only 1 constant.
    // VM must return OutOfBounds error instead of silently loading nil.
    let chunk = vec![encode_abx(OpCode::LoadConst.as_u8(), 0, 9999)];
    let err = expect_err(
        run_raw(chunk, vec![Value::int(1)], 4),
        "oob constant index must return error",
    );
    assert!(
        matches!(err, RuntimeError::OutOfBounds(_)),
        "expected OutOfBounds, got {err:?}"
    );
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
    // Jump target 9999 far exceeds chunk length 1 → OutOfBounds error.
    let chunk = vec![encode_abx(OpCode::Jump.as_u8(), 0, 9999)];
    let err = expect_err(run_raw(chunk, vec![], 4), "OOB jump should error");
    assert!(
        matches!(err, RuntimeError::OutOfBounds(_)),
        "expected OutOfBounds, got {err:?}"
    );
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
    let result = run_raw(chunk, vec![Value::int(42)], 4);
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
    assert!(
        result.is_ok(),
        "BuildList within physical stack should not panic"
    );
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
