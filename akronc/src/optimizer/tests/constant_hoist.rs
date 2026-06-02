use super::helpers::*;

// ── Pass 2: constant_hoisting ───────────────────────────────────────

#[test]
fn hoist_simple_load_const() {
    let instrs = vec![
        (abx(OpCode::LoadConst, 3, 0), 1), // 0: LoadConst R3
        (abc(OpCode::Add, 1, 1, 3), 1),    // 1: Add R1, R1, R3
        (abx(OpCode::Jump, 0, 0), 1),      // 2: Jump → 0 (back-edge)
    ];
    let result = constant_hoisting(instrs);
    assert_eq!(result.len(), 3);
    assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8());
    assert_eq!(decode_a(result[0].0), 3);
    assert_eq!(decode_opcode(result[1].0), OpCode::Add.as_u8());
    assert_eq!(decode_opcode(result[2].0), OpCode::Jump.as_u8());
    assert_eq!(decode_bx(result[2].0), 1); // back-edge skips hoisted
}

#[test]
fn hoist_does_not_move_conflicting_register() {
    let instrs = vec![
        (abx(OpCode::LoadConst, 2, 0), 1),
        (abc(OpCode::Add, 1, 1, 2), 1),
        (abc(OpCode::Move, 2, 1, 0), 1), // conflict!
        (abx(OpCode::Jump, 0, 0), 1),
    ];
    let result = constant_hoisting(instrs);
    assert_eq!(result.len(), 4);
    assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8());
    assert_eq!(decode_bx(result[3].0), 0);
}

#[test]
fn hoist_remaps_forward_jumps() {
    let instrs = vec![
        (abx(OpCode::LoadConst, 0, 0), 1),   // 0
        (abx(OpCode::LoadConst, 3, 1), 1),   // 1: hoistable
        (abc(OpCode::Add, 1, 1, 3), 2),      // 2
        (abx(OpCode::JumpIfFalse, 1, 5), 2), // 3: → 5
        (abx(OpCode::Jump, 0, 1), 2),        // 4: back-edge → 1
        (abc(OpCode::Return, 0, 0, 0), 3),   // 5
    ];
    let result = constant_hoisting(instrs);
    assert_eq!(result.len(), 6);
    assert_eq!(decode_bx(result[3].0), 5); // forward jump
    assert_eq!(decode_bx(result[4].0), 2); // back-edge → Add
}

#[test]
fn hoist_multiple_consts_from_same_loop() {
    let instrs = vec![
        (abx(OpCode::LoadConst, 3, 0), 1),
        (abx(OpCode::LoadConst, 4, 1), 1),
        (abc(OpCode::Add, 1, 3, 4), 1),
        (abx(OpCode::Jump, 0, 0), 1),
    ];
    let result = constant_hoisting(instrs);
    assert_eq!(result.len(), 4);
    assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8());
    assert_eq!(decode_a(result[0].0), 3);
    assert_eq!(decode_opcode(result[1].0), OpCode::LoadConst.as_u8());
    assert_eq!(decode_a(result[1].0), 4);
    assert_eq!(decode_bx(result[3].0), 2); // back-edge → Add
}

#[test]
fn hoist_no_loops_returns_unchanged() {
    let instrs = vec![
        (abx(OpCode::LoadConst, 0, 0), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let result = constant_hoisting(instrs.clone());
    assert_eq!(result, instrs);
}

#[test]
fn hoist_preserves_line_info() {
    let instrs = vec![
        (abx(OpCode::LoadConst, 3, 0), 42),
        (abc(OpCode::Add, 1, 1, 3), 43),
        (abx(OpCode::Jump, 0, 0), 44),
    ];
    let result = constant_hoisting(instrs);
    assert_eq!(result[0].1, 42);
    assert_eq!(result[1].1, 43);
    assert_eq!(result[2].1, 44);
}
