use super::helpers::*;

// ── jump_targets ────────────────────────────────────────────────────

#[test]
fn jump_targets_finds_all_targets() {
    let instrs = vec![
        (abx(OpCode::Jump, 0, 3), 1),
        (abx(OpCode::LoadConst, 1, 0), 1),
        (abx(OpCode::JumpIfFalse, 1, 0), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let targets = jump_targets(&instrs);
    assert!(targets[3], "Jump target at 3");
    assert!(targets[0], "JumpIfFalse target at 0");
    assert!(!targets[1]);
    assert!(!targets[2]);
}

// ── dest_reg ────────────────────────────────────────────────────────

#[test]
fn dest_reg_for_writes() {
    assert_eq!(dest_reg(abx(OpCode::LoadConst, 3, 0)), Some(3));
    assert_eq!(dest_reg(abc(OpCode::Add, 5, 1, 2)), Some(5));
    assert_eq!(dest_reg(abc(OpCode::Move, 7, 3, 0)), Some(7));
}

#[test]
fn dest_reg_none_for_non_writes() {
    assert_eq!(dest_reg(abx(OpCode::SetGlobal, 1, 5)), None);
    assert_eq!(dest_reg(abx(OpCode::Jump, 0, 10)), None);
    assert_eq!(dest_reg(abx(OpCode::JumpIfFalse, 2, 10)), None);
    assert_eq!(dest_reg(abc(OpCode::Return, 0, 0, 0)), None);
    assert_eq!(dest_reg(abx(OpCode::Print, 1, 0)), None);
}

// ── find_loops ──────────────────────────────────────────────────────

#[test]
fn find_loops_detects_back_edges() {
    let instrs = vec![
        (abc(OpCode::Add, 1, 1, 2), 1),    // 0
        (abx(OpCode::Jump, 0, 0), 1),      // 1 → back-edge to 0
        (abc(OpCode::Return, 0, 0, 0), 1), // 2
    ];
    let loops = find_loops(&instrs);
    assert_eq!(loops, vec![(0, 1)]);
}

#[test]
fn find_loops_ignores_forward_jumps() {
    let instrs = vec![
        (abx(OpCode::Jump, 0, 2), 1), // forward
        (abc(OpCode::Add, 1, 1, 2), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let loops = find_loops(&instrs);
    assert!(loops.is_empty());
}
