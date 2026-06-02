use super::helpers::*;

// ── Pass 1: redundant_load_elim ─────────────────────────────────────

#[test]
fn rle_replaces_set_get_same_global() {
    let mut instrs = vec![
        (abx(OpCode::SetGlobal, 1, 5), 10),
        (abx(OpCode::GetGlobal, 2, 5), 10),
    ];
    redundant_load_elim(&mut instrs);

    let op1 = decode_opcode(instrs[1].0);
    assert_eq!(op1, OpCode::Move.as_u8());
    assert_eq!(decode_a(instrs[1].0), 2);
    assert_eq!(decode_b(instrs[1].0), 1);
}

#[test]
fn rle_does_not_replace_different_globals() {
    let mut instrs = vec![
        (abx(OpCode::SetGlobal, 1, 5), 10),
        (abx(OpCode::GetGlobal, 2, 6), 10),
    ];
    redundant_load_elim(&mut instrs);
    assert_eq!(
        decode_opcode(instrs[1].0),
        OpCode::GetGlobal.as_u8(),
        "should not be replaced"
    );
}

#[test]
fn rle_respects_jump_target_barrier() {
    let mut instrs = vec![
        (abx(OpCode::SetGlobal, 1, 5), 10),
        (abx(OpCode::GetGlobal, 2, 5), 10),
        (abx(OpCode::JumpIfFalse, 0, 1), 10),
    ];
    redundant_load_elim(&mut instrs);
    assert_eq!(
        decode_opcode(instrs[1].0),
        OpCode::GetGlobal.as_u8(),
        "barrier: should not be replaced"
    );
}

#[test]
fn rle_preserves_line_info() {
    let mut instrs = vec![
        (abx(OpCode::SetGlobal, 1, 5), 42),
        (abx(OpCode::GetGlobal, 2, 5), 43),
    ];
    redundant_load_elim(&mut instrs);
    assert_eq!(instrs[0].1, 42);
    assert_eq!(instrs[1].1, 43);
}

#[test]
fn rle_handles_multiple_pairs() {
    let mut instrs = vec![
        (abx(OpCode::SetGlobal, 1, 5), 1),
        (abx(OpCode::GetGlobal, 2, 5), 1),
        (abc(OpCode::Add, 3, 2, 4), 2),
        (abx(OpCode::SetGlobal, 3, 7), 3),
        (abx(OpCode::GetGlobal, 5, 7), 3),
    ];
    redundant_load_elim(&mut instrs);
    assert_eq!(decode_opcode(instrs[1].0), OpCode::Move.as_u8());
    assert_eq!(decode_opcode(instrs[4].0), OpCode::Move.as_u8());
    assert_eq!(decode_a(instrs[4].0), 5);
    assert_eq!(decode_b(instrs[4].0), 3);
}

#[test]
fn rle_no_crash_on_empty() {
    let mut instrs: Vec<(u32, u32)> = vec![];
    redundant_load_elim(&mut instrs);
    assert!(instrs.is_empty());
}

#[test]
fn rle_no_crash_on_single_instruction() {
    let mut instrs = vec![(abx(OpCode::SetGlobal, 1, 5), 1)];
    redundant_load_elim(&mut instrs);
    assert_eq!(instrs.len(), 1);
}
