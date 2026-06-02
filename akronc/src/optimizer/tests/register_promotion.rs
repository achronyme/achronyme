use super::helpers::*;

// ── Pass 3: register_promotion ──────────────────────────────────────

#[test]
fn promo_replaces_get_set_global_with_move() {
    // Loop: GetGlobal R1, 5; Add R1, R1, R2; SetGlobal R1, 5; Jump → 0
    // Expected: GET_GLOBAL R_prom (before); Move R1, R_prom; Add; Move R_prom, R1; Jump;
    //           SET_GLOBAL R_prom (at exit)
    let mut max_slots: u16 = 4; // R0-R3 in use
    let instrs = vec![
        (abx(OpCode::GetGlobal, 1, 5), 1), // 0
        (abc(OpCode::Add, 1, 1, 2), 1),    // 1
        (abx(OpCode::SetGlobal, 1, 5), 1), // 2
        (abx(OpCode::Jump, 0, 0), 1),      // 3: back-edge
        (abc(OpCode::Return, 0, 0, 0), 1), // 4: exit point
    ];
    let result = register_promotion(instrs, &mut max_slots);

    assert_eq!(max_slots, 5); // allocated R4 for promoted global

    // Pre-loop: GET_GLOBAL R4, 5
    assert_eq!(decode_opcode(result[0].0), OpCode::GetGlobal.as_u8());
    assert_eq!(decode_a(result[0].0), 4); // promoted reg
    assert_eq!(decode_bx(result[0].0), 5); // global idx

    // Loop body: Move R1, R4; Add R1, R1, R2; Move R4, R1; Jump
    assert_eq!(decode_opcode(result[1].0), OpCode::Move.as_u8());
    assert_eq!(decode_a(result[1].0), 1);
    assert_eq!(decode_b(result[1].0), 4);

    assert_eq!(decode_opcode(result[2].0), OpCode::Add.as_u8());

    assert_eq!(decode_opcode(result[3].0), OpCode::Move.as_u8());
    assert_eq!(decode_a(result[3].0), 4);
    assert_eq!(decode_b(result[3].0), 1);

    // Back-edge: Jump → 1 (the Move, not the hoisted GET_GLOBAL)
    assert_eq!(decode_opcode(result[4].0), OpCode::Jump.as_u8());
    assert_eq!(decode_bx(result[4].0), 1);

    // Exit: SET_GLOBAL R4, 5 (intercepted at old exit point)
    assert_eq!(decode_opcode(result[5].0), OpCode::SetGlobal.as_u8());
    assert_eq!(decode_a(result[5].0), 4);
    assert_eq!(decode_bx(result[5].0), 5);

    // Original return follows
    assert_eq!(decode_opcode(result[6].0), OpCode::Return.as_u8());
}

#[test]
fn promo_skips_loops_with_calls() {
    // Loop with a Call → no promotion
    let mut max_slots: u16 = 4;
    let instrs = vec![
        (abx(OpCode::GetGlobal, 1, 5), 1),
        (abc(OpCode::Call, 1, 1, 0), 1), // Call!
        (abx(OpCode::SetGlobal, 1, 5), 1),
        (abx(OpCode::Jump, 0, 0), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let result = register_promotion(instrs.clone(), &mut max_slots);
    assert_eq!(max_slots, 4); // no new register allocated
    assert_eq!(result, instrs); // unchanged
}

#[test]
fn promo_break_jump_lands_on_set_global() {
    // Loop with a break that jumps to exit.  The exit should have SET_GLOBAL.
    //
    // 0: GetGlobal R1, 5        (loop start)
    // 1: JumpIfFalse R1, 4      (break → exit at 4)
    // 2: SetGlobal R1, 5
    // 3: Jump → 0               (back-edge)
    // 4: Return R0              (exit point)
    let mut max_slots: u16 = 4;
    let instrs = vec![
        (abx(OpCode::GetGlobal, 1, 5), 1),
        (abx(OpCode::JumpIfFalse, 1, 4), 1),
        (abx(OpCode::SetGlobal, 1, 5), 1),
        (abx(OpCode::Jump, 0, 0), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let result = register_promotion(instrs, &mut max_slots);

    // The JumpIfFalse originally targeted 4 (Return).
    // After promotion, it should target the intercepted SET_GLOBAL.
    // Find the JumpIfFalse in the result:
    let jif_pos = result
        .iter()
        .position(|&(w, _)| decode_opcode(w) == OpCode::JumpIfFalse.as_u8())
        .unwrap();
    let jif_target = decode_bx(result[jif_pos].0) as usize;

    // The instruction at that target should be SET_GLOBAL (the interceptor).
    assert_eq!(
        decode_opcode(result[jif_target].0),
        OpCode::SetGlobal.as_u8(),
        "break jump should land on the write-back SET_GLOBAL"
    );
    assert_eq!(decode_a(result[jif_target].0), 4); // promoted reg
}

#[test]
fn promo_no_loops_returns_unchanged() {
    let mut max_slots: u16 = 4;
    let instrs = vec![
        (abx(OpCode::GetGlobal, 1, 5), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let result = register_promotion(instrs.clone(), &mut max_slots);
    assert_eq!(result, instrs);
    assert_eq!(max_slots, 4);
}

#[test]
fn promo_multiple_globals_same_loop() {
    // Loop accessing two globals (idx 5 and 7)
    let mut max_slots: u16 = 4;
    let instrs = vec![
        (abx(OpCode::GetGlobal, 1, 5), 1),
        (abx(OpCode::GetGlobal, 2, 7), 1),
        (abc(OpCode::Add, 1, 1, 2), 1),
        (abx(OpCode::SetGlobal, 1, 5), 1),
        (abx(OpCode::Jump, 0, 0), 1),
        (abc(OpCode::Return, 0, 0, 0), 1),
    ];
    let result = register_promotion(instrs, &mut max_slots);
    assert_eq!(max_slots, 6); // two new registers (R4, R5)

    // Count GET_GLOBAL before loop (should be 2 hoisted)
    let pre_loop_gets: Vec<_> = result
        .iter()
        .take_while(|&&(w, _)| {
            let op = decode_opcode(w);
            op == OpCode::GetGlobal.as_u8() || op == OpCode::Move.as_u8()
        })
        .filter(|&&(w, _)| decode_opcode(w) == OpCode::GetGlobal.as_u8())
        .collect();
    assert_eq!(pre_loop_gets.len(), 2, "two globals hoisted before loop");
}

#[test]
fn promo_read_only_global_no_writeback() {
    // Loop that only reads a global (no SET_GLOBAL) — no write-back at exit.
    // This is critical for immutable globals defined with `let`.
    let mut max_slots: u16 = 4;
    let instrs = vec![
        (abx(OpCode::GetGlobal, 1, 5), 1), // 0: read-only
        (abc(OpCode::Add, 2, 1, 1), 1),    // 1
        (abx(OpCode::Jump, 0, 0), 1),      // 2: back-edge
        (abc(OpCode::Return, 0, 0, 0), 1), // 3: exit
    ];
    let result = register_promotion(instrs, &mut max_slots);

    // Should still promote (save hash lookups on read)
    assert_eq!(max_slots, 5);

    // Pre-loop GET_GLOBAL should exist
    assert_eq!(decode_opcode(result[0].0), OpCode::GetGlobal.as_u8());
    assert_eq!(decode_a(result[0].0), 4); // promoted reg

    // But NO SET_GLOBAL should exist at exit
    for &(w, _) in &result {
        if decode_opcode(w) == OpCode::SetGlobal.as_u8() {
            panic!("read-only global must not have SET_GLOBAL at exit");
        }
    }
}
