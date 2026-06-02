use super::helpers::*;

// ── optimize (integration) ──────────────────────────────────────────

#[test]
fn optimize_returns_split_vecs() {
    let bc = vec![abx(OpCode::SetGlobal, 1, 5), abx(OpCode::GetGlobal, 2, 5)];
    let li = vec![10, 11];
    let mut ms: u16 = 4;
    let (opt_bc, opt_li) = optimize(bc, li, &mut ms);
    assert_eq!(opt_bc.len(), 2);
    assert_eq!(opt_li.len(), 2);
    assert_eq!(decode_opcode(opt_bc[1]), OpCode::Move.as_u8());
    assert_eq!(opt_li[1], 11);
}

#[test]
fn optimize_all_three_passes() {
    // Simulate the benchmark pattern:
    //
    //  0: GetGlobal R1, 5         (loop start)
    //  1: LoadConst R2, K[0]      (constant 1)
    //  2: Add R1, R1, R2
    //  3: SetGlobal R1, 5
    //  4: GetGlobal R2, 5         → Pass 1: Move R2, R1
    //  5: LoadConst R3, K[1]      (constant 10M)
    //  6: Gt R2, R2, R3
    //  7: JumpIfFalse R2, 9       → after loop
    //  8: Jump → 0                (back-edge)
    //  9: Return R0
    let bc = vec![
        abx(OpCode::GetGlobal, 1, 5),   // 0
        abx(OpCode::LoadConst, 2, 0),   // 1
        abc(OpCode::Add, 1, 1, 2),      // 2
        abx(OpCode::SetGlobal, 1, 5),   // 3
        abx(OpCode::GetGlobal, 2, 5),   // 4 → RLE → Move
        abx(OpCode::LoadConst, 3, 1),   // 5
        abc(OpCode::Gt, 2, 2, 3),       // 6
        abx(OpCode::JumpIfFalse, 2, 9), // 7
        abx(OpCode::Jump, 0, 0),        // 8: back-edge
        abc(OpCode::Return, 0, 0, 0),   // 9
    ];
    let li = vec![1; 10];
    let mut ms: u16 = 4;
    let (opt_bc, _opt_li) = optimize(bc, li, &mut ms);

    // After all passes:
    // - No GetGlobal or SetGlobal inside the hot loop
    // - LoadConst R3 hoisted before loop
    // - GetGlobal for promoted reg before loop
    // - SetGlobal for promoted reg at exit (intercepted)

    // Verify: no GetGlobal or SetGlobal between the first back-edge Jump
    // and the instruction it targets (the loop body).
    let back_edge_pos = opt_bc
        .iter()
        .enumerate()
        .rev()
        .find(|&(_, &w)| {
            let op = decode_opcode(w);
            if op != OpCode::Jump.as_u8() {
                return false;
            }
            let target = decode_bx(w) as usize;
            target < opt_bc.len()
        })
        .map(|(i, _)| i);

    if let Some(be) = back_edge_pos {
        let target = decode_bx(opt_bc[be]) as usize;
        for (i, w) in opt_bc.iter().enumerate().take(be).skip(target) {
            let op = decode_opcode(*w);
            assert_ne!(
                op,
                OpCode::GetGlobal.as_u8(),
                "GetGlobal should not be in hot loop body (at {i})"
            );
            assert_ne!(
                op,
                OpCode::SetGlobal.as_u8(),
                "SetGlobal should not be in hot loop body (at {i})"
            );
        }
    }

    // Promoted register was allocated
    assert!(ms > 4, "max_slots should have been bumped");
}
