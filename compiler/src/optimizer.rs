//! Bytecode peephole optimizer.
//!
//! Runs after compilation of each function (and the top-level script) to
//! eliminate redundant instructions.  All passes operate on a paired
//! `Vec<(u32, u32)>` of (instruction_word, line_number) so that moving or
//! removing instructions automatically preserves source-map correspondence.

use std::collections::{BTreeMap, HashSet};
use vm::opcode::instruction::*;
use vm::opcode::OpCode;

// ── Instruction helpers ─────────────────────────────────────────────────

/// Opcodes whose Bx field is an absolute jump target.
fn is_jump_opcode(op: u8) -> bool {
    matches!(
        OpCode::from_u8(op),
        Some(OpCode::Jump | OpCode::JumpIfFalse | OpCode::ForIter)
    )
}

/// Build the set of instruction indices that are jump targets.
/// Any instruction at one of these addresses may be entered from a non-linear
/// path and therefore acts as a **barrier** for dataflow assumptions.
fn jump_targets(instrs: &[(u32, u32)]) -> Vec<bool> {
    let mut targets = vec![false; instrs.len()];
    for &(word, _) in instrs {
        let op = decode_opcode(word);
        if is_jump_opcode(op) {
            let target = decode_bx(word) as usize;
            if target < targets.len() {
                targets[target] = true;
            }
        }
    }
    targets
}

/// Returns the destination register for an instruction, or `None` if it
/// does not write to any register.
fn dest_reg(word: u32) -> Option<u8> {
    let op = decode_opcode(word);
    match OpCode::from_u8(op) {
        Some(
            OpCode::SetGlobal
            | OpCode::DefGlobalVar
            | OpCode::DefGlobalLet
            | OpCode::Print
            | OpCode::Jump
            | OpCode::JumpIfFalse
            | OpCode::SetUpvalue
            | OpCode::CloseUpvalue
            | OpCode::Return
            | OpCode::SetIndex
            | OpCode::Nop,
        ) => None,
        Some(_) => Some(decode_a(word)),
        None => None,
    }
}

/// Find loops as (start, back_edge_pos) pairs by detecting backward Jump edges.
fn find_loops(instrs: &[(u32, u32)]) -> Vec<(usize, usize)> {
    let mut loops = Vec::new();
    for (i, &(word, _)) in instrs.iter().enumerate() {
        let op = decode_opcode(word);
        if op == OpCode::Jump.as_u8() {
            let target = decode_bx(word) as usize;
            if target < i {
                loops.push((target, i));
            }
        }
    }
    loops
}

/// Rewrite all jump targets using an old→new address map.
fn remap_jumps(instrs: &mut [(u32, u32)], old_to_new: &[usize]) {
    for (word, _) in instrs.iter_mut() {
        let op = decode_opcode(*word);
        if is_jump_opcode(op) {
            let old_target = decode_bx(*word) as usize;
            if old_target < old_to_new.len() {
                let new_target = old_to_new[old_target];
                let a = decode_a(*word);
                *word = encode_abx(op, a, new_target as u16);
            }
        }
    }
}

// ── Pass 1: Redundant Load Elimination ──────────────────────────────────

/// Replace `SetGlobal Ra, idx; GetGlobal Rb, idx` → `SetGlobal Ra, idx; Move Rb, Ra`
/// when there is no jump target on the GetGlobal (i.e. it cannot be reached
/// from another path that might have a different value for the global).
fn redundant_load_elim(instrs: &mut [(u32, u32)]) {
    if instrs.len() < 2 {
        return;
    }
    let targets = jump_targets(instrs);

    for i in 0..instrs.len() - 1 {
        let (w0, _) = instrs[i];
        let (w1, _) = instrs[i + 1];

        let op0 = decode_opcode(w0);
        let op1 = decode_opcode(w1);

        if op0 != OpCode::SetGlobal.as_u8() || op1 != OpCode::GetGlobal.as_u8() {
            continue;
        }

        // Same global index?
        let idx0 = decode_bx(w0);
        let idx1 = decode_bx(w1);
        if idx0 != idx1 {
            continue;
        }

        // Jump target barrier?
        if targets[i + 1] {
            continue;
        }

        // Replace GetGlobal Rb, idx → Move Rb, Ra
        let ra = decode_a(w0); // register that was written to the global
        let rb = decode_a(w1); // register that wants the global's value
        instrs[i + 1].0 = encode_abc(OpCode::Move.as_u8(), rb, ra, 0);
    }
}

// ── Pass 2: Constant Hoisting (LICM) ───────────────────────────────────

/// Find `LoadConst` instructions inside a loop whose destination register is
/// not written by any other instruction in the loop body.  These are safe to
/// hoist before the loop without register renaming.
fn find_hoistable_consts(
    instrs: &[(u32, u32)],
    start: usize,
    back_edge: usize,
) -> Vec<usize> {
    let mut result = Vec::new();
    for pos in start..=back_edge {
        let op = decode_opcode(instrs[pos].0);
        if op != OpCode::LoadConst.as_u8() {
            continue;
        }
        let reg = decode_a(instrs[pos].0);

        // Check no other instruction in the loop writes to `reg`.
        let conflict = (start..=back_edge)
            .any(|other| other != pos && dest_reg(instrs[other].0) == Some(reg));

        if !conflict {
            result.push(pos);
        }
    }
    result
}

/// Move loop-invariant `LoadConst` instructions to before their enclosing
/// loop.  Rebuilds the instruction stream and remaps all jump targets.
fn constant_hoisting(instrs: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let loops = find_loops(&instrs);
    if loops.is_empty() {
        return instrs;
    }

    // Collect hoist plan: loop_start → [positions to hoist]
    let mut to_hoist: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut skip: HashSet<usize> = HashSet::new();

    for &(start, back_edge) in &loops {
        let hoistable = find_hoistable_consts(&instrs, start, back_edge);
        if !hoistable.is_empty() {
            for &pos in &hoistable {
                skip.insert(pos);
            }
            to_hoist.insert(start, hoistable);
        }
    }

    if to_hoist.is_empty() {
        return instrs;
    }

    // Build new stream + address map.
    // old_to_new[i] = new address of instruction that was at old index i.
    // For skipped instructions, it points to the next non-skipped instruction.
    let old_len = instrs.len();
    let mut new_instrs = Vec::with_capacity(old_len + skip.len());
    let mut old_to_new = vec![0usize; old_len + 1]; // +1 for past-the-end

    for (old_idx, &instr) in instrs.iter().enumerate() {
        // Insert hoisted instructions just before the loop start.
        if let Some(positions) = to_hoist.get(&old_idx) {
            for &pos in positions {
                new_instrs.push(instrs[pos]);
            }
        }

        old_to_new[old_idx] = new_instrs.len();

        if !skip.contains(&old_idx) {
            new_instrs.push(instr);
        }
    }
    old_to_new[old_len] = new_instrs.len();

    // Remap all jump targets.
    remap_jumps(&mut new_instrs, &old_to_new);

    new_instrs
}

// ── Public API ──────────────────────────────────────────────────────────

/// Run all optimization passes on the bytecode + line info pair.
/// Returns the optimized (bytecode, line_info).
pub fn optimize(bytecode: Vec<u32>, line_info: Vec<u32>) -> (Vec<u32>, Vec<u32>) {
    debug_assert_eq!(bytecode.len(), line_info.len());

    let mut instrs: Vec<(u32, u32)> = bytecode.into_iter().zip(line_info).collect();

    // Pass 1: redundant load elimination (in-place, no length change)
    redundant_load_elim(&mut instrs);

    // Pass 2: constant hoisting — move loop-invariant LoadConst before loop
    instrs = constant_hoisting(instrs);

    instrs.into_iter().unzip()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vm::opcode::OpCode;

    /// Helper: build an ABx instruction
    fn abx(op: OpCode, a: u8, bx: u16) -> u32 {
        encode_abx(op.as_u8(), a, bx)
    }

    /// Helper: build an ABC instruction
    fn abc(op: OpCode, a: u8, b: u8, c: u8) -> u32 {
        encode_abc(op.as_u8(), a, b, c)
    }

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
            (abc(OpCode::Add, 1, 1, 2), 1),   // 0
            (abx(OpCode::Jump, 0, 0), 1),      // 1 → back-edge to 0
            (abc(OpCode::Return, 0, 0, 0), 1), // 2
        ];
        let loops = find_loops(&instrs);
        assert_eq!(loops, vec![(0, 1)]);
    }

    #[test]
    fn find_loops_ignores_forward_jumps() {
        let instrs = vec![
            (abx(OpCode::Jump, 0, 2), 1),      // forward
            (abc(OpCode::Add, 1, 1, 2), 1),
            (abc(OpCode::Return, 0, 0, 0), 1),
        ];
        let loops = find_loops(&instrs);
        assert!(loops.is_empty());
    }

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

    // ── Pass 2: constant_hoisting ───────────────────────────────────────

    #[test]
    fn hoist_simple_load_const() {
        // Minimal loop: LoadConst R3, K[0]; Add R1, R1, R3; Jump → 0
        // R3 is only written by LoadConst → hoistable.
        let instrs = vec![
            (abx(OpCode::LoadConst, 3, 0), 1), // 0: LoadConst R3
            (abc(OpCode::Add, 1, 1, 3), 1),    // 1: Add R1, R1, R3
            (abx(OpCode::Jump, 0, 0), 1),      // 2: Jump → 0 (back-edge)
        ];
        let result = constant_hoisting(instrs);
        // LoadConst should now be at position 0 (before loop start),
        // followed by Add at 1, Jump at 2.  Jump target remapped.
        assert_eq!(result.len(), 3); // same count (1 removed + 1 inserted)
        assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8());
        assert_eq!(decode_a(result[0].0), 3);
        assert_eq!(decode_opcode(result[1].0), OpCode::Add.as_u8());
        assert_eq!(decode_opcode(result[2].0), OpCode::Jump.as_u8());
        // The back-edge should now point to the Add (index 1), not the
        // hoisted LoadConst (index 0).
        assert_eq!(decode_bx(result[2].0), 1);
    }

    #[test]
    fn hoist_does_not_move_conflicting_register() {
        // Loop: LoadConst R2, K[0]; Add R1, R1, R2; Move R2, R1; Jump → 0
        // R2 is written by both LoadConst and Move → NOT hoistable.
        let instrs = vec![
            (abx(OpCode::LoadConst, 2, 0), 1), // 0: LoadConst R2
            (abc(OpCode::Add, 1, 1, 2), 1),    // 1: Add R1, R1, R2
            (abc(OpCode::Move, 2, 1, 0), 1),   // 2: Move R2, R1 (conflict!)
            (abx(OpCode::Jump, 0, 0), 1),      // 3: Jump → 0
        ];
        let result = constant_hoisting(instrs);
        // Should be unchanged (no hoisting possible).
        assert_eq!(result.len(), 4);
        assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8());
        assert_eq!(decode_bx(result[3].0), 0); // jump target unchanged
    }

    #[test]
    fn hoist_remaps_forward_jumps() {
        // Pre-loop setup, then a loop with a hoistable LoadConst + forward jump.
        //
        //  0: LoadConst R0, K[0]  (pre-loop setup)
        //  1: LoadConst R3, K[1]  (loop body — hoistable, R3 unique)
        //  2: Add R1, R1, R3
        //  3: JumpIfFalse R1, 5   (forward jump to after loop)
        //  4: Jump → 1            (back-edge)
        //  5: Return R0
        let instrs = vec![
            (abx(OpCode::LoadConst, 0, 0), 1),  // 0
            (abx(OpCode::LoadConst, 3, 1), 1),  // 1: hoistable
            (abc(OpCode::Add, 1, 1, 3), 2),     // 2
            (abx(OpCode::JumpIfFalse, 1, 5), 2),// 3: forward jump → 5
            (abx(OpCode::Jump, 0, 1), 2),       // 4: back-edge → 1
            (abc(OpCode::Return, 0, 0, 0), 3),  // 5
        ];
        let result = constant_hoisting(instrs);
        // Hoisted LoadConst goes before loop start (old 1).
        // Old 1 is removed (skipped).
        // Result: [LoadConst R0 K0, LoadConst R3 K1, Add, JumpIfFalse, Jump, Return]
        assert_eq!(result.len(), 6); // same count
        assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8()); // setup
        assert_eq!(decode_a(result[0].0), 0);
        assert_eq!(decode_opcode(result[1].0), OpCode::LoadConst.as_u8()); // hoisted
        assert_eq!(decode_a(result[1].0), 3);
        assert_eq!(decode_opcode(result[2].0), OpCode::Add.as_u8());
        // JumpIfFalse target: old 5 → new 5 (past Return didn't move)
        assert_eq!(decode_bx(result[3].0), 5);
        // Back-edge: old 1 → new 2 (the Add, which is the new loop start)
        assert_eq!(decode_bx(result[4].0), 2);
    }

    #[test]
    fn hoist_multiple_consts_from_same_loop() {
        // Loop with two hoistable LoadConsts (R3, R4 — neither written elsewhere).
        //  0: LoadConst R3, K[0]   (hoistable)
        //  1: LoadConst R4, K[1]   (hoistable)
        //  2: Add R1, R3, R4
        //  3: Jump → 0
        let instrs = vec![
            (abx(OpCode::LoadConst, 3, 0), 1),
            (abx(OpCode::LoadConst, 4, 1), 1),
            (abc(OpCode::Add, 1, 3, 4), 1),
            (abx(OpCode::Jump, 0, 0), 1),
        ];
        let result = constant_hoisting(instrs);
        // Both hoisted before the loop.  Loop body is just Add + Jump.
        assert_eq!(result.len(), 4);
        // Positions 0,1 = hoisted LoadConsts; 2 = Add; 3 = Jump
        assert_eq!(decode_opcode(result[0].0), OpCode::LoadConst.as_u8());
        assert_eq!(decode_a(result[0].0), 3);
        assert_eq!(decode_opcode(result[1].0), OpCode::LoadConst.as_u8());
        assert_eq!(decode_a(result[1].0), 4);
        assert_eq!(decode_opcode(result[2].0), OpCode::Add.as_u8());
        // Back-edge should target position 2 (the Add).
        assert_eq!(decode_bx(result[3].0), 2);
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
            (abx(OpCode::LoadConst, 3, 0), 42), // hoistable
            (abc(OpCode::Add, 1, 1, 3), 43),
            (abx(OpCode::Jump, 0, 0), 44),
        ];
        let result = constant_hoisting(instrs);
        assert_eq!(result[0].1, 42); // hoisted instruction keeps its line
        assert_eq!(result[1].1, 43);
        assert_eq!(result[2].1, 44);
    }

    // ── optimize (integration) ──────────────────────────────────────────

    #[test]
    fn optimize_returns_split_vecs() {
        let bc = vec![
            abx(OpCode::SetGlobal, 1, 5),
            abx(OpCode::GetGlobal, 2, 5),
        ];
        let li = vec![10, 11];
        let (opt_bc, opt_li) = optimize(bc, li);
        assert_eq!(opt_bc.len(), 2);
        assert_eq!(opt_li.len(), 2);
        assert_eq!(decode_opcode(opt_bc[1]), OpCode::Move.as_u8());
        assert_eq!(opt_li[1], 11);
    }

    #[test]
    fn optimize_both_passes() {
        // SetGlobal/GetGlobal pair (Pass 1) + hoistable LoadConst in loop (Pass 2).
        //
        //  0: SetGlobal R1, 5
        //  1: GetGlobal R2, 5        → Pass 1: Move R2, R1
        //  2: LoadConst R3, K[0]     → hoistable (loop body)
        //  3: Add R1, R1, R3
        //  4: Jump → 2               → back-edge
        //
        // After Pass 1: instruction 1 becomes Move.
        // After Pass 2: LoadConst R3 hoisted before loop.
        let bc = vec![
            abx(OpCode::SetGlobal, 1, 5),   // 0
            abx(OpCode::GetGlobal, 2, 5),   // 1
            abx(OpCode::LoadConst, 3, 0),   // 2: loop start, hoistable
            abc(OpCode::Add, 1, 1, 3),      // 3
            abx(OpCode::Jump, 0, 2),        // 4: back-edge
        ];
        let li = vec![1, 1, 2, 2, 2];
        let (opt_bc, opt_li) = optimize(bc, li);

        // Pass 1: index 1 → Move
        assert_eq!(decode_opcode(opt_bc[1]), OpCode::Move.as_u8());
        // Pass 2: LoadConst hoisted before loop; loop body = Add + Jump
        // Result: [SetGlobal, Move, LoadConst(hoisted), Add, Jump]
        assert_eq!(opt_bc.len(), 5);
        assert_eq!(decode_opcode(opt_bc[2]), OpCode::LoadConst.as_u8());
        assert_eq!(decode_opcode(opt_bc[3]), OpCode::Add.as_u8());
        // Back-edge targets the Add now (not the LoadConst).
        assert_eq!(decode_bx(opt_bc[4]), 3);
        assert_eq!(opt_li.len(), 5);
    }
}
