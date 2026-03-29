//! Bytecode peephole optimizer.
//!
//! Runs after compilation of each function (and the top-level script) to
//! eliminate redundant instructions.  All passes operate on a paired
//! `Vec<(u32, u32)>` of (instruction_word, line_number) so that moving or
//! removing instructions automatically preserves source-map correspondence.

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

// ── Public API ──────────────────────────────────────────────────────────

/// Run all optimization passes on the bytecode + line info pair.
/// Returns the optimized (bytecode, line_info).
pub fn optimize(bytecode: Vec<u32>, line_info: Vec<u32>) -> (Vec<u32>, Vec<u32>) {
    debug_assert_eq!(bytecode.len(), line_info.len());

    let mut instrs: Vec<(u32, u32)> = bytecode.into_iter().zip(line_info).collect();

    // Pass 1: redundant load elimination (in-place, no length change)
    redundant_load_elim(&mut instrs);

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

    // ── Pass 1: redundant_load_elim ─────────────────────────────────────

    #[test]
    fn rle_replaces_set_get_same_global() {
        // SetGlobal R1, 5 ; GetGlobal R2, 5 → SetGlobal R1, 5 ; Move R2, R1
        let mut instrs = vec![
            (abx(OpCode::SetGlobal, 1, 5), 10),
            (abx(OpCode::GetGlobal, 2, 5), 10),
        ];
        redundant_load_elim(&mut instrs);

        let op1 = decode_opcode(instrs[1].0);
        assert_eq!(op1, OpCode::Move.as_u8());
        assert_eq!(decode_a(instrs[1].0), 2); // dest = R2
        assert_eq!(decode_b(instrs[1].0), 1); // src = R1
    }

    #[test]
    fn rle_does_not_replace_different_globals() {
        let mut instrs = vec![
            (abx(OpCode::SetGlobal, 1, 5), 10),
            (abx(OpCode::GetGlobal, 2, 6), 10), // different index
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
        // Some branch jumps to instruction 1 (the GetGlobal), so it's a barrier.
        let mut instrs = vec![
            (abx(OpCode::SetGlobal, 1, 5), 10),
            (abx(OpCode::GetGlobal, 2, 5), 10), // jump target → barrier
            (abx(OpCode::JumpIfFalse, 0, 1), 10), // jumps to index 1
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
        assert_eq!(instrs[1].1, 43, "line info should be preserved");
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

        // First pair replaced
        assert_eq!(decode_opcode(instrs[1].0), OpCode::Move.as_u8());
        // Second pair replaced
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
}
