use akron::opcode::instruction::*;
use akron::opcode::OpCode;
use std::collections::HashMap;

// ── Instruction helpers ─────────────────────────────────────────────────

/// Opcodes whose Bx field is an absolute jump target.
pub(super) fn is_jump_opcode(op: u8) -> bool {
    matches!(
        OpCode::from_u8(op),
        Some(OpCode::Jump | OpCode::JumpIfFalse | OpCode::ForIter)
    )
}

/// Build the set of instruction indices that are jump targets.
/// Any instruction at one of these addresses may be entered from a non-linear
/// path and therefore acts as a **barrier** for dataflow assumptions.
pub(super) fn jump_targets(instrs: &[(u32, u32)]) -> Vec<bool> {
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
pub(super) fn dest_reg(word: u32) -> Option<u8> {
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
///
/// Multiple backward jumps to the same target (e.g. `continue` + the real
/// back-edge) are collapsed: only the **furthest** back-edge is kept, as it
/// defines the actual loop boundary.  Earlier backward jumps to the same
/// target are `continue` statements and must not be treated as separate loops.
pub(super) fn find_loops(instrs: &[(u32, u32)]) -> Vec<(usize, usize)> {
    let mut loop_map: HashMap<usize, usize> = HashMap::new();
    for (i, &(word, _)) in instrs.iter().enumerate() {
        let op = decode_opcode(word);
        if op == OpCode::Jump.as_u8() {
            let target = decode_bx(word) as usize;
            if target < i {
                let entry = loop_map.entry(target).or_insert(i);
                if i > *entry {
                    *entry = i;
                }
            }
        }
    }
    loop_map.into_iter().collect()
}

/// Rewrite all jump targets using an old→new address map.
pub(super) fn remap_jumps(instrs: &mut [(u32, u32)], old_to_new: &[usize]) {
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
