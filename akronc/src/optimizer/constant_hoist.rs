use super::helpers::{dest_reg, find_loops, remap_jumps};
use akron::opcode::instruction::*;
use akron::opcode::OpCode;
use std::collections::{BTreeMap, HashSet};

// ── Pass 2: Constant Hoisting (LICM) ───────────────────────────────────

/// Find `LoadConst` instructions inside a loop whose destination register is
/// not written by any other instruction in the loop body.  These are safe to
/// hoist before the loop without register renaming.
pub(super) fn find_hoistable_consts(
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
        let conflict =
            (start..=back_edge).any(|other| other != pos && dest_reg(instrs[other].0) == Some(reg));

        if !conflict {
            result.push(pos);
        }
    }
    result
}

/// Move loop-invariant `LoadConst` instructions to before their enclosing
/// loop.  Rebuilds the instruction stream and remaps all jump targets.
pub(super) fn constant_hoisting(instrs: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
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
