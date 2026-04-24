//! Bytecode peephole optimizer.
//!
//! Runs after compilation of each function (and the top-level script) to
//! eliminate redundant instructions.  All passes operate on a paired
//! `Vec<(u32, u32)>` of (instruction_word, line_number) so that moving or
//! removing instructions automatically preserves source-map correspondence.

use akron::opcode::instruction::*;
use akron::opcode::OpCode;
use std::collections::{BTreeMap, HashMap, HashSet};

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
///
/// Multiple backward jumps to the same target (e.g. `continue` + the real
/// back-edge) are collapsed: only the **furthest** back-edge is kept, as it
/// defines the actual loop boundary.  Earlier backward jumps to the same
/// target are `continue` statements and must not be treated as separate loops.
fn find_loops(instrs: &[(u32, u32)]) -> Vec<(usize, usize)> {
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
fn find_hoistable_consts(instrs: &[(u32, u32)], start: usize, back_edge: usize) -> Vec<usize> {
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

// ── Pass 3: Register Promotion for Loop Globals ─────────────────────────

/// True if the opcode can execute arbitrary code (function calls, method
/// dispatch, ZK prove) and therefore could modify globals as a side effect.
fn can_call(op: u8) -> bool {
    matches!(
        OpCode::from_u8(op),
        Some(OpCode::Call | OpCode::MethodCall | OpCode::Prove)
    )
}

/// Promote global variables accessed inside call-free loops to dedicated
/// local registers.  GET_GLOBAL/SET_GLOBAL inside the loop become cheap
/// Move instructions; a single GET_GLOBAL before the loop and SET_GLOBAL
/// at each exit point keeps the global in sync.
///
/// Rebuilds the instruction stream, allocating new registers via
/// `max_slots`.
fn register_promotion(instrs: Vec<(u32, u32)>, max_slots: &mut u16) -> Vec<(u32, u32)> {
    let loops = find_loops(&instrs);
    if loops.is_empty() {
        return instrs;
    }

    // Only process innermost loops: skip any loop whose body contains
    // another loop's back-edge.  This avoids conflicts where nested loops
    // both try to promote the same global variable.
    let innermost: Vec<(usize, usize)> = loops
        .iter()
        .filter(|&&(start, back_edge)| !loops.iter().any(|&(s, be)| s > start && be < back_edge))
        .copied()
        .collect();

    struct Promotion {
        loop_start: usize,
        exit_point: usize, // back_edge + 1
        global_idx: u16,
        promoted_reg: u8,
        gets: Vec<usize>,
        sets: Vec<usize>,
    }

    let mut promotions: Vec<Promotion> = Vec::new();

    for &(start, back_edge) in &innermost {
        // Safety: skip loops containing calls.
        let has_call = (start..=back_edge).any(|i| can_call(decode_opcode(instrs[i].0)));
        if has_call {
            continue;
        }

        // Collect global accesses: idx → (get_positions, set_positions)
        let mut globals: HashMap<u16, (Vec<usize>, Vec<usize>)> = HashMap::new();
        for (pos, &(word, _)) in instrs.iter().enumerate().take(back_edge + 1).skip(start) {
            let op = decode_opcode(word);
            let idx = decode_bx(word);
            match OpCode::from_u8(op) {
                Some(OpCode::GetGlobal) => globals.entry(idx).or_default().0.push(pos),
                Some(OpCode::SetGlobal) => globals.entry(idx).or_default().1.push(pos),
                _ => {}
            }
        }

        let exit_point = back_edge + 1;

        for (idx, (gets, sets)) in globals {
            if gets.is_empty() && sets.is_empty() {
                continue;
            }
            if *max_slots >= 255 {
                break; // register space exhausted
            }
            let promoted_reg = *max_slots as u8;
            *max_slots += 1;
            promotions.push(Promotion {
                loop_start: start,
                exit_point,
                global_idx: idx,
                promoted_reg,
                gets,
                sets,
            });
        }
    }

    if promotions.is_empty() {
        return instrs;
    }

    // ── Build the rewrite plan ──────────────────────────────────────────

    // hoist_before[pos]: emit before pos, jumps to pos skip past these
    let mut hoist_before: BTreeMap<usize, Vec<(u32, u32)>> = BTreeMap::new();
    // intercept[pos]: emit before pos, jumps to pos land on first of these
    let mut intercept: BTreeMap<usize, Vec<(u32, u32)>> = BTreeMap::new();
    // replace[pos]: emit this instead of the original instruction
    let mut replace: HashMap<usize, (u32, u32)> = HashMap::new();

    for p in &promotions {
        let line = instrs[p.loop_start].1;

        // Pre-loop: load global into promoted register
        hoist_before.entry(p.loop_start).or_default().push((
            encode_abx(OpCode::GetGlobal.as_u8(), p.promoted_reg, p.global_idx),
            line,
        ));

        // Post-loop exit: write promoted register back to global — only if
        // the loop actually WRITES to this global.  Read-only globals don't
        // need write-back and may be immutable (`let`).
        if !p.sets.is_empty() && p.exit_point < instrs.len() {
            intercept.entry(p.exit_point).or_default().push((
                encode_abx(OpCode::SetGlobal.as_u8(), p.promoted_reg, p.global_idx),
                line,
            ));
        }

        // In-loop: replace GET_GLOBAL R, idx → Move R, promoted_reg
        for &pos in &p.gets {
            let dest = decode_a(instrs[pos].0);
            replace.insert(
                pos,
                (
                    encode_abc(OpCode::Move.as_u8(), dest, p.promoted_reg, 0),
                    instrs[pos].1,
                ),
            );
        }

        // In-loop: replace SET_GLOBAL R, idx → Move promoted_reg, R
        for &pos in &p.sets {
            let src = decode_a(instrs[pos].0);
            replace.insert(
                pos,
                (
                    encode_abc(OpCode::Move.as_u8(), p.promoted_reg, src, 0),
                    instrs[pos].1,
                ),
            );
        }
    }

    // ── Build new instruction stream ────────────────────────────────────

    let old_len = instrs.len();
    let mut new_instrs = Vec::with_capacity(old_len + promotions.len() * 2);
    let mut old_to_new = vec![0usize; old_len + 1];

    for (old_idx, &instr) in instrs.iter().enumerate() {
        let has_intercept = intercept.contains_key(&old_idx);

        // intercept: jumps to old_idx land on the first interceptor
        if has_intercept {
            old_to_new[old_idx] = new_instrs.len();
            for &ins in &intercept[&old_idx] {
                new_instrs.push(ins);
            }
        }

        // hoist_before: jumps to old_idx skip past these
        if let Some(hoisted) = hoist_before.get(&old_idx) {
            for &ins in hoisted {
                new_instrs.push(ins);
            }
        }

        // Map old_idx (unless already mapped by intercept)
        if !has_intercept {
            old_to_new[old_idx] = new_instrs.len();
        }

        // Emit original or replacement
        if let Some(&repl) = replace.get(&old_idx) {
            new_instrs.push(repl);
        } else {
            new_instrs.push(instr);
        }
    }
    old_to_new[old_len] = new_instrs.len();

    remap_jumps(&mut new_instrs, &old_to_new);
    new_instrs
}

// ── Public API ──────────────────────────────────────────────────────────

/// Run all optimization passes on the bytecode + line info pair.
/// `max_slots` may be bumped if register promotion allocates new registers.
/// Returns the optimized (bytecode, line_info).
pub fn optimize(
    bytecode: Vec<u32>,
    line_info: Vec<u32>,
    max_slots: &mut u16,
) -> (Vec<u32>, Vec<u32>) {
    debug_assert_eq!(bytecode.len(), line_info.len());

    let mut instrs: Vec<(u32, u32)> = bytecode.into_iter().zip(line_info).collect();

    // Pass 1: redundant load elimination (in-place, no length change)
    redundant_load_elim(&mut instrs);

    // Pass 2: constant hoisting — move loop-invariant LoadConst before loop
    instrs = constant_hoisting(instrs);

    // Pass 3: register promotion — keep loop globals in registers
    instrs = register_promotion(instrs, max_slots);

    // Re-run Pass 2: after promotion, some LoadConst registers may no longer
    // conflict (the GET_GLOBAL that wrote the same register is now a Move to
    // a different register).
    instrs = constant_hoisting(instrs);

    instrs.into_iter().unzip()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use akron::opcode::OpCode;

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
}
