use super::helpers::{find_loops, remap_jumps};
use akron::opcode::instruction::*;
use akron::opcode::OpCode;
use std::collections::{BTreeMap, HashMap};

/// True if the opcode can execute arbitrary code (function calls, method
/// dispatch, ZK prove) and therefore could modify globals as a side effect.
pub(super) fn can_call(op: u8) -> bool {
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
pub(super) fn register_promotion(instrs: Vec<(u32, u32)>, max_slots: &mut u16) -> Vec<(u32, u32)> {
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
