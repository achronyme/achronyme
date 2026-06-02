//! Bytecode peephole optimizer.
//!
//! Runs after compilation of each function (and the top-level script) to
//! eliminate redundant instructions.  All passes operate on a paired
//! `Vec<(u32, u32)>` of (instruction_word, line_number) so that moving or
//! removing instructions automatically preserves source-map correspondence.

mod constant_hoist;
mod helpers;
mod redundant_load;
mod register_promotion;

#[cfg(test)]
mod tests;

use constant_hoist::constant_hoisting;
use redundant_load::redundant_load_elim;
use register_promotion::register_promotion;

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
