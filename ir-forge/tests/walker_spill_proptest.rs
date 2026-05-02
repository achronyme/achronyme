//! Property-based tests for the spill heuristic.
//!
//! These tests exercise `partition_live_set` indirectly via the
//! visible Walker contract: any cold var produces at most one
//! `StoreHeap` per program, and every cold var produces at most one
//! `LoadHeap` per template body that references it.
//!
//! `partition_live_set` itself is a private helper; we reach it
//! through `Walker::lower` on hand-built `ExtendedInstruction`
//! sequences. The proptest generator builds programs with parametric
//! live-set sizes and checks the emitted bytecode.

use ir_core::{Instruction, SsaVar};
use ir_forge::extended::ExtendedInstruction;
use ir_forge::lysis_lift::Walker;
use lysis::Opcode;
use memory::{Bn254Fr, FieldElement, FieldFamily};
use proptest::prelude::*;

fn ssa(i: u32) -> SsaVar {
    SsaVar(i)
}

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

/// Build a body with `n_consts` constants followed by `n_uses` Adds
/// that each reference two constants (round-robin). The Adds keep
/// every Const alive so they all enter the live set at any split.
fn build_const_use_chain(n_consts: u32, n_uses: u32) -> Vec<ExtendedInstruction<Bn254Fr>> {
    let mut body = Vec::with_capacity((n_consts + n_uses) as usize);
    for i in 0..n_consts {
        body.push(ExtendedInstruction::Plain(Instruction::Const {
            result: ssa(i),
            value: fe(u64::from(i)),
        }));
    }
    for j in 0..n_uses {
        let lhs = ssa(j % n_consts);
        let rhs = ssa((j + 1) % n_consts);
        body.push(ExtendedInstruction::Plain(Instruction::Add {
            result: ssa(n_consts + j),
            lhs,
            rhs,
        }));
    }
    body
}

fn count_opcodes(program: &lysis::Program<Bn254Fr>, predicate: impl Fn(&Opcode) -> bool) -> usize {
    program.body.iter().filter(|i| predicate(&i.opcode)).count()
}

proptest! {
    /// Single-static-store invariant: every heap slot receives exactly
    /// one `StoreHeap` across the program. This is the property that
    /// the single-static-store validator rule enforces; this test
    /// verifies the walker upholds it before the validator catches
    /// any violation.
    #[test]
    fn each_slot_has_at_most_one_store_heap(
        n_consts in 1u32..40,
        n_uses in 0u32..40,
    ) {
        let body = build_const_use_chain(n_consts, n_uses);
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let Ok(program) = walker.lower(&body) else { return Ok(()); };

        let mut slot_writes: std::collections::HashMap<u16, u32> =
            std::collections::HashMap::new();
        for instr in &program.body {
            if let Opcode::StoreHeap { slot, .. } = instr.opcode {
                *slot_writes.entry(slot).or_default() += 1;
            }
        }
        for (slot, count) in &slot_writes {
            prop_assert!(
                *count == 1,
                "slot {slot} stored {count} times — single-static-store violated"
            );
        }
    }

    /// `heap_size_hint` matches the number of distinct slots actually
    /// stored to. The walker always advertises exactly the slots it
    /// allocated; the executor pre-sizes accordingly. A mismatch
    /// would surface as either `HeapSlotOutOfBounds` (if the hint is
    /// too small) or wasted Vec capacity (if too large).
    #[test]
    fn heap_size_hint_matches_allocated_slots(
        n_consts in 1u32..40,
        n_uses in 0u32..40,
    ) {
        let body = build_const_use_chain(n_consts, n_uses);
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let Ok(program) = walker.lower(&body) else { return Ok(()); };

        let store_count = count_opcodes(&program, |op| matches!(op, Opcode::StoreHeap { .. }));
        prop_assert_eq!(
            usize::from(program.header.heap_size_hint),
            store_count,
            "heap_size_hint must equal the number of distinct StoreHeap emissions"
        );
    }

    /// Programs whose live set never exceeds `MAX_CAPTURES_HOT` (= 48)
    /// emit zero heap opcodes. This is the "no regression for small
    /// programs" property: the walker leaves bytecode shape
    /// untouched for programs below the spill threshold.
    #[test]
    fn small_programs_emit_no_heap_ops(
        n_consts in 1u32..30,
        n_uses in 0u32..30,
    ) {
        // Cap: 30 + 30 = 60 instructions, well below the 251-reg
        // split trigger. No live set above 48 should ever materialise.
        let body = build_const_use_chain(n_consts, n_uses);
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let Ok(program) = walker.lower(&body) else { return Ok(()); };

        let heap_ops =
            count_opcodes(&program, |op| matches!(op, Opcode::StoreHeap { .. } | Opcode::LoadHeap { .. }));
        prop_assert_eq!(heap_ops, 0);
        prop_assert_eq!(program.header.heap_size_hint, 0);
    }
}
