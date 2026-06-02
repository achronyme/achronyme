use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::program::Program;

// ---------------------------------------------------------------------
// Rule 12 — heap slot < heap_size_hint (heap-slot-bounds rule).
// ---------------------------------------------------------------------

pub(super) fn check_heap_slot_bounds<F: FieldBackend>(
    program: &Program<F>,
) -> Result<(), LysisError> {
    let cap = program.header.heap_size_hint;
    for instr in &program.body {
        match &instr.opcode {
            Opcode::StoreHeap { slot, .. } | Opcode::LoadHeap { slot, .. } => {
                if *slot >= cap {
                    return Err(LysisError::ValidationFailed {
                        rule: 12,
                        location: instr.offset,
                        detail: "heap slot exceeds header heap_size_hint",
                    });
                }
            }
            Opcode::EmitWitnessCallHeap {
                inputs, out_slots, ..
            } => {
                for src in inputs.iter() {
                    if let crate::bytecode::opcode::InputSrc::Slot(slot) = src {
                        if *slot >= cap {
                            return Err(LysisError::ValidationFailed {
                                rule: 12,
                                location: instr.offset,
                                detail:
                                    "EmitWitnessCallHeap input Slot exceeds header heap_size_hint",
                            });
                        }
                    }
                }
                for slot in out_slots.iter() {
                    if *slot >= cap {
                        return Err(LysisError::ValidationFailed {
                            rule: 12,
                            location: instr.offset,
                            detail: "EmitWitnessCallHeap out_slot exceeds header heap_size_hint",
                        });
                    }
                }
            }
            _ => continue,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Rule 13 — single-static-store invariant.
//
// Every heap slot is written exactly once before any read. The
// SlotState lattice is binary in v1: `Unwritten → Written`. A future
// `Sealed` state is reserved for when `FreeHeap` is wired — keeping
// the enum binary in v1 simplifies the validator and avoids a "dead
// state" landmine for future readers.
//
// Soundness of this forward linear scan depends on the **walker
// emission-position invariant**:
//
//  1. The walker emits zero `Jump` / `JumpIf` opcodes (zero matches
//     in `ir-forge/src/lysis_lift/walker.rs`).
//  2. `StoreHeap` is emitted only in straight-line template prologue
//     position, never inside an inline `LoopUnroll` body or under a
//     conditional branch (which the walker never produces in v1).
//
// Together these mean "earlier in the byte stream" implies
// "dominates in execution order"; a forward linear scan over the
// body is path-safe by construction. **A future walker change that
// introduces real conditional branches around `StoreHeap` requires
// this validator to be upgraded to a CFG-based dominance check** —
// v2 future work, not v1.
//
// Slots that end the program in state `Unwritten` are legal: the
// walker may legitimately reserve a slot via lookahead and then
// have the using path pruned by const-folding. Rejection only fires
// on illegal *transitions*, never on the absence of transitions.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeapSlotState {
    Unwritten,
    Written,
}

pub(super) fn check_heap_single_static_store<F: FieldBackend>(
    program: &Program<F>,
) -> Result<(), LysisError> {
    let cap = program.header.heap_size_hint as usize;
    if cap == 0 {
        // No heap declared. Rule 12 has already rejected any heap
        // opcode whose slot is outside this empty range, so a
        // surviving program at this point has zero heap opcodes.
        // Skip the allocation entirely.
        return Ok(());
    }
    let mut state = vec![HeapSlotState::Unwritten; cap];
    for instr in &program.body {
        match &instr.opcode {
            Opcode::StoreHeap { slot, .. } => {
                let s = *slot as usize;
                // Rule 12 already bounded this; defensive guard.
                if s >= state.len() {
                    continue;
                }
                if state[s] == HeapSlotState::Written {
                    return Err(LysisError::ValidationFailed {
                        rule: 13,
                        location: instr.offset,
                        detail: "double StoreHeap to the same slot",
                    });
                }
                state[s] = HeapSlotState::Written;
            }
            Opcode::LoadHeap { slot, .. } => {
                let s = *slot as usize;
                if s >= state.len() {
                    continue;
                }
                if state[s] != HeapSlotState::Written {
                    return Err(LysisError::ValidationFailed {
                        rule: 13,
                        location: instr.offset,
                        detail: "LoadHeap from unwritten slot",
                    });
                }
            }
            Opcode::EmitWitnessCallHeap {
                inputs, out_slots, ..
            } => {
                // Read-side inputs (Slot variant): each slot must be
                // Written. Same contract as LoadHeap.
                for src in inputs.iter() {
                    if let crate::bytecode::opcode::InputSrc::Slot(slot) = src {
                        let s = *slot as usize;
                        if s >= state.len() {
                            continue;
                        }
                        if state[s] != HeapSlotState::Written {
                            return Err(LysisError::ValidationFailed {
                                rule: 13,
                                location: instr.offset,
                                detail: "EmitWitnessCallHeap reads from unwritten input Slot",
                            });
                        }
                    }
                }
                // Write-side outputs: each slot must be Unwritten,
                // transitions to Written.
                for slot in out_slots.iter() {
                    let s = *slot as usize;
                    if s >= state.len() {
                        continue;
                    }
                    if state[s] == HeapSlotState::Written {
                        return Err(LysisError::ValidationFailed {
                            rule: 13,
                            location: instr.offset,
                            detail: "EmitWitnessCallHeap writes a slot already written",
                        });
                    }
                    state[s] = HeapSlotState::Written;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
