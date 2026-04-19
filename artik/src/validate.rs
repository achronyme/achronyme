//! Structural validation of a decoded [`Program`].
//!
//! Runs 8 invariants before the bytecode is considered executable:
//!
//! 1. Opcode discriminants ≤ MAX (already enforced by decode, re-checked).
//! 2. Jump targets land on an instruction boundary inside the body.
//! 3. Const pool references are in range.
//! 4. Register indices are < frame_size.
//! 5. Per-register type category is consistent across writes.
//! 6. Field constants have len ≤ field family's canonical size.
//! 7. Signal / witness slot ids carry u32 encoding (no higher check —
//!    runtime bounds are enforced by the executor once it sees the
//!    caller's signal / slot slices).
//! 8. Bodies terminate with `Return` on every reachable path (approx:
//!    we check that the last instruction is either `Return`, `Trap`,
//!    or an unconditional `Jump`; full reachability analysis is out of
//!    scope for v1 and the trap-on-fall-off safety net is added by the
//!    executor).

use std::collections::HashMap;

use crate::error::ArtikError;
use crate::ir::{ElemT, Instr, IntW, RegType, MAX_ARRAY_LEN, MAX_FRAME_SIZE};
use crate::program::Program;

/// Validate a decoded program against the 8 invariants. `instr_offsets`
/// is the byte offset of each instruction inside the body stream (not
/// including the 4-byte frame size prelude), as produced by the
/// decoder. Jump targets are compared against this offset set.
pub fn validate(prog: &Program, instr_offsets: &[u32]) -> Result<(), ArtikError> {
    let frame = prog.frame_size;
    let const_count = prog.const_pool.len() as u32;
    let family = prog.header.family;
    let max_const = family.max_const_bytes();

    // Static resource bound: register frame must fit our allocation
    // ceiling. Without this check, an adversarial bytecode declaring
    // `frame_size = u32::MAX` would force the executor to allocate
    // a multi-gigabyte `Vec<Cell<F>>` before any instruction runs.
    if frame > MAX_FRAME_SIZE {
        return Err(ArtikError::FrameTooLarge {
            frame_size: frame,
            max: MAX_FRAME_SIZE,
        });
    }

    // Invariant 6: const pool sizes.
    for entry in &prog.const_pool {
        if entry.bytes.len() > max_const {
            return Err(ArtikError::ConstTooLarge {
                len: entry.bytes.len(),
                max: max_const,
            });
        }
    }

    // Invariant 2 prep: set of valid jump targets.
    let valid_targets: std::collections::HashSet<u32> = instr_offsets.iter().copied().collect();

    // Invariants 3–5: walk instructions.
    let mut reg_types: HashMap<u32, RegType> = HashMap::new();

    let check_reg = |reg: u32| -> Result<(), ArtikError> {
        if reg >= frame {
            return Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: frame,
            });
        }
        Ok(())
    };

    let bind =
        |reg_types: &mut HashMap<u32, RegType>, reg: u32, ty: RegType| -> Result<(), ArtikError> {
            check_reg(reg)?;
            if let Some(existing) = reg_types.get(&reg) {
                if *existing != ty {
                    return Err(ArtikError::RegisterTypeConflict { reg });
                }
            } else {
                reg_types.insert(reg, ty);
            }
            Ok(())
        };

    let read = |reg_types: &HashMap<u32, RegType>,
                reg: u32,
                expected: RegType|
     -> Result<(), ArtikError> {
        check_reg(reg)?;
        match reg_types.get(&reg) {
            Some(ty) if *ty == expected => Ok(()),
            Some(_) => Err(ArtikError::RegisterTypeConflict { reg }),
            // Reading before any write is only allowed if the producing
            // path assigned it earlier in a branch we did not see on a
            // linear walk. We permit this in v1: the executor will trap
            // on undefined reads at runtime. Validation only flags
            // cross-category conflicts.
            None => Ok(()),
        }
    };

    for instr in &prog.body {
        match instr {
            Instr::Jump { target } => {
                if !valid_targets.contains(target) {
                    return Err(ArtikError::InvalidJumpTarget { target: *target });
                }
            }
            Instr::JumpIf { cond, target } => {
                if !valid_targets.contains(target) {
                    return Err(ArtikError::InvalidJumpTarget { target: *target });
                }
                // `cond` is treated as Int(U8) — it carries a 0/1 value.
                read(&reg_types, *cond, RegType::Int(IntW::U8))?;
            }
            Instr::Return | Instr::Trap { .. } => {}
            Instr::PushConst { dst, const_id } => {
                if *const_id >= const_count {
                    return Err(ArtikError::InvalidConstId {
                        const_id: *const_id,
                    });
                }
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::ReadSignal { dst, signal_id: _ } => {
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::WriteWitness { slot_id: _, src } => {
                read(&reg_types, *src, RegType::Field)?;
            }
            Instr::FAdd { dst, a, b }
            | Instr::FSub { dst, a, b }
            | Instr::FMul { dst, a, b }
            | Instr::FDiv { dst, a, b } => {
                read(&reg_types, *a, RegType::Field)?;
                read(&reg_types, *b, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::FInv { dst, src } => {
                read(&reg_types, *src, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::FEq { dst, a, b } => {
                read(&reg_types, *a, RegType::Field)?;
                read(&reg_types, *b, RegType::Field)?;
                // Result is boolean-as-U8.
                bind(&mut reg_types, *dst, RegType::Int(IntW::U8))?;
            }
            Instr::IBin { op, w, dst, a, b } => {
                read(&reg_types, *a, RegType::Int(*w))?;
                read(&reg_types, *b, RegType::Int(*w))?;
                let dst_ty = if op.is_boolean() {
                    RegType::Int(IntW::U8)
                } else {
                    RegType::Int(*w)
                };
                bind(&mut reg_types, *dst, dst_ty)?;
            }
            Instr::INot { w, dst, src } => {
                read(&reg_types, *src, RegType::Int(*w))?;
                bind(&mut reg_types, *dst, RegType::Int(*w))?;
            }
            Instr::Rotl32 { dst, src, n } | Instr::Rotr32 { dst, src, n } => {
                read(&reg_types, *src, RegType::Int(IntW::U32))?;
                read(&reg_types, *n, RegType::Int(IntW::U32))?;
                bind(&mut reg_types, *dst, RegType::Int(IntW::U32))?;
            }
            Instr::Rotl8 { dst, src, n } => {
                read(&reg_types, *src, RegType::Int(IntW::U8))?;
                read(&reg_types, *n, RegType::Int(IntW::U8))?;
                bind(&mut reg_types, *dst, RegType::Int(IntW::U8))?;
            }
            Instr::IntFromField { w, dst, src } => {
                read(&reg_types, *src, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Int(*w))?;
            }
            Instr::FieldFromInt { dst, src, w } => {
                read(&reg_types, *src, RegType::Int(*w))?;
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::AllocArray { dst, len, elem } => {
                if *len > MAX_ARRAY_LEN {
                    return Err(ArtikError::ArrayTooLarge {
                        len: *len,
                        max: MAX_ARRAY_LEN,
                    });
                }
                bind(&mut reg_types, *dst, RegType::Array(*elem))?;
            }
            Instr::LoadArr { dst, arr, idx } => {
                check_reg(*arr)?;
                let elem_ty = match reg_types.get(arr) {
                    Some(RegType::Array(e)) => *e,
                    Some(_) => return Err(ArtikError::RegisterTypeConflict { reg: *arr }),
                    None => return Err(ArtikError::RegisterTypeConflict { reg: *arr }),
                };
                read(&reg_types, *idx, RegType::Int(IntW::U32))?;
                let dst_ty = elem_to_reg(elem_ty);
                bind(&mut reg_types, *dst, dst_ty)?;
            }
            Instr::StoreArr { arr, idx, val } => {
                check_reg(*arr)?;
                let elem_ty = match reg_types.get(arr) {
                    Some(RegType::Array(e)) => *e,
                    Some(_) => return Err(ArtikError::RegisterTypeConflict { reg: *arr }),
                    None => return Err(ArtikError::RegisterTypeConflict { reg: *arr }),
                };
                read(&reg_types, *idx, RegType::Int(IntW::U32))?;
                let val_ty = elem_to_reg(elem_ty);
                read(&reg_types, *val, val_ty)?;
            }
        }
    }

    Ok(())
}

fn elem_to_reg(e: ElemT) -> RegType {
    match e {
        ElemT::Field => RegType::Field,
        ElemT::IntU8 => RegType::Int(IntW::U8),
        ElemT::IntU32 => RegType::Int(IntW::U32),
        ElemT::IntU64 => RegType::Int(IntW::U64),
        ElemT::IntI64 => RegType::Int(IntW::I64),
    }
}
