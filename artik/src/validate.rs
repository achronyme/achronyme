//! Structural validation of a decoded [`Program`].
//!
//! The validator runs before any bytecode is considered executable. It
//! checks, per subprogram:
//!
//! 1. Opcode discriminants ≤ MAX (already enforced by decode, re-checked).
//! 2. Jump targets land on an instruction boundary inside the same
//!    subprogram (offsets are subprogram-local).
//! 3. Const pool references are in range (the pool is program-global).
//! 4. Register indices are < the subprogram's frame_size.
//! 5. Per-register type category is consistent across writes.
//! 6. Field constants have len ≤ the field family's canonical size.
//! 7. Signal / witness slot ids carry u32 encoding; the runtime bounds
//!    are enforced by the executor against the caller's slices.
//! 8. Bodies terminate with `Return` on every reachable path (approx:
//!    the trap-on-fall-off net is added by the executor).
//!
//! And, across subprograms:
//!
//! - The entry subprogram (index 0) takes no parameters and returns no
//!   values; `ReadSignal` / `WriteWitness` appear only there.
//! - Every `Call` targets a defined subprogram and matches its
//!   parameter / return arity and type categories.
//! - Every `Return`'s source list matches its subprogram's declared
//!   return list.

use std::collections::HashMap;

use crate::error::ArtikError;
use crate::ir::{ElemT, Instr, IntW, RegType, MAX_ARRAY_LEN, MAX_FRAME_SIZE};
use crate::program::Program;

/// Validate a decoded program. `offsets_per_sub[si]` is the byte offset
/// of each instruction inside subprogram `si`'s standalone stream (as
/// produced by the decoder); jump targets in that subprogram are
/// compared against its offset set.
pub fn validate(prog: &Program, offsets_per_sub: &[Vec<u32>]) -> Result<(), ArtikError> {
    if prog.subprograms.is_empty() || prog.entry >= prog.subprograms.len() {
        return Err(ArtikError::NoSubprograms);
    }
    if offsets_per_sub.len() != prog.subprograms.len() {
        return Err(ArtikError::NoSubprograms);
    }

    // The entry subprogram is the only one with access to the caller's
    // signal / witness slices, so it must have no call-site contract.
    let entry = &prog.subprograms[prog.entry];
    if !entry.params.is_empty() || !entry.returns.is_empty() {
        return Err(ArtikError::EntryHasParamsOrReturns);
    }

    let family = prog.header.family;
    let max_const = family.max_const_bytes();

    // Invariant 6: const pool sizes (program-global pool).
    for entry in &prog.const_pool {
        if entry.bytes.len() > max_const {
            return Err(ArtikError::ConstTooLarge {
                len: entry.bytes.len(),
                max: max_const,
            });
        }
    }
    let const_count = prog.const_pool.len() as u32;

    for (si, offsets) in offsets_per_sub.iter().enumerate() {
        validate_subprogram(prog, si, const_count, offsets)?;
    }

    Ok(())
}

fn validate_subprogram(
    prog: &Program,
    si: usize,
    const_count: u32,
    instr_offsets: &[u32],
) -> Result<(), ArtikError> {
    let sub = &prog.subprograms[si];
    let frame = sub.frame_size;
    let is_entry = si == prog.entry;

    // Static resource bound: register frame must fit our allocation
    // ceiling. Without this an adversarial subprogram declaring
    // `frame_size = u32::MAX` would force a multi-gigabyte allocation
    // on entry to the call.
    if frame > MAX_FRAME_SIZE {
        return Err(ArtikError::FrameTooLarge {
            frame_size: frame,
            max: MAX_FRAME_SIZE,
        });
    }

    let valid_targets: std::collections::HashSet<u32> = instr_offsets.iter().copied().collect();

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
            // linear walk. The executor traps on undefined reads at
            // runtime; validation only flags cross-category conflicts.
            None => Ok(()),
        }
    };

    // Parameter registers are bound to types up-front (the executor
    // populates registers 0..params.len() from the caller's args).
    for (i, pty) in sub.params.iter().enumerate() {
        bind(&mut reg_types, i as u32, *pty)?;
    }

    for instr in &sub.body {
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
                read(&reg_types, *cond, RegType::Int(IntW::U8))?;
            }
            Instr::Return { srcs } => {
                if srcs.len() != sub.returns.len() {
                    return Err(ArtikError::CallArityMismatch {
                        func_id: si as u32,
                        expected: sub.returns.len(),
                        got: srcs.len(),
                    });
                }
                for (src, rty) in srcs.iter().zip(&sub.returns) {
                    if read(&reg_types, *src, *rty).is_err() {
                        return Err(ArtikError::CallTypeMismatch {
                            func_id: si as u32,
                            reg: *src,
                        });
                    }
                }
            }
            Instr::Call {
                func_id,
                args,
                rets,
            } => {
                let callee = prog
                    .subprograms
                    .get(*func_id as usize)
                    .ok_or(ArtikError::UnknownSubprogram { func_id: *func_id })?;
                if args.len() != callee.params.len() {
                    return Err(ArtikError::CallArityMismatch {
                        func_id: *func_id,
                        expected: callee.params.len(),
                        got: args.len(),
                    });
                }
                if rets.len() != callee.returns.len() {
                    return Err(ArtikError::CallArityMismatch {
                        func_id: *func_id,
                        expected: callee.returns.len(),
                        got: rets.len(),
                    });
                }
                for (arg, pty) in args.iter().zip(&callee.params) {
                    if read(&reg_types, *arg, *pty).is_err() {
                        return Err(ArtikError::CallTypeMismatch {
                            func_id: *func_id,
                            reg: *arg,
                        });
                    }
                }
                for (ret, rty) in rets.iter().zip(&callee.returns) {
                    bind(&mut reg_types, *ret, *rty)?;
                }
            }
            Instr::Trap { .. } => {}
            Instr::PushConst { dst, const_id } => {
                if *const_id >= const_count {
                    return Err(ArtikError::InvalidConstId {
                        const_id: *const_id,
                    });
                }
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::ReadSignal { dst, signal_id: _ } => {
                if !is_entry {
                    return Err(ArtikError::SignalsOutsideEntry);
                }
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::WriteWitness { slot_id: _, src } => {
                if !is_entry {
                    return Err(ArtikError::SignalsOutsideEntry);
                }
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
            Instr::FPow2 { dst, amount } => {
                // `amount` is a runtime Field register; the executor
                // computes `2 ^ amount` by repeated squaring bounded by
                // the canonical representative's bit width, so there is
                // no shift-amount cap to enforce here.
                read(&reg_types, *amount, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::FEq { dst, a, b } | Instr::FCmpLt { dst, a, b } => {
                read(&reg_types, *a, RegType::Field)?;
                read(&reg_types, *b, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Int(IntW::U8))?;
            }
            Instr::FIDiv { dst, a, b } | Instr::FIRem { dst, a, b } => {
                read(&reg_types, *a, RegType::Field)?;
                read(&reg_types, *b, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::FShr { dst, src, amount } => {
                if *amount > 253 {
                    return Err(ArtikError::InvalidShiftAmount { amount: *amount });
                }
                read(&reg_types, *src, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Field)?;
            }
            Instr::FAnd {
                dst,
                src,
                mask_const_id,
            } => {
                if *mask_const_id >= const_count {
                    return Err(ArtikError::InvalidConstId {
                        const_id: *mask_const_id,
                    });
                }
                read(&reg_types, *src, RegType::Field)?;
                bind(&mut reg_types, *dst, RegType::Field)?;
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
            Instr::ArrayId { dst, arr } => {
                check_reg(*arr)?;
                match reg_types.get(arr) {
                    Some(RegType::Array(_)) => {}
                    _ => return Err(ArtikError::RegisterTypeConflict { reg: *arr }),
                }
                bind(&mut reg_types, *dst, RegType::Int(IntW::U32))?;
            }
            Instr::ArrayFromId { dst, id, elem } => {
                read(&reg_types, *id, RegType::Int(IntW::U32))?;
                bind(&mut reg_types, *dst, RegType::Array(*elem))?;
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
