use memory::field::FieldBackend;

use crate::bytecode::const_pool::ConstPoolEntry;
use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::intern::InstructionKind;

use super::super::loops::enter_loop_unroll;
use super::super::runtime::{read_reg, resolve_jump};
use super::super::step::Step;
use super::super::PLACEHOLDER_ID;
use super::DispatchCtx;

pub(super) fn dispatch<F: FieldBackend, S: super::super::ir_sink::IrSink<F>>(
    opcode: &Opcode,
    ctx: &mut DispatchCtx<'_, F, S>,
) -> Result<Step, LysisError> {
    use Opcode::*;

    match opcode {
        // -----------------------------------------------------------
        // Capture / environment
        // -----------------------------------------------------------
        LoadCapture { dst, idx } => {
            if (*idx as usize) >= ctx.captures.len() {
                return Err(LysisError::CaptureIdxOutOfRange {
                    at_offset: ctx.offset,
                    idx: *idx as u32,
                    len: ctx.captures.len() as u32,
                });
            }
            let fe = ctx.captures[*idx as usize];
            let id = ctx.sink.intern_pure(InstructionKind::Const {
                result: PLACEHOLDER_ID,
                value: fe,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        LoadConst { dst, idx } => {
            let entry = ctx.program.const_pool.get(*idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: ctx.offset,
                    idx: *idx,
                    len: ctx.program.const_pool.len() as u32,
                },
            )?;
            let fe = match entry {
                ConstPoolEntry::Field(fe) => *fe,
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: ctx.offset,
                        detail: "LoadConst target is not a field entry",
                    });
                }
            };
            let id = ctx.sink.intern_pure(InstructionKind::Const {
                result: PLACEHOLDER_ID,
                value: fe,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        LoadInput { dst, name_idx, vis } => {
            let entry = ctx.program.const_pool.get(*name_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: ctx.offset,
                    idx: *name_idx,
                    len: ctx.program.const_pool.len() as u32,
                },
            )?;
            let name = match entry {
                ConstPoolEntry::String(s) => s.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: ctx.offset,
                        detail: "LoadInput name_idx does not reference a string entry",
                    });
                }
            };
            let id = ctx.sink.fresh_id();
            ctx.sink.emit_effect(InstructionKind::Input {
                result: id,
                name,
                visibility: *vis,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EnterScope | ExitScope => {
            // Scopes are informational at this layer: the lowering
            // pass is what actually constructs the scoped environment;
            // the executor currently carries no env.
            Ok(Step::Next)
        }

        // -----------------------------------------------------------
        // Control flow
        // -----------------------------------------------------------
        Jump { offset: rel } => {
            let target = (ctx.offset as i64) + (*rel as i64);
            resolve_jump(target, ctx.program).map(Step::JumpToIndex)
        }
        JumpIf { cond, offset: _rel } => {
            // Conservative semantics: the executor does not interpret
            // field-element truth values, so it always falls through.
            // Real conditional branching is future work — once a BTA
            // pass is wired in, JumpIf will only appear in loop bodies
            // where the condition is a compile-time-known NodeId.
            let _ = read_reg(&ctx.frames[ctx.frame_idx], *cond, ctx.offset)?; // rule 9 backstop
            Ok(Step::Next)
        }
        Return => {
            if ctx.frames.len() == 1 {
                return Err(LysisError::UnreachableReturn {
                    at_offset: ctx.offset,
                });
            }
            Ok(Step::PopFrame)
        }
        Halt => Ok(Step::Halt),
        Trap { code } => Err(LysisError::Trap {
            code: *code,
            at_offset: ctx.offset,
        }),

        // -----------------------------------------------------------
        // Loop semantics
        // -----------------------------------------------------------
        LoopUnroll {
            iter_var,
            start,
            end,
            body_len,
        } => enter_loop_unroll(
            ctx.offset,
            ctx.frame_idx,
            ctx.frames,
            *iter_var,
            *start,
            *end,
            *body_len,
            ctx.program,
            ctx.sink,
        ),
        LoopRolled { .. } | LoopRange { .. } => {
            // Only LoopUnroll is wired today. LoopRolled / LoopRange
            // need the opcode schema to carry capture plumbing
            // (currently missing from the bytecode layout); they
            // remain future work until InstantiateTemplate's capture
            // flow is proven in-loop.
            Err(LysisError::ValidationFailed {
                rule: 0,
                location: ctx.offset,
                detail: "LoopRolled/LoopRange not yet implemented — use LoopUnroll",
            })
        }

        _ => unreachable!("non environment/control opcode routed to env_control"),
    }
}
