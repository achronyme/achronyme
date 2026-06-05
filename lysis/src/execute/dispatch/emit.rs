use memory::field::FieldBackend;

use crate::bytecode::const_pool::ConstPoolEntry;
use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::intern::{InstructionKind, NodeId, WitnessCallBody};

use super::super::runtime::{read_binary, read_reg};
use super::super::step::Step;
use super::super::PLACEHOLDER_ID;
use super::DispatchCtx;

pub(super) fn dispatch<F: FieldBackend, S: super::super::ir_sink::IrSink<F>>(
    opcode: &Opcode,
    ctx: &mut DispatchCtx<'_, F, S>,
) -> Result<Step, LysisError> {
    use Opcode::*;

    match opcode {
        EmitConst { dst, src_reg } => {
            // `src_reg` already holds a Const-emitted NodeId (produced
            // by a prior `LoadConst`/`LoadCapture`). The RFC treats
            // `EmitConst` as an alias — writing the same id into `dst`.
            let frame = &ctx.frames[ctx.frame_idx];
            let src = read_reg(frame, *src_reg, ctx.offset)?;
            ctx.frames[ctx.frame_idx].write(*dst, src);
            Ok(Step::Next)
        }

        EmitAdd { dst, lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::Add {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitSub { dst, lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::Sub {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitMul { dst, lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::Mul {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitDiv { dst, lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::Div {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitNeg { dst, operand } => {
            let op = read_reg(&ctx.frames[ctx.frame_idx], *operand, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::Neg {
                result: PLACEHOLDER_ID,
                operand: op,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        } => {
            let frame = &ctx.frames[ctx.frame_idx];
            let c = read_reg(frame, *cond, ctx.offset)?;
            let t = read_reg(frame, *then_v, ctx.offset)?;
            let e = read_reg(frame, *else_v, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::Mux {
                result: PLACEHOLDER_ID,
                cond: c,
                if_true: t,
                if_false: e,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitDecompose {
            dst_arr,
            src,
            n_bits,
        } => {
            let operand = read_reg(&ctx.frames[ctx.frame_idx], *src, ctx.offset)?;
            let bit_results: Vec<NodeId> = (0..*n_bits).map(|_| ctx.sink.fresh_id()).collect();
            let result_id = operand; // mirror of ir::Instruction::Decompose
            ctx.sink.emit_effect(InstructionKind::Decompose {
                result: result_id,
                bit_results: bit_results.clone(),
                operand,
                num_bits: *n_bits as u32,
            });
            // Lay out bits into regs[dst_arr..dst_arr+n_bits].
            let frame = &mut ctx.frames[ctx.frame_idx];
            for (i, b) in bit_results.iter().enumerate() {
                let reg = (*dst_arr as usize).saturating_add(i);
                if reg < frame.regs.len() {
                    frame.regs[reg] = Some(*b);
                }
            }
            Ok(Step::Next)
        }

        EmitAssertEq { lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.fresh_id();
            ctx.sink.emit_effect(InstructionKind::AssertEq {
                result: id,
                lhs: l,
                rhs: r,
                message: None,
            });
            Ok(Step::Next)
        }

        EmitAssertEqMsg { lhs, rhs, msg_idx } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let entry = ctx.program.const_pool.get(*msg_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: ctx.offset,
                    idx: *msg_idx,
                    len: ctx.program.const_pool.len() as u32,
                },
            )?;
            let message = match entry {
                ConstPoolEntry::String(s) => s.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: ctx.offset,
                        detail: "EmitAssertEqMsg msg_idx does not reference a string entry",
                    });
                }
            };
            let id = ctx.sink.fresh_id();
            ctx.sink.emit_effect(InstructionKind::AssertEq {
                result: id,
                lhs: l,
                rhs: r,
                message: Some(message),
            });
            Ok(Step::Next)
        }

        EmitRangeCheck { var, max_bits } => {
            let operand = read_reg(&ctx.frames[ctx.frame_idx], *var, ctx.offset)?;
            let id = ctx.sink.fresh_id();
            ctx.sink.emit_effect(InstructionKind::RangeCheck {
                result: id,
                operand,
                bits: *max_bits as u32,
            });
            Ok(Step::Next)
        }

        EmitWitnessCall {
            bytecode_const_idx,
            in_regs,
            out_regs,
        } => {
            let entry = ctx
                .program
                .const_pool
                .get(*bytecode_const_idx as usize)
                .ok_or(LysisError::ConstIdxOutOfRange {
                    at_offset: ctx.offset,
                    idx: *bytecode_const_idx,
                    len: ctx.program.const_pool.len() as u32,
                })?;
            let blob = match entry {
                ConstPoolEntry::ArtikBytecode(b) => b.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: ctx.offset,
                        detail: "EmitWitnessCall bytecode_const_idx is not an Artik blob",
                    });
                }
            };
            let inputs: Vec<NodeId> = in_regs
                .iter()
                .map(|r| read_reg(&ctx.frames[ctx.frame_idx], *r, ctx.offset))
                .collect::<Result<_, _>>()?;
            let outputs: Vec<NodeId> = (0..out_regs.len()).map(|_| ctx.sink.fresh_id()).collect();
            ctx.sink
                .emit_effect(InstructionKind::WitnessCall(Box::new(WitnessCallBody {
                    outputs: outputs.clone(),
                    inputs,
                    program_bytes: blob,
                })));
            let frame = &mut ctx.frames[ctx.frame_idx];
            for (out_reg, id) in out_regs.iter().zip(outputs.iter()) {
                if (*out_reg as usize) < frame.regs.len() {
                    frame.regs[*out_reg as usize] = Some(*id);
                }
            }
            Ok(Step::Next)
        }

        EmitPoseidonHash { dst, in_regs } => {
            let inputs: Vec<NodeId> = in_regs
                .iter()
                .map(|r| read_reg(&ctx.frames[ctx.frame_idx], *r, ctx.offset))
                .collect::<Result<_, _>>()?;
            // The mirror enum is `PoseidonHash(result, left, right)`,
            // so we treat the first two inputs as left/right. Hashes
            // with arity ≠ 2 are future work.
            if inputs.len() != 2 {
                return Err(LysisError::ValidationFailed {
                    rule: 0,
                    location: ctx.offset,
                    detail: "PoseidonHash supports arity 2 only",
                });
            }
            let id = ctx.sink.intern_pure(InstructionKind::PoseidonHash {
                result: PLACEHOLDER_ID,
                left: inputs[0],
                right: inputs[1],
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsEq { dst, lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::IsEq {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsLt { dst, lhs, rhs } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::IsLt {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsLtBounded {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::IsLtBounded {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
                bitwidth: u32::from(*max_bits),
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIntDiv {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::IntDiv {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
                max_bits: u32::from(*max_bits),
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIntMod {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            let (l, r) = read_binary(&ctx.frames[ctx.frame_idx], *lhs, *rhs, ctx.offset)?;
            let id = ctx.sink.intern_pure(InstructionKind::IntMod {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
                max_bits: u32::from(*max_bits),
            });
            ctx.frames[ctx.frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        _ => unreachable!("non IR-emission opcode routed to emit"),
    }
}
