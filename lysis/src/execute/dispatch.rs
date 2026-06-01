// NOTE: >500 LOC justified because dispatch is one cohesive opcode match; splitting arms would obscure mechanical parity.

use memory::field::{FieldBackend, FieldElement};

use crate::bytecode::const_pool::ConstPoolEntry;
use crate::bytecode::Opcode;
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::intern::{InstructionKind, NodeId, WitnessCallBody};
use crate::program::Program;

use super::frame::Frame;
use super::ir_sink::IrSink;
use super::loops::enter_loop_unroll;
use super::runtime::{read_binary, read_reg, resolve_jump};
use super::step::Step;
use super::PLACEHOLDER_ID;

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch<F: FieldBackend, S: IrSink<F>>(
    instr: &crate::program::Instr,
    frame_idx: usize,
    frames: &mut [Frame],
    program: &Program<F>,
    captures: &[FieldElement<F>],
    config: &LysisConfig,
    sink: &mut S,
    template_lookup: &[Option<crate::program::Template>],
    template_body_ranges: &[Option<(usize, usize)>],
    heap: &mut [Option<NodeId>],
) -> Result<Step, LysisError> {
    use Opcode::*;
    let offset = instr.offset;

    match &instr.opcode {
        // -----------------------------------------------------------
        // Capture / environment
        // -----------------------------------------------------------
        LoadCapture { dst, idx } => {
            if (*idx as usize) >= captures.len() {
                return Err(LysisError::CaptureIdxOutOfRange {
                    at_offset: offset,
                    idx: *idx as u32,
                    len: captures.len() as u32,
                });
            }
            let fe = captures[*idx as usize];
            let id = sink.intern_pure(InstructionKind::Const {
                result: PLACEHOLDER_ID,
                value: fe,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        LoadConst { dst, idx } => {
            let entry =
                program
                    .const_pool
                    .get(*idx as usize)
                    .ok_or(LysisError::ConstIdxOutOfRange {
                        at_offset: offset,
                        idx: *idx,
                        len: program.const_pool.len() as u32,
                    })?;
            let fe = match entry {
                ConstPoolEntry::Field(fe) => *fe,
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "LoadConst target is not a field entry",
                    });
                }
            };
            let id = sink.intern_pure(InstructionKind::Const {
                result: PLACEHOLDER_ID,
                value: fe,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        LoadInput { dst, name_idx, vis } => {
            let entry = program.const_pool.get(*name_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: offset,
                    idx: *name_idx,
                    len: program.const_pool.len() as u32,
                },
            )?;
            let name = match entry {
                ConstPoolEntry::String(s) => s.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "LoadInput name_idx does not reference a string entry",
                    });
                }
            };
            let id = sink.fresh_id();
            sink.emit_effect(InstructionKind::Input {
                result: id,
                name,
                visibility: *vis,
            });
            frames[frame_idx].write(*dst, id);
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
            let target = (offset as i64) + (*rel as i64);
            resolve_jump(target, program).map(Step::JumpToIndex)
        }
        JumpIf { cond, offset: _rel } => {
            // Conservative semantics: the executor does not interpret
            // field-element truth values, so it always falls through.
            // Real conditional branching is future work — once a BTA
            // pass is wired in, JumpIf will only appear in loop bodies
            // where the condition is a compile-time-known NodeId.
            let _ = read_reg(&frames[frame_idx], *cond, offset)?; // rule 9 backstop
            Ok(Step::Next)
        }
        Return => {
            if frames.len() == 1 {
                return Err(LysisError::UnreachableReturn { at_offset: offset });
            }
            Ok(Step::PopFrame)
        }
        Halt => Ok(Step::Halt),
        Trap { code } => Err(LysisError::Trap {
            code: *code,
            at_offset: offset,
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
            offset, frame_idx, frames, *iter_var, *start, *end, *body_len, program, sink,
        ),
        LoopRolled { .. } | LoopRange { .. } => {
            // Only LoopUnroll is wired today. LoopRolled / LoopRange
            // need the opcode schema to carry capture plumbing
            // (currently missing from the bytecode layout); they
            // remain future work until InstantiateTemplate's capture
            // flow is proven in-loop.
            Err(LysisError::ValidationFailed {
                rule: 0,
                location: offset,
                detail: "LoopRolled/LoopRange not yet implemented — use LoopUnroll",
            })
        }

        // -----------------------------------------------------------
        // Template instantiation
        // -----------------------------------------------------------
        DefineTemplate { .. } => {
            // Pure metadata: already harvested during decode. Skip.
            Ok(Step::Next)
        }
        InstantiateTemplate {
            template_id,
            capture_regs,
            output_regs,
        } => {
            let template = template_lookup
                .get(*template_id as usize)
                .and_then(|slot| *slot)
                .ok_or(LysisError::UndefinedTemplate {
                    at_offset: offset,
                    template_id: *template_id,
                })?;
            // Runtime rule-11 backstop.
            if (frames.len() as u32) >= config.max_call_depth {
                return Err(LysisError::CallStackOverflow {
                    depth: frames.len() as u32,
                    max: config.max_call_depth,
                });
            }
            let (body_start, body_end) = template_body_ranges
                .get(*template_id as usize)
                .and_then(|slot| *slot)
                .ok_or(LysisError::ValidationFailed {
                    rule: 7,
                    location: offset,
                    detail: "template body_offset does not resolve to an instruction index",
                })?;

            // Move captures from caller regs into new frame.
            let caller = &frames[frame_idx];
            let mut new_frame_regs: Vec<Option<NodeId>> = vec![None; template.frame_size as usize];
            for (i, cap_reg) in capture_regs.iter().enumerate() {
                if i >= new_frame_regs.len() {
                    break;
                }
                let val = read_reg(caller, *cap_reg, offset)?;
                new_frame_regs[i] = Some(val);
            }

            let new_frame = Frame {
                regs: new_frame_regs,
                pc: body_start,
                body_start_idx: body_start,
                body_end_idx: body_end,
                template_id: Some(*template_id),
                output_slots: vec![None; output_regs.len()],
                caller_output_regs: output_regs.as_ref().clone(),
                caller_frame_idx: Some(frame_idx),
                loop_stack: Vec::new(),
            };

            // Tail-call elimination. The caller has nothing left to do
            // after the callee returns iff the instruction right after
            // this `InstantiateTemplate` is `Return`, the caller is not
            // mid-loop-iteration, and there are no outputs to project
            // back (this call's `output_regs` and the caller's own
            // `caller_output_regs` are both empty). The walker's
            // split-chain (`InstantiateTemplate(next); Return`, empty
            // output_regs) satisfies this for every link, so the chain
            // runs in O(1) frames. Any other shape falls back to the
            // stack-growing push.
            let caller = &frames[frame_idx];
            let tail = output_regs.is_empty()
                && caller.caller_output_regs.is_empty()
                && caller.loop_stack.is_empty()
                && matches!(
                    program.body.get(caller.pc + 1).map(|i| &i.opcode),
                    Some(Opcode::Return)
                );
            if tail {
                Ok(Step::TailCall(new_frame))
            } else {
                Ok(Step::PushFrame(new_frame))
            }
        }
        TemplateOutput {
            output_idx,
            src_reg,
        } => {
            let frame = &mut frames[frame_idx];
            let val = frame
                .read(*src_reg)
                .ok_or(LysisError::ReadUndefinedRegister {
                    reg: *src_reg,
                    at_offset: offset,
                })?;
            if (*output_idx as usize) < frame.output_slots.len() {
                frame.output_slots[*output_idx as usize] = Some(val);
            }
            Ok(Step::Next)
        }

        // -----------------------------------------------------------
        // IR emission
        // -----------------------------------------------------------
        EmitConst { dst, src_reg } => {
            // `src_reg` already holds a Const-emitted NodeId (produced
            // by a prior `LoadConst`/`LoadCapture`). The RFC treats
            // `EmitConst` as an alias — writing the same id into `dst`.
            let frame = &frames[frame_idx];
            let src = read_reg(frame, *src_reg, offset)?;
            frames[frame_idx].write(*dst, src);
            Ok(Step::Next)
        }

        EmitAdd { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::Add {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitSub { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::Sub {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitMul { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::Mul {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitDiv { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::Div {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitNeg { dst, operand } => {
            let op = read_reg(&frames[frame_idx], *operand, offset)?;
            let id = sink.intern_pure(InstructionKind::Neg {
                result: PLACEHOLDER_ID,
                operand: op,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        } => {
            let frame = &frames[frame_idx];
            let c = read_reg(frame, *cond, offset)?;
            let t = read_reg(frame, *then_v, offset)?;
            let e = read_reg(frame, *else_v, offset)?;
            let id = sink.intern_pure(InstructionKind::Mux {
                result: PLACEHOLDER_ID,
                cond: c,
                if_true: t,
                if_false: e,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitDecompose {
            dst_arr,
            src,
            n_bits,
        } => {
            let operand = read_reg(&frames[frame_idx], *src, offset)?;
            let bit_results: Vec<NodeId> = (0..*n_bits).map(|_| sink.fresh_id()).collect();
            let result_id = operand; // mirror of ir::Instruction::Decompose
            sink.emit_effect(InstructionKind::Decompose {
                result: result_id,
                bit_results: bit_results.clone(),
                operand,
                num_bits: *n_bits as u32,
            });
            // Lay out bits into regs[dst_arr..dst_arr+n_bits].
            let frame = &mut frames[frame_idx];
            for (i, b) in bit_results.iter().enumerate() {
                let reg = (*dst_arr as usize).saturating_add(i);
                if reg < frame.regs.len() {
                    frame.regs[reg] = Some(*b);
                }
            }
            Ok(Step::Next)
        }

        EmitAssertEq { lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit_effect(InstructionKind::AssertEq {
                result: id,
                lhs: l,
                rhs: r,
                message: None,
            });
            Ok(Step::Next)
        }

        EmitAssertEqMsg { lhs, rhs, msg_idx } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let entry = program.const_pool.get(*msg_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: offset,
                    idx: *msg_idx,
                    len: program.const_pool.len() as u32,
                },
            )?;
            let message = match entry {
                ConstPoolEntry::String(s) => s.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "EmitAssertEqMsg msg_idx does not reference a string entry",
                    });
                }
            };
            let id = sink.fresh_id();
            sink.emit_effect(InstructionKind::AssertEq {
                result: id,
                lhs: l,
                rhs: r,
                message: Some(message),
            });
            Ok(Step::Next)
        }

        EmitRangeCheck { var, max_bits } => {
            let operand = read_reg(&frames[frame_idx], *var, offset)?;
            let id = sink.fresh_id();
            sink.emit_effect(InstructionKind::RangeCheck {
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
            let entry = program.const_pool.get(*bytecode_const_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: offset,
                    idx: *bytecode_const_idx,
                    len: program.const_pool.len() as u32,
                },
            )?;
            let blob = match entry {
                ConstPoolEntry::ArtikBytecode(b) => b.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "EmitWitnessCall bytecode_const_idx is not an Artik blob",
                    });
                }
            };
            let inputs: Vec<NodeId> = in_regs
                .iter()
                .map(|r| read_reg(&frames[frame_idx], *r, offset))
                .collect::<Result<_, _>>()?;
            let outputs: Vec<NodeId> = (0..out_regs.len()).map(|_| sink.fresh_id()).collect();
            sink.emit_effect(InstructionKind::WitnessCall(Box::new(WitnessCallBody {
                outputs: outputs.clone(),
                inputs,
                program_bytes: blob,
            })));
            let frame = &mut frames[frame_idx];
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
                .map(|r| read_reg(&frames[frame_idx], *r, offset))
                .collect::<Result<_, _>>()?;
            // The mirror enum is `PoseidonHash(result, left, right)`,
            // so we treat the first two inputs as left/right. Hashes
            // with arity ≠ 2 are future work.
            if inputs.len() != 2 {
                return Err(LysisError::ValidationFailed {
                    rule: 0,
                    location: offset,
                    detail: "PoseidonHash supports arity 2 only",
                });
            }
            let id = sink.intern_pure(InstructionKind::PoseidonHash {
                result: PLACEHOLDER_ID,
                left: inputs[0],
                right: inputs[1],
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsEq { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::IsEq {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsLt { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::IsLt {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIntDiv {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::IntDiv {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
                max_bits: u32::from(*max_bits),
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIntMod {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.intern_pure(InstructionKind::IntMod {
                result: PLACEHOLDER_ID,
                lhs: l,
                rhs: r,
                max_bits: u32::from(*max_bits),
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        // Heap opcodes. The validator (heap-slot-bounds and
        // single-static-store rules) is the primary gatekeeper for
        // slot bounds and single-static-store; the runtime checks
        // here are defensive — a programmer running execute() without
        // first calling validate() must still get a structured error
        // rather than UB.
        StoreHeap { src_reg, slot } => {
            let id = read_reg(&frames[frame_idx], *src_reg, offset)?;
            let slot_idx = *slot as usize;
            if slot_idx >= heap.len() {
                return Err(LysisError::ValidationFailed {
                    rule: 12,
                    location: offset,
                    detail: "StoreHeap slot >= heap_size_hint",
                });
            }
            heap[slot_idx] = Some(id);
            Ok(Step::Next)
        }
        LoadHeap { dst_reg, slot } => {
            let slot_idx = *slot as usize;
            if slot_idx >= heap.len() {
                return Err(LysisError::ValidationFailed {
                    rule: 12,
                    location: offset,
                    detail: "LoadHeap slot >= heap_size_hint",
                });
            }
            let id = heap[slot_idx].ok_or(LysisError::ValidationFailed {
                rule: 13,
                location: offset,
                detail: "LoadHeap from unwritten slot",
            })?;
            frames[frame_idx].write(*dst_reg, id);
            Ok(Step::Next)
        }

        // Heap-output WitnessCall. Mirrors `EmitWitnessCall` but
        // reads inputs from regs OR heap slots
        // (per `InputSrc` tag) and writes outputs to heap[slot]
        // instead of frame.regs[reg]. Used when input or output
        // counts exceed the u8 reg cap (canonical: SHA-256 with
        // 700+ cold inputs and 256 outputs).
        EmitWitnessCallHeap {
            bytecode_const_idx,
            inputs,
            out_slots,
        } => {
            let entry = program.const_pool.get(*bytecode_const_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: offset,
                    idx: *bytecode_const_idx,
                    len: program.const_pool.len() as u32,
                },
            )?;
            let blob = match entry {
                ConstPoolEntry::ArtikBytecode(b) => b.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "EmitWitnessCallHeap bytecode_const_idx is not an Artik blob",
                    });
                }
            };
            // Read inputs in order. Reg sources go through read_reg
            // (same as classic), Slot sources read heap[slot]
            // directly — no LoadHeap emit, no register allocation.
            let resolved_inputs: Vec<NodeId> = inputs
                .iter()
                .map(|src| match src {
                    crate::bytecode::opcode::InputSrc::Reg(r) => {
                        read_reg(&frames[frame_idx], *r, offset)
                    }
                    crate::bytecode::opcode::InputSrc::Slot(slot) => {
                        let slot_idx = *slot as usize;
                        if slot_idx >= heap.len() {
                            return Err(LysisError::ValidationFailed {
                                rule: 12,
                                location: offset,
                                detail: "EmitWitnessCallHeap input Slot >= heap_size_hint",
                            });
                        }
                        heap[slot_idx].ok_or(LysisError::ValidationFailed {
                            rule: 13,
                            location: offset,
                            detail: "EmitWitnessCallHeap reads from unwritten input Slot",
                        })
                    }
                })
                .collect::<Result<_, _>>()?;
            let outputs: Vec<NodeId> = (0..out_slots.len()).map(|_| sink.fresh_id()).collect();
            sink.emit_effect(InstructionKind::WitnessCall(Box::new(WitnessCallBody {
                outputs: outputs.clone(),
                inputs: resolved_inputs,
                program_bytes: blob,
            })));
            for (slot, id) in out_slots.iter().zip(outputs.iter()) {
                let slot_idx = *slot as usize;
                if slot_idx >= heap.len() {
                    return Err(LysisError::ValidationFailed {
                        rule: 12,
                        location: offset,
                        detail: "EmitWitnessCallHeap out_slot >= heap_size_hint",
                    });
                }
                heap[slot_idx] = Some(*id);
            }
            Ok(Step::Next)
        }
    }
}
