use memory::field::FieldBackend;

use crate::bytecode::const_pool::ConstPoolEntry;
use crate::bytecode::Opcode;
use crate::error::LysisError;
use crate::intern::{InstructionKind, NodeId, WitnessCallBody};

use super::super::runtime::read_reg;
use super::super::step::Step;
use super::DispatchCtx;

pub(super) fn dispatch<F: FieldBackend, S: super::super::ir_sink::IrSink<F>>(
    opcode: &Opcode,
    ctx: &mut DispatchCtx<'_, F, S>,
) -> Result<Step, LysisError> {
    use Opcode::*;

    match opcode {
        // Heap opcodes. The validator (heap-slot-bounds and
        // single-static-store rules) is the primary gatekeeper for
        // slot bounds and single-static-store; the runtime checks
        // here are defensive — a programmer running execute() without
        // first calling validate() must still get a structured error
        // rather than UB.
        StoreHeap { src_reg, slot } => {
            let id = read_reg(&ctx.frames[ctx.frame_idx], *src_reg, ctx.offset)?;
            let slot_idx = *slot as usize;
            if slot_idx >= ctx.heap.len() {
                return Err(LysisError::ValidationFailed {
                    rule: 12,
                    location: ctx.offset,
                    detail: "StoreHeap slot >= heap_size_hint",
                });
            }
            ctx.heap[slot_idx] = Some(id);
            Ok(Step::Next)
        }
        LoadHeap { dst_reg, slot } => {
            let slot_idx = *slot as usize;
            if slot_idx >= ctx.heap.len() {
                return Err(LysisError::ValidationFailed {
                    rule: 12,
                    location: ctx.offset,
                    detail: "LoadHeap slot >= heap_size_hint",
                });
            }
            let id = ctx.heap[slot_idx].ok_or(LysisError::ValidationFailed {
                rule: 13,
                location: ctx.offset,
                detail: "LoadHeap from unwritten slot",
            })?;
            ctx.frames[ctx.frame_idx].write(*dst_reg, id);
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
                        read_reg(&ctx.frames[ctx.frame_idx], *r, ctx.offset)
                    }
                    crate::bytecode::opcode::InputSrc::Slot(slot) => {
                        let slot_idx = *slot as usize;
                        if slot_idx >= ctx.heap.len() {
                            return Err(LysisError::ValidationFailed {
                                rule: 12,
                                location: ctx.offset,
                                detail: "EmitWitnessCallHeap input Slot >= heap_size_hint",
                            });
                        }
                        ctx.heap[slot_idx].ok_or(LysisError::ValidationFailed {
                            rule: 13,
                            location: ctx.offset,
                            detail: "EmitWitnessCallHeap reads from unwritten input Slot",
                        })
                    }
                })
                .collect::<Result<_, _>>()?;
            let outputs: Vec<NodeId> = (0..out_slots.len()).map(|_| ctx.sink.fresh_id()).collect();
            ctx.sink
                .emit_effect(InstructionKind::WitnessCall(Box::new(WitnessCallBody {
                    outputs: outputs.clone(),
                    inputs: resolved_inputs,
                    program_bytes: blob,
                })));
            for (slot, id) in out_slots.iter().zip(outputs.iter()) {
                let slot_idx = *slot as usize;
                if slot_idx >= ctx.heap.len() {
                    return Err(LysisError::ValidationFailed {
                        rule: 12,
                        location: ctx.offset,
                        detail: "EmitWitnessCallHeap out_slot >= heap_size_hint",
                    });
                }
                ctx.heap[slot_idx] = Some(*id);
            }
            Ok(Step::Next)
        }

        _ => unreachable!("non heap opcode routed to heap"),
    }
}
