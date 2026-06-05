use memory::field::FieldBackend;

use crate::bytecode::opcode::{InputSrc, Opcode, INPUT_SRC_REG, INPUT_SRC_SLOT};
use crate::program::Program;

/// Encode a full program to canonical bytes. The returned vector is
/// self-contained: header, const pool, body.
pub fn encode<F: FieldBackend>(program: &Program<F>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&program.header.encode());
    out.extend_from_slice(&program.const_pool.encode());
    for instr in &program.body {
        encode_opcode(&instr.opcode, &mut out);
    }
    out
}

/// Encode a single opcode into `buf`. Kept public so builders and
/// fuzz harnesses can emit without owning a whole program.
pub fn encode_opcode(op: &Opcode, buf: &mut Vec<u8>) {
    buf.push(op.code());
    match op {
        Opcode::LoadCapture { dst, idx } => {
            buf.push(*dst);
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        Opcode::LoadConst { dst, idx } => {
            buf.push(*dst);
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        Opcode::LoadInput { dst, name_idx, vis } => {
            buf.push(*dst);
            buf.extend_from_slice(&name_idx.to_le_bytes());
            buf.push(vis.as_u8());
        }
        Opcode::EnterScope | Opcode::ExitScope | Opcode::Return | Opcode::Halt => {}
        Opcode::Jump { offset } => {
            buf.extend_from_slice(&offset.to_le_bytes());
        }
        Opcode::JumpIf { cond, offset } => {
            buf.push(*cond);
            buf.extend_from_slice(&offset.to_le_bytes());
        }
        Opcode::Trap { code } => {
            buf.push(*code);
        }
        Opcode::LoopUnroll {
            iter_var,
            start,
            end,
            body_len,
        } => {
            buf.push(*iter_var);
            buf.extend_from_slice(&start.to_le_bytes());
            buf.extend_from_slice(&end.to_le_bytes());
            buf.extend_from_slice(&body_len.to_le_bytes());
        }
        Opcode::LoopRolled {
            iter_var,
            start,
            end,
            body_template_id,
        } => {
            buf.push(*iter_var);
            buf.extend_from_slice(&start.to_le_bytes());
            buf.extend_from_slice(&end.to_le_bytes());
            buf.extend_from_slice(&body_template_id.to_le_bytes());
        }
        Opcode::LoopRange {
            iter_var,
            end_reg,
            body_template_id,
        } => {
            buf.push(*iter_var);
            buf.push(*end_reg);
            buf.extend_from_slice(&body_template_id.to_le_bytes());
        }
        Opcode::DefineTemplate {
            template_id,
            frame_size,
            n_params,
            body_offset,
            body_len,
        } => {
            buf.extend_from_slice(&template_id.to_le_bytes());
            buf.push(*frame_size);
            buf.push(*n_params);
            buf.extend_from_slice(&body_offset.to_le_bytes());
            buf.extend_from_slice(&body_len.to_le_bytes());
        }
        Opcode::InstantiateTemplate {
            template_id,
            capture_regs,
            output_regs,
        } => {
            buf.extend_from_slice(&template_id.to_le_bytes());
            buf.push(capture_regs.len() as u8);
            buf.extend_from_slice(capture_regs);
            buf.push(output_regs.len() as u8);
            buf.extend_from_slice(output_regs);
        }
        Opcode::TemplateOutput {
            output_idx,
            src_reg,
        } => {
            buf.push(*output_idx);
            buf.push(*src_reg);
        }
        Opcode::EmitConst { dst, src_reg } => {
            buf.push(*dst);
            buf.push(*src_reg);
        }
        Opcode::EmitAdd { dst, lhs, rhs }
        | Opcode::EmitSub { dst, lhs, rhs }
        | Opcode::EmitMul { dst, lhs, rhs }
        | Opcode::EmitIsEq { dst, lhs, rhs }
        | Opcode::EmitIsLt { dst, lhs, rhs }
        | Opcode::EmitDiv { dst, lhs, rhs } => {
            buf.push(*dst);
            buf.push(*lhs);
            buf.push(*rhs);
        }
        Opcode::EmitIsLtBounded {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            buf.push(*dst);
            buf.push(*lhs);
            buf.push(*rhs);
            buf.push(*max_bits);
        }
        Opcode::EmitNeg { dst, operand } => {
            buf.push(*dst);
            buf.push(*operand);
        }
        Opcode::EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        } => {
            buf.push(*dst);
            buf.push(*cond);
            buf.push(*then_v);
            buf.push(*else_v);
        }
        Opcode::EmitDecompose {
            dst_arr,
            src,
            n_bits,
        } => {
            buf.push(*dst_arr);
            buf.push(*src);
            buf.push(*n_bits);
        }
        Opcode::EmitAssertEq { lhs, rhs } => {
            buf.push(*lhs);
            buf.push(*rhs);
        }
        Opcode::EmitAssertEqMsg { lhs, rhs, msg_idx } => {
            buf.push(*lhs);
            buf.push(*rhs);
            buf.extend_from_slice(&msg_idx.to_le_bytes());
        }
        Opcode::EmitRangeCheck { var, max_bits } => {
            buf.push(*var);
            buf.push(*max_bits);
        }
        Opcode::EmitWitnessCall {
            bytecode_const_idx,
            in_regs,
            out_regs,
        } => {
            buf.extend_from_slice(&bytecode_const_idx.to_le_bytes());
            buf.push(in_regs.len() as u8);
            buf.extend_from_slice(in_regs);
            buf.push(out_regs.len() as u8);
            buf.extend_from_slice(out_regs);
        }
        Opcode::EmitPoseidonHash { dst, in_regs } => {
            buf.push(*dst);
            buf.push(in_regs.len() as u8);
            buf.extend_from_slice(in_regs);
        }
        Opcode::EmitIntDiv {
            dst,
            lhs,
            rhs,
            max_bits,
        }
        | Opcode::EmitIntMod {
            dst,
            lhs,
            rhs,
            max_bits,
        } => {
            buf.push(*dst);
            buf.push(*lhs);
            buf.push(*rhs);
            buf.push(*max_bits);
        }
        // StoreHeap.src_reg and LoadHeap.dst_reg are distinct fields
        // semantically (one reads a reg, one writes one) but identical
        // on the wire — both are `u8 reg + u32 slot`. The shared
        // pattern keeps the encoder honest about that.
        Opcode::StoreHeap { src_reg: reg, slot } | Opcode::LoadHeap { dst_reg: reg, slot } => {
            buf.push(*reg);
            buf.extend_from_slice(&slot.to_le_bytes());
        }
        // EmitWitnessCallHeap is the heap-output twin of
        // EmitWitnessCall. Inputs and outputs both length-prefixed
        // by `u16` (so the design supports up to 65535 of each, well
        // above the SHA-256 ~700-input + 256-output worst case — a
        // single call's input/output arity is structurally bounded by
        // the Artik program, not by circuit size, so the count prefix
        // stays u16). Each input is tagged Reg(u8) or Slot(u32) so the
        // executor
        // can read it from a frame register or a heap slot without
        // an intermediate LoadHeap emit.
        Opcode::EmitWitnessCallHeap {
            bytecode_const_idx,
            inputs,
            out_slots,
        } => {
            buf.extend_from_slice(&bytecode_const_idx.to_le_bytes());
            buf.extend_from_slice(&(inputs.len() as u16).to_le_bytes());
            for input in inputs.iter() {
                match input {
                    InputSrc::Reg(reg) => {
                        buf.push(INPUT_SRC_REG);
                        buf.push(*reg);
                    }
                    InputSrc::Slot(slot) => {
                        buf.push(INPUT_SRC_SLOT);
                        buf.extend_from_slice(&slot.to_le_bytes());
                    }
                }
            }
            buf.extend_from_slice(&(out_slots.len() as u16).to_le_bytes());
            for slot in out_slots.iter() {
                buf.extend_from_slice(&slot.to_le_bytes());
            }
        }
    }
}
