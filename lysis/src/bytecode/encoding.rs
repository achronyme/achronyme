//! Bytecode encode / decode for Lysis programs.
//!
//! The entry points are [`encode`] and [`decode`]:
//!
//! ```text
//! encode:  &Program<F>  →  Vec<u8>
//! decode:  &[u8]        →  Program<F>          (structural-decode only)
//! ```
//!
//! Decoding is split into two passes, matching what a validator wants:
//!
//! 1. **Structural decode** (this module): read the header, walk the
//!    const pool, and linearly scan the body producing a
//!    `Vec<Instr>` + a parallel `Vec<Template>` harvested from
//!    `DefineTemplate` opcodes. Fails fast on truncated input or
//!    unknown opcodes.
//! 2. **Semantic validation** ([`super::validate`]): the 11 rules of
//!    RFC §4.5. Operates on the decoded `Program` and never looks at
//!    raw bytes.
//!
//! Every operand here is little-endian, matching RFC §4.3 and the
//! encoding already used by Artik.

use memory::field::FieldBackend;

use crate::bytecode::opcode::{code, InputSrc, Opcode, INPUT_SRC_REG, INPUT_SRC_SLOT};
use crate::bytecode::ConstPool;
use crate::error::LysisError;
use crate::header::LysisHeader;
use crate::intern::Visibility;
use crate::program::{Instr, Program, Template};

// ---------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------

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
        // on the wire — both are `u8 reg + u16 slot`. The shared
        // pattern keeps the encoder honest about that.
        Opcode::StoreHeap { src_reg: reg, slot } | Opcode::LoadHeap { dst_reg: reg, slot } => {
            buf.push(*reg);
            buf.extend_from_slice(&slot.to_le_bytes());
        }
        // EmitWitnessCallHeap is the heap-output twin of
        // EmitWitnessCall. Inputs and outputs both length-prefixed
        // by `u16` (so the design supports up to 65535 of each, well
        // above the SHA-256 ~700-input + 256-output worst case).
        // Each input is tagged Reg(u8) or Slot(u16) so the executor
        // can read it from a frame register or a heap slot without
        // an intermediate LoadHeap emit.
        Opcode::EmitWitnessCallHeap {
            bytecode_const_idx,
            inputs,
            out_slots,
        } => {
            buf.extend_from_slice(&bytecode_const_idx.to_le_bytes());
            buf.extend_from_slice(&(inputs.len() as u16).to_le_bytes());
            for input in inputs {
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
            for slot in out_slots {
                buf.extend_from_slice(&slot.to_le_bytes());
            }
        }
    }
}

// ---------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------

/// Decode a full program from canonical bytes. Returns the structural
/// form of [`Program`] plus an implicit `templates` vector harvested
/// from `DefineTemplate` opcodes. Semantic validation (RFC §4.5) is
/// *not* performed here — call [`super::validate`] before handing the
/// program to an executor.
pub fn decode<F: FieldBackend>(bytes: &[u8]) -> Result<Program<F>, LysisError> {
    let header = LysisHeader::decode(bytes)?;

    // Header validates its own length internally, but the slice we
    // consume here has version-dependent size (16 for v1, 18 for v2).
    let header_size = header.size_in_bytes();
    if bytes.len() < header_size {
        return Err(LysisError::UnexpectedEof {
            needed: header_size,
            remaining: bytes.len(),
        });
    }
    let after_header = &bytes[header_size..];
    let (const_pool, pool_used) =
        ConstPool::<F>::decode(after_header, header.const_pool_len, header.family)?;

    let body_bytes = &after_header[pool_used..];
    if body_bytes.len() != header.body_len as usize {
        return Err(LysisError::BodyLenMismatch {
            declared: header.body_len,
            actual: body_bytes.len() as u32,
        });
    }

    let (body, templates) = decode_body(body_bytes)?;

    Ok(Program {
        header,
        const_pool,
        templates,
        body,
    })
}

/// Decode a body byte stream to its instruction vector plus the
/// `Template` table harvested from every `DefineTemplate` encountered.
/// Public so the validator can reuse it on subsets of a body (e.g.,
/// walking a template body slice).
pub fn decode_body(bytes: &[u8]) -> Result<(Vec<Instr>, Vec<Template>), LysisError> {
    let mut body = Vec::new();
    let mut templates = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let offset = pos as u32;
        let op = decode_opcode_at(bytes, &mut pos, offset)?;
        if let Opcode::DefineTemplate {
            template_id,
            frame_size,
            n_params,
            body_offset,
            body_len,
        } = &op
        {
            templates.push(Template {
                id: *template_id,
                frame_size: *frame_size,
                n_params: *n_params,
                body_offset: *body_offset,
                body_len: *body_len,
            });
        }
        body.push(Instr { opcode: op, offset });
    }
    Ok((body, templates))
}

fn take(bytes: &[u8], pos: &mut usize, n: usize, offset: u32) -> Result<(), LysisError> {
    if *pos + n > bytes.len() {
        return Err(LysisError::UnexpectedEof {
            needed: n,
            remaining: bytes.len().saturating_sub(*pos),
        });
    }
    // Caller advances the cursor via read_* below; this fn is a bounds
    // check paired with those.
    let _ = offset;
    let _ = n;
    Ok(())
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8, LysisError> {
    take(bytes, pos, 1, *pos as u32)?;
    let v = bytes[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, LysisError> {
    take(bytes, pos, 2, *pos as u32)?;
    let v = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_i16(bytes: &[u8], pos: &mut usize) -> Result<i16, LysisError> {
    take(bytes, pos, 2, *pos as u32)?;
    let v = i16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, LysisError> {
    take(bytes, pos, 4, *pos as u32)?;
    let v = u32::from_le_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
    ]);
    *pos += 4;
    Ok(v)
}

fn read_length_prefixed_regs(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>, LysisError> {
    let n = read_u8(bytes, pos)? as usize;
    take(bytes, pos, n, *pos as u32)?;
    let out = bytes[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(out)
}

fn decode_opcode_at(
    bytes: &[u8],
    pos: &mut usize,
    instr_offset: u32,
) -> Result<Opcode, LysisError> {
    let op_byte = read_u8(bytes, pos)?;
    match op_byte {
        code::LOAD_CAPTURE => {
            let dst = read_u8(bytes, pos)?;
            let idx = read_u16(bytes, pos)?;
            Ok(Opcode::LoadCapture { dst, idx })
        }
        code::LOAD_CONST => {
            let dst = read_u8(bytes, pos)?;
            let idx = read_u16(bytes, pos)?;
            Ok(Opcode::LoadConst { dst, idx })
        }
        code::LOAD_INPUT => {
            let dst = read_u8(bytes, pos)?;
            let name_idx = read_u16(bytes, pos)?;
            let vis_byte = read_u8(bytes, pos)?;
            let vis = Visibility::from_u8(vis_byte).ok_or(LysisError::BadVisibility {
                at_offset: instr_offset,
                got: vis_byte,
            })?;
            Ok(Opcode::LoadInput { dst, name_idx, vis })
        }
        code::ENTER_SCOPE => Ok(Opcode::EnterScope),
        code::EXIT_SCOPE => Ok(Opcode::ExitScope),
        code::JUMP => Ok(Opcode::Jump {
            offset: read_i16(bytes, pos)?,
        }),
        code::JUMP_IF => {
            let cond = read_u8(bytes, pos)?;
            let offset = read_i16(bytes, pos)?;
            Ok(Opcode::JumpIf { cond, offset })
        }
        code::RETURN => Ok(Opcode::Return),
        code::HALT => Ok(Opcode::Halt),
        code::TRAP => Ok(Opcode::Trap {
            code: read_u8(bytes, pos)?,
        }),
        code::LOOP_UNROLL => {
            let iter_var = read_u8(bytes, pos)?;
            let start = read_u32(bytes, pos)?;
            let end = read_u32(bytes, pos)?;
            let body_len = read_u16(bytes, pos)?;
            Ok(Opcode::LoopUnroll {
                iter_var,
                start,
                end,
                body_len,
            })
        }
        code::LOOP_ROLLED => {
            let iter_var = read_u8(bytes, pos)?;
            let start = read_u32(bytes, pos)?;
            let end = read_u32(bytes, pos)?;
            let body_template_id = read_u16(bytes, pos)?;
            Ok(Opcode::LoopRolled {
                iter_var,
                start,
                end,
                body_template_id,
            })
        }
        code::LOOP_RANGE => {
            let iter_var = read_u8(bytes, pos)?;
            let end_reg = read_u8(bytes, pos)?;
            let body_template_id = read_u16(bytes, pos)?;
            Ok(Opcode::LoopRange {
                iter_var,
                end_reg,
                body_template_id,
            })
        }
        code::DEFINE_TEMPLATE => {
            let template_id = read_u16(bytes, pos)?;
            let frame_size = read_u8(bytes, pos)?;
            let n_params = read_u8(bytes, pos)?;
            let body_offset = read_u32(bytes, pos)?;
            let body_len = read_u32(bytes, pos)?;
            Ok(Opcode::DefineTemplate {
                template_id,
                frame_size,
                n_params,
                body_offset,
                body_len,
            })
        }
        code::INSTANTIATE_TEMPLATE => {
            let template_id = read_u16(bytes, pos)?;
            let capture_regs = read_length_prefixed_regs(bytes, pos)?;
            let output_regs = read_length_prefixed_regs(bytes, pos)?;
            Ok(Opcode::InstantiateTemplate {
                template_id,
                capture_regs,
                output_regs,
            })
        }
        code::TEMPLATE_OUTPUT => {
            let output_idx = read_u8(bytes, pos)?;
            let src_reg = read_u8(bytes, pos)?;
            Ok(Opcode::TemplateOutput {
                output_idx,
                src_reg,
            })
        }
        code::EMIT_CONST => {
            let dst = read_u8(bytes, pos)?;
            let src_reg = read_u8(bytes, pos)?;
            Ok(Opcode::EmitConst { dst, src_reg })
        }
        c @ (code::EMIT_ADD
        | code::EMIT_SUB
        | code::EMIT_MUL
        | code::EMIT_IS_EQ
        | code::EMIT_IS_LT
        | code::EMIT_DIV) => {
            let dst = read_u8(bytes, pos)?;
            let lhs = read_u8(bytes, pos)?;
            let rhs = read_u8(bytes, pos)?;
            Ok(match c {
                code::EMIT_ADD => Opcode::EmitAdd { dst, lhs, rhs },
                code::EMIT_SUB => Opcode::EmitSub { dst, lhs, rhs },
                code::EMIT_MUL => Opcode::EmitMul { dst, lhs, rhs },
                code::EMIT_IS_EQ => Opcode::EmitIsEq { dst, lhs, rhs },
                code::EMIT_IS_LT => Opcode::EmitIsLt { dst, lhs, rhs },
                code::EMIT_DIV => Opcode::EmitDiv { dst, lhs, rhs },
                _ => unreachable!("match guard covers only these 6"),
            })
        }
        code::EMIT_NEG => {
            let dst = read_u8(bytes, pos)?;
            let operand = read_u8(bytes, pos)?;
            Ok(Opcode::EmitNeg { dst, operand })
        }
        code::EMIT_MUX => {
            let dst = read_u8(bytes, pos)?;
            let cond = read_u8(bytes, pos)?;
            let then_v = read_u8(bytes, pos)?;
            let else_v = read_u8(bytes, pos)?;
            Ok(Opcode::EmitMux {
                dst,
                cond,
                then_v,
                else_v,
            })
        }
        code::EMIT_DECOMPOSE => {
            let dst_arr = read_u8(bytes, pos)?;
            let src = read_u8(bytes, pos)?;
            let n_bits = read_u8(bytes, pos)?;
            Ok(Opcode::EmitDecompose {
                dst_arr,
                src,
                n_bits,
            })
        }
        code::EMIT_ASSERT_EQ => {
            let lhs = read_u8(bytes, pos)?;
            let rhs = read_u8(bytes, pos)?;
            Ok(Opcode::EmitAssertEq { lhs, rhs })
        }
        code::EMIT_ASSERT_EQ_MSG => {
            let lhs = read_u8(bytes, pos)?;
            let rhs = read_u8(bytes, pos)?;
            let msg_idx = read_u16(bytes, pos)?;
            Ok(Opcode::EmitAssertEqMsg { lhs, rhs, msg_idx })
        }
        code::EMIT_RANGE_CHECK => {
            let var = read_u8(bytes, pos)?;
            let max_bits = read_u8(bytes, pos)?;
            Ok(Opcode::EmitRangeCheck { var, max_bits })
        }
        code::EMIT_WITNESS_CALL => {
            let bytecode_const_idx = read_u16(bytes, pos)?;
            let in_regs = read_length_prefixed_regs(bytes, pos)?;
            let out_regs = read_length_prefixed_regs(bytes, pos)?;
            Ok(Opcode::EmitWitnessCall {
                bytecode_const_idx,
                in_regs,
                out_regs,
            })
        }
        code::EMIT_POSEIDON_HASH => {
            let dst = read_u8(bytes, pos)?;
            let in_regs = read_length_prefixed_regs(bytes, pos)?;
            Ok(Opcode::EmitPoseidonHash { dst, in_regs })
        }
        c @ (code::EMIT_INT_DIV | code::EMIT_INT_MOD) => {
            let dst = read_u8(bytes, pos)?;
            let lhs = read_u8(bytes, pos)?;
            let rhs = read_u8(bytes, pos)?;
            let max_bits = read_u8(bytes, pos)?;
            Ok(match c {
                code::EMIT_INT_DIV => Opcode::EmitIntDiv {
                    dst,
                    lhs,
                    rhs,
                    max_bits,
                },
                code::EMIT_INT_MOD => Opcode::EmitIntMod {
                    dst,
                    lhs,
                    rhs,
                    max_bits,
                },
                _ => unreachable!("match guard covers only these 2"),
            })
        }
        code::STORE_HEAP => {
            let src_reg = read_u8(bytes, pos)?;
            let slot = read_u16(bytes, pos)?;
            Ok(Opcode::StoreHeap { src_reg, slot })
        }
        code::LOAD_HEAP => {
            let dst_reg = read_u8(bytes, pos)?;
            let slot = read_u16(bytes, pos)?;
            Ok(Opcode::LoadHeap { dst_reg, slot })
        }
        code::EMIT_WITNESS_CALL_HEAP => {
            let bytecode_const_idx = read_u16(bytes, pos)?;
            let n_in = read_u16(bytes, pos)? as usize;
            let mut inputs = Vec::with_capacity(n_in);
            for _ in 0..n_in {
                let tag = read_u8(bytes, pos)?;
                let src = match tag {
                    INPUT_SRC_REG => InputSrc::Reg(read_u8(bytes, pos)?),
                    INPUT_SRC_SLOT => InputSrc::Slot(read_u16(bytes, pos)?),
                    _ => {
                        return Err(LysisError::ValidationFailed {
                            rule: 4,
                            location: instr_offset,
                            detail: "EmitWitnessCallHeap input source has unknown tag",
                        });
                    }
                };
                inputs.push(src);
            }
            let n_out = read_u16(bytes, pos)? as usize;
            let mut out_slots = Vec::with_capacity(n_out);
            for _ in 0..n_out {
                out_slots.push(read_u16(bytes, pos)?);
            }
            Ok(Opcode::EmitWitnessCallHeap {
                bytecode_const_idx,
                inputs,
                out_slots,
            })
        }
        other => Err(LysisError::UnknownOpcode {
            code: other,
            at_offset: instr_offset,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::field::{Bn254Fr, FieldElement};
    use memory::FieldFamily;

    use crate::bytecode::const_pool::{ConstPool, ConstPoolEntry};
    use crate::header::LysisHeader;

    fn roundtrip_opcode(op: Opcode) {
        let mut buf = Vec::new();
        encode_opcode(&op, &mut buf);
        let mut pos = 0usize;
        let decoded = decode_opcode_at(&buf, &mut pos, 0).unwrap();
        assert_eq!(pos, buf.len(), "{op:?} did not consume all bytes");
        assert_eq!(decoded, op);
    }

    #[test]
    fn roundtrip_every_zero_operand_opcode() {
        roundtrip_opcode(Opcode::EnterScope);
        roundtrip_opcode(Opcode::ExitScope);
        roundtrip_opcode(Opcode::Return);
        roundtrip_opcode(Opcode::Halt);
    }

    #[test]
    fn roundtrip_capture_family() {
        roundtrip_opcode(Opcode::LoadCapture { dst: 5, idx: 42 });
        roundtrip_opcode(Opcode::LoadConst { dst: 1, idx: 1234 });
        roundtrip_opcode(Opcode::LoadInput {
            dst: 7,
            name_idx: 8,
            vis: Visibility::Public,
        });
        roundtrip_opcode(Opcode::LoadInput {
            dst: 9,
            name_idx: 2,
            vis: Visibility::Witness,
        });
    }

    #[test]
    fn roundtrip_control_flow() {
        roundtrip_opcode(Opcode::Jump { offset: -17 });
        roundtrip_opcode(Opcode::Jump { offset: 100 });
        roundtrip_opcode(Opcode::JumpIf {
            cond: 3,
            offset: -5,
        });
        roundtrip_opcode(Opcode::Trap { code: 0x42 });
    }

    #[test]
    fn roundtrip_loop_ops() {
        roundtrip_opcode(Opcode::LoopUnroll {
            iter_var: 1,
            start: 0,
            end: 64,
            body_len: 32,
        });
        roundtrip_opcode(Opcode::LoopRolled {
            iter_var: 2,
            start: 0,
            end: 8,
            body_template_id: 3,
        });
        roundtrip_opcode(Opcode::LoopRange {
            iter_var: 4,
            end_reg: 5,
            body_template_id: 6,
        });
    }

    #[test]
    fn roundtrip_template_ops() {
        roundtrip_opcode(Opcode::DefineTemplate {
            template_id: 1,
            frame_size: 16,
            n_params: 2,
            body_offset: 128,
            body_len: 256,
        });
        roundtrip_opcode(Opcode::InstantiateTemplate {
            template_id: 2,
            capture_regs: vec![3, 4, 5],
            output_regs: vec![6, 7],
        });
        roundtrip_opcode(Opcode::TemplateOutput {
            output_idx: 1,
            src_reg: 8,
        });
    }

    #[test]
    fn roundtrip_emit_rrr_family() {
        roundtrip_opcode(Opcode::EmitAdd {
            dst: 1,
            lhs: 2,
            rhs: 3,
        });
        roundtrip_opcode(Opcode::EmitSub {
            dst: 4,
            lhs: 5,
            rhs: 6,
        });
        roundtrip_opcode(Opcode::EmitMul {
            dst: 7,
            lhs: 8,
            rhs: 9,
        });
        roundtrip_opcode(Opcode::EmitIsEq {
            dst: 10,
            lhs: 11,
            rhs: 12,
        });
        roundtrip_opcode(Opcode::EmitIsLt {
            dst: 13,
            lhs: 14,
            rhs: 15,
        });
        roundtrip_opcode(Opcode::EmitDiv {
            dst: 16,
            lhs: 17,
            rhs: 18,
        });
    }

    #[test]
    fn roundtrip_emit_variable_length() {
        roundtrip_opcode(Opcode::EmitPoseidonHash {
            dst: 1,
            in_regs: vec![2, 3, 4, 5],
        });
        roundtrip_opcode(Opcode::EmitWitnessCall {
            bytecode_const_idx: 7,
            in_regs: vec![1, 2],
            out_regs: vec![3, 4, 5],
        });
    }

    #[test]
    fn roundtrip_emit_witness_call_heap() {
        // Smoke + boundary: empty inputs/outputs, mixed Reg/Slot
        // inputs, and a 256-output case (the SHA-256 hash motivating
        // WitnessCallHeap).
        roundtrip_opcode(Opcode::EmitWitnessCallHeap {
            bytecode_const_idx: 0,
            inputs: vec![],
            out_slots: vec![],
        });
        roundtrip_opcode(Opcode::EmitWitnessCallHeap {
            bytecode_const_idx: 42,
            inputs: vec![InputSrc::Reg(1), InputSrc::Slot(2), InputSrc::Reg(3)],
            out_slots: vec![100, 101, 102],
        });
        let big_outputs: Vec<u16> = (0u16..256).collect();
        roundtrip_opcode(Opcode::EmitWitnessCallHeap {
            bytecode_const_idx: 0xCAFE,
            inputs: vec![InputSrc::Reg(1), InputSrc::Reg(2)],
            out_slots: big_outputs,
        });
    }

    #[test]
    fn emit_witness_call_heap_handles_u16_input_and_output_counts() {
        // Wire format invariant: input and output count fields are
        // both u16 — the design supports up to 65535 of each, well
        // above any expected workload.
        let big_inputs: Vec<InputSrc> = (0u16..1024).map(InputSrc::Slot).collect();
        let big_outputs: Vec<u16> = (0u16..1024).collect();
        roundtrip_opcode(Opcode::EmitWitnessCallHeap {
            bytecode_const_idx: 1,
            inputs: big_inputs,
            out_slots: big_outputs,
        });
    }

    #[test]
    fn roundtrip_remaining_emit_ops() {
        roundtrip_opcode(Opcode::EmitConst { dst: 1, src_reg: 2 });
        roundtrip_opcode(Opcode::EmitNeg { dst: 3, operand: 4 });
        roundtrip_opcode(Opcode::EmitMux {
            dst: 5,
            cond: 6,
            then_v: 7,
            else_v: 8,
        });
        roundtrip_opcode(Opcode::EmitDecompose {
            dst_arr: 9,
            src: 10,
            n_bits: 8,
        });
        roundtrip_opcode(Opcode::EmitAssertEq { lhs: 11, rhs: 12 });
        roundtrip_opcode(Opcode::EmitAssertEqMsg {
            lhs: 11,
            rhs: 12,
            msg_idx: 0,
        });
        roundtrip_opcode(Opcode::EmitAssertEqMsg {
            lhs: 200,
            rhs: 201,
            msg_idx: u16::MAX,
        });
        roundtrip_opcode(Opcode::EmitRangeCheck {
            var: 13,
            max_bits: 64,
        });
    }

    #[test]
    fn roundtrip_heap_ops() {
        // Sample edge cases for the u16 slot field: zero, mid-range,
        // and the maximum so a regression on slot width (e.g.,
        // accidental u8 truncation) trips the test.
        roundtrip_opcode(Opcode::StoreHeap {
            src_reg: 0,
            slot: 0,
        });
        roundtrip_opcode(Opcode::StoreHeap {
            src_reg: 17,
            slot: 4096,
        });
        roundtrip_opcode(Opcode::StoreHeap {
            src_reg: 255,
            slot: u16::MAX,
        });
        roundtrip_opcode(Opcode::LoadHeap {
            dst_reg: 0,
            slot: 0,
        });
        roundtrip_opcode(Opcode::LoadHeap {
            dst_reg: 42,
            slot: 12345,
        });
        roundtrip_opcode(Opcode::LoadHeap {
            dst_reg: 255,
            slot: u16::MAX,
        });
    }

    #[test]
    fn heap_ops_emit_4_bytes() {
        // Wire-format invariant from research report §2.2: each heap
        // op is `u8 opcode + u8 reg + u16 slot = 4 bytes`. A change
        // in this number is an ABI break.
        let mut buf = Vec::new();
        encode_opcode(
            &Opcode::StoreHeap {
                src_reg: 7,
                slot: 0xDEAD,
            },
            &mut buf,
        );
        assert_eq!(buf.len(), 4, "StoreHeap must encode to exactly 4 bytes");
        let mut buf = Vec::new();
        encode_opcode(
            &Opcode::LoadHeap {
                dst_reg: 7,
                slot: 0xBEEF,
            },
            &mut buf,
        );
        assert_eq!(buf.len(), 4, "LoadHeap must encode to exactly 4 bytes");
    }

    #[test]
    fn heap_ops_round_trip_through_full_decode_body() {
        // The decoder's `decode_body` path must accept heap ops
        // alongside other opcodes. This is the integration check that
        // pairs with `roundtrip_heap_ops` (which goes through the
        // single-opcode helper).
        let mut buf = Vec::new();
        encode_opcode(
            &Opcode::StoreHeap {
                src_reg: 3,
                slot: 100,
            },
            &mut buf,
        );
        encode_opcode(&Opcode::Halt, &mut buf);
        encode_opcode(
            &Opcode::LoadHeap {
                dst_reg: 4,
                slot: 100,
            },
            &mut buf,
        );
        encode_opcode(&Opcode::Return, &mut buf);
        let (body, templates) = decode_body(&buf).unwrap();
        assert!(templates.is_empty());
        assert_eq!(body.len(), 4);
        assert_eq!(
            body[0].opcode,
            Opcode::StoreHeap {
                src_reg: 3,
                slot: 100,
            }
        );
        assert_eq!(
            body[2].opcode,
            Opcode::LoadHeap {
                dst_reg: 4,
                slot: 100
            }
        );
    }

    #[test]
    fn full_program_roundtrips() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        pool.push(ConstPoolEntry::String("in".to_owned()));

        let body = vec![
            Instr {
                opcode: Opcode::LoadInput {
                    dst: 0,
                    name_idx: 0,
                    vis: Visibility::Witness,
                },
                offset: 0,
            },
            Instr {
                opcode: Opcode::EmitRangeCheck {
                    var: 0,
                    max_bits: 8,
                },
                offset: 5,
            },
            Instr {
                opcode: Opcode::Halt,
                offset: 8,
            },
        ];

        // Serialize body once to measure length.
        let body_bytes: Vec<u8> = {
            let mut b = Vec::new();
            for instr in &body {
                encode_opcode(&instr.opcode, &mut b);
            }
            b
        };

        let header = LysisHeader::new(
            FieldFamily::BnLike256,
            0,
            pool.len() as u32,
            body_bytes.len() as u32,
        );

        let program = Program {
            header,
            const_pool: pool,
            templates: Vec::new(),
            body,
        };

        let bytes = encode(&program);
        let decoded = decode::<Bn254Fr>(&bytes).unwrap();
        assert_eq!(decoded.header.body_len, program.header.body_len);
        assert_eq!(decoded.body.len(), program.body.len());
        for (a, b) in decoded.body.iter().zip(program.body.iter()) {
            assert_eq!(a.opcode, b.opcode);
        }
    }

    #[test]
    fn decode_rejects_unknown_opcode() {
        let header = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 1);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.encode());
        bytes.push(0xEE); // unknown opcode
        let err = decode::<Bn254Fr>(&bytes).unwrap_err();
        assert!(matches!(err, LysisError::UnknownOpcode { code: 0xEE, .. }));
    }

    #[test]
    fn decode_rejects_bad_visibility() {
        let header = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 5);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.encode());
        bytes.push(code::LOAD_INPUT);
        bytes.push(0); // dst
        bytes.extend_from_slice(&0u16.to_le_bytes()); // name_idx
        bytes.push(9); // bad visibility
        let err = decode::<Bn254Fr>(&bytes).unwrap_err();
        assert!(matches!(err, LysisError::BadVisibility { got: 9, .. }));
    }

    #[test]
    fn decode_rejects_body_len_mismatch() {
        // Header says body_len=10 but only 1 byte follows.
        let header = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 10);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.encode());
        bytes.push(code::HALT);
        let err = decode::<Bn254Fr>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            LysisError::BodyLenMismatch {
                declared: 10,
                actual: 1
            }
        ));
    }

    #[test]
    fn decode_with_template_harvest() {
        let header = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.encode());

        let define = Opcode::DefineTemplate {
            template_id: 3,
            frame_size: 8,
            n_params: 1,
            body_offset: 32,
            body_len: 20,
        };
        let mut body_bytes = Vec::new();
        encode_opcode(&define, &mut body_bytes);
        encode_opcode(&Opcode::Halt, &mut body_bytes);

        bytes[12..16].copy_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body_bytes);

        let program = decode::<Bn254Fr>(&bytes).unwrap();
        assert_eq!(program.templates.len(), 1);
        assert_eq!(program.templates[0].id, 3);
        assert_eq!(program.templates[0].frame_size, 8);
        assert_eq!(program.body.len(), 2);
    }

    #[test]
    fn const_pool_and_body_coexist() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        pool.push(ConstPoolEntry::Field(
            FieldElement::<Bn254Fr>::from_canonical([7, 0, 0, 0]),
        ));
        pool.push(ConstPoolEntry::String("x".to_owned()));

        let mut body_bytes = Vec::new();
        encode_opcode(&Opcode::LoadConst { dst: 0, idx: 0 }, &mut body_bytes);
        encode_opcode(&Opcode::Halt, &mut body_bytes);

        let header = LysisHeader::new(
            FieldFamily::BnLike256,
            0,
            pool.len() as u32,
            body_bytes.len() as u32,
        );

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.encode());
        bytes.extend_from_slice(&pool.encode());
        bytes.extend_from_slice(&body_bytes);

        let program = decode::<Bn254Fr>(&bytes).unwrap();
        assert_eq!(program.const_pool.len(), 2);
        assert_eq!(program.body.len(), 2);
    }
}
