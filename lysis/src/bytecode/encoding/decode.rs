use memory::field::FieldBackend;

use crate::bytecode::opcode::{code, InputSrc, Opcode, INPUT_SRC_REG, INPUT_SRC_SLOT};
use crate::bytecode::ConstPool;
use crate::error::LysisError;
use crate::header::LysisHeader;
use crate::intern::Visibility;
use crate::program::{Instr, Program, Template};

/// Decode a full program from canonical bytes. Returns the structural
/// form of [`Program`] plus an implicit `templates` vector harvested
/// from `DefineTemplate` opcodes. Semantic validation is
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

pub(super) fn decode_opcode_at(
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
            let idx = read_u32(bytes, pos)?;
            Ok(Opcode::LoadConst { dst, idx })
        }
        code::LOAD_INPUT => {
            let dst = read_u8(bytes, pos)?;
            let name_idx = read_u32(bytes, pos)?;
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
                capture_regs: Box::new(capture_regs),
                output_regs: Box::new(output_regs),
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
        code::EMIT_IS_LT_BOUNDED => {
            let dst = read_u8(bytes, pos)?;
            let lhs = read_u8(bytes, pos)?;
            let rhs = read_u8(bytes, pos)?;
            let max_bits = read_u8(bytes, pos)?;
            Ok(Opcode::EmitIsLtBounded {
                dst,
                lhs,
                rhs,
                max_bits,
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
            let msg_idx = read_u32(bytes, pos)?;
            Ok(Opcode::EmitAssertEqMsg { lhs, rhs, msg_idx })
        }
        code::EMIT_RANGE_CHECK => {
            let var = read_u8(bytes, pos)?;
            let max_bits = read_u8(bytes, pos)?;
            Ok(Opcode::EmitRangeCheck { var, max_bits })
        }
        code::EMIT_WITNESS_CALL => {
            let bytecode_const_idx = read_u32(bytes, pos)?;
            let in_regs = read_length_prefixed_regs(bytes, pos)?;
            let out_regs = read_length_prefixed_regs(bytes, pos)?;
            Ok(Opcode::EmitWitnessCall {
                bytecode_const_idx,
                in_regs: Box::new(in_regs),
                out_regs: Box::new(out_regs),
            })
        }
        code::EMIT_POSEIDON_HASH => {
            let dst = read_u8(bytes, pos)?;
            let in_regs = read_length_prefixed_regs(bytes, pos)?;
            Ok(Opcode::EmitPoseidonHash {
                dst,
                in_regs: Box::new(in_regs),
            })
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
            let slot = read_u32(bytes, pos)?;
            Ok(Opcode::StoreHeap { src_reg, slot })
        }
        code::LOAD_HEAP => {
            let dst_reg = read_u8(bytes, pos)?;
            let slot = read_u32(bytes, pos)?;
            Ok(Opcode::LoadHeap { dst_reg, slot })
        }
        code::EMIT_WITNESS_CALL_HEAP => {
            let bytecode_const_idx = read_u32(bytes, pos)?;
            let n_in = read_u16(bytes, pos)? as usize;
            let mut inputs = Vec::with_capacity(n_in);
            for _ in 0..n_in {
                let tag = read_u8(bytes, pos)?;
                let src = match tag {
                    INPUT_SRC_REG => InputSrc::Reg(read_u8(bytes, pos)?),
                    INPUT_SRC_SLOT => InputSrc::Slot(read_u32(bytes, pos)?),
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
                out_slots.push(read_u32(bytes, pos)?);
            }
            Ok(Opcode::EmitWitnessCallHeap {
                bytecode_const_idx,
                inputs: Box::new(inputs),
                out_slots: Box::new(out_slots),
            })
        }
        other => Err(LysisError::UnknownOpcode {
            code: other,
            at_offset: instr_offset,
        }),
    }
}
