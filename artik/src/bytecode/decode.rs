//! Decode wire bytes to a validated `Program`.

use memory::FieldFamily;

use crate::error::ArtikError;
use crate::header::{ArtikHeader, HEADER_SIZE};
use crate::ir::{ElemT, Instr, IntBinOp, IntW, OpTag};
use crate::program::{FieldConstEntry, Program};
use crate::validate::validate;

/// Read the full byte buffer and produce a `Program`. Runs the
/// structural validator before returning so executor-level code may
/// assume every invariant.
///
/// `expected_family` allows the caller to assert that the bytecode was
/// emitted for a compatible field family. Passing `None` accepts any
/// family declared in the header; this is useful for tooling (e.g.
/// disassemblers) but execution paths should always pin the family.
pub fn decode(bytes: &[u8], expected_family: Option<FieldFamily>) -> Result<Program, ArtikError> {
    if bytes.len() < HEADER_SIZE {
        return Err(ArtikError::UnexpectedEof {
            needed: HEADER_SIZE,
            remaining: bytes.len(),
        });
    }
    let header = ArtikHeader::decode_prefix(&bytes[..HEADER_SIZE])?;

    if let Some(expected) = expected_family {
        if header.family != expected {
            return Err(ArtikError::FieldFamilyMismatch {
                declared: header.family as u8,
                expected: expected as u8,
            });
        }
    }

    let cp_start = HEADER_SIZE;
    let cp_end = cp_start + header.const_pool_len as usize;
    let body_end = cp_end + header.body_len as usize;
    if bytes.len() < body_end {
        return Err(ArtikError::UnexpectedEof {
            needed: body_end,
            remaining: bytes.len(),
        });
    }

    let const_pool = decode_const_pool(&bytes[cp_start..cp_end], header.family)?;
    let body_bytes = &bytes[cp_end..body_end];
    if body_bytes.len() < 4 {
        return Err(ArtikError::UnexpectedEof {
            needed: 4,
            remaining: body_bytes.len(),
        });
    }
    let frame_size =
        u32::from_le_bytes([body_bytes[0], body_bytes[1], body_bytes[2], body_bytes[3]]);
    let (instrs, offsets) = decode_instrs(&body_bytes[4..])?;

    let mut header = header;
    header.frame_size = frame_size;

    let program = Program {
        header,
        const_pool,
        frame_size,
        body: instrs,
    };

    validate(&program, &offsets)?;
    Ok(program)
}

fn decode_const_pool(
    bytes: &[u8],
    family: FieldFamily,
) -> Result<Vec<FieldConstEntry>, ArtikError> {
    let max = family.max_const_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let len = bytes[i] as usize;
        i += 1;
        if i + len > bytes.len() {
            return Err(ArtikError::UnexpectedEof {
                needed: len,
                remaining: bytes.len() - i,
            });
        }
        if len > max {
            return Err(ArtikError::ConstTooLarge { len, max });
        }
        out.push(FieldConstEntry {
            bytes: bytes[i..i + len].to_vec(),
        });
        i += len;
    }
    Ok(out)
}

/// Decode the instruction stream. Returns the list of instructions
/// plus a parallel vector of byte offsets so validation can translate
/// jump targets (which are byte offsets inside the instruction stream
/// relative to the stream start — **not** including the 4-byte frame
/// size prelude) into instruction indices.
fn decode_instrs(bytes: &[u8]) -> Result<(Vec<Instr>, Vec<u32>), ArtikError> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    let mut cur = Cursor::new(bytes);
    while !cur.is_empty() {
        let instr_offset = cur.offset() as u32;
        offsets.push(instr_offset);
        let tag = cur.u8()?;
        let tag = OpTag::from_u8(tag).ok_or(ArtikError::UnknownOpcode(tag))?;
        let instr = match tag {
            OpTag::Jump => Instr::Jump { target: cur.u32()? },
            OpTag::JumpIf => Instr::JumpIf {
                cond: cur.u32()?,
                target: cur.u32()?,
            },
            OpTag::Return => Instr::Return,
            OpTag::Trap => Instr::Trap { code: cur.u16()? },
            OpTag::PushConst => Instr::PushConst {
                dst: cur.u32()?,
                const_id: cur.u32()?,
            },
            OpTag::ReadSignal => Instr::ReadSignal {
                dst: cur.u32()?,
                signal_id: cur.u32()?,
            },
            OpTag::WriteWitness => Instr::WriteWitness {
                slot_id: cur.u32()?,
                src: cur.u32()?,
            },
            OpTag::FAdd => Instr::FAdd {
                dst: cur.u32()?,
                a: cur.u32()?,
                b: cur.u32()?,
            },
            OpTag::FSub => Instr::FSub {
                dst: cur.u32()?,
                a: cur.u32()?,
                b: cur.u32()?,
            },
            OpTag::FMul => Instr::FMul {
                dst: cur.u32()?,
                a: cur.u32()?,
                b: cur.u32()?,
            },
            OpTag::FDiv => Instr::FDiv {
                dst: cur.u32()?,
                a: cur.u32()?,
                b: cur.u32()?,
            },
            OpTag::FInv => Instr::FInv {
                dst: cur.u32()?,
                src: cur.u32()?,
            },
            OpTag::FEq => Instr::FEq {
                dst: cur.u32()?,
                a: cur.u32()?,
                b: cur.u32()?,
            },
            OpTag::IBin => {
                let op_byte = cur.u8()?;
                let w_byte = cur.u8()?;
                let op = IntBinOp::from_u8(op_byte).ok_or(ArtikError::UnknownIntBinOp(op_byte))?;
                let w = IntW::from_u8(w_byte).ok_or(ArtikError::UnknownIntWidth(w_byte))?;
                Instr::IBin {
                    op,
                    w,
                    dst: cur.u32()?,
                    a: cur.u32()?,
                    b: cur.u32()?,
                }
            }
            OpTag::INot => {
                let w_byte = cur.u8()?;
                let w = IntW::from_u8(w_byte).ok_or(ArtikError::UnknownIntWidth(w_byte))?;
                Instr::INot {
                    w,
                    dst: cur.u32()?,
                    src: cur.u32()?,
                }
            }
            OpTag::Rotl32 => Instr::Rotl32 {
                dst: cur.u32()?,
                src: cur.u32()?,
                n: cur.u32()?,
            },
            OpTag::Rotr32 => Instr::Rotr32 {
                dst: cur.u32()?,
                src: cur.u32()?,
                n: cur.u32()?,
            },
            OpTag::Rotl8 => Instr::Rotl8 {
                dst: cur.u32()?,
                src: cur.u32()?,
                n: cur.u32()?,
            },
            OpTag::IntFromField => {
                let w_byte = cur.u8()?;
                let w = IntW::from_u8(w_byte).ok_or(ArtikError::UnknownIntWidth(w_byte))?;
                Instr::IntFromField {
                    w,
                    dst: cur.u32()?,
                    src: cur.u32()?,
                }
            }
            OpTag::FieldFromInt => {
                let w_byte = cur.u8()?;
                let w = IntW::from_u8(w_byte).ok_or(ArtikError::UnknownIntWidth(w_byte))?;
                Instr::FieldFromInt {
                    dst: cur.u32()?,
                    src: cur.u32()?,
                    w,
                }
            }
            OpTag::AllocArray => {
                let elem_byte = cur.u8()?;
                let elem =
                    ElemT::from_u8(elem_byte).ok_or(ArtikError::UnknownElemTag(elem_byte))?;
                Instr::AllocArray {
                    elem,
                    dst: cur.u32()?,
                    len: cur.u32()?,
                }
            }
            OpTag::LoadArr => Instr::LoadArr {
                dst: cur.u32()?,
                arr: cur.u32()?,
                idx: cur.u32()?,
            },
            OpTag::StoreArr => Instr::StoreArr {
                arr: cur.u32()?,
                idx: cur.u32()?,
                val: cur.u32()?,
            },
        };
        out.push(instr);
    }
    Ok((out, offsets))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn offset(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ArtikError> {
        if self.pos + n > self.bytes.len() {
            return Err(ArtikError::UnexpectedEof {
                needed: n,
                remaining: self.bytes.len() - self.pos,
            });
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ArtikError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ArtikError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, ArtikError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}
