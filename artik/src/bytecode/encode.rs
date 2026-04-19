//! Encode a `Program` to its wire bytes.

use crate::header::HEADER_SIZE;
use crate::ir::{ElemT, Instr, IntBinOp, IntW, OpTag};
use crate::program::Program;

/// Serialize a program to bytes. The output has layout:
///
/// ```text
/// [ 16 bytes header ][ frame_size (4 LE) ][ const pool ][ body ]
/// ```
///
/// The `header.const_pool_len` and `header.body_len` fields are
/// overwritten with the actual encoded sizes. `frame_size` is written
/// as the first 4 bytes of the body region so the validator can read
/// it before any register is checked.
pub fn encode(prog: &Program) -> Vec<u8> {
    let mut const_pool_bytes = Vec::with_capacity(prog.const_pool.len() * 33);
    for entry in &prog.const_pool {
        assert!(entry.bytes.len() <= u8::MAX as usize);
        const_pool_bytes.push(entry.bytes.len() as u8);
        const_pool_bytes.extend_from_slice(&entry.bytes);
    }

    let mut body_bytes = Vec::with_capacity(prog.body.len() * 8 + 4);
    body_bytes.extend_from_slice(&prog.frame_size.to_le_bytes());
    for instr in &prog.body {
        encode_instr(instr, &mut body_bytes);
    }

    let mut header = prog.header;
    header.const_pool_len = const_pool_bytes.len() as u32;
    header.body_len = body_bytes.len() as u32;
    header.frame_size = prog.frame_size;

    let mut out = Vec::with_capacity(HEADER_SIZE + const_pool_bytes.len() + body_bytes.len());
    out.extend_from_slice(&header.encode_prefix());
    out.extend_from_slice(&const_pool_bytes);
    out.extend_from_slice(&body_bytes);
    out
}

fn encode_instr(instr: &Instr, out: &mut Vec<u8>) {
    match instr {
        Instr::Jump { target } => {
            out.push(OpTag::Jump as u8);
            out.extend_from_slice(&target.to_le_bytes());
        }
        Instr::JumpIf { cond, target } => {
            out.push(OpTag::JumpIf as u8);
            out.extend_from_slice(&cond.to_le_bytes());
            out.extend_from_slice(&target.to_le_bytes());
        }
        Instr::Return => {
            out.push(OpTag::Return as u8);
        }
        Instr::Trap { code } => {
            out.push(OpTag::Trap as u8);
            out.extend_from_slice(&code.to_le_bytes());
        }
        Instr::PushConst { dst, const_id } => {
            out.push(OpTag::PushConst as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&const_id.to_le_bytes());
        }
        Instr::ReadSignal { dst, signal_id } => {
            out.push(OpTag::ReadSignal as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&signal_id.to_le_bytes());
        }
        Instr::WriteWitness { slot_id, src } => {
            out.push(OpTag::WriteWitness as u8);
            out.extend_from_slice(&slot_id.to_le_bytes());
            out.extend_from_slice(&src.to_le_bytes());
        }
        Instr::FAdd { dst, a, b } => emit_rrr(out, OpTag::FAdd, *dst, *a, *b),
        Instr::FSub { dst, a, b } => emit_rrr(out, OpTag::FSub, *dst, *a, *b),
        Instr::FMul { dst, a, b } => emit_rrr(out, OpTag::FMul, *dst, *a, *b),
        Instr::FDiv { dst, a, b } => emit_rrr(out, OpTag::FDiv, *dst, *a, *b),
        Instr::FInv { dst, src } => {
            out.push(OpTag::FInv as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&src.to_le_bytes());
        }
        Instr::FEq { dst, a, b } => emit_rrr(out, OpTag::FEq, *dst, *a, *b),
        Instr::IBin { op, w, dst, a, b } => {
            out.push(OpTag::IBin as u8);
            out.push(*op as u8);
            out.push(*w as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        Instr::INot { w, dst, src } => {
            out.push(OpTag::INot as u8);
            out.push(*w as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&src.to_le_bytes());
        }
        Instr::Rotl32 { dst, src, n } => emit_rrr(out, OpTag::Rotl32, *dst, *src, *n),
        Instr::Rotr32 { dst, src, n } => emit_rrr(out, OpTag::Rotr32, *dst, *src, *n),
        Instr::Rotl8 { dst, src, n } => emit_rrr(out, OpTag::Rotl8, *dst, *src, *n),
        Instr::IntFromField { w, dst, src } => {
            out.push(OpTag::IntFromField as u8);
            out.push(*w as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&src.to_le_bytes());
        }
        Instr::FieldFromInt { dst, src, w } => {
            out.push(OpTag::FieldFromInt as u8);
            out.push(*w as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&src.to_le_bytes());
        }
        Instr::AllocArray { dst, len, elem } => {
            out.push(OpTag::AllocArray as u8);
            out.push(*elem as u8);
            out.extend_from_slice(&dst.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
        }
        Instr::LoadArr { dst, arr, idx } => emit_rrr(out, OpTag::LoadArr, *dst, *arr, *idx),
        Instr::StoreArr { arr, idx, val } => emit_rrr(out, OpTag::StoreArr, *arr, *idx, *val),
    }
    let _ = (IntW::U8, IntBinOp::Add, ElemT::Field); // silence unused warnings on re-exports
}

fn emit_rrr(out: &mut Vec<u8>, tag: OpTag, a: u32, b: u32, c: u32) {
    out.push(tag as u8);
    out.extend_from_slice(&a.to_le_bytes());
    out.extend_from_slice(&b.to_le_bytes());
    out.extend_from_slice(&c.to_le_bytes());
}
