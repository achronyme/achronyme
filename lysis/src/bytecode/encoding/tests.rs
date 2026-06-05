use super::decode::decode_opcode_at;
#[cfg(test)]
use super::*;
use crate::bytecode::opcode::{code, InputSrc, Opcode};
use crate::error::LysisError;
use crate::intern::Visibility;
use crate::program::{Instr, Program};
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
        capture_regs: Box::new(vec![3, 4, 5]),
        output_regs: Box::new(vec![6, 7]),
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
    roundtrip_opcode(Opcode::EmitIsLtBounded {
        dst: 16,
        lhs: 17,
        rhs: 18,
        max_bits: 64,
    });
    roundtrip_opcode(Opcode::EmitDiv {
        dst: 19,
        lhs: 20,
        rhs: 21,
    });
}

#[test]
fn roundtrip_emit_variable_length() {
    roundtrip_opcode(Opcode::EmitPoseidonHash {
        dst: 1,
        in_regs: Box::new(vec![2, 3, 4, 5]),
    });
    roundtrip_opcode(Opcode::EmitWitnessCall {
        bytecode_const_idx: 7,
        in_regs: Box::new(vec![1, 2]),
        out_regs: Box::new(vec![3, 4, 5]),
    });
}

#[test]
fn roundtrip_emit_witness_call_heap() {
    // Smoke + boundary: empty inputs/outputs, mixed Reg/Slot
    // inputs, and a 256-output case (the SHA-256 hash motivating
    // WitnessCallHeap).
    roundtrip_opcode(Opcode::EmitWitnessCallHeap {
        bytecode_const_idx: 0,
        inputs: Box::new(vec![]),
        out_slots: Box::new(vec![]),
    });
    roundtrip_opcode(Opcode::EmitWitnessCallHeap {
        bytecode_const_idx: 42,
        inputs: Box::new(vec![InputSrc::Reg(1), InputSrc::Slot(2), InputSrc::Reg(3)]),
        out_slots: Box::new(vec![100, 101, 102]),
    });
    let big_outputs: Vec<u32> = (0u32..256).collect();
    roundtrip_opcode(Opcode::EmitWitnessCallHeap {
        bytecode_const_idx: 0xCAFE,
        inputs: Box::new(vec![InputSrc::Reg(1), InputSrc::Reg(2)]),
        out_slots: Box::new(big_outputs),
    });
}

#[test]
fn emit_witness_call_heap_handles_u16_input_and_output_counts() {
    // Wire format invariant: input and output count fields are
    // both u16 — the design supports up to 65535 of each, well
    // above any expected workload.
    let big_inputs: Vec<InputSrc> = (0u32..1024).map(InputSrc::Slot).collect();
    let big_outputs: Vec<u32> = (0u32..1024).collect();
    roundtrip_opcode(Opcode::EmitWitnessCallHeap {
        bytecode_const_idx: 1,
        inputs: Box::new(big_inputs),
        out_slots: Box::new(big_outputs),
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
        msg_idx: u32::MAX,
    });
    roundtrip_opcode(Opcode::EmitRangeCheck {
        var: 13,
        max_bits: 64,
    });
}

#[test]
fn roundtrip_heap_ops() {
    // Sample edge cases for the u32 slot field: zero, mid-range,
    // the old u16 ceiling, and values past it (a >1.5 M-constraint
    // circuit spills >65 535 cold vars) so a regression that
    // narrows the slot back to u16/u8 trips the test.
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
        slot: u32::from(u16::MAX) + 1,
    });
    roundtrip_opcode(Opcode::StoreHeap {
        src_reg: 255,
        slot: u32::MAX,
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
        slot: 250_000,
    });
    roundtrip_opcode(Opcode::LoadHeap {
        dst_reg: 255,
        slot: u32::MAX,
    });
}

#[test]
fn heap_ops_emit_6_bytes() {
    // Wire-format invariant: each heap op is
    // `u8 opcode + u8 reg + u32 slot = 6 bytes`. A change in this
    // number is an ABI break.
    let mut buf = Vec::new();
    encode_opcode(
        &Opcode::StoreHeap {
            src_reg: 7,
            slot: 0xDEAD,
        },
        &mut buf,
    );
    assert_eq!(buf.len(), 6, "StoreHeap must encode to exactly 6 bytes");
    let mut buf = Vec::new();
    encode_opcode(
        &Opcode::LoadHeap {
            dst_reg: 7,
            slot: 0xBEEF,
        },
        &mut buf,
    );
    assert_eq!(buf.len(), 6, "LoadHeap must encode to exactly 6 bytes");
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
    // LOAD_INPUT body = opcode(1) + dst(1) + name_idx(4) + vis(1).
    let header = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 7);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.encode());
    bytes.push(code::LOAD_INPUT);
    bytes.push(0); // dst
    bytes.extend_from_slice(&0u32.to_le_bytes()); // name_idx
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
