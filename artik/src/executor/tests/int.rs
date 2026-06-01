use super::*;

// ── Integer arithmetic ─────────────────────────────────────────

fn int_prog(body: Vec<Instr>, frame_size: u32) -> Program {
    roundtrip(Program::new(
        FieldFamily::BnLike256,
        frame_size,
        Vec::new(),
        body,
    ))
}

fn run_int(prog: &Program, sig_u32: u32) -> FE {
    let sig = [FE::from_u64(sig_u32 as u64)];
    let mut slots = [FE::zero()];
    run_bn(prog, &sig, &mut slots).unwrap();
    slots[0]
}

#[test]
fn ibin_u32_add_wraps() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 1,
            src: 0,
        },
        Instr::IBin {
            op: IntBinOp::Add,
            w: IntW::U32,
            dst: 2,
            a: 1,
            b: 1,
        },
        Instr::FieldFromInt {
            dst: 3,
            src: 2,
            w: IntW::U32,
        },
        Instr::WriteWitness { slot_id: 0, src: 3 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = int_prog(body, 4);
    // 0x8000_0000 + 0x8000_0000 == 0 (mod 2^32)
    let out = run_int(&prog, 0x8000_0000);
    assert_eq!(out, FE::zero());
}

#[test]
fn ibin_u8_xor_masks() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U8,
            dst: 1,
            src: 0,
        },
        Instr::IBin {
            op: IntBinOp::Xor,
            w: IntW::U8,
            dst: 2,
            a: 1,
            b: 1,
        },
        Instr::FieldFromInt {
            dst: 3,
            src: 2,
            w: IntW::U8,
        },
        Instr::WriteWitness { slot_id: 0, src: 3 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = int_prog(body, 4);
    let out = run_int(&prog, 0xAB);
    assert_eq!(out, FE::zero());
}

#[test]
fn inot_u32_inverts_low_32_bits() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 1,
            src: 0,
        },
        Instr::INot {
            w: IntW::U32,
            dst: 2,
            src: 1,
        },
        Instr::FieldFromInt {
            dst: 3,
            src: 2,
            w: IntW::U32,
        },
        Instr::WriteWitness { slot_id: 0, src: 3 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = int_prog(body, 4);
    let out = run_int(&prog, 0);
    assert_eq!(out, FE::from_u64(0xFFFF_FFFF));
}

#[test]
fn cmplt_u32_boolean() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 1,
            src: 0,
        },
        Instr::ReadSignal {
            dst: 2,
            signal_id: 1,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 3,
            src: 2,
        },
        Instr::IBin {
            op: IntBinOp::CmpLt,
            w: IntW::U32,
            dst: 4,
            a: 1,
            b: 3,
        },
        Instr::FieldFromInt {
            dst: 5,
            src: 4,
            w: IntW::U8,
        },
        Instr::WriteWitness { slot_id: 0, src: 5 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));
    let sig = [FE::from_u64(3), FE::from_u64(7)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(1));
}
