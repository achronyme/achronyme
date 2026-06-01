use super::*;

// ── Extra semantic gaps uncovered during audit ────────────────

#[test]
fn shr_i64_is_arithmetic_shift() {
    // A 64-bit bit pattern with the high bit set must sign-extend
    // under right shift in I64 width, matching hardware SAR.
    //
    // Note: `IntFromField` truncates to the low 64 bits of the
    // canonical field representation (documented behavior). Pass
    // the two's-complement bit pattern of -8 as a field element
    // directly; `from_i64(-8)` would NOT round-trip, because the
    // low limb of `p - 8` is not `0xFFFF_FFFF_FFFF_FFF8`.
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::I64,
            dst: 1,
            src: 0,
        },
        Instr::ReadSignal {
            dst: 2,
            signal_id: 1,
        },
        Instr::IntFromField {
            w: IntW::I64,
            dst: 3,
            src: 2,
        },
        Instr::IBin {
            op: IntBinOp::Shr,
            w: IntW::I64,
            dst: 4,
            a: 1,
            b: 3,
        },
        Instr::FieldFromInt {
            dst: 5,
            src: 4,
            w: IntW::I64,
        },
        Instr::WriteWitness { slot_id: 0, src: 5 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));

    let neg8_bits: u64 = (-8i64) as u64;
    let sig = [FE::from_u64(neg8_bits), FE::from_u64(1)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    // SAR on the raw bit pattern produces -4 in two's complement
    // (0xFFFF_FFFF_FFFF_FFFC). `FieldFromInt I64` then maps the
    // negative interpretation back to `p - 4`.
    assert_eq!(slots[0], FE::from_i64(-4));
}

#[test]
fn int_array_store_load_roundtrips_values() {
    // Fill an IntU32 array with [0xAAAA_AAAA, 0x5555_5555] and
    // read them back; the masking in store_array / the width-tag
    // on the buf must not corrupt the value.
    let body = vec![
        Instr::AllocArray {
            dst: 0,
            len: 2,
            elem: ElemT::IntU32,
        },
        // idx0, idx1 from signals 2, 3.
        Instr::ReadSignal {
            dst: 1,
            signal_id: 2,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 2,
            src: 1,
        },
        Instr::ReadSignal {
            dst: 3,
            signal_id: 3,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 4,
            src: 3,
        },
        // val0, val1 from signals 0, 1.
        Instr::ReadSignal {
            dst: 5,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 6,
            src: 5,
        },
        Instr::ReadSignal {
            dst: 7,
            signal_id: 1,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 8,
            src: 7,
        },
        Instr::StoreArr {
            arr: 0,
            idx: 2,
            val: 6,
        },
        Instr::StoreArr {
            arr: 0,
            idx: 4,
            val: 8,
        },
        // Load back and XOR them so we get a single witness slot.
        Instr::LoadArr {
            dst: 9,
            arr: 0,
            idx: 2,
        },
        Instr::LoadArr {
            dst: 10,
            arr: 0,
            idx: 4,
        },
        Instr::IBin {
            op: IntBinOp::Xor,
            w: IntW::U32,
            dst: 11,
            a: 9,
            b: 10,
        },
        Instr::FieldFromInt {
            dst: 12,
            src: 11,
            w: IntW::U32,
        },
        Instr::WriteWitness {
            slot_id: 0,
            src: 12,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 13, Vec::new(), body));
    let sig = [
        FE::from_u64(0xAAAA_AAAA),
        FE::from_u64(0x5555_5555),
        FE::zero(),
        FE::from_u64(1),
    ];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    // 0xAAAA_AAAA ^ 0x5555_5555 == 0xFFFF_FFFF
    assert_eq!(slots[0], FE::from_u64(0xFFFF_FFFF));
}
