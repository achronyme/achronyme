use super::*;

// ── Rotations (RFC 4634 / SHA-256 ρ₀ sanity vectors) ───────────

/// Hardware reference: SHA-256 small sigma 0, σ₀(x) = ROTR7(x) ⊕
/// ROTR18(x) ⊕ SHR3(x). We compute σ₀(0x12345678) two ways — with
/// Artik rotations and natively — and require them to agree.
fn sha256_sigma0_native(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[test]
fn rotr32_matches_native() {
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
        Instr::Rotr32 {
            dst: 4,
            src: 1,
            n: 3,
        },
        Instr::FieldFromInt {
            dst: 5,
            src: 4,
            w: IntW::U32,
        },
        Instr::WriteWitness { slot_id: 0, src: 5 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));
    let test_values: [(u32, u32); 5] = [
        (0x12345678, 7),
        (0xDEADBEEF, 13),
        (0xFFFFFFFF, 1),
        (0x00000001, 31),
        (0x80000000, 17),
    ];
    for (x, n) in test_values {
        let sig = [FE::from_u64(x as u64), FE::from_u64(n as u64)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(
            slots[0],
            FE::from_u64(x.rotate_right(n) as u64),
            "rotr32({x:#010x}, {n}) mismatch"
        );
    }
}

#[test]
fn sha256_sigma0_full_pipeline() {
    // Construct σ₀ from 3 rotations + 2 xors in Artik.
    //
    //   t1 = rotr32(x, 7)
    //   t2 = rotr32(x, 18)
    //   t3 = shr_u32(x, 3)
    //   out = t1 ^ t2 ^ t3
    let body = vec![
        // Read x (sig 0) and decode to u32.
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 1,
            src: 0,
        },
        // Read shift amounts 7, 18, 3 as u32.
        Instr::ReadSignal {
            dst: 2,
            signal_id: 1,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 3,
            src: 2,
        },
        Instr::ReadSignal {
            dst: 4,
            signal_id: 2,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 5,
            src: 4,
        },
        Instr::ReadSignal {
            dst: 6,
            signal_id: 3,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 7,
            src: 6,
        },
        Instr::Rotr32 {
            dst: 8,
            src: 1,
            n: 3,
        },
        Instr::Rotr32 {
            dst: 9,
            src: 1,
            n: 5,
        },
        Instr::IBin {
            op: IntBinOp::Shr,
            w: IntW::U32,
            dst: 10,
            a: 1,
            b: 7,
        },
        Instr::IBin {
            op: IntBinOp::Xor,
            w: IntW::U32,
            dst: 11,
            a: 8,
            b: 9,
        },
        Instr::IBin {
            op: IntBinOp::Xor,
            w: IntW::U32,
            dst: 12,
            a: 11,
            b: 10,
        },
        Instr::FieldFromInt {
            dst: 13,
            src: 12,
            w: IntW::U32,
        },
        Instr::WriteWitness {
            slot_id: 0,
            src: 13,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 14, Vec::new(), body));

    for &x in &[
        0x12345678u32,
        0x00000000,
        0xFFFFFFFF,
        0xDEADBEEF,
        0x80000001,
    ] {
        let sig = [
            FE::from_u64(x as u64),
            FE::from_u64(7),
            FE::from_u64(18),
            FE::from_u64(3),
        ];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        let expected = sha256_sigma0_native(x);
        assert_eq!(
            slots[0],
            FE::from_u64(expected as u64),
            "σ₀({x:#010x}) mismatch: got {:?}, want {expected:#010x}",
            slots[0]
        );
    }
}

#[test]
fn rotl8_wraps_modulo_8() {
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
        Instr::ReadSignal {
            dst: 2,
            signal_id: 1,
        },
        Instr::IntFromField {
            w: IntW::U8,
            dst: 3,
            src: 2,
        },
        Instr::Rotl8 {
            dst: 4,
            src: 1,
            n: 3,
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
    // rotl8(0xA5, 11) == rotl8(0xA5, 3) since rot wraps mod 8.
    let sig = [FE::from_u64(0xA5), FE::from_u64(11)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    let expected = 0xA5u8.rotate_left(3) as u64;
    assert_eq!(slots[0], FE::from_u64(expected));
}
