use super::*;

// ── Differential-by-proxy: external cryptographic vectors ─────

/// `FInv` on 7 mod BN254_Fr must match the canonical value used by
/// iden3 / circom witness calculators. This is the cheapest
/// credible "differential vs CVM" check we can run without pulling
/// the external tool in as a dep.
#[test]
fn finv_7_matches_external_vector() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::FInv { dst: 1, src: 0 },
        Instr::WriteWitness { slot_id: 0, src: 1 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, Vec::new(), body));
    let sig = [FE::from_u64(7)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    let expected = FE::from_decimal_str(
        "3126891838834182174606629392179610726935480628630862049099743455225115499374",
    )
    .unwrap();
    assert_eq!(slots[0], expected);
}

/// SHA-256 `Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)` computed
/// through Artik must match the native composition on u32 inputs.
#[test]
fn sha256_ch_function_matches_native() {
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
        Instr::ReadSignal {
            dst: 4,
            signal_id: 2,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 5,
            src: 4,
        },
        Instr::IBin {
            op: IntBinOp::And,
            w: IntW::U32,
            dst: 6,
            a: 1,
            b: 3,
        },
        Instr::INot {
            w: IntW::U32,
            dst: 7,
            src: 1,
        },
        Instr::IBin {
            op: IntBinOp::And,
            w: IntW::U32,
            dst: 8,
            a: 7,
            b: 5,
        },
        Instr::IBin {
            op: IntBinOp::Xor,
            w: IntW::U32,
            dst: 9,
            a: 6,
            b: 8,
        },
        Instr::FieldFromInt {
            dst: 10,
            src: 9,
            w: IntW::U32,
        },
        Instr::WriteWitness {
            slot_id: 0,
            src: 10,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 11, Vec::new(), body));

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    for (x, y, z) in [
        (0x6a09e667u32, 0xbb67ae85, 0x3c6ef372),
        (0xFFFFFFFF, 0x00000000, 0xAAAAAAAA),
        (0x12345678, 0x9ABCDEF0, 0x0F0F0F0F),
    ] {
        let sig = [
            FE::from_u64(x as u64),
            FE::from_u64(y as u64),
            FE::from_u64(z as u64),
        ];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(
            slots[0],
            FE::from_u64(ch(x, y, z) as u64),
            "Ch({x:#010x},{y:#010x},{z:#010x}) mismatch"
        );
    }
}

/// Regression: a program whose final instruction flows to Next
/// (no Halt/Return) must not panic — it should surface a clean
/// `InvalidJumpTarget` instead of indexing past the end of
/// `prog.body`. Discovered by fuzz_artik_exec on adversarial
/// bytecode that passed validation but omitted the tail Halt.
#[test]
fn pc_past_end_returns_error_not_panic() {
    // PushConst 0 then fall off the end — no Halt/Return.
    let prog = roundtrip(Program::new(
        FieldFamily::BnLike256,
        1,
        vec![crate::program::FieldConstEntry { bytes: vec![0u8] }],
        vec![Instr::PushConst {
            dst: 0,
            const_id: 0,
        }],
    ));
    let err = run_bn(&prog, &[], &mut []).unwrap_err();
    assert!(
        matches!(err, ArtikError::InvalidJumpTarget { target: 1 }),
        "expected InvalidJumpTarget, got {err:?}"
    );
}

#[test]
fn undefined_register_read_traps() {
    // r0 never written; WriteWitness reads it.
    let body = vec![
        Instr::WriteWitness { slot_id: 0, src: 0 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), body));
    let mut slots = [FE::zero()];
    let err = run_bn(&prog, &[], &mut slots).unwrap_err();
    assert_eq!(err, ArtikError::UndefinedRegister { reg: 0 });
}
