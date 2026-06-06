use super::*;

// ── Field arithmetic ────────────────────────────────────────────

#[test]
fn square_signal() {
    // out = signal[0] * signal[0]
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::FMul { dst: 1, a: 0, b: 0 },
        Instr::WriteWitness { slot_id: 0, src: 1 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, Vec::new(), body));
    let sig = [FE::from_u64(7)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(49));
}

#[test]
fn field_add_sub_mul_div() {
    // Push const 6, const 2, compute (6+2)*2 - 6/2 = 13.
    let pool = vec![
        FieldConstEntry { bytes: vec![6] },
        FieldConstEntry { bytes: vec![2] },
    ];
    let body = vec![
        Instr::PushConst {
            dst: 0,
            const_id: 0,
        },
        Instr::PushConst {
            dst: 1,
            const_id: 1,
        },
        Instr::FAdd { dst: 2, a: 0, b: 1 }, // 8
        Instr::FMul { dst: 3, a: 2, b: 1 }, // 16
        Instr::FDiv { dst: 4, a: 0, b: 1 }, // 3
        Instr::FSub { dst: 5, a: 3, b: 4 }, // 13
        Instr::WriteWitness { slot_id: 0, src: 5 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, pool, body));
    let mut slots = [FE::zero()];
    run_bn(&prog, &[], &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(13));
}

#[test]
fn repeated_push_of_one_const_id_yields_identical_value() {
    // A const-pool entry is decoded on its first `PushConst` and the
    // field element is memoized for the rest of the run, so a second
    // push of the same id must return the same correct value — not a
    // zeroed or stale cache slot. Push const 7 into two registers, then
    // assert both carry 7 and their product is 49.
    let pool = vec![FieldConstEntry { bytes: vec![7] }];
    let body = vec![
        Instr::PushConst {
            dst: 0,
            const_id: 0,
        },
        Instr::PushConst {
            dst: 1,
            const_id: 0,
        },
        Instr::FMul { dst: 2, a: 0, b: 1 },
        Instr::WriteWitness { slot_id: 0, src: 0 },
        Instr::WriteWitness { slot_id: 1, src: 1 },
        Instr::WriteWitness { slot_id: 2, src: 2 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 3, pool, body));
    let mut slots = [FE::zero(); 3];
    run_bn(&prog, &[], &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(7));
    assert_eq!(slots[1], FE::from_u64(7));
    assert_eq!(slots[2], FE::from_u64(49));
}

#[test]
fn field_div_by_zero_traps() {
    let pool = vec![FieldConstEntry { bytes: vec![0] }];
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::PushConst {
            dst: 1,
            const_id: 0,
        },
        Instr::FDiv { dst: 2, a: 0, b: 1 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 3, pool, body));
    let sig = [FE::from_u64(42)];
    let mut slots = [];
    let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
    assert_eq!(err, ArtikError::FieldDivByZero);
}

#[test]
fn field_eq_produces_boolean_int() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 1,
        },
        Instr::FEq { dst: 2, a: 0, b: 1 },
        Instr::FieldFromInt {
            dst: 3,
            src: 2,
            w: IntW::U8,
        },
        Instr::WriteWitness { slot_id: 0, src: 3 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));

    // equal
    let sig = [FE::from_u64(42), FE::from_u64(42)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(1));

    // not equal
    let sig = [FE::from_u64(42), FE::from_u64(41)];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::zero());
}

/// `FCmpLt` compares canonical representatives as unsigned integers
/// in `[0, p)` with no fixed-width truncation. The pinned case is
/// the `2^64 - 1` vs `2^64` boundary: the fixed-width `IBin{CmpLt}`
/// path demoted both operands to `u64`, mapping `2^64` to `0` and
/// answering `2^64 - 1 < 0` = false — the exact mis-branch behind
/// circomlib bigint `long_sub`'s `a[i] >= b[i] + borrow` at n=64.
#[test]
fn field_cmplt_is_exact_at_two_to_the_64_boundary() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 1,
        },
        Instr::FCmpLt { dst: 2, a: 0, b: 1 },
        Instr::FieldFromInt {
            dst: 3,
            src: 2,
            w: IntW::U8,
        },
        Instr::WriteWitness { slot_id: 0, src: 3 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));

    let two_pow_64 = FE::from_canonical([0, 1, 0, 0]);
    let max_u64 = FE::from_u64(u64::MAX); // 2^64 - 1

    // 2^64 - 1 < 2^64  →  true (the borrow-taken case)
    let mut slots = [FE::zero()];
    run_bn(&prog, &[max_u64, two_pow_64], &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(1));

    // 2^64 < 2^64 - 1  →  false
    let mut slots = [FE::zero()];
    run_bn(&prog, &[two_pow_64, max_u64], &mut slots).unwrap();
    assert_eq!(slots[0], FE::zero());

    // equal  →  false
    let mut slots = [FE::zero()];
    run_bn(&prog, &[two_pow_64, two_pow_64], &mut slots).unwrap();
    assert_eq!(slots[0], FE::zero());
}
