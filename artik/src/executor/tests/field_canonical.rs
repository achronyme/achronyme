use super::*;

// ── Field-level canonical-rep ops (FIDiv / FIRem / FShr / FAnd) ──

/// `FPow2` must yield `2 ^ n` as a field value for every shift
/// amount, including amounts at and beyond a machine word. The
/// width-masked integer shift it replaces returned `1` for any
/// `n` that is a multiple of the int width (e.g. `1 << 64`), a
/// silent wrong answer; this pins the field-correct result across
/// the boundary cases.
#[test]
fn fpow2_is_field_correct_two_to_the_n() {
    for n in [0u64, 1, 31, 32, 63, 64, 65, 127, 128, 129, 191, 192, 253] {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::FPow2 { dst: 1, amount: 0 },
            Instr::WriteWitness { slot_id: 0, src: 1 },
            Instr::Return { srcs: Vec::new() },
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, Vec::new(), body));
        let sig = [FE::from_u64(n)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();

        let mut limbs = [0u64; 4];
        limbs[(n / 64) as usize] = 1u64 << (n % 64);
        assert_eq!(
            slots[0],
            FE::from_canonical(limbs),
            "FPow2 must yield 2^{n} as a field value, not a width-masked shift"
        );
    }
}

/// Drive an FIDiv computation from two signals, return the field result.
fn run_fidiv(a: FE, b: FE) -> Result<FE, ArtikError> {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 1,
        },
        Instr::FIDiv { dst: 2, a: 0, b: 1 },
        Instr::WriteWitness { slot_id: 0, src: 2 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 3, Vec::new(), body));
    let sig = [a, b];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots)?;
    Ok(slots[0])
}

fn run_firem(a: FE, b: FE) -> Result<FE, ArtikError> {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 1,
        },
        Instr::FIRem { dst: 2, a: 0, b: 1 },
        Instr::WriteWitness { slot_id: 0, src: 2 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 3, Vec::new(), body));
    let sig = [a, b];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots)?;
    Ok(slots[0])
}

fn run_fshr(a: FE, amount: u32) -> FE {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::FShr {
            dst: 1,
            src: 0,
            amount,
        },
        Instr::WriteWitness { slot_id: 0, src: 1 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, Vec::new(), body));
    let sig = [a];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    slots[0]
}

fn run_fand(a: FE, mask_bytes: Vec<u8>) -> FE {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::FAnd {
            dst: 1,
            src: 0,
            mask_const_id: 0,
        },
        Instr::WriteWitness { slot_id: 0, src: 1 },
        Instr::Return { srcs: Vec::new() },
    ];
    let pool = vec![FieldConstEntry { bytes: mask_bytes }];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, pool, body));
    let sig = [a];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    slots[0]
}

/// Helper: build a field element from a u128 value (zero-padded).
fn fe_from_u128(v: u128) -> FE {
    let mut bytes = [0u8; 32];
    bytes[0..16].copy_from_slice(&v.to_le_bytes());
    FE::from_le_bytes(&bytes).expect("u128 fits canonical")
}

#[test]
fn fidiv_matches_u128_div_euclid_on_qhat_shape() {
    // qhat shape: dividend = (max_u64 << 64) | (max_u64 - 7), divisor = 0x100000007.
    // Verifies u128-class operands route through canonical-rep div.
    let dividend_u128 = ((u64::MAX as u128) << 64) | ((u64::MAX - 7) as u128);
    let divisor_u128: u128 = 0x100000007;
    let a = fe_from_u128(dividend_u128);
    let b = fe_from_u128(divisor_u128);
    let expected = fe_from_u128(dividend_u128 / divisor_u128);
    assert_eq!(run_fidiv(a, b).unwrap(), expected);
}

#[test]
fn fidiv_zero_divides_to_zero() {
    // 0 / 5 = 0
    assert_eq!(run_fidiv(FE::zero(), FE::from_u64(5)).unwrap(), FE::zero());
}

#[test]
fn fidiv_a_lt_b_yields_zero() {
    assert_eq!(
        run_fidiv(FE::from_u64(3), FE::from_u64(7)).unwrap(),
        FE::zero()
    );
}

#[test]
fn fidiv_a_eq_b_yields_one() {
    assert_eq!(
        run_fidiv(FE::from_u64(42), FE::from_u64(42)).unwrap(),
        FE::from_u64(1)
    );
}

#[test]
fn fidiv_traps_on_zero_b() {
    let err = run_fidiv(FE::from_u64(7), FE::zero()).unwrap_err();
    assert_eq!(err, ArtikError::FieldDivByZero);
}

#[test]
fn firem_matches_u128_rem_euclid_on_qhat_shape() {
    let dividend_u128 = ((u64::MAX as u128) << 64) | ((u64::MAX - 7) as u128);
    let divisor_u128: u128 = 0x100000007;
    let a = fe_from_u128(dividend_u128);
    let b = fe_from_u128(divisor_u128);
    let expected = fe_from_u128(dividend_u128 % divisor_u128);
    assert_eq!(run_firem(a, b).unwrap(), expected);
}

#[test]
fn firem_traps_on_zero_b() {
    let err = run_firem(FE::from_u64(7), FE::zero()).unwrap_err();
    assert_eq!(err, ArtikError::FieldDivByZero);
}

#[test]
fn fidiv_firem_round_trip_identity() {
    // For 20 deterministic (a, b) with b != 0 and a, b < 2^128:
    // FIDiv(a, b) * b + FIRem(a, b) == a, and quotient/remainder
    // each match host u128 arithmetic. Mix of small, mid, edge,
    // and qhat-shape vectors.
    let cases: [(u128, u128); 20] = [
        (0, 1),
        (1, 1),
        (12345, 67),
        (0, u64::MAX as u128),
        (u64::MAX as u128, 1),
        (u64::MAX as u128, u64::MAX as u128),
        (u64::MAX as u128, u64::MAX as u128 - 1),
        ((u64::MAX as u128) << 60, 0xDEAD_BEEF),
        (0xCAFEBABE_F00DBEEFu128, 0x123456789ABCDEFu128),
        (
            (u64::MAX as u128) * (u64::MAX as u128 - 1),
            u64::MAX as u128,
        ),
        ((u64::MAX as u128) << 64, 0x100000007),
        (((u64::MAX as u128) << 64) | 1, u64::MAX as u128),
        (((u64::MAX as u128) << 64) | (u64::MAX as u128 / 2), 0x12345),
        (1u128 << 127, 1u128 << 63),
        ((1u128 << 127) - 1, (1u128 << 63) - 1),
        (0xFEDC_BA98_7654_3210_FEDC_BA98_7654_3210u128, 0x1FFu128),
        (u128::MAX - 1, 2),
        (u128::MAX, 1),
        (u128::MAX, u128::MAX / 2),
        (u128::MAX, 0xFFFF_FFFFu128),
    ];
    for (a_v, b_v) in cases {
        let a = fe_from_u128(a_v);
        let b = fe_from_u128(b_v);
        let q = run_fidiv(a, b).unwrap();
        let r = run_firem(a, b).unwrap();
        // q*b + r == a in field arithmetic — values stay below p so
        // canonical rep matches integer math.
        assert_eq!(q.mul(&b).add(&r), a, "round-trip failed for ({a_v}, {b_v})");
        assert_eq!(
            q,
            fe_from_u128(a_v / b_v),
            "quotient mismatch for ({a_v}, {b_v})"
        );
        assert_eq!(
            r,
            fe_from_u128(a_v % b_v),
            "remainder mismatch for ({a_v}, {b_v})"
        );
    }
}

#[test]
fn fshr_amount_zero_is_identity() {
    let v = fe_from_u128((u64::MAX as u128) << 64 | 0xCAFEBABE);
    assert_eq!(run_fshr(v, 0), v);
}

#[test]
fn fshr_64_drops_low_limb() {
    // (max_u64 << 64 | low) >> 64 == max_u64
    let v = fe_from_u128((u64::MAX as u128) << 64 | 0x1234_5678_9ABC_DEF0u128);
    let expected = FE::from_u64(u64::MAX);
    assert_eq!(run_fshr(v, 64), expected);
}

#[test]
fn fshr_128_zeroes_anything_under_2_to_128() {
    let v = fe_from_u128(((u64::MAX as u128) << 64) | (u64::MAX as u128));
    assert_eq!(run_fshr(v, 128), FE::zero());
}

#[test]
fn fshr_full_canonical_rep_matches_native_at_192() {
    // Build a value at the high end of the canonical rep (within
    // BN254's `p ≈ 2^254`). 2^192 fits because p has its high limb
    // around 2^61. Choose `a = 1 << 192` (high limb = 1, others 0)
    // and shift by 192 to recover 1.
    let a_canonical: [u64; 4] = [0, 0, 0, 1];
    let a = FE::from_canonical(a_canonical);
    assert_eq!(run_fshr(a, 192), FE::from_u64(1));
}

#[test]
fn fshr_amount_253_boundary_accepted() {
    // 253 is the highest amount the validator accepts. Pick a
    // canonical-rep value with bit 253 set (limb 3 = 1 << 61) and
    // shift by 253 — should recover 1. Confirms the boundary is
    // inclusive and the limb math is correct at the extreme.
    let limbs: [u64; 4] = [0, 0, 0, 1u64 << 61];
    let a = FE::from_canonical(limbs);
    assert_eq!(run_fshr(a, 253), FE::from_u64(1));
}

#[test]
fn fshr_amount_above_253_rejected_by_validator() {
    // `decode` runs the validator. We construct a body with FShr amount=254,
    // encode it, then expect decode to reject.
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::FShr {
            dst: 1,
            src: 0,
            amount: 254,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = Program::new(FieldFamily::BnLike256, 2, Vec::new(), body);
    let bytes = encode(&prog);
    let err = decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert_eq!(err, ArtikError::InvalidShiftAmount { amount: 254 });
}

#[test]
fn fand_extracts_low_64_bits() {
    // Mask = 2^64 - 1 (low 64 bits set) → keep only the bottom limb.
    let mut mask_bytes = vec![0xFFu8; 8];
    mask_bytes.extend(vec![0u8; 24]); // pad to 32 bytes
    let v = fe_from_u128((u64::MAX as u128) << 64 | 0xDEAD_BEEF_CAFE_BABEu128);
    let expected = FE::from_u64(0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(run_fand(v, mask_bytes), expected);
}

#[test]
fn fand_with_zero_mask_yields_zero() {
    // `% 1` lowers to `FAnd(src, mask=0)`. The result must be zero
    // for any input — the lift's `intern_low_bit_mask(0)` path
    // depends on this so callers like `temp \ (1 << 0)` (vacuous
    // shift) and `temp % (1 << 0)` (always zero) compose correctly.
    let v = fe_from_u128(0xDEAD_BEEF_CAFE_BABE_F00D_C0DE_8BAD_F00Du128);
    let mask_bytes = vec![0u8];
    assert_eq!(run_fand(v, mask_bytes), FE::from_u64(0));
}

#[test]
fn fand_extracts_high_limb_via_shift_then_mask() {
    // Confirm the FShr/FAnd pair extracts limb-1 cleanly:
    // ((max_u64 << 64) | low) >> 64 == max_u64, then & 0xFFFF_FFFF == 0xFFFF_FFFF.
    let v = fe_from_u128((u64::MAX as u128) << 64 | 0x1234u128);
    let shifted = run_fshr(v, 64);
    let mask_bytes = vec![0xFFu8, 0xFF, 0xFF, 0xFF]; // 4 bytes ⇒ low 32 bits of limb0
    let masked = run_fand(shifted, mask_bytes);
    assert_eq!(masked, FE::from_u64(0xFFFF_FFFF));
}

#[test]
fn fshr_fand_round_trip_recovers_low_n_bits() {
    // For x < 2^128, n ∈ {32, 64, 96}: (x >> n) << n + (x & ((1 << n) - 1)) == x.
    for &x_v in &[
        0xDEAD_BEEF_CAFE_BABE_F00D_C0DE_8BAD_F00Du128,
        12345,
        u128::MAX,
    ] {
        for &n in &[32u32, 64, 96] {
            let x = fe_from_u128(x_v);
            let shifted = run_fshr(x, n);
            let mut mask_bytes = vec![0u8; 32];
            let mask_bits = 1u128 << n;
            let mask = mask_bits.wrapping_sub(1);
            mask_bytes[0..16].copy_from_slice(&mask.to_le_bytes());
            let low = run_fand(x, mask_bytes);
            // Compose back: `shifted << n` is field arithmetic
            // shift via repeated *2; here we just do it with mul.
            let factor = fe_from_u128(1u128 << n);
            let restored = shifted.mul(&factor).add(&low);
            assert_eq!(restored, x, "round-trip failed for x={x_v:#x}, n={n}");
        }
    }
}

#[test]
fn new_opcodes_round_trip_through_bytecode() {
    // Encode all 4 new opcodes in one body and verify decode agrees.
    let pool = vec![FieldConstEntry {
        bytes: vec![0xFF, 0xFF],
    }];
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 1,
        },
        Instr::FIDiv { dst: 2, a: 0, b: 1 },
        Instr::FIRem { dst: 3, a: 0, b: 1 },
        Instr::FShr {
            dst: 4,
            src: 0,
            amount: 17,
        },
        Instr::FAnd {
            dst: 5,
            src: 0,
            mask_const_id: 0,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = Program::new(FieldFamily::BnLike256, 6, pool, body.clone());
    let prog = roundtrip(prog);
    assert_eq!(prog.subprograms[0].body, body);
}
