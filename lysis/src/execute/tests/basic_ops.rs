use super::*;

// -----------------------------------------------------------------
// Smoke: bare halt runs.
// -----------------------------------------------------------------

#[test]
fn bare_halt_terminates() {
    let mut builder = b();
    builder.halt();
    let sink = run(&builder.finish(), &[]);
    assert_eq!(sink.count(), 0);
}

// -----------------------------------------------------------------
// LoadConst + emission ordering.
// -----------------------------------------------------------------

#[test]
fn load_const_emits_const_instruction() {
    let mut builder = b();
    builder.intern_field(one());
    builder.load_const(0, 0).halt();
    let sink = run(&builder.finish(), &[]);
    assert_eq!(sink.count(), 1);
    assert!(matches!(
        sink.instructions()[0],
        InstructionKind::Const { .. }
    ));
}

#[test]
fn load_capture_emits_const() {
    let mut builder = b();
    builder.load_capture(0, 0).halt();
    let sink = run(&builder.finish(), &[seven()]);
    assert_eq!(sink.count(), 1);
    match &sink.instructions()[0] {
        InstructionKind::Const { value, .. } => assert_eq!(*value, seven()),
        _ => panic!(),
    }
}

#[test]
fn load_capture_out_of_range_errors() {
    let mut builder = b();
    builder.load_capture(0, 3).halt();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(matches!(
        err,
        LysisError::CaptureIdxOutOfRange { idx: 3, .. }
    ));
}

// -----------------------------------------------------------------
// Pure arithmetic chain.
// -----------------------------------------------------------------

#[test]
fn add_mul_chain_emits_expected_sequence() {
    let mut builder = b();
    builder.intern_field(seven());
    builder.intern_field(one());
    builder
        .load_const(0, 0) // r0 = Const(7)
        .load_const(1, 1) // r1 = Const(1)
        .emit_add(2, 0, 1) // r2 = 7 + 1
        .emit_mul(3, 2, 2) // r3 = r2 * r2
        .halt();
    let sink = run(&builder.finish(), &[]);
    // 2 Consts + 1 Add + 1 Mul = 4 emissions.
    assert_eq!(sink.count(), 4);
    assert!(matches!(
        sink.instructions()[0],
        InstructionKind::Const { .. }
    ));
    assert!(matches!(
        sink.instructions()[1],
        InstructionKind::Const { .. }
    ));
    assert!(matches!(
        sink.instructions()[2],
        InstructionKind::Add { .. }
    ));
    assert!(matches!(
        sink.instructions()[3],
        InstructionKind::Mul { .. }
    ));
}

#[test]
fn input_witness_then_range_check() {
    let mut builder = b();
    builder.intern_string("x");
    builder
        .load_input(0, 0, Visibility::Witness)
        .emit_range_check(0, 8)
        .halt();
    let sink = run(&builder.finish(), &[]);
    assert_eq!(sink.count(), 2);
    assert!(matches!(
        sink.instructions()[0],
        InstructionKind::Input { .. }
    ));
    assert!(matches!(
        sink.instructions()[1],
        InstructionKind::RangeCheck { .. }
    ));
}

// -----------------------------------------------------------------
// Decompose lays out bits.
// -----------------------------------------------------------------

#[test]
fn decompose_emits_and_binds_bits() {
    let mut builder = b();
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .emit_decompose(1, 0, 4) // r1..r4 = bits of r0
        .halt();
    let sink = run(&builder.finish(), &[]);
    // Const + Decompose = 2 emissions.
    assert_eq!(sink.count(), 2);
    match &sink.instructions()[1] {
        InstructionKind::Decompose {
            bit_results,
            num_bits,
            ..
        } => {
            assert_eq!(*num_bits, 4);
            assert_eq!(bit_results.len(), 4);
        }
        _ => panic!("expected Decompose"),
    }
}

// -----------------------------------------------------------------
// AssertEq / IsEq / IsLt emit the right variants.
// -----------------------------------------------------------------

#[test]
fn assert_eq_emits_side_effect() {
    let mut builder = b();
    builder.intern_field(seven());
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_assert_eq(0, 1)
        .halt();
    let sink = run(&builder.finish(), &[]);
    assert_eq!(sink.count(), 3);
    assert!(matches!(
        sink.instructions()[2],
        InstructionKind::AssertEq { .. }
    ));
}

#[test]
fn is_eq_emits_pure_compare() {
    let mut builder = b();
    builder.intern_field(seven());
    builder.intern_field(one());
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_is_eq(2, 0, 1)
        .halt();
    let sink = run(&builder.finish(), &[]);
    assert!(matches!(
        sink.instructions()[2],
        InstructionKind::IsEq { .. }
    ));
}

#[test]
fn is_lt_emits() {
    let mut builder = b();
    builder.intern_field(one());
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_is_lt(2, 0, 1)
        .halt();
    let sink = run(&builder.finish(), &[]);
    assert!(matches!(
        sink.instructions()[2],
        InstructionKind::IsLt { .. }
    ));
}

// -----------------------------------------------------------------
// Poseidon arity-2.
// -----------------------------------------------------------------

#[test]
fn poseidon_hash_arity_2_ok() {
    let mut builder = b();
    builder.intern_field(one());
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_poseidon_hash(2, vec![0, 1])
        .halt();
    let sink = run(&builder.finish(), &[]);
    assert!(matches!(
        sink.instructions()[2],
        InstructionKind::PoseidonHash { .. }
    ));
}

// -----------------------------------------------------------------
// Trap surfaces as error.
// -----------------------------------------------------------------

#[test]
fn trap_returns_trap_error() {
    let mut builder = b();
    builder.trap(0x42);
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(matches!(err, LysisError::Trap { code: 0x42, .. }));
}

// -----------------------------------------------------------------
// Budget.
// -----------------------------------------------------------------

#[test]
fn budget_exhausted_triggers() {
    let mut builder = b();
    builder.intern_field(one());
    builder.intern_field(seven());
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_add(2, 0, 1)
        .halt();
    let cfg = LysisConfig {
        instruction_budget: 2,
        ..Default::default()
    };
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&builder.finish(), &[], &cfg, &mut sink).unwrap_err();
    assert!(matches!(err, LysisError::BudgetExhausted { .. }));
}

#[test]
fn for_internal_replay_lifts_the_instruction_ceiling() {
    // One program, built once. The executor ticks the budget once
    // per loop turn including the turn that reaches `Halt`, so this
    // 4-instruction body needs 4 ticks to complete.
    let prog = {
        let mut builder = b();
        builder.intern_field(one());
        builder.intern_field(seven());
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .emit_add(2, 0, 1)
            .halt();
        builder.finish()
    };
    const K: u64 = 4;

    // The trusted internal-replay config lifts the instruction
    // ceiling: the same program runs to completion.
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&prog, &[], &LysisConfig::for_internal_replay(), &mut sink)
        .expect("internal-replay config must not impose the instruction ceiling");

    // The same program under a finite budget one short of what it
    // needs still trips the backstop, fail-loud, with the exact
    // `ran`/`budget` — the ceiling stays real for non-replay
    // callers using `Default`.
    let capped = LysisConfig {
        instruction_budget: K - 1,
        ..Default::default()
    };
    let mut sink2 = StubSink::<Bn254Fr>::new();
    let err = execute(&prog, &[], &capped, &mut sink2).unwrap_err();
    assert!(
        matches!(err, LysisError::BudgetExhausted { ran, budget } if ran == K && budget == K - 1),
        "expected BudgetExhausted {{ ran: {K}, budget: {} }}, got {err:?}",
        K - 1
    );
}

// -----------------------------------------------------------------
// Scope opcodes are no-ops.
// -----------------------------------------------------------------

#[test]
fn scope_ops_are_noops() {
    let mut builder = b();
    builder.enter_scope().exit_scope().halt();
    let sink = run(&builder.finish(), &[]);
    assert_eq!(sink.count(), 0);
}

// -----------------------------------------------------------------
// Neg / Mux.
// -----------------------------------------------------------------

#[test]
fn neg_emits() {
    let mut builder = b();
    builder.intern_field(seven());
    builder.load_const(0, 0).emit_neg(1, 0).halt();
    let sink = run(&builder.finish(), &[]);
    assert_eq!(sink.count(), 2);
    assert!(matches!(
        sink.instructions()[1],
        InstructionKind::Neg { .. }
    ));
}

#[test]
fn mux_emits() {
    let mut builder = b();
    builder.intern_field(seven());
    builder.intern_field(one());
    builder
        .load_const(0, 0) // r0 = cond
        .load_const(1, 1) // r1 = then
        .load_const(2, 0) // r2 = else
        .emit_mux(3, 0, 1, 2)
        .halt();
    let sink = run(&builder.finish(), &[]);
    assert!(matches!(
        sink.instructions()[3],
        InstructionKind::Mux { .. }
    ));
}
