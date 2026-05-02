//! End-to-end round-trip tests.
//!
//! Each test builds a realistic little program with
//! [`ProgramBuilder`], runs it through the whole pipeline — encode →
//! decode → validate → execute — and asserts the emission shape is
//! what we expected. This complements the raw-byte fixtures in
//! `bytecode_fixtures.rs` with a semantic-level check of the
//! pipeline.

use lysis::{
    decode, encode, execute, InstructionKind, LysisConfig, ProgramBuilder, StubSink, Visibility,
};
use memory::field::{Bn254Fr, FieldElement};
use memory::FieldFamily;

fn fe(x: u64) -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([x, 0, 0, 0])
}

fn b() -> ProgramBuilder<Bn254Fr> {
    ProgramBuilder::new(FieldFamily::BnLike256)
}

/// encode → decode → validate → execute, returning the emitted
/// `InstructionKind` stream.
fn pipeline(
    program: lysis::Program<Bn254Fr>,
    captures: &[FieldElement<Bn254Fr>],
) -> Vec<InstructionKind<Bn254Fr>> {
    let bytes = encode(&program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    lysis::bytecode::validate(&decoded, &LysisConfig::default()).expect("validate");
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&decoded, captures, &LysisConfig::default(), &mut sink).expect("execute");
    sink.into_instructions()
}

// ---------------------------------------------------------------------
// Num2Bits(4)
// ---------------------------------------------------------------------
// Circom reference:
//   template Num2Bits(n) {
//       signal input in;
//       signal output out[n];
//       ...
//   }
//
// We drop the n to 4 so the test stays compact while still exercising
// `Decompose` at `n_bits > 1` and four consecutive `RangeCheck`s.

#[test]
fn num2bits_4_runs_through_full_pipeline() {
    let mut builder = b();
    let in_name = builder.intern_string("in");

    builder
        .load_input(0, in_name as u16, Visibility::Witness) // r0 = in
        .emit_decompose(1, 0, 4) // r1..r4 = bits(r0)
        .emit_range_check(1, 1)
        .emit_range_check(2, 1)
        .emit_range_check(3, 1)
        .emit_range_check(4, 1)
        .halt();

    let emissions = pipeline(builder.finish(), &[]);
    // Input + Decompose + 4 RangeChecks = 6 emissions.
    assert_eq!(emissions.len(), 6);
    assert!(matches!(&emissions[0], InstructionKind::Input { .. }));
    assert!(matches!(&emissions[1], InstructionKind::Decompose { .. }));
    for check in &emissions[2..] {
        assert!(matches!(check, InstructionKind::RangeCheck { .. }));
    }
}

// ---------------------------------------------------------------------
// Poseidon round (t=3, α=5)
// ---------------------------------------------------------------------
// One pseudo-round: add 3 round constants, then raise each slot to
// the 5th power. MDS mix is omitted; the linear layer is future
// work.

#[test]
fn poseidon_pseudo_round_runs() {
    let mut builder = b();
    let c0 = builder.intern_field(fe(1));
    let c1 = builder.intern_field(fe(2));
    let c2 = builder.intern_field(fe(3));
    let s0 = builder.intern_string("s0");
    let s1 = builder.intern_string("s1");
    let s2 = builder.intern_string("s2");

    builder
        .load_input(0, s0 as u16, Visibility::Witness)
        .load_input(1, s1 as u16, Visibility::Witness)
        .load_input(2, s2 as u16, Visibility::Witness)
        .load_const(3, c0 as u16)
        .load_const(4, c1 as u16)
        .load_const(5, c2 as u16)
        .emit_add(6, 0, 3)
        .emit_add(7, 1, 4)
        .emit_add(8, 2, 5)
        // x^5 = x * x * x * x * x  (expanded as (x^2)·(x^2)·x)
        .emit_mul(9, 6, 6) // r6^2
        .emit_mul(10, 9, 9) // r6^4
        .emit_mul(11, 10, 6) // r6^5
        .emit_mul(12, 7, 7)
        .emit_mul(13, 12, 12)
        .emit_mul(14, 13, 7)
        .emit_mul(15, 8, 8)
        .emit_mul(16, 15, 15)
        .emit_mul(17, 16, 8)
        .halt();

    let emissions = pipeline(builder.finish(), &[]);
    // 3 Inputs + 3 Consts + 3 Adds + 9 Muls = 18 emissions.
    assert_eq!(emissions.len(), 18);
    assert_eq!(
        emissions
            .iter()
            .filter(|k| matches!(k, InstructionKind::Mul { .. }))
            .count(),
        9
    );
    assert_eq!(
        emissions
            .iter()
            .filter(|k| matches!(k, InstructionKind::Input { .. }))
            .count(),
        3
    );
}

// ---------------------------------------------------------------------
// SHA-256 round skeleton
// ---------------------------------------------------------------------

#[test]
fn sha256_round_skeleton_runs() {
    let mut builder = b();
    let k_t = builder.intern_field(fe(0x428a_2f98));
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "w"] {
        builder.intern_string(name);
    }

    builder
        .load_input(0, 1, Visibility::Public) // a — name_idx 1 is "a"
        .load_input(1, 2, Visibility::Public) // b
        .load_input(2, 3, Visibility::Public) // c
        .load_input(3, 4, Visibility::Public) // d
        .load_input(4, 5, Visibility::Public) // e
        .load_input(5, 6, Visibility::Public) // f
        .load_input(6, 7, Visibility::Public) // g
        .load_input(7, 8, Visibility::Public) // h
        .load_input(8, 9, Visibility::Witness) // w
        .load_const(9, k_t as u16) // K_t
        .emit_add(10, 7, 9) // h + K_t
        .emit_add(11, 10, 8) // + w
        .emit_add(12, 11, 4) // + e
        .emit_add(13, 12, 0) // + a
        .halt();

    let emissions = pipeline(builder.finish(), &[]);
    // 9 Inputs + 1 Const + 4 Adds = 14 emissions.
    assert_eq!(emissions.len(), 14);
}

// ---------------------------------------------------------------------
// Program with captures + arithmetic
// ---------------------------------------------------------------------

#[test]
fn captures_thread_into_emissions() {
    let mut builder = b();
    builder
        .load_capture(0, 0) // r0 = captures[0]
        .load_capture(1, 1) // r1 = captures[1]
        .emit_mul(2, 0, 1) // r2 = r0 * r1
        .emit_add(3, 2, 2) // r3 = r2 + r2
        .halt();

    let emissions = pipeline(builder.finish(), &[fe(7), fe(11)]);
    // 2 Consts (from captures) + 1 Mul + 1 Add = 4.
    assert_eq!(emissions.len(), 4);
    match &emissions[0] {
        InstructionKind::Const { value, .. } => assert_eq!(*value, fe(7)),
        _ => panic!(),
    }
    match &emissions[1] {
        InstructionKind::Const { value, .. } => assert_eq!(*value, fe(11)),
        _ => panic!(),
    }
}

// ---------------------------------------------------------------------
// Assertion pipeline — verify side-effect emission order
// ---------------------------------------------------------------------

#[test]
fn side_effects_preserve_emission_order() {
    let mut builder = b();
    let seven = builder.intern_field(fe(7));
    builder
        .load_const(0, seven as u16)
        .load_const(1, seven as u16)
        .emit_assert_eq(0, 1) // first assertion
        .emit_assert_eq(0, 0) // second assertion, textually identical
        .halt();

    let emissions = pipeline(builder.finish(), &[]);
    let assert_eqs: Vec<_> = emissions
        .iter()
        .filter(|k| matches!(k, InstructionKind::AssertEq { .. }))
        .collect();
    // Even though the two AssertEq's look similar, both must appear —
    // the side-effect wall forbids dedup of assertions.
    assert_eq!(assert_eqs.len(), 2);
}

// ---------------------------------------------------------------------
// Validator catches the "forgot a Halt" bug upstream
// ---------------------------------------------------------------------

#[test]
fn pipeline_rejects_program_without_terminator() {
    let mut builder = b();
    builder.enter_scope(); // no halt / return / trap
    let program = builder.finish();
    let err = lysis::bytecode::validate(&program, &LysisConfig::default()).unwrap_err();
    assert!(matches!(err, lysis::LysisError::UnreachableReturn { .. }));
}

// ---------------------------------------------------------------------
// Executor surfaces a trap
// ---------------------------------------------------------------------

#[test]
fn pipeline_surfaces_trap_opcode() {
    let mut builder = b();
    builder.trap(0x42);
    let program = builder.finish();
    let bytes = encode(&program);
    let decoded = decode::<Bn254Fr>(&bytes).unwrap();
    // Validator accepts a Trap as a terminator.
    lysis::bytecode::validate(&decoded, &LysisConfig::default()).unwrap();
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&decoded, &[], &LysisConfig::default(), &mut sink).unwrap_err();
    assert!(matches!(err, lysis::LysisError::Trap { code: 0x42, .. }));
}
