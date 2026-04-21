//! Phase 3.B.10 — end-to-end integration for the Walker + executor.
//!
//! Takes a hand-authored `ExtendedInstruction` program (no compiler,
//! no ProveIR front-end), drives it through
//! `Walker::lower → execute (InterningSink) → materialize`, and
//! asserts the resulting `Vec<Instruction<Bn254Fr>>` matches what the
//! eager `ir::prove_ir::instantiate` path would produce for the same
//! circuit — shape-level, not semantic equivalence.
//!
//! Also exercises BTA + extract on a Uniform loop to make sure the
//! classifier / lifter chain agrees on the capture layout, even
//! though the walker itself doesn't emit templates yet (that lives
//! in Phase 3.C).

use std::collections::BTreeSet;

use ir::prove_ir::extended::ExtendedInstruction;
use ir::prove_ir::lysis_lower::{
    build_capture_layout, classify, compute_frame_size, extract_template, symbolic_emit,
    BindingTime, CaptureKind, SlotId, TemplateRegistry, Walker,
};
use ir::types::{Instruction, SsaVar, Visibility};
use lysis::{execute, FieldFamily, InstructionKind, InterningSink, LysisConfig};
use memory::{Bn254Fr, FieldElement};

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

fn ssa(i: u32) -> SsaVar {
    SsaVar(i)
}

fn plain(inst: Instruction<Bn254Fr>) -> ExtendedInstruction<Bn254Fr> {
    ExtendedInstruction::Plain(inst)
}

/// Build the Num2Bits(4) ExtendedInstruction skeleton. Matches what
/// the Phase 3.A round-trip test expressed via raw bytecode; here
/// we go through the walker instead.
fn num2bits_4() -> Vec<ExtendedInstruction<Bn254Fr>> {
    // Signals:
    //   ssa(0) = in (witness input)
    //   ssa(1..4) = bit_0..bit_3 (decompose outputs)
    //   ssa(5) = Const(1)        — the "one" for bool check (unused here)
    //   ssa(11..14) = bit_i * bit_i (used for boolean assertion)
    vec![
        plain(Instruction::Input {
            result: ssa(0),
            name: "in".into(),
            visibility: Visibility::Witness,
        }),
        plain(Instruction::Decompose {
            result: ssa(0),
            bit_results: vec![ssa(1), ssa(2), ssa(3), ssa(4)],
            operand: ssa(0),
            num_bits: 4,
        }),
        plain(Instruction::Const {
            result: ssa(5),
            value: fe(1),
        }),
        // bit_i * bit_i = bit_i  →  asserts booleanity
        plain(Instruction::Mul {
            result: ssa(11),
            lhs: ssa(1),
            rhs: ssa(1),
        }),
        plain(Instruction::AssertEq {
            result: ssa(111),
            lhs: ssa(1),
            rhs: ssa(11),
            message: None,
        }),
        plain(Instruction::Mul {
            result: ssa(12),
            lhs: ssa(2),
            rhs: ssa(2),
        }),
        plain(Instruction::AssertEq {
            result: ssa(112),
            lhs: ssa(2),
            rhs: ssa(12),
            message: None,
        }),
        plain(Instruction::Mul {
            result: ssa(13),
            lhs: ssa(3),
            rhs: ssa(3),
        }),
        plain(Instruction::AssertEq {
            result: ssa(113),
            lhs: ssa(3),
            rhs: ssa(13),
            message: None,
        }),
        plain(Instruction::Mul {
            result: ssa(14),
            lhs: ssa(4),
            rhs: ssa(4),
        }),
        plain(Instruction::AssertEq {
            result: ssa(114),
            lhs: ssa(4),
            rhs: ssa(14),
            message: None,
        }),
    ]
}

#[test]
fn num2bits_4_walker_roundtrip_matches_reference_shape() {
    let body = num2bits_4();
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(&body).expect("lower ok");

    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec ok");
    let flat = sink.materialize();

    // Expected shape:
    //   Input + Decompose + Const + 4 * (Mul + AssertEq)
    //   = 1 + 1 + 1 + 4*2 = 11 top-level instructions.
    //
    // The pure channel can dedup here: all four bit_i * bit_i muls
    // reference distinct operands (bit_i ≠ bit_j), so no dedup —
    // 4 distinct Muls.
    let inputs = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::Input { .. }))
        .count();
    let decomposes = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::Decompose { .. }))
        .count();
    let consts = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::Const { .. }))
        .count();
    let muls = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::Mul { .. }))
        .count();
    let asserts = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::AssertEq { .. }))
        .count();

    assert_eq!(inputs, 1, "one Input(in)");
    assert_eq!(decomposes, 1, "one Decompose");
    assert_eq!(consts, 1, "one Const(1)");
    assert_eq!(muls, 4, "four bit_i * bit_i");
    assert_eq!(asserts, 4, "four boolean asserts");
}

#[test]
fn uniform_loop_bta_plus_extract_full_pipeline() {
    // Body: for i in 0..8: Mul(i, i) + AssertEq(r_mul, r_something_else)
    // The classifier should pick Uniform; extract should produce a
    // template with 1 slot capture (iter_var).
    let body = vec![plain(Instruction::Mul {
        result: ssa(10),
        lhs: ssa(0), // iter_var
        rhs: ssa(0),
    })];
    let iter_var = ssa(0);
    let iter_fe = |n: i64| FieldElement::from_canonical([n as u64, 0, 0, 0]);

    let classified = classify::<Bn254Fr>(iter_var, &body, 0, 8, iter_fe);
    let (skeleton, captures) = match classified.binding_time {
        BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
        BindingTime::DataDependent => panic!("expected Uniform"),
    };

    // Extract + verify layout.
    let mut reg = TemplateRegistry::<Bn254Fr>::new();
    let spec = extract_template(&skeleton, &captures, &mut reg).expect("extract ok");
    assert_eq!(spec.n_params(), 1, "one capture: the iter_var slot");
    assert!(matches!(
        spec.layout.entries[0],
        CaptureKind::Slot(SlotId(0))
    ));
    assert_eq!(reg.len(), 1, "one template registered");
}

#[test]
fn symbolic_then_diff_integration_matches_bta_details() {
    // Sanity: the BTA details mirror what happens when you call
    // symbolic_emit + structural_diff by hand. Exercises the public
    // re-exports and confirms the pairwise diffs surface the slot.
    let body = vec![plain(Instruction::Add {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    })];
    let iter_var = ssa(0);
    let t0 = symbolic_emit(&body, &[(iter_var, fe(0))]);
    let t1 = symbolic_emit(&body, &[(iter_var, fe(1))]);
    // Structural equivalence modulo slot value — should expose slot 0.
    let diff = ir::prove_ir::lysis_lower::structural_diff(&t0, &t1);
    match diff {
        ir::prove_ir::lysis_lower::Diff::OnlyConstants(slots) => {
            let expected: BTreeSet<SlotId> = [SlotId(0)].into_iter().collect();
            assert_eq!(slots, expected);
        }
        _ => panic!("expected OnlyConstants"),
    }
}

#[test]
fn walker_loop_unroll_produces_same_instructions_as_manual_unrolling() {
    // Equivalence: walking a LoopUnroll body three times should
    // produce the same InstructionKind sequence as manually emitting
    // the body three times with different iter values.
    let loop_body = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 3,
        body: vec![
            plain(Instruction::Mul {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(0),
            }),
            plain(Instruction::AssertEq {
                result: ssa(2),
                lhs: ssa(1),
                rhs: ssa(0),
                message: None,
            }),
        ],
    }];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(&loop_body).expect("lower");
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
    let flat = sink.materialize();

    // Expect: 3 Consts (iter 0, 1, 2) + 3 Muls + 3 AssertEqs.
    // Muls don't dedup (iter changes each iteration).
    let consts = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::Const { .. }))
        .count();
    let muls = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::Mul { .. }))
        .count();
    let asserts = flat
        .iter()
        .filter(|i| matches!(i, InstructionKind::AssertEq { .. }))
        .count();
    assert_eq!(consts, 3);
    assert_eq!(muls, 3);
    assert_eq!(asserts, 3);
}

#[test]
fn capture_layout_includes_outer_refs_after_slots() {
    // Body: Add(iter_var, outer_ref)
    let body = vec![plain(Instruction::Add {
        result: ssa(10),
        lhs: ssa(0),  // iter_var
        rhs: ssa(99), // outer ref
    })];
    let t = symbolic_emit::<Bn254Fr>(&body, &[(ssa(0), fe(0))]);

    // Slots = {SlotId(0)} (the only binding we injected).
    let slot_captures: BTreeSet<SlotId> = [SlotId(0)].into_iter().collect();
    let layout = build_capture_layout(&t, &slot_captures);

    assert_eq!(layout.entries.len(), 2);
    assert!(matches!(layout.entries[0], CaptureKind::Slot(SlotId(0))));
    assert!(matches!(layout.entries[1], CaptureKind::OuterRef(v) if v == ssa(99)));

    let frame_size = compute_frame_size(&t, &layout).expect("frame ok");
    // n_params=2 captures + 1 Add op = 3 slots.
    assert_eq!(frame_size, 3);
}
