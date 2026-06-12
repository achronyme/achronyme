//! Differential pins for the direct interning path: the synthetic
//! all-Plain body covering the walker-desugared forms (unreachable
//! from real fixtures) and the rolled-loop fallback.

use std::collections::HashMap;

use ir_core::{Instruction, SsaVar};
use memory::Bn254Fr;

use crate::extended::ExtendedInstruction;
use crate::test_utils::compile_circuit;

type F = Bn254Fr;

#[test]
fn direct_core_matches_cable_on_desugared_forms() {
    // Differential pin for the direct interning core: a synthetic
    // all-Plain body that exercises every walker-desugared form
    // (Not, And, Or, IsNeq, IsLe, IsLeBounded, Assert), a RangeCheck
    // whose result is consumed downstream (it aliases the operand,
    // not the effect id), Decompose bit consumption, and the u8-width
    // forms. These forms are unreachable from the instantiate walk
    // (the Instantiator pre-desugars them), so no source fixture can
    // cover the mirror arms — the body is built by hand and the
    // direct core's output is compared byte-for-byte against the
    // Walker -> bytecode -> executor cable on the same body.
    use crate::extended_program::ExtendedIrProgram;
    use crate::lysis_materialize::materialize_interning_sink;
    use memory::FieldElement;

    let p = |inst| ExtendedInstruction::Plain(inst);
    let v = SsaVar;
    let body = vec![
        p(Instruction::Input {
            result: v(0),
            name: "a".into(),
            visibility: ir_core::Visibility::Witness,
        }),
        p(Instruction::Input {
            result: v(1),
            name: "b".into(),
            visibility: ir_core::Visibility::Public,
        }),
        p(Instruction::Const {
            result: v(2),
            value: FieldElement::<F>::from_u64(7),
        }),
        p(Instruction::Not {
            result: v(3),
            operand: v(0),
        }),
        p(Instruction::And {
            result: v(4),
            lhs: v(0),
            rhs: v(1),
        }),
        p(Instruction::Or {
            result: v(5),
            lhs: v(3),
            rhs: v(4),
        }),
        p(Instruction::IsNeq {
            result: v(6),
            lhs: v(5),
            rhs: v(2),
        }),
        p(Instruction::IsLe {
            result: v(7),
            lhs: v(0),
            rhs: v(2),
        }),
        p(Instruction::IsLeBounded {
            result: v(8),
            lhs: v(1),
            rhs: v(2),
            bitwidth: 8,
        }),
        p(Instruction::RangeCheck {
            result: v(9),
            operand: v(4),
            bits: 8,
        }),
        p(Instruction::Mux {
            result: v(10),
            cond: v(6),
            if_true: v(9),
            if_false: v(7),
        }),
        p(Instruction::IsLtBounded {
            result: v(11),
            lhs: v(0),
            rhs: v(1),
            bitwidth: 16,
        }),
        p(Instruction::IntDiv {
            result: v(12),
            lhs: v(2),
            rhs: v(2),
            max_bits: 16,
        }),
        p(Instruction::IntMod {
            result: v(13),
            lhs: v(2),
            rhs: v(2),
            max_bits: 16,
        }),
        p(Instruction::Div {
            result: v(14),
            lhs: v(12),
            rhs: v(2),
        }),
        p(Instruction::Neg {
            result: v(15),
            operand: v(14),
        }),
        p(Instruction::IsEq {
            result: v(16),
            lhs: v(15),
            rhs: v(13),
        }),
        p(Instruction::IsLt {
            result: v(17),
            lhs: v(16),
            rhs: v(11),
        }),
        p(Instruction::PoseidonHash {
            result: v(18),
            left: v(0),
            right: v(1),
        }),
        p(Instruction::Sub {
            result: v(19),
            lhs: v(18),
            rhs: v(10),
        }),
        p(Instruction::Add {
            result: v(20),
            lhs: v(19),
            rhs: v(17),
        }),
        p(Instruction::Mul {
            result: v(21),
            lhs: v(20),
            rhs: v(3),
        }),
        p(Instruction::Assert {
            result: v(22),
            operand: v(16),
            message: Some("must hold".into()),
        }),
        p(Instruction::AssertEq {
            result: v(23),
            lhs: v(21),
            rhs: v(2),
            message: None,
        }),
        p(Instruction::Decompose {
            result: v(24),
            bit_results: vec![v(25), v(26), v(27), v(28)],
            operand: v(9),
            num_bits: 4,
        }),
        p(Instruction::Add {
            result: v(29),
            lhs: v(25),
            rhs: v(28),
        }),
        p(Instruction::AssertEq {
            result: v(30),
            lhs: v(29),
            rhs: v(9),
            message: Some("bits".into()),
        }),
    ];
    let next_var = 31;

    let cable_program =
        super::lowering::lower_extended_through_lysis_lean::<F>(ExtendedIrProgram {
            body: body.clone(),
            next_var,
            var_names: HashMap::new(),
            var_types: HashMap::new(),
            input_spans: HashMap::new(),
            var_spans: HashMap::new(),
        })
        .expect("cable lowering");

    let mut interner = lysis::InterningSink::<F>::without_span_tracking();
    let mut state = super::direct_core::DirectInternState::new();
    for ext in body {
        let ExtendedInstruction::Plain(inst) = ext else {
            unreachable!("synthetic body is all-Plain");
        };
        state.feed_plain(&mut interner, inst);
    }
    assert!(state.take_error().is_none(), "direct core must not error");
    let instructions = materialize_interning_sink(interner);
    let direct_next_var = super::lowering::ssa_watermark(&instructions).max(next_var);

    assert_eq!(instructions.len(), cable_program.instructions.len());
    for (d, c) in instructions.iter().zip(cable_program.instructions.iter()) {
        assert_eq!(format!("{d:?}"), format!("{c:?}"));
    }
    assert_eq!(direct_next_var, cable_program.next_var);
}

#[test]
fn lean_entry_falls_back_to_cable_on_rolled_loop_bodies() {
    // The direct interning path serves all-Plain walks only; a body
    // that emits a symbolic LoopUnroll poisons the direct sink and the
    // lean entry re-runs the walk through the extended-body cable.
    // Pin: the fallback output matches the full entry's stream.
    let source = "public out\nwitness arr[4]\nfor i in 0..4 { assert_eq(arr[i], arr[i]) }\nassert(out == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");

    let extended = prove_ir
        .instantiate_extended::<F>(&HashMap::new())
        .expect("instantiate_extended");
    assert!(
        !extended.is_fully_plain(),
        "fixture precondition: the body must exercise the fallback"
    );

    let full = prove_ir
        .instantiate_lysis::<F>(&HashMap::new())
        .expect("instantiate_lysis");
    let lean = prove_ir
        .instantiate_lysis_lean::<F>(&HashMap::new())
        .expect("instantiate_lysis_lean");

    assert_eq!(lean.instructions.len(), full.instructions.len());
    for (l, f) in lean.instructions.iter().zip(full.instructions.iter()) {
        assert_eq!(format!("{l:?}"), format!("{f:?}"));
    }
    assert_eq!(lean.next_var, full.next_var);
}
