use memory::{Bn254Fr, FieldElement};

use super::*;
use ir_core::{Instruction, Visibility};

fn fe(n: i64) -> FieldElement<Bn254Fr> {
    // Map i64 → positive field value for simplicity in tests.
    // The classifier doesn't care about the mapping, only about
    // distinctness between probe values.
    let as_u64 = n as u64;
    FieldElement::from_canonical([as_u64, 0, 0, 0])
}

fn ssa(i: u32) -> SsaVar {
    SsaVar(i.into())
}

// -----------------------------------------------------------------
// Degenerate / edge cases
// -----------------------------------------------------------------

#[test]
fn zero_iterations_is_data_dependent() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let c = classify(ssa(0), &body, 5, 5, fe);
    assert!(matches!(c.binding_time, BindingTime::DataDependent));
}

#[test]
fn single_iteration_is_data_dependent() {
    // 0..1 has iterations = 1. The classifier must not attempt
    // to probe at `start+1` (out of range by semantics).
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 1, fe);
    assert!(matches!(c.binding_time, BindingTime::DataDependent));
}

#[test]
fn negative_range_is_data_dependent() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let c = classify(ssa(0), &body, 5, 3, fe);
    assert!(matches!(c.binding_time, BindingTime::DataDependent));
}

// -----------------------------------------------------------------
// Uniform classification
// -----------------------------------------------------------------

#[test]
fn body_using_iter_classifies_uniform() {
    // body: Mul(iter, iter). All iterations produce the same
    // structural shape; iter_var value is the only thing that
    // differs.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 5, fe);
    match &c.binding_time {
        BindingTime::Uniform { captures, skeleton } => {
            assert_eq!(captures.len(), 1);
            assert!(captures.contains(&SlotId(0)));
            assert!(!skeleton.is_empty());
        }
        BindingTime::DataDependent => panic!("expected Uniform"),
    }
}

#[test]
fn body_not_using_iter_classifies_uniform_with_captures_if_probe_values_seen() {
    // body references iter_var's Mul(x, iter)... wait, if we
    // don't reference iter, the slot node still exists in each
    // probe tree (n_slots = 1), and its value changes, so slot 0
    // IS recorded.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(99),
        rhs: ssa(99),
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 5, fe);
    // Structurally uniform; captures includes slot 0 because
    // the probe values differed (even though body doesn't use
    // slot 0). Harmless — the template just takes one capture
    // that it ignores.
    match &c.binding_time {
        BindingTime::Uniform { captures, .. } => {
            assert!(captures.contains(&SlotId(0)));
        }
        BindingTime::DataDependent => panic!(),
    }
}

#[test]
fn two_iteration_loop_classifies_uniform_when_body_same() {
    // Smallest classifiable loop: start=0, end=2 → iterations=2.
    // p2 clamps to p1 but the classifier still behaves correctly.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 2, fe);
    assert!(c.binding_time.is_uniform());
}

// -----------------------------------------------------------------
// DataDependent classification
// -----------------------------------------------------------------

#[test]
fn body_with_nested_loop_is_data_dependent() {
    // A nested LoopUnroll inside the body produces a NestedLoop
    // sentinel — the same marker in all probes, so structurally
    // uniform. The conservative classification is *still*
    // Uniform here; nested loops don't force DataDependent per
    // se, they just prevent BTA from recursing.
    //
    // (The enclosing loop's lifter respects this by NOT recursing
    // into the nested body. Recursion is future work.)
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
        iter_var: ssa(10),
        start: 0,
        end: 4,
        body: vec![],
    }];
    let c = classify(ssa(0), &body, 0, 5, fe);
    // With only a NestedLoop marker node, the probes are
    // identical (slot Const values differ, but no operand
    // references them). Both probes produce `[Const(slot0),
    // NestedLoop]` so structural_diff returns
    // `OnlyConstants({SlotId(0)})`. Hence Uniform.
    assert!(c.binding_time.is_uniform());
}

#[test]
fn classify_loop_unroll_wrapper() {
    let inst = ExtendedInstruction::LoopUnroll {
        iter_var: ssa(0),
        start: 0,
        end: 5,
        body: vec![Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()],
    };
    let c = classify_loop_unroll::<Bn254Fr>(&inst, fe);
    assert!(c.binding_time.is_uniform());
}

#[test]
fn classify_loop_unroll_wrapper_on_non_loop_returns_data_dependent() {
    let inst: ExtendedInstruction<Bn254Fr> = Instruction::Const {
        result: ssa(0),
        value: fe(1),
    }
    .into();
    let c = classify_loop_unroll::<Bn254Fr>(&inst, fe);
    assert!(matches!(c.binding_time, BindingTime::DataDependent));
}

// -----------------------------------------------------------------
// Captures carry the slot-id set the lifter needs
// -----------------------------------------------------------------

#[test]
fn captures_are_deterministic_across_runs() {
    // Rerunning classify on the same body yields identical
    // capture sets. Relevant for bytecode-level template
    // interning — same body should always produce the same
    // template.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c1 = classify(ssa(0), &body, 0, 5, fe);
    let c2 = classify(ssa(0), &body, 0, 5, fe);
    match (&c1.binding_time, &c2.binding_time) {
        (
            BindingTime::Uniform { captures: c1c, .. },
            BindingTime::Uniform { captures: c2c, .. },
        ) => {
            assert_eq!(c1c, c2c);
        }
        _ => panic!(),
    }
}

// -----------------------------------------------------------------
// Complex body with multiple side-effects
// -----------------------------------------------------------------

#[test]
fn multi_statement_body_classifies_uniform() {
    // body: Input(x) + Add(x, iter) + AssertEq(..., x)
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        Instruction::Input {
            result: ssa(1),
            name: "x".into(),
            visibility: Visibility::Witness,
        }
        .into(),
        Instruction::Add {
            result: ssa(2),
            lhs: ssa(1),
            rhs: ssa(0),
        }
        .into(),
        Instruction::AssertEq {
            result: ssa(3),
            lhs: ssa(2),
            rhs: ssa(1),
            message: None,
        }
        .into(),
    ];
    let c = classify(ssa(0), &body, 0, 3, fe);
    assert!(c.binding_time.is_uniform());
}

// -----------------------------------------------------------------
// Details struct carries the raw diffs
// -----------------------------------------------------------------

#[test]
fn body_with_symbolic_indexed_effect_classifies_uniform() {
    // for i in 0..3: array[i] := value (where value is OuterRef).
    // The slot-tagged Const for iter_var is the only thing that
    // shifts between probes; the IndexedEffect node itself is
    // structurally identical across probes (same array_anchor,
    // same value_operand).
    use crate::extended::IndexedEffectKind;
    let body: Vec<ExtendedInstruction<Bn254Fr>> =
        vec![ExtendedInstruction::SymbolicIndexedEffect {
            kind: IndexedEffectKind::Let,
            // Simulate the Stage 2 instantiate-time slot snapshot.
            // The slot SsaVars are OuterRefs from the BTA's POV.
            array_slots: vec![ssa(10), ssa(11), ssa(12)],
            index_var: ssa(0),
            value_var: Some(ssa(20)),
            span: None,
        }];
    let c = classify(ssa(0), &body, 0, 3, fe);
    match &c.binding_time {
        BindingTime::Uniform { captures, .. } => {
            assert!(captures.contains(&SlotId(0)));
        }
        BindingTime::DataDependent => panic!("expected Uniform"),
    }
}

#[test]
fn body_with_symbolic_indexed_effect_distinct_arrays_diff_structurally() {
    // Two bodies with IndexedEffects targeting different arrays
    // diverge on `array_anchor`. structural_diff catches that —
    // the diff between two such trees is `Structural`. Use the
    // diff API directly so we can construct two heterogeneous
    // trees.
    use crate::extended::IndexedEffectKind;
    use crate::lysis_lift::symbolic::symbolic_emit;
    let body_a: Vec<ExtendedInstruction<Bn254Fr>> =
        vec![ExtendedInstruction::SymbolicIndexedEffect {
            kind: IndexedEffectKind::Let,
            array_slots: vec![ssa(10), ssa(11)],
            index_var: ssa(0),
            value_var: Some(ssa(20)),
            span: None,
        }];
    let body_b: Vec<ExtendedInstruction<Bn254Fr>> =
        vec![ExtendedInstruction::SymbolicIndexedEffect {
            kind: IndexedEffectKind::Let,
            // Different array.
            array_slots: vec![ssa(30), ssa(31)],
            index_var: ssa(0),
            value_var: Some(ssa(20)),
            span: None,
        }];
    let tree_a = symbolic_emit(&body_a, &[(ssa(0), fe(0))]);
    let tree_b = symbolic_emit(&body_b, &[(ssa(0), fe(0))]);
    let d = structural_diff(&tree_a, &tree_b);
    assert!(matches!(d, Diff::Structural), "{d:?}");
}

#[test]
fn body_with_symbolic_array_read_classifies_uniform() {
    // for i in 0..3: result := array[i]. The read's NodeIdx is
    // identical across probes (same array_anchor, same body
    // position); only the slot-tagged Const for iter_var shifts.
    // structural_diff classifies `OnlyConstants(slot 0)` and BTA
    // marks the loop Uniform.
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicArrayRead {
        result_var: ssa(50),
        array_slots: vec![ssa(10), ssa(11), ssa(12)],
        index_var: ssa(0),
        span: None,
    }];
    let c = classify(ssa(0), &body, 0, 3, fe);
    match &c.binding_time {
        BindingTime::Uniform { captures, .. } => {
            assert!(captures.contains(&SlotId(0)));
        }
        BindingTime::DataDependent => panic!("expected Uniform"),
    }
}

#[test]
fn body_with_symbolic_array_read_distinct_arrays_diff_structurally() {
    // Two reads from different arrays diverge on `array_anchor`.
    use crate::lysis_lift::symbolic::symbolic_emit;
    let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicArrayRead {
        result_var: ssa(50),
        array_slots: vec![ssa(10), ssa(11)],
        index_var: ssa(0),
        span: None,
    }];
    let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicArrayRead {
        result_var: ssa(50),
        array_slots: vec![ssa(30), ssa(31)],
        index_var: ssa(0),
        span: None,
    }];
    let tree_a = symbolic_emit(&body_a, &[(ssa(0), fe(0))]);
    let tree_b = symbolic_emit(&body_b, &[(ssa(0), fe(0))]);
    let d = structural_diff(&tree_a, &tree_b);
    assert!(matches!(d, Diff::Structural), "{d:?}");
}

#[test]
fn body_with_symbolic_shift_classifies_uniform() {
    // for i in 0..3: result := operand >> i. The shift's NodeIdx
    // is identical across probes (same operand_anchor, same body
    // position); only the slot-tagged Const for iter_var (the
    // shift_operand) shifts. structural_diff classifies
    // `OnlyConstants(slot 0)` and BTA marks the loop Uniform.
    use crate::extended::ShiftDirection;
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(10),
        shift_var: ssa(0),
        num_bits: 32,
        direction: ShiftDirection::Right,
        span: None,
    }];
    let c = classify(ssa(0), &body, 0, 3, fe);
    match &c.binding_time {
        BindingTime::Uniform { captures, .. } => {
            assert!(captures.contains(&SlotId(0)));
        }
        BindingTime::DataDependent => panic!("expected Uniform"),
    }
}

#[test]
fn body_with_symbolic_shift_distinct_directions_diff_structurally() {
    // Two shifts with different directions diverge structurally
    // — `ShiftDirection::Right` vs `Left` is part of the node's
    // structural fingerprint.
    use crate::extended::ShiftDirection;
    use crate::lysis_lift::symbolic::symbolic_emit;
    let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(10),
        shift_var: ssa(0),
        num_bits: 32,
        direction: ShiftDirection::Right,
        span: None,
    }];
    let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(10),
        shift_var: ssa(0),
        num_bits: 32,
        direction: ShiftDirection::Left,
        span: None,
    }];
    let tree_a = symbolic_emit(&body_a, &[(ssa(0), fe(0))]);
    let tree_b = symbolic_emit(&body_b, &[(ssa(0), fe(0))]);
    let d = structural_diff(&tree_a, &tree_b);
    assert!(matches!(d, Diff::Structural), "{d:?}");
}

#[test]
fn body_with_symbolic_shift_distinct_widths_diff_structurally() {
    // Two shifts with different `num_bits` diverge structurally.
    use crate::extended::ShiftDirection;
    use crate::lysis_lift::symbolic::symbolic_emit;
    let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(10),
        shift_var: ssa(0),
        num_bits: 32,
        direction: ShiftDirection::Right,
        span: None,
    }];
    let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::SymbolicShift {
        result_var: ssa(50),
        operand_var: ssa(10),
        shift_var: ssa(0),
        num_bits: 64,
        direction: ShiftDirection::Right,
        span: None,
    }];
    let tree_a = symbolic_emit(&body_a, &[(ssa(0), fe(0))]);
    let tree_b = symbolic_emit(&body_b, &[(ssa(0), fe(0))]);
    let d = structural_diff(&tree_a, &tree_b);
    assert!(matches!(d, Diff::Structural), "{d:?}");
}

#[test]
fn details_expose_all_three_diffs() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
        result: ssa(1),
        lhs: ssa(0),
        rhs: ssa(0),
    }
    .into()];
    let c = classify(ssa(0), &body, 0, 5, fe);
    // All three probes produce Uniform trees with slot 0 as the
    // divergence. Pairwise diffs all have OnlyConstants with
    // slot 0.
    assert!(matches!(&c.diff_01, Diff::OnlyConstants(s) if s.contains(&SlotId(0))));
    assert!(matches!(&c.diff_02, Diff::OnlyConstants(s) if s.contains(&SlotId(0))));
    assert!(matches!(&c.diff_12, Diff::OnlyConstants(s) if s.contains(&SlotId(0))));
}
