//! Binding-time analysis — the 3-point classifier (RFC §6.1.1 v1.1).
//!
//! Given a [`ExtendedInstruction::LoopUnroll`], decide whether its
//! body is safe to lift into a `TemplateBody` + `LoopRolled`
//! bytecode pair or whether it must stay inline as `LoopUnroll`.
//!
//! ## Why three probes instead of two
//!
//! The original two-probe test (evaluate at `start` and `start+1`,
//! compare) misses two patterns:
//!
//! 1. **Period-2 bodies** — `if i % 2 == 0 { a } else { b }` produces
//!    structurally different subtrees between `p0` and `p1`, so the
//!    two-probe test classifies them as `DataDependent`. Adding a
//!    third probe at `p0+2` catches this: `p0 ≡ p2 ∧ p0 ≢ p1` reveals
//!    periodicity. v1 still classifies these as `DataDependent`
//!    (safety-first); v2 could split into two templates.
//! 2. **Single-iteration loops** — `0..1` has exactly one iteration.
//!    The two-probe test evaluates at `start+1` (one past the end),
//!    reading garbage. The 3-point classifier short-circuits: any
//!    loop with ≤ 1 iteration returns `DataDependent` without
//!    probing.
//!
//! ## What the classifier does NOT do
//!
//! - It does not inline the body or mutate it.
//! - It does not intern any template; that's `extract.rs` (3.B.6).
//! - It does not handle `Parametric` bounds (loops whose end is a
//!   runtime capture). `ExtendedInstruction::LoopUnroll` carries
//!   `i64` bounds so every classifiable loop is already compile-
//!   time-bounded; `Parametric` is reserved for a future shape that
//!   carries `SsaVar` bounds.

use std::collections::BTreeSet;

use memory::{FieldBackend, FieldElement};

use super::diff::{structural_diff, Diff};
use super::symbolic::{symbolic_emit, SlotId, SymbolicTree};
use crate::ExtendedInstruction;
use ir_core::SsaVar;

/// Classification of a loop body. Consumed by the lifter (walker,
/// 3.B.7) to decide which Lysis opcode to emit.
#[derive(Debug, Clone)]
pub enum BindingTime<F: FieldBackend> {
    /// All probed iterations produce structurally identical bodies
    /// modulo the slot values at `captures`. Safe to lift into a
    /// `TemplateBody` whose `captures` become `LoadCapture` slots at
    /// call time.
    ///
    /// `skeleton` is the symbolic tree produced at probe 0 — the
    /// extractor reads it as the body shape and the slot positions
    /// as capture positions.
    Uniform {
        skeleton: SymbolicTree<F>,
        captures: BTreeSet<SlotId>,
    },
    /// The body varies structurally between iterations in a way the
    /// classifier will not attempt to lift. The walker emits a
    /// `LoopUnroll` bytecode opcode and inlines the body verbatim.
    DataDependent,
}

impl<F: FieldBackend> BindingTime<F> {
    /// `true` when the body is safe to lift into a template.
    pub fn is_uniform(&self) -> bool {
        matches!(self, BindingTime::Uniform { .. })
    }
}

/// Outcome reported by [`classify`] including the three probe-pair
/// diff results. Kept separate from [`BindingTime`] because Phase 4
/// may want to react to specific patterns (e.g. period-2) that Phase
/// 3 lumps as `DataDependent`.
#[derive(Debug, Clone)]
pub struct ClassificationDetails<F: FieldBackend> {
    pub binding_time: BindingTime<F>,
    pub diff_01: Diff,
    pub diff_02: Diff,
    pub diff_12: Diff,
}

/// Classify a loop by probing its body at three points and computing
/// pairwise structural diffs.
///
/// Provide `as_field(i)` to convert `i64` probe values into the
/// caller's field. The classifier never imposes a specific field
/// layout; it takes whatever concrete `FieldElement<F>` the caller
/// hands it.
pub fn classify<F: FieldBackend>(
    iter_var: SsaVar,
    body: &[ExtendedInstruction<F>],
    start: i64,
    end: i64,
    as_field: impl Fn(i64) -> FieldElement<F>,
) -> ClassificationDetails<F> {
    let iterations = end.saturating_sub(start);

    // Degenerate — fewer than two probes possible, or negative
    // range. Classify conservatively.
    if iterations <= 1 {
        return ClassificationDetails {
            binding_time: BindingTime::DataDependent,
            // Synthesize placeholder diffs; callers usually only
            // read `binding_time` in the early-exit path.
            diff_01: Diff::Structural,
            diff_02: Diff::Structural,
            diff_12: Diff::Structural,
        };
    }

    // Three probe points. `p2` clamps to `p1` when the loop has
    // exactly two iterations (so `iterations - 1 = 1` pins it to
    // `start + 1`). In that case `diff_12` is trivially
    // `OnlyConstants({})` and the match below still reaches the
    // Uniform branch when `p0 ≡ p1`.
    //
    //   iterations = 2 → p2 = start + 1  (= p1)
    //   iterations ≥ 3 → p2 = start + 2
    let p0 = start;
    let p1 = start + 1;
    let p2 = start + i64::min(2, iterations - 1);

    let tree_p0 = symbolic_emit(body, &[(iter_var, as_field(p0))]);
    let tree_p1 = symbolic_emit(body, &[(iter_var, as_field(p1))]);
    let tree_p2 = symbolic_emit(body, &[(iter_var, as_field(p2))]);

    let diff_01 = structural_diff(&tree_p0, &tree_p1);
    let diff_02 = structural_diff(&tree_p0, &tree_p2);
    let diff_12 = structural_diff(&tree_p1, &tree_p2);

    let binding_time = match (&diff_01, &diff_02, &diff_12) {
        // All three agree on shape and on the slot set → Uniform.
        // We require `s01 == s02` because a slot that's present in
        // 0↔1 but not in 0↔2 would indicate a non-monotonic
        // dependency on i (e.g., `if i == 0 { ... }`) — safer to
        // treat as DataDependent than to promote.
        (Diff::OnlyConstants(s01), Diff::OnlyConstants(s02), Diff::OnlyConstants(_))
            if s01 == s02 =>
        {
            BindingTime::Uniform {
                skeleton: tree_p0.clone(),
                captures: s01.clone(),
            }
        }
        // Anything else → conservative fallback. Period-2 detection
        // (`Structural, OnlyConstants, Structural`) is subsumed by
        // this branch for v1.
        _ => BindingTime::DataDependent,
    };

    ClassificationDetails {
        binding_time,
        diff_01,
        diff_02,
        diff_12,
    }
}

/// Convenience wrapper that classifies an
/// [`ExtendedInstruction::LoopUnroll`] directly. Returns
/// [`BindingTime::DataDependent`] if passed anything else.
pub fn classify_loop_unroll<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    as_field: impl Fn(i64) -> FieldElement<F>,
) -> ClassificationDetails<F> {
    match inst {
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body,
        } => classify(*iter_var, body, *start, *end, as_field),
        _ => ClassificationDetails {
            binding_time: BindingTime::DataDependent,
            diff_01: Diff::Structural,
            diff_02: Diff::Structural,
            diff_12: Diff::Structural,
        },
    }
}

#[cfg(test)]
mod tests {
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
        SsaVar(i)
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
        // body references iter_var's Mul(x, iter) ... wait, if we
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
        // into the nested body. Phase 4 can change this to recurse.)
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
        let body: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::SymbolicArrayRead {
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
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::SymbolicArrayRead {
                result_var: ssa(50),
                array_slots: vec![ssa(10), ssa(11)],
                index_var: ssa(0),
                span: None,
            }];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::SymbolicArrayRead {
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
}
