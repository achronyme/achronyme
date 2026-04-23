//! Structural diff between two [`SymbolicTree`]s produced by the
//! same body at different probe values (RFC §6.1, watchpoint #3).
//!
//! The BTA classifier calls [`symbolic_emit`] at least twice (three
//! times once Phase 3 uses the RFC §6.1.1 v1.1 algorithm) with
//! different `(loop_var, concrete_i)` bindings; the results differ
//! iff the loop body's structure depends on the loop variable. This
//! module answers the question "how do they differ?" in one of two
//! shapes:
//!
//! - [`Diff::OnlyConstants`] — both trees have identical topology
//!   (node count, variant sequence, operand indices, op tags, etc.)
//!   and differ only in the values stored at slot-tagged `Const`
//!   nodes. The set of slots that actually diverged is returned so
//!   the lifter can turn them into template captures.
//! - [`Diff::Structural`] — at least one topological mismatch
//!   (different kinds, arities, operand wiring, input names,
//!   tags, ...). The caller classifies the enclosing loop as
//!   `DataDependent` and falls back to inline unrolling.
//!
//! ## Why position-based comparison is sound (watchpoint #3)
//!
//! `symbolic_emit` is deterministic: for a fixed body, the walk
//! pushes nodes in the same order regardless of probe value. Bindings
//! are pushed first, in the order the caller supplied them. Each
//! body instruction contributes a fixed number of nodes, and
//! `OuterRef` synthesis for an unresolved SsaVar happens at the first
//! reference site — same site across probes.
//!
//! Consequence: `a.nodes[i]` and `b.nodes[i]` are the "same position"
//! in the AST walk. Linear index alignment *is* AST-path identity for
//! this algorithm. Two probes that agree on shape must be equal
//! index-by-index; two probes that disagree on shape can diverge
//! anywhere in the stream.
//!
//! This is O(N) in the combined node count, avoiding the DAG-
//! traversal + memoization path a shape-only comparison would take.

use std::collections::BTreeSet;

use memory::FieldBackend;

use super::symbolic::{SlotId, SymbolicNode, SymbolicTree};

/// Outcome of [`structural_diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diff {
    /// Both trees are structurally identical; the only divergence is
    /// the set of slot-tagged `Const` positions whose values differed.
    ///
    /// An empty `OnlyConstants` (slot set is empty) means the two
    /// probes produced byte-identical trees — possible when the body
    /// never references the loop variable. Downstream logic treats it
    /// the same as any other `Uniform` classification.
    OnlyConstants(BTreeSet<SlotId>),
    /// The trees diverge in a way that cannot be explained purely by
    /// slot-value differences. The caller should classify as
    /// `DataDependent`.
    Structural,
}

impl Diff {
    /// Convenience — true if every divergence is at a slot position.
    pub fn is_slot_only(&self) -> bool {
        matches!(self, Diff::OnlyConstants(_))
    }
}

/// Compare two symbolic trees built from the same body at different
/// probe values. See module docs for the algorithm.
pub fn structural_diff<F: FieldBackend>(a: &SymbolicTree<F>, b: &SymbolicTree<F>) -> Diff {
    // Shape checks: node count, top-level body order, slot arity.
    if a.nodes.len() != b.nodes.len() {
        return Diff::Structural;
    }
    if a.body_order != b.body_order {
        return Diff::Structural;
    }
    if a.n_slots != b.n_slots {
        return Diff::Structural;
    }

    // Walk the pools in lockstep.
    let mut diff_slots: BTreeSet<SlotId> = BTreeSet::new();
    for (na, nb) in a.nodes.iter().zip(b.nodes.iter()) {
        if !nodes_equal(na, nb, &mut diff_slots) {
            return Diff::Structural;
        }
    }

    Diff::OnlyConstants(diff_slots)
}

/// Return `true` if the two nodes are structurally equivalent. Slot-
/// tagged `Const` values can differ and still compare equal — the
/// differing slot is recorded in `diff_slots` as a side effect. A
/// `None`/`Some` mismatch on `from_slot`, or any other variant
/// mismatch, is a structural divergence.
fn nodes_equal<F: FieldBackend>(
    a: &SymbolicNode<F>,
    b: &SymbolicNode<F>,
    diff_slots: &mut BTreeSet<SlotId>,
) -> bool {
    use SymbolicNode as N;
    match (a, b) {
        (
            N::Const {
                value: va,
                from_slot: fa,
            },
            N::Const {
                value: vb,
                from_slot: fb,
            },
        ) => {
            if fa != fb {
                // One is a literal, the other is a slot — structural.
                return false;
            }
            match fa {
                Some(sid) => {
                    // Slot: values may differ; record the divergence.
                    if va != vb {
                        diff_slots.insert(*sid);
                    }
                    true
                }
                None => {
                    // Literal: must match.
                    va == vb
                }
            }
        }
        (
            N::Input {
                name: na,
                visibility: va,
            },
            N::Input {
                name: nb,
                visibility: vb,
            },
        ) => na == nb && va == vb,
        (N::OuterRef(va), N::OuterRef(vb)) => va == vb,
        (
            N::Op {
                tag: ta,
                operands: oa,
            },
            N::Op {
                tag: tb,
                operands: ob,
            },
        ) => ta == tb && oa == ob,
        (
            N::TemplateCall {
                template_id: ta,
                capture_operands: ca,
                n_outputs: na,
            },
            N::TemplateCall {
                template_id: tb,
                capture_operands: cb,
                n_outputs: nb,
            },
        ) => ta == tb && ca == cb && na == nb,
        (N::NestedLoop, N::NestedLoop) => true,
        // Different variants → structural.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::lysis_lift::symbolic::symbolic_emit;
    use crate::ExtendedInstruction;
    use ir_core::{Instruction, SsaVar, Visibility};

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    // -----------------------------------------------------------------
    // Empty / trivial
    // -----------------------------------------------------------------

    #[test]
    fn empty_trees_are_slot_only_empty_set() {
        let a = SymbolicTree::<Bn254Fr>::new();
        let b = SymbolicTree::<Bn254Fr>::new();
        match structural_diff(&a, &b) {
            Diff::OnlyConstants(s) => assert!(s.is_empty()),
            Diff::Structural => panic!(),
        }
    }

    #[test]
    fn different_node_counts_are_structural() {
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(0),
                value: fe(1),
            }
            .into(),
            Instruction::Const {
                result: ssa(1),
                value: fe(2),
            }
            .into(),
        ];
        let a = symbolic_emit::<Bn254Fr>(&body_a, &[]);
        let b = symbolic_emit::<Bn254Fr>(&body_b, &[]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    // -----------------------------------------------------------------
    // Uniform bodies produced from the same source at different probes
    // -----------------------------------------------------------------

    #[test]
    fn body_without_iter_var_probes_identical() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(1),
                value: fe(7),
            }
            .into(),
            Instruction::Add {
                result: ssa(2),
                lhs: ssa(1),
                rhs: ssa(1),
            }
            .into(),
        ];
        let a = symbolic_emit(&body, &[(ssa(0), fe(0))]);
        let b = symbolic_emit(&body, &[(ssa(0), fe(1))]);
        match structural_diff(&a, &b) {
            // Body never references iter_var (ssa(0)), so the slot
            // Const is emitted but the difference in its value is
            // invisible when no Op references it. Hmm, actually the
            // slot IS compared even if not referenced — values
            // differ so slot 0 is recorded.
            Diff::OnlyConstants(s) => {
                assert!(s.contains(&SlotId(0)));
                assert_eq!(s.len(), 1);
            }
            Diff::Structural => panic!(),
        }
    }

    #[test]
    fn body_using_iter_var_records_slot() {
        // body: Mul(iter_var, iter_var)
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(10),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()];
        let a = symbolic_emit(&body, &[(ssa(0), fe(2))]);
        let b = symbolic_emit(&body, &[(ssa(0), fe(5))]);
        match structural_diff(&a, &b) {
            Diff::OnlyConstants(s) => {
                assert_eq!(s.len(), 1);
                assert!(s.contains(&SlotId(0)));
            }
            Diff::Structural => panic!(),
        }
    }

    #[test]
    fn equal_probes_produce_empty_slot_set() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(10),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()];
        let a = symbolic_emit(&body, &[(ssa(0), fe(3))]);
        let b = symbolic_emit(&body, &[(ssa(0), fe(3))]);
        match structural_diff(&a, &b) {
            Diff::OnlyConstants(s) => assert!(s.is_empty()),
            Diff::Structural => panic!(),
        }
    }

    #[test]
    fn multiple_slots_record_every_divergence() {
        // body: Add(v0, v1) — two bindings, values differ between probes.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Add {
            result: ssa(10),
            lhs: ssa(0),
            rhs: ssa(1),
        }
        .into()];
        let a = symbolic_emit(&body, &[(ssa(0), fe(0)), (ssa(1), fe(0))]);
        let b = symbolic_emit(&body, &[(ssa(0), fe(2)), (ssa(1), fe(5))]);
        match structural_diff(&a, &b) {
            Diff::OnlyConstants(s) => {
                assert!(s.contains(&SlotId(0)));
                assert!(s.contains(&SlotId(1)));
                assert_eq!(s.len(), 2);
            }
            Diff::Structural => panic!(),
        }
    }

    #[test]
    fn literal_const_mismatch_is_structural() {
        // Same SsaVar numbering but different literal values → the
        // bodies are genuinely different programs. Should be Structural.
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Const {
            result: ssa(0),
            value: fe(999),
        }
        .into()];
        let a = symbolic_emit::<Bn254Fr>(&body_a, &[]);
        let b = symbolic_emit::<Bn254Fr>(&body_b, &[]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    // -----------------------------------------------------------------
    // Topology mismatches
    // -----------------------------------------------------------------

    #[test]
    fn different_ops_are_structural() {
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Add {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }
        .into()];
        let a = symbolic_emit(&body_a, &[(ssa(0), fe(0)), (ssa(1), fe(0))]);
        let b = symbolic_emit(&body_b, &[(ssa(0), fe(0)), (ssa(1), fe(0))]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    #[test]
    fn different_input_names_are_structural() {
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: Visibility::Witness,
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Input {
            result: ssa(0),
            name: "y".into(),
            visibility: Visibility::Witness,
        }
        .into()];
        let a = symbolic_emit::<Bn254Fr>(&body_a, &[]);
        let b = symbolic_emit::<Bn254Fr>(&body_b, &[]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    #[test]
    fn different_visibility_is_structural() {
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: Visibility::Public,
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: Visibility::Witness,
        }
        .into()];
        let a = symbolic_emit::<Bn254Fr>(&body_a, &[]);
        let b = symbolic_emit::<Bn254Fr>(&body_b, &[]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    #[test]
    fn slot_const_vs_literal_const_is_structural() {
        // body_a has Mul(iter, iter) — iter resolves to slot Const.
        // body_b has Mul(lit, lit) — lit is a literal Const.
        // Node layout differs (slot node exists in a, not in b)
        // plus the types of the referenced Const differ. Structural.
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(10),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(1),
                value: fe(3),
            }
            .into(),
            Instruction::Mul {
                result: ssa(10),
                lhs: ssa(1),
                rhs: ssa(1),
            }
            .into(),
        ];
        let a = symbolic_emit(&body_a, &[(ssa(0), fe(3))]);
        let b = symbolic_emit::<Bn254Fr>(&body_b, &[]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    #[test]
    fn different_outer_refs_are_structural() {
        let body_a: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Add {
            result: ssa(10),
            lhs: ssa(98),
            rhs: ssa(99),
        }
        .into()];
        let body_b: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Add {
            result: ssa(10),
            lhs: ssa(98),
            rhs: ssa(100),
        }
        .into()];
        let a = symbolic_emit::<Bn254Fr>(&body_a, &[]);
        let b = symbolic_emit::<Bn254Fr>(&body_b, &[]);
        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    #[test]
    fn nested_loop_markers_compare_equal() {
        // Two identical bodies with NestedLoop sentinels should
        // classify as structurally equal — the enclosing loop will
        // still be DataDependent (classification isn't about diff,
        // it's about NestedLoop presence), but structural_diff
        // alone shouldn't flag them.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 4,
            body: vec![],
        }];
        let a = symbolic_emit::<Bn254Fr>(&body, &[]);
        let b = symbolic_emit::<Bn254Fr>(&body, &[]);
        assert!(structural_diff(&a, &b).is_slot_only());
    }

    #[test]
    fn body_order_mismatch_is_structural() {
        // Manually construct two trees with different body_order
        // even though nodes pool matches — simulates a defensive
        // check against a future buggy emitter.
        let mut a: SymbolicTree<Bn254Fr> = SymbolicTree::new();
        a.push(SymbolicNode::Const {
            value: fe(1),
            from_slot: None,
        });
        a.push(SymbolicNode::Const {
            value: fe(2),
            from_slot: None,
        });
        a.body_order = vec![0, 1];

        let mut b: SymbolicTree<Bn254Fr> = SymbolicTree::new();
        b.push(SymbolicNode::Const {
            value: fe(1),
            from_slot: None,
        });
        b.push(SymbolicNode::Const {
            value: fe(2),
            from_slot: None,
        });
        b.body_order = vec![1, 0];

        assert_eq!(structural_diff(&a, &b), Diff::Structural);
    }

    #[test]
    fn is_slot_only_helper() {
        assert!(Diff::OnlyConstants(BTreeSet::new()).is_slot_only());
        assert!(!Diff::Structural.is_slot_only());
    }
}
