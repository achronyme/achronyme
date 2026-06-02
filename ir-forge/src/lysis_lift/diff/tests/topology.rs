use super::*;

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
