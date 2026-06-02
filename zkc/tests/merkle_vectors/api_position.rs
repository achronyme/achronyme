use std::collections::HashMap;

use ir::IrLowering;
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

use super::helpers::*;

#[test]
fn merkle_depth2_via_lower_circuit() {
    let p = params();
    let leaves = make_leaves(2, 900);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 2);

    let source = "\
let l0 = mux(d0, s0, leaf)\n\
let r0 = mux(d0, leaf, s0)\n\
let h0 = poseidon(l0, r0)\n\
let l1 = mux(d1, s1, h0)\n\
let r1 = mux(d1, h0, s1)\n\
let h1 = poseidon(l1, r1)\n\
assert_eq(h1, root)";

    let program =
        IrLowering::lower_circuit(source, &["root"], &["leaf", "s0", "s1", "d0", "d1"]).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("root".into(), root);
    inputs.insert("leaf".into(), leaves[2]);
    inputs.insert("s0".into(), sibs[0]);
    inputs.insert("s1".into(), sibs[1]);
    inputs.insert("d0".into(), dirs[0]);
    inputs.insert("d1".into(), dirs[1]);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
}

#[test]
fn merkle_depth3_swapped_position_fails() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    // Get proof for index 0
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    // But try to prove leaf[1] at index 0 — should fail
    let inputs = merkle_inputs(root, leaves[1], &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(3), &inputs);
}

#[test]
fn merkle_depth3_cross_position_fails() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    // Proof for index 5, but use leaf from index 2
    let (sibs, dirs) = merkle_proof(&p, &leaves, 5);
    let inputs = merkle_inputs(root, leaves[2], &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(3), &inputs);
}

#[test]
fn merkle_different_trees_different_roots() {
    let p = params();
    let leaves_a = make_leaves(3, 100);
    let leaves_b = make_leaves(3, 200);
    let root_a = build_merkle_tree(&p, &leaves_a);
    let root_b = build_merkle_tree(&p, &leaves_b);
    assert_ne!(
        root_a, root_b,
        "different leaf sets should produce different roots"
    );

    // Prove membership in tree A
    let (sibs_a, dirs_a) = merkle_proof(&p, &leaves_a, 3);
    let inputs_a = merkle_inputs(root_a, leaves_a[3], &sibs_a, &dirs_a);
    compile_merkle(&merkle_source(3), &inputs_a);

    // Using tree A proof against tree B root should fail
    let inputs_wrong = merkle_inputs(root_b, leaves_a[3], &sibs_a, &dirs_a);
    compile_merkle_expect_fail(&merkle_source(3), &inputs_wrong);
}
