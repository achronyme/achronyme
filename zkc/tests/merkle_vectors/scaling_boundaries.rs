use memory::FieldElement;

use super::helpers::*;

#[test]
fn merkle_depth10_selected() {
    let p = params();
    let leaves = make_leaves(10, 1000);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(10);
    for &idx in &[0, 511, 512, 1023] {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth10_constraint_count() {
    let p = params();
    let leaves = make_leaves(10, 1000);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    let n = compile_merkle(&merkle_source(10), &inputs);
    // 10 levels: ~3,650
    assert!(
        (3500..=3800).contains(&n),
        "depth-10 constraint count unexpected: {n}"
    );
}

#[test]
fn merkle_depth10_wrong_leaf() {
    let p = params();
    let leaves = make_leaves(10, 1000);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 512);
    let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(10), &inputs);
}

#[test]
fn merkle_constraint_scaling_linear() {
    let p = params();
    let mut counts = Vec::new();
    for depth in 1..=5 {
        let leaves = make_leaves(depth, depth as u64 * 100);
        let root = build_merkle_tree(&p, &leaves);
        let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
        let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
        let n = compile_merkle(&merkle_source(depth), &inputs);
        counts.push((depth, n));
    }
    // Verify approximately linear scaling: each level adds ~365 constraints
    for i in 1..counts.len() {
        let delta = counts[i].1 as i64 - counts[i - 1].1 as i64;
        assert!(
            (340..=390).contains(&delta),
            "constraint delta between depth {} and {} is {delta} (expected ~365)",
            counts[i - 1].0,
            counts[i].0,
        );
    }
}

#[test]
fn merkle_depth2_boundary_leaves() {
    let p = params();
    let p_minus_1 = FieldElement::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap();
    let p_minus_2 = FieldElement::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495615",
    )
    .unwrap();
    let leaves = vec![fe(0), fe(1), p_minus_1, p_minus_2];
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(2);
    for idx in 0..4 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth1_zero_leaves() {
    let p = params();
    let leaves = vec![fe(0), fe(0)];
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    compile_merkle(&merkle_source(1), &inputs);
}

#[test]
fn merkle_depth2_identical_leaves() {
    let p = params();
    let leaves = vec![fe(42); 4];
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(2);
    for idx in 0..4 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}
