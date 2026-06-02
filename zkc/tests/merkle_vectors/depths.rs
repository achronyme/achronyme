use super::helpers::*;

#[test]
fn merkle_depth1_leaf0() {
    let p = params();
    let leaves = make_leaves(1, 100);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    compile_merkle(&merkle_source(1), &inputs);
}

#[test]
fn merkle_depth1_leaf1() {
    let p = params();
    let leaves = make_leaves(1, 100);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 1);
    let inputs = merkle_inputs(root, leaves[1], &sibs, &dirs);
    compile_merkle(&merkle_source(1), &inputs);
}

#[test]
fn merkle_depth1_wrong_leaf() {
    let p = params();
    let leaves = make_leaves(1, 100);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(1), &inputs);
}

#[test]
fn merkle_depth1_wrong_sibling() {
    let p = params();
    let leaves = make_leaves(1, 100);
    let root = build_merkle_tree(&p, &leaves);
    let (_, dirs) = merkle_proof(&p, &leaves, 0);
    let wrong_sibs = vec![fe(9999)];
    let inputs = merkle_inputs(root, leaves[0], &wrong_sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(1), &inputs);
}

#[test]
fn merkle_depth1_wrong_root() {
    let p = params();
    let leaves = make_leaves(1, 100);
    let _root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(fe(9999), leaves[0], &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(1), &inputs);
}

#[test]
fn merkle_depth1_constraint_count() {
    let p = params();
    let leaves = make_leaves(1, 100);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    let n = compile_merkle(&merkle_source(1), &inputs);
    // 1 level: conditional swap (2 mux) + 1 poseidon (~361) + 1 assert_eq ≈ 365
    assert!(
        (350..=380).contains(&n),
        "depth-1 constraint count unexpected: {n}"
    );
}

#[test]
fn merkle_depth2_all_positions() {
    let p = params();
    let leaves = make_leaves(2, 200);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(2);
    for idx in 0..4 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth2_wrong_leaf_all() {
    let p = params();
    let leaves = make_leaves(2, 200);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(2);
    for _idx in 0..4 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, _idx);
        let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
        compile_merkle_expect_fail(&source, &inputs);
    }
}

#[test]
fn merkle_depth2_constraint_count() {
    let p = params();
    let leaves = make_leaves(2, 200);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    let n = compile_merkle(&merkle_source(2), &inputs);
    // 2 levels: ~730
    assert!(
        (700..=760).contains(&n),
        "depth-2 constraint count unexpected: {n}"
    );
}

#[test]
fn merkle_depth3_all_positions_vectorized() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(3);
    for idx in 0..8 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth3_wrong_direction_bit() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, mut dirs) = merkle_proof(&p, &leaves, 0);
    // Flip the first direction bit: 0→1
    dirs[0] = fe(1 - dirs[0].to_canonical()[0]);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(3), &inputs);
}

#[test]
fn merkle_depth3_wrong_sibling_level1() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    let (mut sibs, dirs) = merkle_proof(&p, &leaves, 3);
    sibs[1] = fe(9999); // corrupt sibling at level 1
    let inputs = merkle_inputs(root, leaves[3], &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(3), &inputs);
}

#[test]
fn merkle_depth3_wrong_sibling_level2() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    let (mut sibs, dirs) = merkle_proof(&p, &leaves, 5);
    sibs[2] = fe(9999); // corrupt sibling at level 2
    let inputs = merkle_inputs(root, leaves[5], &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(3), &inputs);
}

#[test]
fn merkle_depth3_constraint_count() {
    let p = params();
    let leaves = make_leaves(3, 300);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    let n = compile_merkle(&merkle_source(3), &inputs);
    // 3 levels: ~1,095
    assert!(
        (1050..=1140).contains(&n),
        "depth-3 constraint count unexpected: {n}"
    );
}

#[test]
fn merkle_depth4_all_positions() {
    let p = params();
    let leaves = make_leaves(4, 400);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(4);
    for idx in 0..16 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth4_constraint_count() {
    let p = params();
    let leaves = make_leaves(4, 400);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    let n = compile_merkle(&merkle_source(4), &inputs);
    // 4 levels: ~1,460
    assert!(
        (1400..=1520).contains(&n),
        "depth-4 constraint count unexpected: {n}"
    );
}

#[test]
fn merkle_depth5_selected_positions() {
    let p = params();
    let leaves = make_leaves(5, 500);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(5);
    // Test first, last, and a few middle positions
    for &idx in &[0, 1, 15, 16, 30, 31] {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth5_wrong_leaf() {
    let p = params();
    let leaves = make_leaves(5, 500);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 15);
    let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(5), &inputs);
}

#[test]
fn merkle_depth6_first_last() {
    let p = params();
    let leaves = make_leaves(6, 600);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(6);
    for &idx in &[0, 63] {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth7_first_last() {
    let p = params();
    let leaves = make_leaves(7, 700);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(7);
    for &idx in &[0, 127] {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth8_first_last() {
    let p = params();
    let leaves = make_leaves(8, 800);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(8);
    for &idx in &[0, 255] {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}
