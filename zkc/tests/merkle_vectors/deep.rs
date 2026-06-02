use super::helpers::*;

#[test]
fn merkle_depth15_first_and_last() {
    let p = params();
    let leaves = make_leaves(15, 1500);
    let root = build_merkle_tree(&p, &leaves);
    let source = merkle_source(15);
    let n_leaves = 1 << 15;
    for &idx in &[0usize, n_leaves - 1] {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
        let inputs = merkle_inputs(root, leaves[idx], &sibs, &dirs);
        compile_merkle(&source, &inputs);
    }
}

#[test]
fn merkle_depth15_wrong_leaf() {
    let p = params();
    let leaves = make_leaves(15, 1500);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 100);
    let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(15), &inputs);
}

#[test]
#[ignore] // ~2 min: 2^20 leaves, run with `cargo test -- --ignored`
fn merkle_depth20_leaf0() {
    let p = params();
    let leaves = make_leaves(20, 2000);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);
    let n = compile_merkle(&merkle_source(20), &inputs);
    // Industry benchmark: Circom ~4,380, Gnark ~5,000
    // Achronyme: 20 * (~365) + 1 ≈ 7,301
    assert!(n > 7000, "depth-20 constraint count unexpectedly low: {n}");
    // Record for benchmark comparison with Table 1
    eprintln!("BENCHMARK: Merkle depth-20 constraint count = {n}");
}

#[test]
#[ignore] // ~2 min: 2^20 leaves, run with `cargo test -- --ignored`
fn merkle_depth20_wrong_leaf() {
    let p = params();
    let leaves = make_leaves(20, 2000);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(20), &inputs);
}
