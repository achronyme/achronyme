use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

pub(super) fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

pub(super) fn params() -> PoseidonParams {
    PoseidonParams::bn254_t3()
}

/// Build a binary Merkle tree of arbitrary depth and return the root.
/// `leaves` must have exactly 2^depth elements.
pub(super) fn build_merkle_tree(p: &PoseidonParams, leaves: &[FieldElement]) -> FieldElement {
    let n = leaves.len();
    assert!(n.is_power_of_two() && n >= 2, "leaves must be 2^depth");
    let mut current: Vec<FieldElement> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            next.push(poseidon_hash(p, pair[0], pair[1]));
        }
        current = next;
    }
    current[0]
}

/// Compute the Merkle proof (siblings + direction bits) for leaf at `index`.
/// Returns (siblings[depth], directions[depth]) bottom-up.
pub(super) fn merkle_proof(
    p: &PoseidonParams,
    leaves: &[FieldElement],
    index: usize,
) -> (Vec<FieldElement>, Vec<FieldElement>) {
    let n = leaves.len();
    let depth = n.trailing_zeros() as usize;
    assert!(index < n);

    // Build all levels bottom-up
    let mut levels: Vec<Vec<FieldElement>> = Vec::new();
    levels.push(leaves.to_vec());
    for d in 0..depth {
        let prev = &levels[d];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for pair in prev.chunks(2) {
            next.push(poseidon_hash(p, pair[0], pair[1]));
        }
        levels.push(next);
    }

    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    let mut idx = index;
    for level in levels.iter().take(depth) {
        let dir = idx & 1; // 0 = left, 1 = right
        let sibling_idx = idx ^ 1;
        siblings.push(level[sibling_idx]);
        directions.push(fe(dir as u64));
        idx >>= 1;
    }
    (siblings, directions)
}

/// Generate the circuit source for a Merkle proof verification of given depth.
pub(super) fn merkle_source(depth: usize) -> String {
    let mut src = String::new();
    src.push_str("public root\nwitness leaf\n");
    for i in 0..depth {
        src.push_str(&format!("witness s{i}\nwitness d{i}\n"));
    }
    src.push('\n');
    // Level 0: hash(leaf, sibling) or hash(sibling, leaf) based on direction
    src.push_str(
        "let l0 = mux(d0, s0, leaf)\nlet r0 = mux(d0, leaf, s0)\nlet h0 = poseidon(l0, r0)\n\n",
    );
    // Levels 1..depth-1
    for i in 1..depth {
        let prev = format!("h{}", i - 1);
        src.push_str(&format!(
            "let l{i} = mux(d{i}, s{i}, {prev})\n\
             let r{i} = mux(d{i}, {prev}, s{i})\n\
             let h{i} = poseidon(l{i}, r{i})\n\n"
        ));
    }
    src.push_str(&format!("assert_eq(h{}, root)\n", depth - 1));
    src
}

/// Build inputs map for a Merkle proof verification.
pub(super) fn merkle_inputs(
    root: FieldElement,
    leaf: FieldElement,
    siblings: &[FieldElement],
    directions: &[FieldElement],
) -> HashMap<String, FieldElement> {
    let mut m = HashMap::new();
    m.insert("root".into(), root);
    m.insert("leaf".into(), leaf);
    for (i, &s) in siblings.iter().enumerate() {
        m.insert(format!("s{i}"), s);
    }
    for (i, &d) in directions.iter().enumerate() {
        m.insert(format!("d{i}"), d);
    }
    m
}

/// Compile, verify, and return constraint count for a Merkle proof circuit.
pub(super) fn compile_merkle(source: &str, inputs: &HashMap<String, FieldElement>) -> usize {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness = compiler
        .compile_ir_with_witness(&program, inputs)
        .expect("R1CS compilation failed");
    compiler
        .cs
        .verify(&witness)
        .expect("R1CS witness verification failed");
    compiler.cs.num_constraints()
}

/// Compile and expect failure for a Merkle proof circuit.
pub(super) fn compile_merkle_expect_fail(source: &str, inputs: &HashMap<String, FieldElement>) {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let result = compiler.compile_ir_with_witness(&program, inputs);
    if let Ok(witness) = result {
        let verify = compiler.cs.verify(&witness);
        assert!(
            verify.is_err(),
            "expected verification failure but it passed"
        );
    }
}

/// Generate leaves for a tree of given depth: [seed, seed+1, ..., seed+2^depth-1]
pub(super) fn make_leaves(depth: usize, seed: u64) -> Vec<FieldElement> {
    (0..(1usize << depth))
        .map(|i| fe(seed + i as u64))
        .collect()
}
