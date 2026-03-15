//! Phase III — Merkle Tree Circuit Vectors (R1CS, BN254 Fr)
//!
//! Parametric depth testing of binary Merkle trees with Poseidon hash (t=3).
//! Depths 1–20, all leaf positions, soundness (wrong leaf/sibling/direction),
//! and constraint count scaling validation.
//!
//! Industry sources:
//!   - gnark std (Apache-2.0): Merkle proof verification gadget
//!     https://github.com/Consensys/gnark
//!     https://github.com/hashcloak/merkle_trees_gnark
//!   - circomlib (GPL-3.0): MerkleTreeChecker.circom
//!     https://github.com/iden3/circomlib
//!   - ZoKrates stdlib (LGPL-3.0): std/hashes/poseidon + merkle
//!     https://zokrates.github.io/toolbox/stdlib.html
//!   - Ethereum Research: constraint benchmarks for Merkle+Poseidon
//!     https://ethresear.ch/t/gas-and-circuit-constraint-benchmarks
//!
//! Reference: "Análisis Integral de Vectores de Prueba y Evaluación de Rendimiento
//! para Entornos de Compilación de Conocimiento Cero" (2026), §Cadenas de Merkle.
//!
//! Constraint benchmark (Table 1):
//!   Circom depth-20: ~4,380 | Gnark depth-20: ~5,000 | Achronyme: TBD
//!
//! License compatibility: all sources GPL-3.0/Apache-2.0/LGPL-3.0, compatible with GPL-3.0.

use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use constraints::poseidon::{poseidon_hash, PoseidonParams};
use constraints::{write_r1cs, write_wtns};
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn params() -> PoseidonParams {
    PoseidonParams::bn254_t3()
}

/// Build a binary Merkle tree of arbitrary depth and return the root.
/// `leaves` must have exactly 2^depth elements.
fn build_merkle_tree(p: &PoseidonParams, leaves: &[FieldElement]) -> FieldElement {
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
fn merkle_proof(
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
    for d in 0..depth {
        let dir = idx & 1; // 0 = left, 1 = right
        let sibling_idx = idx ^ 1;
        siblings.push(levels[d][sibling_idx]);
        directions.push(fe(dir as u64));
        idx >>= 1;
    }
    (siblings, directions)
}

/// Generate the circuit source for a Merkle proof verification of given depth.
fn merkle_source(depth: usize) -> String {
    let mut src = String::new();
    src.push_str("public root\nwitness leaf\n");
    for i in 0..depth {
        src.push_str(&format!("witness s{i}\nwitness d{i}\n"));
    }
    src.push('\n');
    // Level 0: hash(leaf, sibling) or hash(sibling, leaf) based on direction
    src.push_str(&format!(
        "let l0 = mux(d0, s0, leaf)\nlet r0 = mux(d0, leaf, s0)\nlet h0 = poseidon(l0, r0)\n\n"
    ));
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
fn merkle_inputs(
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
fn compile_merkle(source: &str, inputs: &HashMap<String, FieldElement>) -> usize {
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
fn compile_merkle_expect_fail(source: &str, inputs: &HashMap<String, FieldElement>) {
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
fn make_leaves(depth: usize, seed: u64) -> Vec<FieldElement> {
    (0..(1usize << depth))
        .map(|i| fe(seed + i as u64))
        .collect()
}

// ============================================================================
// 1. Depth 1 — 2 leaves, simplest tree
// ============================================================================

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
    // 1 level: 2 mux + 1 poseidon (~361) + 1 assert_eq ≈ 365
    assert!(
        (350..=380).contains(&n),
        "depth-1 constraint count unexpected: {n}"
    );
}

// ============================================================================
// 2. Depth 2 — 4 leaves
// ============================================================================

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
    for idx in 0..4 {
        let (sibs, dirs) = merkle_proof(&p, &leaves, idx);
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

// ============================================================================
// 3. Depth 3 — 8 leaves (matches existing merkle_e2e_test but vectorized)
// ============================================================================

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

// ============================================================================
// 4. Depth 4 — 16 leaves
// ============================================================================

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

// ============================================================================
// 5. Depth 5 — 32 leaves
// ============================================================================

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

// ============================================================================
// 6. Depth 6-8 — medium trees
// ============================================================================

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

// ============================================================================
// 7. Depth 10 — stress test (1,024 leaves)
// ============================================================================

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

// ============================================================================
// 8. Constraint count scaling — linear in depth
// Source: Ethereum Research — constraint scaling O(depth * poseidon_cost)
// ============================================================================

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

// ============================================================================
// 9. Large leaf values — field element boundary leaves
// Source: arkworks test-templates — boundary value methodology.
// ============================================================================

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

// ============================================================================
// 10. Export roundtrip — .r1cs and .wtns binary format validation
// Source: SnarkJS compatibility — r1cs/wtns format compliance.
// ============================================================================

#[test]
fn merkle_depth2_export_roundtrip() {
    let p = params();
    let leaves = make_leaves(2, 500);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);

    let source = merkle_source(2);
    let (_, _, mut program) =
        IrLowering::lower_self_contained(&source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness = compiler
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compilation failed");
    compiler.cs.verify(&witness).expect("verification failed");

    // Export and validate magic bytes
    let r1cs_data = write_r1cs(&compiler.cs);
    assert_eq!(&r1cs_data[0..4], b"r1cs", "R1CS magic mismatch");

    let wtns_data = write_wtns(&witness);
    assert_eq!(&wtns_data[0..4], b"wtns", "WTNS magic mismatch");

    // Wire counts must match
    let n_wires = u32::from_le_bytes(r1cs_data[60..64].try_into().unwrap());
    let n_witness = u32::from_le_bytes(wtns_data[60..64].try_into().unwrap());
    assert_eq!(
        n_wires, n_witness,
        "wire count mismatch between R1CS and WTNS"
    );
}

#[test]
fn merkle_depth4_export_roundtrip() {
    let p = params();
    let leaves = make_leaves(4, 700);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 7);
    let inputs = merkle_inputs(root, leaves[7], &sibs, &dirs);

    let source = merkle_source(4);
    let (_, _, mut program) =
        IrLowering::lower_self_contained(&source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness = compiler
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compilation failed");
    compiler.cs.verify(&witness).expect("verification failed");

    let r1cs_data = write_r1cs(&compiler.cs);
    assert_eq!(&r1cs_data[0..4], b"r1cs");

    let wtns_data = write_wtns(&witness);
    assert_eq!(&wtns_data[0..4], b"wtns");

    let n_wires = u32::from_le_bytes(r1cs_data[60..64].try_into().unwrap());
    let n_witness = u32::from_le_bytes(wtns_data[60..64].try_into().unwrap());
    assert_eq!(n_wires, n_witness);
}

// ============================================================================
// 11. Depth 15 — deep tree stress test
// ============================================================================

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

// ============================================================================
// 12. Depth 20 — industry benchmark depth (Circom ~4,380, Gnark ~5,000)
// ============================================================================

#[test]
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
fn merkle_depth20_wrong_leaf() {
    let p = params();
    let leaves = make_leaves(20, 2000);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, fe(9999), &sibs, &dirs);
    compile_merkle_expect_fail(&merkle_source(20), &inputs);
}

// ============================================================================
// 13. Merkle with lower_circuit API (alternative lowering path)
// ============================================================================

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

// ============================================================================
// 14. Swapped leaf positions — proving leaf[i] at index j should fail
// Source: validates position-binding of Merkle proofs.
// ============================================================================

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

// ============================================================================
// 15. Multiple trees — different leaf sets produce different roots
// ============================================================================

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
