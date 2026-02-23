use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use constraints::poseidon::{poseidon_hash, PoseidonParams};
use constraints::{write_r1cs, write_wtns};
use ir::IrLowering;
use memory::FieldElement;

/// Build an 8-leaf Merkle tree using Poseidon and return the root.
fn build_merkle_tree(params: &PoseidonParams, leaves: &[FieldElement; 8]) -> FieldElement {
    // Level 0→1: hash pairs of leaves
    let h01 = poseidon_hash(params, leaves[0], leaves[1]);
    let h23 = poseidon_hash(params, leaves[2], leaves[3]);
    let h45 = poseidon_hash(params, leaves[4], leaves[5]);
    let h67 = poseidon_hash(params, leaves[6], leaves[7]);
    // Level 1→2
    let h0123 = poseidon_hash(params, h01, h23);
    let h4567 = poseidon_hash(params, h45, h67);
    // Level 2→3 (root)
    poseidon_hash(params, h0123, h4567)
}

/// Get the Merkle proof for a leaf at `index` (0..8).
/// Returns (siblings, direction_bits) bottom-up.
fn merkle_proof(
    params: &PoseidonParams,
    leaves: &[FieldElement; 8],
    index: usize,
) -> ([FieldElement; 3], [FieldElement; 3]) {
    // Level 0: leaf hashes
    let h01 = poseidon_hash(params, leaves[0], leaves[1]);
    let h23 = poseidon_hash(params, leaves[2], leaves[3]);
    let h45 = poseidon_hash(params, leaves[4], leaves[5]);
    let h67 = poseidon_hash(params, leaves[6], leaves[7]);
    let h0123 = poseidon_hash(params, h01, h23);
    let h4567 = poseidon_hash(params, h45, h67);

    let level0_hashes = [h01, h23, h45, h67];
    let level1_hashes = [h0123, h4567];

    // Direction bits (bottom-up): bit 0 of index, bit 1, bit 2
    let d0 = (index & 1) as u64; // 0 = left, 1 = right
    let d1 = ((index >> 1) & 1) as u64;
    let d2 = ((index >> 2) & 1) as u64;

    // Sibling at level 0: the other leaf in the same pair
    let s0 = leaves[index ^ 1];
    // Sibling at level 1: the other hash at level 1
    let s1 = level0_hashes[(index >> 1) ^ 1];
    // Sibling at level 2: the other hash at level 2
    let s2 = level1_hashes[(index >> 2) ^ 1];

    let siblings = [s0, s1, s2];
    let directions = [
        FieldElement::from_u64(d0),
        FieldElement::from_u64(d1),
        FieldElement::from_u64(d2),
    ];
    (siblings, directions)
}

/// Shared circuit source for Merkle proof
const MERKLE_SOURCE: &str = r#"
let l0 = mux(d0, s0, leaf)
let r0 = mux(d0, leaf, s0)
let h0 = poseidon(l0, r0)

let l1 = mux(d1, s1, h0)
let r1 = mux(d1, h0, s1)
let h1 = poseidon(l1, r1)

let l2 = mux(d2, s2, h1)
let r2 = mux(d2, h1, s2)
let h2 = poseidon(l2, r2)

assert_eq(h2, root)
"#;

/// Self-contained source (with in-source declarations)
const MERKLE_SOURCE_SELF_CONTAINED: &str = r#"
public root
witness leaf
witness s0, s1, s2
witness d0, d1, d2

let l0 = mux(d0, s0, leaf)
let r0 = mux(d0, leaf, s0)
let h0 = poseidon(l0, r0)

let l1 = mux(d1, s1, h0)
let r1 = mux(d1, h0, s1)
let h1 = poseidon(l1, r1)

let l2 = mux(d2, s2, h1)
let r2 = mux(d2, h1, s2)
let h2 = poseidon(l2, r2)

assert_eq(h2, root)
"#;

fn make_inputs(
    root: FieldElement,
    leaf: FieldElement,
    siblings: &[FieldElement; 3],
    directions: &[FieldElement; 3],
) -> HashMap<String, FieldElement> {
    let mut m = HashMap::new();
    m.insert("root".into(), root);
    m.insert("leaf".into(), leaf);
    m.insert("s0".into(), siblings[0]);
    m.insert("s1".into(), siblings[1]);
    m.insert("s2".into(), siblings[2]);
    m.insert("d0".into(), directions[0]);
    m.insert("d1".into(), directions[1]);
    m.insert("d2".into(), directions[2]);
    m
}

#[test]
fn merkle_depth3_via_lower_circuit() {
    let params = PoseidonParams::bn254_t3();
    let leaves: [FieldElement; 8] = std::array::from_fn(|i| FieldElement::from_u64(i as u64 + 100));
    let root = build_merkle_tree(&params, &leaves);

    // Prove membership of leaf at index 3
    let index = 3;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inputs = make_inputs(root, leaves[index], &siblings, &directions);

    // Lower via IR
    let program = IrLowering::lower_circuit(
        MERKLE_SOURCE,
        &["root"],
        &["leaf", "s0", "s1", "s2", "d0", "d1", "d2"],
    )
    .unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    // Witness generation + verification
    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Check constraint count: ~3*(2 mux + 360 poseidon) + 1 assert_eq
    assert!(
        compiler.cs.num_constraints() > 1000,
        "expected >1000 constraints for depth-3 Merkle"
    );
}

#[test]
fn merkle_depth3_via_lower_self_contained() {
    let params = PoseidonParams::bn254_t3();
    let leaves: [FieldElement; 8] = std::array::from_fn(|i| FieldElement::from_u64(i as u64 + 100));
    let root = build_merkle_tree(&params, &leaves);

    let index = 5;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inputs = make_inputs(root, leaves[index], &siblings, &directions);

    // Lower via self-contained (in-source declarations)
    let (pub_names, wit_names, program) =
        IrLowering::lower_self_contained(MERKLE_SOURCE_SELF_CONTAINED).unwrap();

    assert_eq!(pub_names, vec!["root"]);
    assert_eq!(wit_names, vec!["leaf", "s0", "s1", "s2", "d0", "d1", "d2"]);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();
}

#[test]
fn merkle_depth3_export_roundtrip() {
    let params = PoseidonParams::bn254_t3();
    let leaves: [FieldElement; 8] = std::array::from_fn(|i| FieldElement::from_u64(i as u64 + 200));
    let root = build_merkle_tree(&params, &leaves);

    let index = 0;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inputs = make_inputs(root, leaves[index], &siblings, &directions);

    let (_, _, program) = IrLowering::lower_self_contained(MERKLE_SOURCE_SELF_CONTAINED).unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    compiler.cs.verify(&witness).unwrap();

    // Export and verify structure
    let r1cs_data = write_r1cs(&compiler.cs);
    assert_eq!(&r1cs_data[0..4], b"r1cs");

    let wtns_data = write_wtns(&witness);
    assert_eq!(&wtns_data[0..4], b"wtns");

    // Wire counts should match
    let n_wires = u32::from_le_bytes(r1cs_data[60..64].try_into().unwrap());
    let n_witness = u32::from_le_bytes(wtns_data[60..64].try_into().unwrap());
    assert_eq!(n_wires, n_witness);
}

#[test]
fn merkle_depth3_all_leaf_positions() {
    let params = PoseidonParams::bn254_t3();
    let leaves: [FieldElement; 8] = std::array::from_fn(|i| FieldElement::from_u64(i as u64 + 42));
    let root = build_merkle_tree(&params, &leaves);

    for index in 0..8 {
        let (siblings, directions) = merkle_proof(&params, &leaves, index);
        let inputs = make_inputs(root, leaves[index], &siblings, &directions);

        let program = IrLowering::lower_circuit(
            MERKLE_SOURCE,
            &["root"],
            &["leaf", "s0", "s1", "s2", "d0", "d1", "d2"],
        )
        .unwrap();

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&program).unwrap();

        let wg = WitnessGenerator::from_compiler(&compiler);
        let witness = wg.generate(&inputs).unwrap();
        compiler.cs.verify(&witness).unwrap_or_else(|idx| {
            panic!("leaf index {index}: verification failed at constraint {idx}")
        });
    }
}

#[test]
fn merkle_depth3_wrong_leaf_fails() {
    let params = PoseidonParams::bn254_t3();
    let leaves: [FieldElement; 8] = std::array::from_fn(|i| FieldElement::from_u64(i as u64 + 100));
    let root = build_merkle_tree(&params, &leaves);

    let index = 3;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    // Use wrong leaf
    let wrong_leaf = FieldElement::from_u64(9999);
    let inputs = make_inputs(root, wrong_leaf, &siblings, &directions);

    let program = IrLowering::lower_circuit(
        MERKLE_SOURCE,
        &["root"],
        &["leaf", "s0", "s1", "s2", "d0", "d1", "d2"],
    )
    .unwrap();

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&witness).is_err(),
        "wrong leaf should fail verification"
    );
}
