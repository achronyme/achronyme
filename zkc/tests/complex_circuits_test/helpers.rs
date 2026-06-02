use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::IrLowering;
use memory::FieldElement;
use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

// ============================================================================
// Helpers
// ============================================================================

pub(super) fn fe(n: u64) -> FieldElement {
    FieldElement::from_u64(n)
}

pub(super) fn inputs(pairs: &[(&str, FieldElement)]) -> HashMap<String, FieldElement> {
    pairs.iter().map(|(n, v)| (n.to_string(), *v)).collect()
}

/// Compile source → IR → R1CS → witness → verify. Returns the compiler.
pub(super) fn r1cs_verify(
    source: &str,
    pub_names: &[&str],
    wit_names: &[&str],
    inp: &HashMap<String, FieldElement>,
) -> R1CSCompiler {
    let mut program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::new();
    rc.set_proven_boolean(proven);
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(inp).unwrap();
    rc.cs.verify(&w).unwrap();
    rc
}

/// Compile source → IR → optimize → Plonkish → witness → verify. Returns the compiler.
pub(super) fn plonkish_verify(
    source: &str,
    pub_names: &[&str],
    wit_names: &[&str],
    inp: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let mut program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(inp, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler.system.verify().expect("verification failed");
    compiler
}

/// Verify on both R1CS and Plonkish backends.
pub(super) fn both_verify(
    source: &str,
    pub_names: &[&str],
    wit_names: &[&str],
    inp: &HashMap<String, FieldElement>,
) {
    r1cs_verify(source, pub_names, wit_names, inp);
    plonkish_verify(source, pub_names, wit_names, inp);
}

/// Build a power-of-2 Merkle tree from leaves, returning the root.
pub(super) fn build_merkle_tree(params: &PoseidonParams, leaves: &[FieldElement]) -> FieldElement {
    assert!(leaves.len().is_power_of_two() && leaves.len() >= 2);
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(poseidon_hash(params, pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Get the Merkle proof (siblings, direction_bits) for a leaf at `index`.
pub(super) fn merkle_proof(
    params: &PoseidonParams,
    leaves: &[FieldElement],
    index: usize,
) -> (Vec<FieldElement>, Vec<FieldElement>) {
    assert!(leaves.len().is_power_of_two());
    let depth = (leaves.len() as f64).log2() as usize;
    let mut level = leaves.to_vec();
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    let mut idx = index;
    for _ in 0..depth {
        let sibling_idx = idx ^ 1;
        siblings.push(level[sibling_idx]);
        directions.push(fe((idx & 1) as u64));
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(poseidon_hash(params, pair[0], pair[1]));
        }
        level = next;
        idx >>= 1;
    }
    (siblings, directions)
}

/// Build Merkle source for a given depth using mux+poseidon pattern.
pub(super) fn merkle_source(depth: usize) -> String {
    let mut lines = Vec::new();
    for i in 0..depth {
        let prev = if i == 0 {
            "leaf".to_string()
        } else {
            format!("h{}", i - 1)
        };
        lines.push(format!("let l{i} = mux(d{i}, s{i}, {prev})"));
        lines.push(format!("let r{i} = mux(d{i}, {prev}, s{i})"));
        lines.push(format!("let h{i} = poseidon(l{i}, r{i})"));
    }
    lines.push(format!("assert_eq(h{}, root)", depth - 1));
    lines.join("\n")
}

/// Build inputs map for a Merkle proof.
pub(super) fn merkle_inputs(
    root: FieldElement,
    leaf: FieldElement,
    siblings: &[FieldElement],
    directions: &[FieldElement],
) -> HashMap<String, FieldElement> {
    let mut m = HashMap::new();
    m.insert("root".into(), root);
    m.insert("leaf".into(), leaf);
    for (i, s) in siblings.iter().enumerate() {
        m.insert(format!("s{i}"), *s);
    }
    for (i, d) in directions.iter().enumerate() {
        m.insert(format!("d{i}"), *d);
    }
    m
}

/// Build witness name list for a Merkle proof of given depth.
pub(super) fn merkle_wit_names(depth: usize) -> Vec<String> {
    let mut names = vec!["leaf".to_string()];
    for i in 0..depth {
        names.push(format!("s{i}"));
    }
    for i in 0..depth {
        names.push(format!("d{i}"));
    }
    names
}

// ============================================================================
// HIGH Priority: Large Merkle Trees (4 tests)
