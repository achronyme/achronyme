use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use memory::FieldElement;

use super::helpers::{cross_validate, fe, fe_to_decimal, snarkjs_available};

#[test]
fn golden_merkle_depth2() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Merkle depth-2 (4 leaves, Poseidon) ===");

    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..4).map(|i| fe(100 + i)).collect();

    // Build tree manually
    let h01 = poseidon_hash(&params, leaves[0], leaves[1]);
    let h23 = poseidon_hash(&params, leaves[2], leaves[3]);
    let root = poseidon_hash(&params, h01, h23);

    let root_str = fe_to_decimal(root);
    eprintln!("  Tree root = {root_str}");

    // Prove leaf[0] membership: sibling = leaves[1], direction = 0
    // Level 0: leaf is on the left, sibling = leaves[1]
    // Level 1: h01 is on the left, sibling = h23
    let source = "\
let l0 = mux(d0, s0, leaf)\n\
let r0 = mux(d0, leaf, s0)\n\
let h0 = poseidon(l0, r0)\n\
let l1 = mux(d1, s1, h0)\n\
let r1 = mux(d1, h0, s1)\n\
let h1 = poseidon(l1, r1)\n\
assert_eq(h1, root)";

    let mut inputs = HashMap::new();
    inputs.insert("root".into(), root);
    inputs.insert("leaf".into(), leaves[0]);
    inputs.insert("s0".into(), leaves[1]);
    inputs.insert("s1".into(), h23);
    inputs.insert("d0".into(), fe(0));
    inputs.insert("d1".into(), fe(0));

    let result = cross_validate(
        source,
        &["root"],
        &["leaf", "s0", "s1", "d0", "d1"],
        &inputs,
    );

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], root_str, "Merkle root wire mismatch");
    eprintln!("  Wire[1] (root) matches native computation: ✓");
    eprintln!("  snarkjs wtns check: ✓ (Merkle proof verified independently)");
    eprintln!(
        "  Constraints: {} (industry depth-2: Circom ~438, Gnark ~500)",
        result.constraint_count
    );
}

// ============================================================================
// 7. Full Groth16 prove + verify for Poseidon(1, 2)
//    The ultimate test: generate a ZK proof and verify it with snarkjs.
