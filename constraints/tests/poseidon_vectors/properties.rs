use super::*;
use constraints::poseidon::native::sbox;

// ============================================================================
// Poseidon properties - from industry testing patterns
// Source: arkworks test-templates (field property tests)
//         https://github.com/arkworks-rs/algebra/blob/master/test-templates/src/fields.rs
// ============================================================================

/// Non-commutativity: poseidon(a, b) != poseidon(b, a)
/// This is fundamental to Merkle tree security - left vs right child must matter.
/// Pattern: arkworks-style exhaustive property verification
#[test]
fn poseidon_non_commutative_exhaustive() {
    let p = params();
    let values = [1u64, 2, 3, 5, 7, 42, 99, 1000];
    for &l in &values {
        for &r in &values {
            if l == r {
                continue;
            }
            let h_lr = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            let h_rl = poseidon_hash(&p, FieldElement::from_u64(r), FieldElement::from_u64(l));
            assert_ne!(
                h_lr, h_rl,
                "poseidon({l}, {r}) == poseidon({r}, {l}) - must be non-commutative"
            );
        }
    }
}

/// Collision resistance: all distinct input pairs produce distinct hashes.
/// Tests 20x20 = 400 input pairs - no two should collide.
#[test]
fn poseidon_no_collisions_20x20() {
    let p = params();
    let mut hashes = std::collections::HashMap::new();
    for l in 0u64..20 {
        for r in 0u64..20 {
            let h = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            let key = (l, r);
            if let Some(prev_key) = hashes.insert(h, key) {
                panic!(
                    "collision: poseidon({}, {}) == poseidon({}, {})",
                    prev_key.0, prev_key.1, l, r
                );
            }
        }
    }
    assert_eq!(
        hashes.len(),
        400,
        "should have 400 distinct hashes for 20x20 inputs"
    );
}

/// Avalanche effect: changing one input bit must change most output bits.
/// Standard cryptographic hash property.
#[test]
fn poseidon_avalanche_effect() {
    let p = params();
    let base = FieldElement::from_u64(1000);
    let h1 = poseidon_hash(&p, base, FieldElement::from_u64(0));
    let h2 = poseidon_hash(&p, base, FieldElement::from_u64(1));
    assert_ne!(h1, h2);

    let c1 = h1.to_canonical();
    let c2 = h2.to_canonical();
    let differing = c1.iter().zip(c2.iter()).filter(|(a, b)| a != b).count();
    assert!(
        differing >= 3,
        "avalanche: expected at least 3/4 limbs to differ, got {differing}"
    );
}

/// Determinism across multiple calls.
/// Pattern: go-iden3-crypto TestPoseidonHash verifies same computation twice.
#[test]
fn poseidon_determinism_stress() {
    let p = params();
    for l in 0u64..20 {
        for r in 0u64..20 {
            let h1 = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            let h2 = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            assert_eq!(h1, h2, "poseidon({l}, {r}) not deterministic");
        }
    }
}

/// Zero input: poseidon(0, 0) must be non-zero (pre-image resistance).
#[test]
fn poseidon_zero_inputs_non_zero() {
    let h = poseidon_hash(&params(), FieldElement::ZERO, FieldElement::ZERO);
    assert!(!h.is_zero(), "poseidon(0, 0) must not be zero");
}

/// poseidon_hash_single(x) == poseidon_hash(x, 0) by construction.
/// Our implementation: state = [0, x, 0] for single, state = [0, left, right] for pair.
#[test]
fn poseidon_single_equals_pair_with_zero() {
    let p = params();
    for v in [0u64, 1, 2, 42, 100, 999, u64::MAX] {
        let x = FieldElement::from_u64(v);
        let h_single = poseidon_hash_single(&p, x);
        let h_pair = poseidon_hash(&p, x, FieldElement::ZERO);
        assert_eq!(h_single, h_pair, "poseidon_single({v}) != poseidon({v}, 0)");
    }
}

// ============================================================================
// S-box (x^5) vectors
// These are derived from the Poseidon specification (ePrint 2019/458)
// S-box: alpha=5, so S(x) = x^5 in the field
// ============================================================================

#[test]
fn sbox_identity_values() {
    // 0^5 = 0
    assert_eq!(sbox(FieldElement::ZERO, 5), FieldElement::ZERO);
    // 1^5 = 1
    assert_eq!(sbox(FieldElement::ONE, 5), FieldElement::ONE);
}

#[test]
fn sbox_small_values() {
    let cases = [(2u64, 32u64), (3, 243), (4, 1024), (5, 3125), (10, 100000)];
    for (input, expected) in cases {
        let x: FieldElement = FieldElement::from_u64(input);
        assert_eq!(
            sbox(x, 5),
            FieldElement::from_u64(expected),
            "{input}^5 != {expected}"
        );
    }
}

/// (-1)^5 = -1 in any field (since 5 is odd)
#[test]
fn sbox_neg_one() {
    let neg1: FieldElement = FieldElement::from_u64(1);
    let neg1 = neg1.neg();
    assert_eq!(sbox(neg1, 5), neg1, "(-1)^5 must be -1");
}

// ============================================================================
// Constraint count regression
// Verifies our R1CS Poseidon matches expected constraint count.
// Industry reference: circomlib Poseidon has ~240 constraints (different encoding).
// Our implementation: 361 constraints (more conservative materialization).
// ============================================================================

#[test]
fn poseidon_r1cs_constraint_count_361() {
    use constraints::poseidon::circuit::poseidon_hash_circuit;
    use constraints::r1cs::ConstraintSystem;

    let p = params();
    let mut cs = ConstraintSystem::new();
    let left = cs.alloc_witness();
    let right = cs.alloc_witness();
    let _hash = poseidon_hash_circuit(&mut cs, &p, left, right);

    // 72 (full round S-boxes) + 171 (partial round S-boxes)
    // + 114 (materialization) + 3 (output) + 1 (capacity) = 361
    assert_eq!(cs.num_constraints(), 361);
}

// ============================================================================
// Large field values - boundary testing near modulus
// Pattern: arkworks test-templates boundary value methodology
// ============================================================================

#[test]
fn poseidon_near_modulus_inputs() {
    let p = params();
    let p_minus_1 =
        fe("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    let p_minus_2 =
        fe("21888242871839275222246405745257275088548364400416034343698204186575808495615");

    let h = poseidon_hash(&p, p_minus_1, p_minus_2);
    assert!(!h.is_zero());
    let h2 = poseidon_hash(&p, p_minus_1, p_minus_2);
    assert_eq!(h, h2);
}

// ============================================================================
// Merkle tree construction with Poseidon
// Pattern: go-iden3-crypto uses Poseidon for Sparse Merkle Trees
// Source: https://github.com/iden3/go-iden3-crypto
// ============================================================================

#[test]
fn poseidon_merkle_two_leaves() {
    let p = params();
    let leaf0 = poseidon_hash(&p, FieldElement::from_u64(100), FieldElement::ZERO);
    let leaf1 = poseidon_hash(&p, FieldElement::from_u64(200), FieldElement::ZERO);
    let root = poseidon_hash(&p, leaf0, leaf1);

    assert!(!root.is_zero());
    assert_ne!(root, leaf0);
    assert_ne!(root, leaf1);
    // Swapping leaves must change root (Merkle ordering)
    let root_swapped = poseidon_hash(&p, leaf1, leaf0);
    assert_ne!(root, root_swapped);
}

#[test]
fn poseidon_merkle_four_leaves() {
    let p = params();
    // Build a balanced binary Merkle tree with 4 leaves
    let l0 = poseidon_hash(&p, FieldElement::from_u64(10), FieldElement::ZERO);
    let l1 = poseidon_hash(&p, FieldElement::from_u64(20), FieldElement::ZERO);
    let l2 = poseidon_hash(&p, FieldElement::from_u64(30), FieldElement::ZERO);
    let l3 = poseidon_hash(&p, FieldElement::from_u64(40), FieldElement::ZERO);

    let n01 = poseidon_hash(&p, l0, l1);
    let n23 = poseidon_hash(&p, l2, l3);
    let root = poseidon_hash(&p, n01, n23);

    assert!(!root.is_zero());
    // Verify determinism
    let root2 = poseidon_hash(&p, n01, n23);
    assert_eq!(root, root2);
}

#[test]
fn poseidon_merkle_depth_8() {
    let p = params();
    // Build a hash chain simulating depth-8 Merkle path verification
    let mut h = poseidon_hash(&p, FieldElement::from_u64(42), FieldElement::ZERO);
    for i in 1u64..=8 {
        let sibling = poseidon_hash(&p, FieldElement::from_u64(i * 100), FieldElement::ZERO);
        h = poseidon_hash(&p, h, sibling);
    }
    assert!(!h.is_zero());
    // Determinism
    let mut h2 = poseidon_hash(&p, FieldElement::from_u64(42), FieldElement::ZERO);
    for i in 1u64..=8 {
        let sibling = poseidon_hash(&p, FieldElement::from_u64(i * 100), FieldElement::ZERO);
        h2 = poseidon_hash(&p, h2, sibling);
    }
    assert_eq!(h, h2);
}
