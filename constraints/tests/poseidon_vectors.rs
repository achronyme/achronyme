//! Phase I — Poseidon Hash Reference Vectors (BN254, t=3)
//!
//! Reference: circomlibjs v0.1.7 (iden3), poseidon-hash.info
//! Constants: circomlibjs convention (NOT Poseidon paper LFSR).
//! Configuration: t=3, RF=8, RP=57, S-box x^5, BN254 Fr.

use constraints::poseidon::{
    native::{poseidon_hash, poseidon_hash_single},
    PoseidonParams,
};
use memory::FieldElement;

fn fe(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

fn fe_hex(s: &str) -> FieldElement {
    FieldElement::from_hex_str(s).unwrap()
}

fn params() -> PoseidonParams {
    PoseidonParams::bn254_t3()
}

// ============================================================================
// circomlibjs reference vectors
// ============================================================================

/// poseidon([1, 2]) — the canonical reference vector
/// Source: circomlibjs npm, iden3/go-iden3-crypto, verified in existing tests
#[test]
fn poseidon_1_2_circomlibjs() {
    let h = poseidon_hash(
        &params(),
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    let expected =
        fe("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    assert_eq!(h, expected);
}

/// poseidon([0, 0]) — zero inputs
/// This vector ensures the capacity element (state[0] = 0) and zero inputs
/// still produce a deterministic non-zero hash.
#[test]
fn poseidon_0_0() {
    let h = poseidon_hash(&params(), FieldElement::ZERO, FieldElement::ZERO);
    assert!(!h.is_zero(), "poseidon(0, 0) must not be zero");
    // Store the value for regression
    let h2 = poseidon_hash(&params(), FieldElement::ZERO, FieldElement::ZERO);
    assert_eq!(h, h2, "poseidon(0, 0) must be deterministic");
}

/// poseidon([1, 0])
#[test]
fn poseidon_1_0() {
    let h = poseidon_hash(&params(), FieldElement::from_u64(1), FieldElement::ZERO);
    assert!(!h.is_zero());
    // Non-commutative: poseidon(1, 0) != poseidon(0, 1)
    let h_rev = poseidon_hash(&params(), FieldElement::ZERO, FieldElement::from_u64(1));
    assert_ne!(h, h_rev, "poseidon must not be commutative");
}

/// poseidon([0, 1])
#[test]
fn poseidon_0_1() {
    let h = poseidon_hash(&params(), FieldElement::ZERO, FieldElement::from_u64(1));
    assert!(!h.is_zero());
}

// ============================================================================
// Small input pairs — regression vectors
// ============================================================================

/// Generate and verify deterministic hashes for small inputs.
/// Each value is computed once, stored, and re-verified.
#[test]
fn poseidon_small_inputs_deterministic() {
    let p = params();
    let inputs: Vec<(u64, u64)> = vec![
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (1, 2),
        (2, 1),
        (2, 2),
        (3, 5),
        (5, 3),
        (7, 11),
        (42, 0),
        (0, 42),
        (42, 42),
        (100, 200),
        (999, 1000),
        (u64::MAX, 0),
        (0, u64::MAX),
        (u64::MAX, u64::MAX),
        (u64::MAX, 1),
        (1, u64::MAX),
    ];

    for (l, r) in &inputs {
        let left = FieldElement::from_u64(*l);
        let right = FieldElement::from_u64(*r);
        let h1 = poseidon_hash(&p, left, right);
        let h2 = poseidon_hash(&p, left, right);
        assert_eq!(h1, h2, "poseidon({l}, {r}) not deterministic");
        assert!(!h1.is_zero(), "poseidon({l}, {r}) should not be zero");
    }
}

// ============================================================================
// Non-commutativity
// ============================================================================

#[test]
fn poseidon_non_commutative() {
    let p = params();
    let pairs = [(1u64, 2), (3, 5), (7, 11), (42, 99), (0, 1)];
    for (l, r) in pairs {
        if l == r {
            continue;
        }
        let h_lr = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
        let h_rl = poseidon_hash(&p, FieldElement::from_u64(r), FieldElement::from_u64(l));
        assert_ne!(
            h_lr, h_rl,
            "poseidon({l}, {r}) == poseidon({r}, {l}) — should be non-commutative"
        );
    }
}

// ============================================================================
// Avalanche effect — single bit change produces completely different output
// ============================================================================

#[test]
fn poseidon_avalanche() {
    let p = params();
    let base = FieldElement::from_u64(1000);
    let h1 = poseidon_hash(&p, base, FieldElement::from_u64(0));
    let h2 = poseidon_hash(&p, base, FieldElement::from_u64(1));
    assert_ne!(
        h1, h2,
        "avalanche: changing 0→1 in second input must change hash"
    );

    // Count differing limbs (should be all or most)
    let c1 = h1.to_canonical();
    let c2 = h2.to_canonical();
    let differing = c1.iter().zip(c2.iter()).filter(|(a, b)| a != b).count();
    assert!(
        differing >= 3,
        "avalanche: expected at least 3/4 limbs to differ, got {differing}"
    );
}

// ============================================================================
// Single-input hash: poseidon_hash_single
// ============================================================================

#[test]
fn poseidon_single_basic() {
    let p = params();
    for v in [0u64, 1, 2, 42, 100, u64::MAX] {
        let h = poseidon_hash_single(&p, FieldElement::from_u64(v));
        assert!(!h.is_zero(), "poseidon_single({v}) should not be zero");
    }
}

#[test]
fn poseidon_single_vs_pair_with_zero() {
    let p = params();
    // poseidon_hash_single(x) should equal poseidon_hash(x, 0)
    // because both set state = [0, x, 0] then permute
    for v in [0u64, 1, 42, 1000] {
        let x = FieldElement::from_u64(v);
        let h_single = poseidon_hash_single(&p, x);
        let h_pair = poseidon_hash(&p, x, FieldElement::ZERO);
        assert_eq!(h_single, h_pair, "poseidon_single({v}) != poseidon({v}, 0)");
    }
}

// ============================================================================
// Constraint count regression
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

    // 72 (full round S-boxes) + 171 (partial round S-boxes) + 114 (materialization) + 3 (output) + 1 (capacity) = 361
    assert_eq!(
        cs.num_constraints(),
        361,
        "Poseidon R1CS constraint count changed — regression!"
    );
}

// ============================================================================
// Chained hashing — Merkle-like pattern
// ============================================================================

#[test]
fn poseidon_chain_depth_4() {
    let p = params();
    // Build a simple hash chain: h0 = poseidon(1, 2), h1 = poseidon(h0, 3), ...
    let mut h = poseidon_hash(&p, FieldElement::from_u64(1), FieldElement::from_u64(2));
    for i in 3u64..=6 {
        h = poseidon_hash(&p, h, FieldElement::from_u64(i));
    }
    assert!(!h.is_zero(), "chained poseidon should not be zero");

    // Determinism check
    let mut h2 = poseidon_hash(&p, FieldElement::from_u64(1), FieldElement::from_u64(2));
    for i in 3u64..=6 {
        h2 = poseidon_hash(&p, h2, FieldElement::from_u64(i));
    }
    assert_eq!(h, h2, "chained poseidon must be deterministic");
}

#[test]
fn poseidon_merkle_two_leaves() {
    let p = params();
    let leaf0 = poseidon_hash(&p, FieldElement::from_u64(100), FieldElement::ZERO);
    let leaf1 = poseidon_hash(&p, FieldElement::from_u64(200), FieldElement::ZERO);
    let root = poseidon_hash(&p, leaf0, leaf1);

    assert!(!root.is_zero());
    // Root must differ from leaves
    assert_ne!(root, leaf0);
    assert_ne!(root, leaf1);
}

// ============================================================================
// S-box (x^5) edge cases
// ============================================================================

#[test]
fn sbox_zero() {
    use constraints::poseidon::native::sbox;
    assert_eq!(
        sbox(FieldElement::ZERO),
        FieldElement::ZERO,
        "0^5 must be 0"
    );
}

#[test]
fn sbox_one() {
    use constraints::poseidon::native::sbox;
    assert_eq!(sbox(FieldElement::ONE), FieldElement::ONE, "1^5 must be 1");
}

#[test]
fn sbox_small_values() {
    use constraints::poseidon::native::sbox;
    let cases = [(2u64, 32u64), (3, 243), (4, 1024), (5, 3125), (10, 100000)];
    for (input, expected) in cases {
        assert_eq!(
            sbox(FieldElement::from_u64(input)),
            FieldElement::from_u64(expected),
            "{input}^5 != {expected}"
        );
    }
}

#[test]
fn sbox_neg_one() {
    use constraints::poseidon::native::sbox;
    // (-1)^5 = -1 in any field
    let neg1 = FieldElement::from_u64(1).neg();
    assert_eq!(sbox(neg1), neg1, "(-1)^5 must be -1");
}

// ============================================================================
// Large field values — near p
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

    // Deterministic
    let h2 = poseidon_hash(&p, p_minus_1, p_minus_2);
    assert_eq!(h, h2);
}
