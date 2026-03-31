use super::*;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use crate::witness::WitnessBuilder;
use memory::{Bls12_381Fr, FieldElement, GoldilocksFr};

// ============================================================================
// BN254 tests (backward compat)
// ============================================================================

#[test]
fn test_poseidon_params_construction() {
    let params = PoseidonParams::bn254_t3();
    assert_eq!(params.t, 3);
    assert_eq!(params.r_f, 8);
    assert_eq!(params.r_p, 57);
    assert_eq!(params.alpha, 5);
    assert_eq!(params.round_constants.len(), 65 * 3);
    assert_eq!(params.mds.len(), 3);
    assert_eq!(params.mds[0].len(), 3);
}

#[test]
fn test_sbox_alpha5() {
    // 2^5 = 32
    let x: FieldElement = FieldElement::from_u64(2);
    assert_eq!(native::sbox(x, 5), FieldElement::from_u64(32));

    // 3^5 = 243
    let x: FieldElement = FieldElement::from_u64(3);
    assert_eq!(native::sbox(x, 5), FieldElement::from_u64(243));
}

#[test]
fn test_sbox_alpha7() {
    // 2^7 = 128
    let x: FieldElement = FieldElement::from_u64(2);
    assert_eq!(native::sbox(x, 7), FieldElement::from_u64(128));

    // 3^7 = 2187
    let x: FieldElement = FieldElement::from_u64(3);
    assert_eq!(native::sbox(x, 7), FieldElement::from_u64(2187));
}

#[test]
fn test_poseidon_deterministic() {
    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(1);
    let b = FieldElement::from_u64(2);

    let h1 = poseidon_hash(&params, a, b);
    let h2 = poseidon_hash(&params, a, b);

    // Same inputs → same output
    assert_eq!(h1, h2);

    // Different inputs → different output
    let h3 = poseidon_hash(&params, b, a);
    assert_ne!(h1, h3);
}

#[test]
fn test_poseidon_not_trivial() {
    let params = PoseidonParams::bn254_t3();

    // Hash of (0, 0) should not be 0
    let h = poseidon_hash(&params, FieldElement::ZERO, FieldElement::ZERO);
    assert!(!h.is_zero());

    // Hash of (1, 2) should not be small
    let h = poseidon_hash(
        &params,
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    assert!(!h.is_zero());
    assert_ne!(h, FieldElement::ONE);
}

#[test]
fn test_poseidon_circomlibjs_reference_vector() {
    // Reference: circomlibjs poseidon([1, 2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    // Decimal: 7853200120776062878684798364095072458815029376092732009249414926327459813530
    let params = PoseidonParams::bn254_t3();
    let hash = poseidon_hash(
        &params,
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    let expected = FieldElement::from_decimal_str(
        "7853200120776062878684798364095072458815029376092732009249414926327459813530",
    )
    .unwrap();
    assert_eq!(
        hash, expected,
        "poseidon(1, 2) must match circomlibjs reference"
    );
}

#[test]
fn test_poseidon_single() {
    let params = PoseidonParams::bn254_t3();
    let x = FieldElement::from_u64(42);
    let h = poseidon_hash_single(&params, x);

    // Verify determinism
    assert_eq!(h, poseidon_hash_single(&params, x));

    // Different from identity
    assert_ne!(h, x);
}

#[test]
fn test_poseidon_circuit_matches_native() {
    // This is the critical test: R1CS computation must match native
    let params = PoseidonParams::bn254_t3();

    let left = FieldElement::from_u64(1);
    let right = FieldElement::from_u64(2);

    // 1. Compute native hash
    let expected_hash = poseidon_hash(&params, left, right);

    // 2. Build R1CS circuit
    let mut cs = ConstraintSystem::new();
    let hash_output = cs.alloc_input(); // public: the hash
    let left_var = cs.alloc_witness();
    let right_var = cs.alloc_witness();

    let computed_hash = poseidon_hash_circuit(&mut cs, &params, left_var, right_var);

    // Constrain: computed_hash == hash_output (public)
    cs.enforce_equal(
        LinearCombination::from_variable(computed_hash),
        LinearCombination::from_variable(hash_output),
    );

    // 3. Build witness by running native Poseidon to get intermediate values
    let mut wb = WitnessBuilder::new(&cs);
    wb.set(hash_output, expected_hash);
    wb.set(left_var, left);
    wb.set(right_var, right);

    // Set capacity = 0
    // Capacity is the 4th variable allocated (after ONE=0, hash_output=1, left=2, right=3)
    let capacity_var = Variable(4);
    wb.set(capacity_var, FieldElement::ZERO);

    // Compute all intermediate witness values by replaying the permutation
    let mut state = vec![FieldElement::ZERO, left, right];
    let total_rounds = params.r_f + params.r_p;
    let half_f = params.r_f / 2;

    // Track variable index (starts after our explicit allocations)
    // Variables 0-4 are: ONE, hash_output, left, right, capacity
    // Then poseidon_permutation_circuit allocates witness vars for each S-box
    let mut var_idx = 5; // first witness var from sbox_circuit

    for r in 0..total_rounds {
        // Add round constants
        for i in 0..params.t {
            state[i] = state[i].add(&params.round_constants[r * params.t + i]);
        }

        // S-box
        if r < half_f || r >= half_f + params.r_p {
            // Full round: 3 S-boxes, each produces 3 variables (x2, x4, x5)
            for i in 0..params.t {
                let x = state[i];
                let x2 = x.mul(&x);
                let x4 = x2.mul(&x2);
                let x5 = x4.mul(&x);
                wb.set(Variable(var_idx), x2);
                wb.set(Variable(var_idx + 1), x4);
                wb.set(Variable(var_idx + 2), x5);
                state[i] = x5;
                var_idx += 3;
            }
        } else {
            // Partial round: 1 S-box (on state[0])
            let x = state[0];
            let x2 = x.mul(&x);
            let x4 = x2.mul(&x2);
            let x5 = x4.mul(&x);
            wb.set(Variable(var_idx), x2);
            wb.set(Variable(var_idx + 1), x4);
            wb.set(Variable(var_idx + 2), x5);
            state[0] = x5;
            var_idx += 3;
        }

        // MDS
        let old = state.clone();
        for i in 0..params.t {
            state[i] = FieldElement::ZERO;
            for j in 0..params.t {
                state[i] = state[i].add(&params.mds[i][j].mul(&old[j]));
            }
        }

        // Materialization variables for state[1..] in partial rounds
        if r >= half_f && r < half_f + params.r_p {
            for i in 1..params.t {
                wb.set(Variable(var_idx), state[i]);
                var_idx += 1;
            }
        }
    }

    // Set output state variables (3 variables allocated by poseidon_permutation_circuit)
    for i in 0..params.t {
        wb.set(Variable(var_idx + i), state[i]);
    }

    // 4. Verify
    let witness = wb.build();
    let result = cs.verify(&witness);
    assert!(
        result.is_ok(),
        "Poseidon R1CS verification failed at constraint {:?}",
        result.err()
    );
}

#[test]
fn test_poseidon_constraint_count() {
    let params = PoseidonParams::bn254_t3();
    let mut cs = ConstraintSystem::new();

    let left = cs.alloc_witness();
    let right = cs.alloc_witness();
    let _hash = poseidon_hash_circuit(&mut cs, &params, left, right);

    // Expected constraints:
    // S-box = 3 constraints each (α=5)
    // Full rounds: 8 rounds * 3 S-boxes = 24 S-boxes = 72 constraints
    // Partial rounds: 57 rounds * 1 S-box = 57 S-boxes = 171 constraints
    // Partial round materialization: 57 rounds * 2 enforce_equal = 114 constraints
    // Output materialization: 3 enforce_equal = 3 constraints
    // Capacity constraint: 1 enforce_equal (capacity == 0)
    // Total = 72 + 171 + 114 + 3 + 1 = 361
    assert_eq!(cs.num_constraints(), 361);
}

// --- LFSR reference tests ---

#[test]
fn test_lfsr_params_construction() {
    let params = PoseidonParams::bn254_t3_lfsr();
    assert_eq!(params.t, 3);
    assert_eq!(params.r_f, 8);
    assert_eq!(params.r_p, 57);
    assert_eq!(params.alpha, 5);
    assert_eq!(params.round_constants.len(), 195);
    assert_eq!(params.mds.len(), 3);
}

#[test]
fn test_lfsr_deterministic() {
    let p1 = PoseidonParams::bn254_t3_lfsr();
    let p2 = PoseidonParams::bn254_t3_lfsr();
    assert_eq!(p1.round_constants, p2.round_constants);
    assert_eq!(p1.mds, p2.mds);
}

#[test]
fn test_lfsr_vs_circomlibjs_constants_differ() {
    // Documents that LFSR-generated constants do NOT match circomlibjs.
    // This is a known divergence (iden3/circomlib#75).
    let lfsr = PoseidonParams::bn254_t3_lfsr();
    let circom = PoseidonParams::bn254_t3();

    // Same structural parameters
    assert_eq!(lfsr.t, circom.t);
    assert_eq!(lfsr.r_f, circom.r_f);
    assert_eq!(lfsr.r_p, circom.r_p);
    assert_eq!(lfsr.round_constants.len(), circom.round_constants.len());

    // But different round constants
    assert_ne!(
        lfsr.round_constants[0], circom.round_constants[0],
        "LFSR and circomlibjs first round constant must differ"
    );

    // And different MDS matrices
    assert_ne!(
        lfsr.mds[0][0], circom.mds[0][0],
        "LFSR and circomlibjs MDS[0][0] must differ"
    );

    // Therefore different hash outputs
    let one = FieldElement::from_u64(1);
    let two = FieldElement::from_u64(2);
    let h_lfsr = poseidon_hash(&lfsr, one, two);
    let h_circom = poseidon_hash(&circom, one, two);
    assert_ne!(
        h_lfsr, h_circom,
        "LFSR and circomlibjs must produce different hashes"
    );
}

#[test]
fn test_parametric_constructor_validates() {
    // Too few round constants → panic
    let result = std::panic::catch_unwind(|| {
        PoseidonParams::new(
            3,
            8,
            57,
            5,
            vec![FieldElement::ZERO; 10], // need 195
            vec![vec![FieldElement::ZERO; 3]; 3],
        );
    });
    assert!(result.is_err());
}

// ============================================================================
// BLS12-381 Poseidon tests
// ============================================================================

#[test]
fn test_bls12_381_params() {
    let params = PoseidonParams::<Bls12_381Fr>::bls12_381_t3();
    assert_eq!(params.t, 3);
    assert_eq!(params.r_f, 8);
    assert_eq!(params.r_p, 57);
    assert_eq!(params.alpha, 5);
    assert_eq!(params.round_constants.len(), 195);
    assert_eq!(params.mds.len(), 3);
}

#[test]
fn test_bls12_381_deterministic() {
    let p1 = PoseidonParams::<Bls12_381Fr>::bls12_381_t3();
    let p2 = PoseidonParams::<Bls12_381Fr>::bls12_381_t3();
    assert_eq!(p1.round_constants, p2.round_constants);
    assert_eq!(p1.mds, p2.mds);
}

#[test]
fn test_bls12_381_hash_not_trivial() {
    let params = PoseidonParams::<Bls12_381Fr>::bls12_381_t3();
    type BlsFE = FieldElement<Bls12_381Fr>;

    let h = poseidon_hash(&params, BlsFE::zero(), BlsFE::zero());
    assert!(!h.is_zero(), "BLS12-381 poseidon(0,0) should not be 0");

    let h2 = poseidon_hash(&params, BlsFE::from_u64(1), BlsFE::from_u64(2));
    assert!(!h2.is_zero());
    assert_ne!(h, h2, "different inputs must produce different hashes");
}

#[test]
fn test_bls12_381_differs_from_bn254() {
    // Same logical inputs (1, 2) hashed in BN254 vs BLS12-381 must differ
    // (different field, different LFSR constants, different modulus)
    let bn_params = PoseidonParams::bn254_t3_lfsr();
    let bls_params = PoseidonParams::<Bls12_381Fr>::bls12_381_t3();

    let bn_hash = poseidon_hash(
        &bn_params,
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    let bls_hash = poseidon_hash(
        &bls_params,
        FieldElement::<Bls12_381Fr>::from_u64(1),
        FieldElement::<Bls12_381Fr>::from_u64(2),
    );

    // They are in different fields, so we compare canonical limbs
    assert_ne!(
        bn_hash.to_canonical(),
        bls_hash.to_canonical(),
        "BN254 and BLS12-381 Poseidon must produce different outputs"
    );
}

// ============================================================================
// Goldilocks Poseidon tests
// ============================================================================

#[test]
fn test_goldilocks_params() {
    let params = PoseidonParams::<GoldilocksFr>::goldilocks_t3();
    assert_eq!(params.t, 3);
    assert_eq!(params.r_f, 8);
    assert_eq!(params.r_p, 22);
    assert_eq!(params.alpha, 7);
    assert_eq!(params.round_constants.len(), 90); // (8+22)*3
    assert_eq!(params.mds.len(), 3);
}

#[test]
fn test_goldilocks_deterministic() {
    let p1 = PoseidonParams::<GoldilocksFr>::goldilocks_t3();
    let p2 = PoseidonParams::<GoldilocksFr>::goldilocks_t3();
    assert_eq!(p1.round_constants, p2.round_constants);
    assert_eq!(p1.mds, p2.mds);
}

#[test]
fn test_goldilocks_hash_not_trivial() {
    let params = PoseidonParams::<GoldilocksFr>::goldilocks_t3();
    type GlFE = FieldElement<GoldilocksFr>;

    let h = poseidon_hash(&params, GlFE::zero(), GlFE::zero());
    assert!(!h.is_zero(), "Goldilocks poseidon(0,0) should not be 0");

    let h2 = poseidon_hash(&params, GlFE::from_u64(1), GlFE::from_u64(2));
    assert!(!h2.is_zero());
    assert_ne!(h, h2);
}

#[test]
fn test_goldilocks_sbox_alpha7() {
    type GlFE = FieldElement<GoldilocksFr>;

    // x^7 for small values
    assert_eq!(native::sbox(GlFE::from_u64(2), 7), GlFE::from_u64(128));
    assert_eq!(native::sbox(GlFE::from_u64(3), 7), GlFE::from_u64(2187));
    assert_eq!(native::sbox(GlFE::zero(), 7), GlFE::zero());
    assert_eq!(native::sbox(GlFE::one(), 7), GlFE::one());
}

#[test]
fn test_goldilocks_poseidon_single() {
    let params = PoseidonParams::<GoldilocksFr>::goldilocks_t3();
    type GlFE = FieldElement<GoldilocksFr>;

    let x = GlFE::from_u64(42);
    let h = poseidon_hash_single(&params, x);

    // Deterministic
    assert_eq!(h, poseidon_hash_single(&params, x));
    // Not trivial
    assert_ne!(h, x);
    assert!(!h.is_zero());
}
