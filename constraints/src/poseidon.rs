/// Poseidon Hash Function over BN254 Scalar Field
///
/// Sponge-based hash designed for arithmetic circuits.
/// Parameters: t=3 (state width), R_f=8 full rounds, R_p=57 partial rounds.
/// S-box: x^5 (alpha=5).
///
/// This implementation provides:
/// 1. Native computation (for witness generation)
/// 2. R1CS constraint synthesis (for proof circuits)
///
/// Round constants are generated via a deterministic PRG seeded with
/// the parameter string. For production interoperability with circomlib,
/// swap in the Grain LFSR constants.

use memory::FieldElement;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};

// ============================================================================
// Parameters
// ============================================================================

/// Poseidon parameters for BN254, t=3
#[derive(Clone)]
pub struct PoseidonParams {
    /// State width (number of field elements in sponge state)
    pub t: usize,
    /// Number of full rounds (split evenly: half at start, half at end)
    pub r_f: usize,
    /// Number of partial rounds (in the middle)
    pub r_p: usize,
    /// Round constants: (r_f + r_p) * t field elements
    pub round_constants: Vec<FieldElement>,
    /// MDS matrix: t x t, stored row-major
    pub mds: Vec<Vec<FieldElement>>,
}

impl PoseidonParams {
    /// Standard BN254 parameters: t=3, R_f=8, R_p=57
    pub fn bn254_t3() -> Self {
        let t = 3;
        let r_f = 8;
        let r_p = 57;
        let total_rounds = r_f + r_p;

        // --- MDS Matrix (Cauchy construction) ---
        // M[i][j] = 1 / (x_i + y_j) in the field
        // x = [0, 1, 2], y = [t, t+1, t+2] = [3, 4, 5]
        let mut mds = vec![vec![FieldElement::ZERO; t]; t];
        for i in 0..t {
            for j in 0..t {
                let sum = (i + j + t) as u64; // x_i + y_j = i + (j + t)
                let denom = FieldElement::from_u64(sum);
                // 1/sum in the field (safe: sum >= 3, never zero)
                mds[i][j] = denom.inv().unwrap();
            }
        }

        // --- Round Constants (deterministic PRG) ---
        // Seed: field element derived from parameters
        // Method: RC[i] = seed^(i+1) where seed = from_u64(golden_ratio_prime)
        // This ensures non-trivial, deterministic constants.
        //
        // NOTE: For production/interop with circomlib, replace with
        // Grain LFSR-generated constants per the Poseidon paper.
        let seed = FieldElement::from_u64(0x9e3779b97f4a7c15); // golden ratio * 2^64
        let mut round_constants = Vec::with_capacity(total_rounds * t);
        let mut current = seed;
        for _ in 0..(total_rounds * t) {
            round_constants.push(current);
            // Recurrence: current = current * seed + offset
            current = current.mul(&seed).add(&FieldElement::from_u64(7));
        }

        Self {
            t,
            r_f,
            r_p,
            round_constants,
            mds,
        }
    }
}

// ============================================================================
// S-box: x^5
// ============================================================================

/// Compute x^5 in the field.
#[inline]
fn sbox(x: FieldElement) -> FieldElement {
    let x2 = x.mul(&x);
    let x4 = x2.mul(&x2);
    x4.mul(&x)
}

// ============================================================================
// Native Poseidon Computation
// ============================================================================

/// Apply the Poseidon permutation to a state vector (in-place).
pub fn poseidon_permutation(params: &PoseidonParams, state: &mut [FieldElement]) {
    let total_rounds = params.r_f + params.r_p;
    let half_f = params.r_f / 2;

    for r in 0..total_rounds {
        // 1. Add round constants
        for i in 0..params.t {
            state[i] = state[i].add(&params.round_constants[r * params.t + i]);
        }

        // 2. S-box layer
        if r < half_f || r >= half_f + params.r_p {
            // Full round: S-box on all elements
            for i in 0..params.t {
                state[i] = sbox(state[i]);
            }
        } else {
            // Partial round: S-box on first element only
            state[0] = sbox(state[0]);
        }

        // 3. MDS matrix multiplication
        let old = state.to_vec();
        for i in 0..params.t {
            state[i] = FieldElement::ZERO;
            for j in 0..params.t {
                state[i] = state[i].add(&params.mds[i][j].mul(&old[j]));
            }
        }
    }
}

/// Compute Poseidon hash of two field elements (2-to-1 hash).
///
/// State: [capacity=0, input1, input2]
/// Output: state[1] after permutation
pub fn poseidon_hash(
    params: &PoseidonParams,
    left: FieldElement,
    right: FieldElement,
) -> FieldElement {
    let mut state = vec![FieldElement::ZERO; params.t]; // capacity = 0
    state[1] = left;
    state[2] = right;
    poseidon_permutation(params, &mut state);
    state[1] // output from first rate element
}

/// Compute Poseidon hash of a single field element.
///
/// State: [capacity=0, input, 0]
/// Output: state[1] after permutation
pub fn poseidon_hash_single(
    params: &PoseidonParams,
    input: FieldElement,
) -> FieldElement {
    let mut state = vec![FieldElement::ZERO; params.t];
    state[1] = input;
    poseidon_permutation(params, &mut state);
    state[1]
}

// ============================================================================
// R1CS Synthesis for Poseidon
// ============================================================================

/// Synthesize S-box (x^5) as R1CS constraints.
///
/// Creates 3 constraints:
///   x2 = x * x
///   x4 = x2 * x2
///   x5 = x4 * x
///
/// Returns the variable holding x^5.
fn sbox_circuit(
    cs: &mut ConstraintSystem,
    x: &LinearCombination,
) -> Variable {
    // x2 = x * x
    let x2 = cs.mul_lc(x, x);

    // x4 = x2 * x2
    let x2_lc = LinearCombination::from_variable(x2);
    let x4 = cs.mul_lc(&x2_lc, &x2_lc);

    // x5 = x4 * x
    let x4_lc = LinearCombination::from_variable(x4);
    cs.mul_lc(&x4_lc, x)
}

/// Synthesize Poseidon permutation as R1CS constraints.
///
/// Takes state variables as input, returns output state variables.
/// All linear operations (add constants, MDS) are folded into LCs
/// without creating constraints. Only S-boxes generate constraints.
pub fn poseidon_permutation_circuit(
    cs: &mut ConstraintSystem,
    params: &PoseidonParams,
    input_vars: &[Variable],
) -> Vec<Variable> {
    let total_rounds = params.r_f + params.r_p;
    let half_f = params.r_f / 2;

    // Current state as LCs (start from input variables)
    let mut state: Vec<LinearCombination> = input_vars
        .iter()
        .map(|v| LinearCombination::from_variable(*v))
        .collect();

    for r in 0..total_rounds {
        // 1. Add round constants (linear: fold into LC)
        for i in 0..params.t {
            let rc = params.round_constants[r * params.t + i];
            state[i] = state[i].clone() + LinearCombination::from_constant(rc);
        }

        // 2. S-box layer
        if r < half_f || r >= half_f + params.r_p {
            // Full round: S-box on all elements
            let mut new_state = Vec::with_capacity(params.t);
            for i in 0..params.t {
                let out = sbox_circuit(cs, &state[i]);
                new_state.push(LinearCombination::from_variable(out));
            }
            state = new_state;
        } else {
            // Partial round: S-box on first element only
            let out = sbox_circuit(cs, &state[0]);
            state[0] = LinearCombination::from_variable(out);
        }

        // 3. MDS matrix multiplication (linear: fold into LC)
        let old_state = state.clone();
        for i in 0..params.t {
            state[i] = LinearCombination::zero();
            for j in 0..params.t {
                let scaled = old_state[j].clone() * params.mds[i][j];
                state[i] = state[i].clone() + scaled;
            }
        }

        // 4. In partial rounds, materialize state[1..] to witness variables.
        //    Without this, LC terms grow exponentially: f(n) = 2·f(n-1)+3 ≈ 2^n.
        //    Materializing keeps each LC bounded to ~5 terms.
        if r >= half_f && r < half_f + params.r_p {
            for i in 1..params.t {
                let v = cs.alloc_witness();
                cs.enforce_equal(state[i].clone(), LinearCombination::from_variable(v));
                state[i] = LinearCombination::from_variable(v);
            }
        }
    }

    // Materialize final state into variables
    let mut output_vars = Vec::with_capacity(params.t);
    for i in 0..params.t {
        let out = cs.alloc_witness();
        cs.enforce_equal(state[i].clone(), LinearCombination::from_variable(out));
        output_vars.push(out);
    }

    output_vars
}

/// Synthesize a complete Poseidon 2-to-1 hash circuit.
///
/// Inputs: two field element variables
/// Output: the hash variable
///
/// Also returns all state variables for witness assignment.
pub fn poseidon_hash_circuit(
    cs: &mut ConstraintSystem,
    params: &PoseidonParams,
    left: Variable,
    right: Variable,
) -> Variable {
    // Capacity variable (always 0)
    let capacity = cs.alloc_witness();

    // Input state: [capacity, left, right]
    let input_vars = vec![capacity, left, right];
    let output_vars = poseidon_permutation_circuit(cs, params, &input_vars);

    // Output = state[1]
    output_vars[1]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::WitnessBuilder;

    #[test]
    fn test_poseidon_params_construction() {
        let params = PoseidonParams::bn254_t3();
        assert_eq!(params.t, 3);
        assert_eq!(params.r_f, 8);
        assert_eq!(params.r_p, 57);
        assert_eq!(params.round_constants.len(), 65 * 3);
        assert_eq!(params.mds.len(), 3);
        assert_eq!(params.mds[0].len(), 3);
    }

    #[test]
    fn test_sbox() {
        // 2^5 = 32
        let x = FieldElement::from_u64(2);
        assert_eq!(sbox(x), FieldElement::from_u64(32));

        // 3^5 = 243
        let x = FieldElement::from_u64(3);
        assert_eq!(sbox(x), FieldElement::from_u64(243));
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
        let h = poseidon_hash(&params, FieldElement::from_u64(1), FieldElement::from_u64(2));
        assert!(!h.is_zero());
        assert_ne!(h, FieldElement::ONE);
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
        assert!(result.is_ok(), "Poseidon R1CS verification failed at constraint {:?}", result.err());
    }

    #[test]
    fn test_poseidon_constraint_count() {
        let params = PoseidonParams::bn254_t3();
        let mut cs = ConstraintSystem::new();

        let left = cs.alloc_witness();
        let right = cs.alloc_witness();
        let _hash = poseidon_hash_circuit(&mut cs, &params, left, right);

        // Expected constraints:
        // S-box = 3 constraints each
        // Full rounds: 8 rounds * 3 S-boxes = 24 S-boxes = 72 constraints
        // Partial rounds: 57 rounds * 1 S-box = 57 S-boxes = 171 constraints
        // Partial round materialization: 57 rounds * 2 enforce_equal = 114 constraints
        // Output materialization: 3 enforce_equal = 3 constraints
        // Total = 72 + 171 + 114 + 3 = 360
        assert_eq!(cs.num_constraints(), 360);
    }
}
