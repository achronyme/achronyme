use memory::FieldElement;

use super::PoseidonParams;

/// Compute x^5 in the field.
#[inline]
pub fn sbox(x: FieldElement) -> FieldElement {
    let x2 = x.mul(&x);
    let x4 = x2.mul(&x2);
    x4.mul(&x)
}

/// Apply the Poseidon permutation to a state vector (in-place).
#[allow(clippy::needless_range_loop)]
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

        // 3. MDS matrix multiplication (stack copy avoids heap allocation)
        let mut old = [FieldElement::ZERO; 3];
        old[..params.t].copy_from_slice(&state[..params.t]);
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
/// Output: state[0] after permutation (circomlibjs convention)
pub fn poseidon_hash(
    params: &PoseidonParams,
    left: FieldElement,
    right: FieldElement,
) -> FieldElement {
    let mut state = [FieldElement::ZERO; 3]; // capacity = 0
    state[1] = left;
    state[2] = right;
    poseidon_permutation(params, &mut state);
    state[0]
}

/// Compute Poseidon hash of a single field element.
///
/// State: [capacity=0, input, 0]
/// Output: state[0] after permutation (circomlibjs convention)
pub fn poseidon_hash_single(params: &PoseidonParams, input: FieldElement) -> FieldElement {
    let mut state = [FieldElement::ZERO; 3];
    state[1] = input;
    poseidon_permutation(params, &mut state);
    state[0]
}
