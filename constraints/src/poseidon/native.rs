use memory::{FieldBackend, FieldElement};

use super::PoseidonParams;

/// Compute x^α in the field (S-box).
///
/// α=5: x² → x⁴ → x⁵ (3 muls)
/// α=7: x² → x³ → x⁶ → x⁷ (4 muls)
#[inline]
pub fn sbox<F: FieldBackend>(x: FieldElement<F>, alpha: u32) -> FieldElement<F> {
    match alpha {
        5 => {
            let x2 = x.mul(&x);
            let x4 = x2.mul(&x2);
            x4.mul(&x)
        }
        7 => {
            let x2 = x.mul(&x);
            let x3 = x2.mul(&x);
            let x6 = x3.mul(&x3);
            x6.mul(&x)
        }
        _ => x.pow(&[alpha as u64, 0, 0, 0]),
    }
}

/// Apply the Poseidon permutation to a state vector (in-place).
#[allow(clippy::needless_range_loop)]
pub fn poseidon_permutation<F: FieldBackend>(
    params: &PoseidonParams<F>,
    state: &mut [FieldElement<F>],
) {
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
                state[i] = sbox(state[i], params.alpha);
            }
        } else {
            // Partial round: S-box on first element only
            state[0] = sbox(state[0], params.alpha);
        }

        // 3. MDS matrix multiplication
        let old: Vec<FieldElement<F>> = state[..params.t].to_vec();
        for i in 0..params.t {
            state[i] = FieldElement::<F>::zero();
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
pub fn poseidon_hash<F: FieldBackend>(
    params: &PoseidonParams<F>,
    left: FieldElement<F>,
    right: FieldElement<F>,
) -> FieldElement<F> {
    let mut state = vec![FieldElement::<F>::zero(); params.t];
    state[1] = left;
    state[2] = right;
    poseidon_permutation(params, &mut state);
    state[0]
}

/// Compute Poseidon hash of a single field element.
///
/// State: [capacity=0, input, 0]
/// Output: state[0] after permutation (circomlibjs convention)
pub fn poseidon_hash_single<F: FieldBackend>(
    params: &PoseidonParams<F>,
    input: FieldElement<F>,
) -> FieldElement<F> {
    let mut state = vec![FieldElement::<F>::zero(); params.t];
    state[1] = input;
    poseidon_permutation(params, &mut state);
    state[0]
}
