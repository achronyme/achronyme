use constraints::poseidon::PoseidonParams;
use constraints::r1cs::Variable;
use memory::{FieldBackend, FieldElement};

use super::WitnessError;

/// Fill the ~361 internal Poseidon wires by replaying the permutation natively.
///
/// This must replicate *exactly* the variable allocation order of
/// `poseidon_hash_circuit` → `poseidon_permutation_circuit` in
/// `constraints/src/poseidon.rs`.
#[allow(clippy::needless_range_loop)]
pub(crate) fn fill_poseidon_witness<F: FieldBackend>(
    witness: &mut [FieldElement<F>],
    params: &PoseidonParams<F>,
    left: Variable,
    right: Variable,
    internal_start: usize,
    internal_count: usize,
) -> Result<(), WitnessError> {
    let total_rounds = params.r_f + params.r_p;
    let half_f = params.r_f / 2;

    let mut var_idx = internal_start;

    // First wire: capacity = 0
    witness[var_idx] = FieldElement::<F>::zero();
    var_idx += 1;

    // Initial state: [capacity=0, left, right]
    let mut state = [
        FieldElement::<F>::zero(),
        witness[left.index()],
        witness[right.index()],
    ];

    for r in 0..total_rounds {
        // 1. Add round constants
        for i in 0..params.t {
            state[i] = state[i].add(&params.round_constants[r * params.t + i]);
        }

        // 2. S-box layer
        if r < half_f || r >= half_f + params.r_p {
            // Full round: S-box on all 3 elements
            for i in 0..params.t {
                let x = state[i];
                let x2 = x.mul(&x);
                witness[var_idx] = x2;
                var_idx += 1;
                let x4 = x2.mul(&x2);
                witness[var_idx] = x4;
                var_idx += 1;
                let x5 = x4.mul(&x);
                witness[var_idx] = x5;
                var_idx += 1;
                state[i] = x5;
            }
        } else {
            // Partial round: S-box on state[0] only
            let x = state[0];
            let x2 = x.mul(&x);
            witness[var_idx] = x2;
            var_idx += 1;
            let x4 = x2.mul(&x2);
            witness[var_idx] = x4;
            var_idx += 1;
            let x5 = x4.mul(&x);
            witness[var_idx] = x5;
            var_idx += 1;
            state[0] = x5;
        }

        // 3. MDS matrix multiplication
        let old = state;
        for i in 0..params.t {
            state[i] = FieldElement::<F>::zero();
            for j in 0..params.t {
                state[i] = state[i].add(&params.mds[i][j].mul(&old[j]));
            }
        }

        // 4. Materialize state[1..] in partial rounds
        if r >= half_f && r < half_f + params.r_p {
            for i in 1..params.t {
                witness[var_idx] = state[i];
                var_idx += 1;
            }
        }
    }

    // Output state materialization (3 variables)
    for i in 0..params.t {
        witness[var_idx] = state[i];
        var_idx += 1;
    }

    // Sanity check: we filled exactly the expected number of wires
    debug_assert_eq!(
        var_idx - internal_start,
        internal_count,
        "Poseidon fill mismatch: filled {} wires but expected {}",
        var_idx - internal_start,
        internal_count
    );

    Ok(())
}
