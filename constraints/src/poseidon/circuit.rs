use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};

use super::PoseidonParams;

/// Synthesize S-box (x^α) as R1CS constraints.
///
/// α=5: x² → x⁴ → x⁵ (3 constraints)
/// α=7: x² → x³ → x⁶ → x⁷ (4 constraints)
///
/// Returns the variable holding x^α.
fn sbox_circuit(cs: &mut ConstraintSystem, x: &LinearCombination, alpha: u32) -> Variable {
    match alpha {
        5 => {
            let x2 = cs.mul_lc(x, x);
            let x2_lc = LinearCombination::from_variable(x2);
            let x4 = cs.mul_lc(&x2_lc, &x2_lc);
            let x4_lc = LinearCombination::from_variable(x4);
            cs.mul_lc(&x4_lc, x)
        }
        7 => {
            let x2 = cs.mul_lc(x, x);
            let x2_lc = LinearCombination::from_variable(x2);
            let x3 = cs.mul_lc(&x2_lc, x);
            let x3_lc = LinearCombination::from_variable(x3);
            let x6 = cs.mul_lc(&x3_lc, &x3_lc);
            let x6_lc = LinearCombination::from_variable(x6);
            cs.mul_lc(&x6_lc, x)
        }
        _ => panic!("unsupported S-box exponent α={alpha} in R1CS circuit"),
    }
}

#[allow(clippy::needless_range_loop)]
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
                let out = sbox_circuit(cs, &state[i], params.alpha);
                new_state.push(LinearCombination::from_variable(out));
            }
            state = new_state;
        } else {
            // Partial round: S-box on first element only
            let out = sbox_circuit(cs, &state[0], params.alpha);
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
    // Capacity variable (always 0) — constrained to prevent malicious provers
    // from using non-zero capacity to forge hash results.
    let capacity = cs.alloc_witness();
    cs.enforce_equal(
        LinearCombination::from_variable(capacity),
        LinearCombination::zero(),
    );

    // Input state: [capacity, left, right]
    let input_vars = vec![capacity, left, right];
    let output_vars = poseidon_permutation_circuit(cs, params, &input_vars);

    // Output = state[0] (circomlibjs convention)
    output_vars[0]
}
