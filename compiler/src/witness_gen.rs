use std::collections::HashMap;
use std::fmt;

use constraints::poseidon::PoseidonParams;
use constraints::r1cs::{LinearCombination, Variable};
use memory::FieldElement;

// ============================================================================
// WitnessOp — records intermediate variable computation
// ============================================================================

/// A single witness computation operation recorded during circuit compilation.
///
/// Each variant corresponds to a point where `R1CSCompiler` allocates an
/// intermediate variable. Replaying these operations with concrete input
/// values produces the full witness vector.
#[derive(Debug, Clone)]
pub enum WitnessOp {
    /// Assign: `target = lc.evaluate(witness)`
    /// Emitted by `materialize_lc` when it allocates a new variable.
    AssignLC {
        target: Variable,
        lc: LinearCombination,
    },
    /// Multiply: `target = a.evaluate(witness) * b.evaluate(witness)`
    /// Emitted by `multiply_lcs` (general case).
    Multiply {
        target: Variable,
        a: LinearCombination,
        b: LinearCombination,
    },
    /// Inverse: `target = 1 / operand.evaluate(witness)`
    /// Emitted by `divide_lcs` (general case).
    Inverse {
        target: Variable,
        operand: LinearCombination,
    },
    /// Bit extraction: target = (source >> bit_index) & 1.
    /// Emitted by RangeCheck boolean decomposition.
    BitExtract {
        target: Variable,
        source: LinearCombination,
        bit_index: u32,
    },
    /// IsZero gadget: if diff==0 then inv=0,result=1 else inv=1/diff,result=0.
    IsZero {
        diff: LinearCombination,
        target_inv: Variable,
        target_result: Variable,
    },
    /// Poseidon hash: compute all ~361 internal wires by replaying the
    /// permutation natively.
    PoseidonHash {
        left: Variable,
        right: Variable,
        output: Variable,
        internal_start: usize,
        internal_count: usize,
    },
}

// ============================================================================
// WitnessError
// ============================================================================

/// Errors that can occur during witness generation.
#[derive(Debug)]
pub enum WitnessError {
    /// A required input variable was not provided.
    MissingInput(String),
    /// Division by zero encountered during witness computation.
    DivisionByZero { variable_index: usize },
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::MissingInput(name) => {
                write!(f, "missing input for variable `{name}`")
            }
            WitnessError::DivisionByZero { variable_index } => {
                write!(
                    f,
                    "division by zero computing witness variable {variable_index}"
                )
            }
        }
    }
}

impl std::error::Error for WitnessError {}

// ============================================================================
// WitnessGenerator
// ============================================================================

/// Generates the complete witness vector for a compiled R1CS circuit.
///
/// After `R1CSCompiler::compile_circuit()`, call `WitnessGenerator::from_compiler()`
/// to capture the compilation trace. Then call `generate()` with concrete input
/// values to produce a witness that satisfies `cs.verify()`.
pub struct WitnessGenerator {
    ops: Vec<WitnessOp>,
    num_variables: usize,
    public_inputs: Vec<(String, Variable)>,
    witnesses: Vec<(String, Variable)>,
    poseidon_params: Option<PoseidonParams>,
}

impl WitnessGenerator {
    /// Build a `WitnessGenerator` from a compiled `R1CSCompiler`.
    ///
    /// Must be called after `compile_circuit()` — captures the ops trace,
    /// variable layout, and (if used) Poseidon parameters.
    pub fn from_compiler(compiler: &crate::r1cs_backend::R1CSCompiler) -> Self {
        let public_inputs: Vec<(String, Variable)> = compiler
            .public_inputs
            .iter()
            .map(|name| (name.clone(), compiler.bindings[name]))
            .collect();

        let witnesses: Vec<(String, Variable)> = compiler
            .witnesses
            .iter()
            .map(|name| (name.clone(), compiler.bindings[name]))
            .collect();

        Self {
            ops: compiler.witness_ops.clone(),
            num_variables: compiler.cs.num_variables(),
            public_inputs,
            witnesses,
            poseidon_params: compiler.poseidon_params.clone(),
        }
    }

    /// Generate the complete witness vector from input values.
    ///
    /// `inputs` maps variable names (both public and witness) to their
    /// field element values. All declared public inputs and witnesses must
    /// be present.
    pub fn generate(
        &self,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<Vec<FieldElement>, WitnessError> {
        let mut witness = vec![FieldElement::ZERO; self.num_variables];
        witness[0] = FieldElement::ONE;

        // Fill public inputs
        for (name, var) in &self.public_inputs {
            let val = inputs
                .get(name)
                .ok_or_else(|| WitnessError::MissingInput(name.clone()))?;
            witness[var.index()] = *val;
        }

        // Fill declared witnesses
        for (name, var) in &self.witnesses {
            let val = inputs
                .get(name)
                .ok_or_else(|| WitnessError::MissingInput(name.clone()))?;
            witness[var.index()] = *val;
        }

        // Replay ops to compute all intermediate wires
        for op in &self.ops {
            self.execute_op(op, &mut witness)?;
        }

        Ok(witness)
    }

    /// Execute a single `WitnessOp`, filling in the target wire(s).
    fn execute_op(
        &self,
        op: &WitnessOp,
        witness: &mut [FieldElement],
    ) -> Result<(), WitnessError> {
        match op {
            WitnessOp::AssignLC { target, lc } => {
                witness[target.index()] = lc.evaluate(witness);
            }
            WitnessOp::Multiply { target, a, b } => {
                let a_val = a.evaluate(witness);
                let b_val = b.evaluate(witness);
                witness[target.index()] = a_val.mul(&b_val);
            }
            WitnessOp::Inverse { target, operand } => {
                let val = operand.evaluate(witness);
                let inv = val.inv().ok_or(WitnessError::DivisionByZero {
                    variable_index: target.index(),
                })?;
                witness[target.index()] = inv;
            }
            WitnessOp::BitExtract {
                target,
                source,
                bit_index,
            } => {
                let val = source.evaluate(witness);
                let limbs = val.to_canonical();
                let limb_idx = (*bit_index / 64) as usize;
                let bit_pos = *bit_index % 64;
                let bit = if limb_idx < 4 {
                    (limbs[limb_idx] >> bit_pos) & 1
                } else {
                    0
                };
                witness[target.index()] = FieldElement::from_u64(bit);
            }
            WitnessOp::IsZero {
                diff,
                target_inv,
                target_result,
            } => {
                let diff_val = diff.evaluate(witness);
                if diff_val.is_zero() {
                    witness[target_inv.index()] = FieldElement::ZERO;
                    witness[target_result.index()] = FieldElement::ONE;
                } else {
                    // Safe: diff_val is non-zero, so inv() always returns Some
                    let inv = diff_val.inv().ok_or(WitnessError::DivisionByZero {
                        variable_index: target_inv.index(),
                    })?;
                    witness[target_inv.index()] = inv;
                    witness[target_result.index()] = FieldElement::ZERO;
                }
            }
            WitnessOp::PoseidonHash {
                left,
                right,
                output: _,
                internal_start,
                internal_count,
            } => {
                self.fill_poseidon(witness, *left, *right, *internal_start, *internal_count)?;
            }
        }
        Ok(())
    }

    /// Fill the ~361 internal Poseidon wires by replaying the permutation natively.
    ///
    /// This must replicate *exactly* the variable allocation order of
    /// `poseidon_hash_circuit` → `poseidon_permutation_circuit` in
    /// `constraints/src/poseidon.rs`.
    fn fill_poseidon(
        &self,
        witness: &mut [FieldElement],
        left: Variable,
        right: Variable,
        internal_start: usize,
        internal_count: usize,
    ) -> Result<(), WitnessError> {
        let params = self.poseidon_params.as_ref().ok_or_else(|| {
            WitnessError::MissingInput("poseidon parameters not initialized".into())
        })?;

        let total_rounds = params.r_f + params.r_p;
        let half_f = params.r_f / 2;

        let mut var_idx = internal_start;

        // First wire: capacity = 0
        witness[var_idx] = FieldElement::ZERO;
        var_idx += 1;

        // Initial state: [capacity=0, left, right]
        let mut state = [
            FieldElement::ZERO,
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
                state[i] = FieldElement::ZERO;
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
}
