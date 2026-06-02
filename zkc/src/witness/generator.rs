use std::collections::HashMap;

use constraints::poseidon::PoseidonParams;
use constraints::r1cs::Variable;
use constraints::r1cs_optimize::SubstitutionMap;
use constraints::PoseidonParamsProvider;
use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::{
    dispatch_artik_call, fill_poseidon_witness, int_divmod_field_pub, WitnessError, WitnessOp,
};

// ============================================================================
// WitnessGenerator
// ============================================================================

/// Generates the complete witness vector for a compiled R1CS circuit.
///
/// After `R1CSCompiler::compile_ir()`, call `WitnessGenerator::from_compiler()`
/// to capture the compilation trace. Then call `generate()` with concrete input
/// values to produce a witness that satisfies `cs.verify()`.
pub struct WitnessGenerator<F: FieldBackend = Bn254Fr> {
    ops: crate::segmented_vec::SegmentedVec<WitnessOp<F>>,
    num_variables: usize,
    public_inputs: Vec<(String, Variable)>,
    witnesses: Vec<(String, Variable)>,
    poseidon_params: Option<PoseidonParams<F>>,
    /// Substitution map from R1CS optimization (if optimize_r1cs was called).
    substitution_map: Option<SubstitutionMap<F>>,
}

impl<F: FieldBackend> WitnessGenerator<F> {
    /// Build a `WitnessGenerator` from a compiled `R1CSCompiler`.
    ///
    /// Must be called after `compile_ir()` — captures the ops trace,
    /// variable layout, and (if used) Poseidon parameters.
    pub fn from_compiler(compiler: &crate::r1cs_backend::R1CSCompiler<F>) -> Self {
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
            substitution_map: compiler.substitution_map.clone(),
        }
    }

    /// Generate the complete witness vector from input values.
    ///
    /// `inputs` maps variable names (both public and witness) to their
    /// field element values. All declared public inputs and witnesses must
    /// be present.
    pub fn generate(
        &self,
        inputs: &HashMap<String, FieldElement<F>>,
    ) -> Result<Vec<FieldElement<F>>, WitnessError>
    where
        F: PoseidonParamsProvider,
    {
        let mut witness = vec![FieldElement::<F>::zero(); self.num_variables];
        witness[0] = FieldElement::<F>::one();

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

        // Post-fixup: fill substituted-away wires from substitution map
        if let Some(subs) = &self.substitution_map {
            for (var_idx, lc) in subs {
                witness[*var_idx] = lc
                    .evaluate(&witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
            }
        }

        Ok(witness)
    }

    /// Execute a single `WitnessOp`, filling in the target wire(s).
    fn execute_op(
        &self,
        op: &WitnessOp<F>,
        witness: &mut [FieldElement<F>],
    ) -> Result<(), WitnessError>
    where
        F: PoseidonParamsProvider,
    {
        match op {
            WitnessOp::AssignLC { target, lc } => {
                witness[target.index()] = lc
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
            }
            WitnessOp::Multiply { target, a, b } => {
                let a_val = a
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                let b_val = b
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                witness[target.index()] = a_val.mul(&b_val);
            }
            WitnessOp::Inverse { target, operand } => {
                let val = operand
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
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
                let val = source
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                let limbs = val.to_canonical();
                let limb_idx = (*bit_index / 64) as usize;
                let bit_pos = *bit_index % 64;
                let bit = if limb_idx < 4 {
                    (limbs[limb_idx] >> bit_pos) & 1
                } else {
                    0
                };
                witness[target.index()] = FieldElement::<F>::from_u64(bit);
            }
            WitnessOp::IsZero {
                diff,
                target_inv,
                target_result,
            } => {
                let diff_val = diff
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                if diff_val.is_zero() {
                    witness[target_inv.index()] = FieldElement::<F>::zero();
                    witness[target_result.index()] = FieldElement::<F>::one();
                } else {
                    // Safe: diff_val is non-zero, so inv() always returns Some
                    let inv = diff_val.inv().ok_or(WitnessError::DivisionByZero {
                        variable_index: target_inv.index(),
                    })?;
                    witness[target_inv.index()] = inv;
                    witness[target_result.index()] = FieldElement::<F>::zero();
                }
            }
            WitnessOp::IntDivMod { q, r, lhs, rhs } => {
                let a = witness[lhs.index()];
                let b = witness[rhs.index()];
                // Integer division on canonical (unsigned) representations
                let a_limbs = a.to_canonical();
                let b_limbs = b.to_canonical();
                // For simplicity, use the first limb if value fits in 64 bits,
                // otherwise fall back to multi-limb division.
                let (q_val, r_val) = int_divmod_field_pub::<F>(&a_limbs, &b_limbs);
                witness[q.index()] = q_val;
                witness[r.index()] = r_val;
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
            WitnessOp::ArtikCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                dispatch_artik_call::<F>(outputs, inputs, &program_bytes[..], witness)?;
            }
        }
        Ok(())
    }

    /// Fill the ~361 internal Poseidon wires by replaying the permutation natively.
    fn fill_poseidon(
        &self,
        witness: &mut [FieldElement<F>],
        left: Variable,
        right: Variable,
        internal_start: usize,
        internal_count: usize,
    ) -> Result<(), WitnessError>
    where
        F: PoseidonParamsProvider,
    {
        let params = self.poseidon_params.as_ref().ok_or_else(|| {
            WitnessError::MissingInput("poseidon parameters not initialized".into())
        })?;
        fill_poseidon_witness(witness, params, left, right, internal_start, internal_count)
    }
}
