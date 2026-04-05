use memory::{FieldBackend, FieldElement};
use std::collections::HashMap;

use constraints::PoseidonParamsProvider;

use crate::r1cs_backend::R1CSCompiler;
use crate::r1cs_error::R1CSError;
use crate::witness_gen::{fill_poseidon_witness, int_divmod_field_pub, WitnessOp};

use ir::types::IrProgram;

/// Witness generation methods for R1CSCompiler.
impl<F: FieldBackend> R1CSCompiler<F> {
    /// Compile an SSA IR program and generate a witness in a single pass.
    ///
    /// Three-pass design (intentional):
    /// 1. **Evaluate**: runs IR with concrete inputs for early validation — catches
    ///    assertion failures, division by zero, and missing inputs *before* emitting
    ///    any constraints. This avoids wasting work on invalid witnesses.
    /// 2. **Compile**: lowers IR → R1CS constraints (same as `compile_ir`), populating
    ///    `witness_ops` as a side-effect.
    /// 3. **Witness**: builds the witness vector by replaying `witness_ops` with
    ///    concrete input values. This is separate from compilation because constraint
    ///    generation must complete before the full witness layout is known.
    ///
    /// Evaluate the IR, compile to R1CS, and build a witness vector in one pass.
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use compiler::r1cs_backend::R1CSCompiler;
    /// use ir::IrLowering;
    /// use memory::FieldElement;
    ///
    /// let prog: ir::types::IrProgram =
    ///     IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
    /// let mut inputs = HashMap::new();
    /// inputs.insert("z".to_string(), FieldElement::from_u64(42));
    /// inputs.insert("x".to_string(), FieldElement::from_u64(6));
    /// inputs.insert("y".to_string(), FieldElement::from_u64(7));
    ///
    /// let mut rc = R1CSCompiler::new();
    /// let witness = rc.compile_ir_with_witness(&prog, &inputs).unwrap();
    /// assert!(rc.cs.verify(&witness).is_ok());
    /// ```
    pub fn compile_ir_with_witness(
        &mut self,
        program: &IrProgram<F>,
        inputs: &HashMap<String, FieldElement<F>>,
    ) -> Result<Vec<FieldElement<F>>, R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        // 1. Evaluate IR — early validation
        let _ssa_values = ir::eval::evaluate(program, inputs)
            .map_err(|e| R1CSError::EvalError(format!("{e}")))?;

        // 2. Compile constraints (populates witness_ops)
        self.compile_ir(program)?;

        // 3. Build witness vector
        let mut witness = vec![FieldElement::<F>::zero(); self.cs.num_variables()];
        witness[0] = FieldElement::<F>::one();

        // 3a. Fill inputs
        for name in &self.public_inputs {
            witness[self.bindings[name].index()] = inputs[name];
        }
        for name in &self.witnesses {
            witness[self.bindings[name].index()] = inputs[name];
        }

        // 3b. Replay witness ops (which may have been filtered by optimize_r1cs)
        for op in &self.witness_ops {
            match op {
                WitnessOp::AssignLC { target, lc } => {
                    witness[target.index()] = lc
                        .evaluate(&witness)
                        .map_err(|e| R1CSError::EvalError(e.to_string()))?;
                }
                WitnessOp::Multiply { target, a, b } => {
                    let a_val = a
                        .evaluate(&witness)
                        .map_err(|e| R1CSError::EvalError(e.to_string()))?;
                    let b_val = b
                        .evaluate(&witness)
                        .map_err(|e| R1CSError::EvalError(e.to_string()))?;
                    witness[target.index()] = a_val.mul(&b_val);
                }
                WitnessOp::Inverse { target, operand } => {
                    let val = operand
                        .evaluate(&witness)
                        .map_err(|e| R1CSError::EvalError(e.to_string()))?;
                    witness[target.index()] = val.inv().ok_or_else(|| {
                        R1CSError::EvalError(format!("division by zero at wire {}", target.index()))
                    })?;
                }
                WitnessOp::BitExtract {
                    target,
                    source,
                    bit_index,
                } => {
                    let val = source
                        .evaluate(&witness)
                        .map_err(|e| R1CSError::EvalError(e.to_string()))?;
                    let limbs = val.to_canonical();
                    let li = (*bit_index / 64) as usize;
                    let bp = *bit_index % 64;
                    let bit = if li < 4 { (limbs[li] >> bp) & 1 } else { 0 };
                    witness[target.index()] = FieldElement::<F>::from_u64(bit);
                }
                WitnessOp::IsZero {
                    diff,
                    target_inv,
                    target_result,
                } => {
                    let d = diff
                        .evaluate(&witness)
                        .map_err(|e| R1CSError::EvalError(e.to_string()))?;
                    if d.is_zero() {
                        witness[target_inv.index()] = FieldElement::<F>::zero();
                        witness[target_result.index()] = FieldElement::<F>::one();
                    } else {
                        witness[target_inv.index()] = d
                            .inv()
                            .ok_or_else(|| R1CSError::EvalError("IsZero inverse failed".into()))?;
                        witness[target_result.index()] = FieldElement::<F>::zero();
                    }
                }
                WitnessOp::IntDivMod { q, r, lhs, rhs } => {
                    let a = witness[lhs.index()];
                    let b = witness[rhs.index()];
                    let a_limbs = a.to_canonical();
                    let b_limbs = b.to_canonical();
                    let (q_val, r_val) = int_divmod_field_pub::<F>(&a_limbs, &b_limbs);
                    witness[q.index()] = q_val;
                    witness[r.index()] = r_val;
                }
                WitnessOp::PoseidonHash {
                    left,
                    right,
                    internal_start,
                    internal_count,
                    ..
                } => {
                    let params = self.poseidon_params.as_ref().ok_or_else(|| {
                        R1CSError::EvalError("poseidon params not initialized".into())
                    })?;
                    fill_poseidon_witness(
                        &mut witness,
                        params,
                        *left,
                        *right,
                        *internal_start,
                        *internal_count,
                    )
                    .map_err(|e| R1CSError::EvalError(format!("{e}")))?;
                }
            }
        }

        // 3c. Post-fixup: fill substituted-away wires from substitution map.
        // After optimize_r1cs(), some wires are defined by LCs of other wires.
        // Since substitutions are fully composed (fixpoint), each LC only
        // references non-substituted wires that are already computed.
        if let Some(subs) = &self.substitution_map {
            for (var_idx, lc) in subs {
                witness[*var_idx] = lc
                    .evaluate(&witness)
                    .map_err(|e| R1CSError::EvalError(e.to_string()))?;
            }
        }

        Ok(witness)
    }
}
