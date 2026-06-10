use memory::{FieldBackend, FieldElement};
use std::collections::HashMap;

use constraints::PoseidonParamsProvider;

use crate::error::R1CSError;
use crate::r1cs_backend::R1CSCompiler;
use crate::witness::{fill_poseidon_witness, int_divmod_field_pub, WitnessOp};

use ir::types::IrProgram;

/// Witness generation methods for R1CSCompiler.
impl<F: FieldBackend> R1CSCompiler<F> {
    /// Compile an SSA IR program and generate a witness in a single pass.
    ///
    /// Three-pass design (intentional):
    /// 1. **Evaluate** (skippable): runs IR with concrete inputs for early
    ///    validation — catches assertion failures and missing inputs *before*
    ///    emitting constraints, avoiding wasted work on invalid witnesses.
    ///    Skipped when `skip_eval_validation` is set; callers that do so must
    ///    verify the produced witness downstream (`cs.verify` / SNARK verify),
    ///    which gives the same guarantee far more cheaply on large circuits.
    /// 2. **Compile**: lowers IR → R1CS constraints (same as `compile_ir`), populating
    ///    `witness_ops` as a side-effect.
    /// 3. **Witness**: builds the witness vector by replaying `witness_ops` with
    ///    concrete input values (see [`fill_witness`](Self::fill_witness)).
    ///
    /// Memory-constrained callers can run the same passes separately —
    /// `compile_ir` then [`fill_witness`](Self::fill_witness) — and drop the
    /// (often multi-GB) IR program in between: the witness fill replays the
    /// recorded ops and never reads the program.
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use zkc::r1cs_backend::R1CSCompiler;
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
        // 1. Evaluate IR — early validation (skippable).
        if !self.skip_eval_validation {
            ir::eval::evaluate(program, inputs)
                .map_err(|e| R1CSError::EvalError(format!("{e}")))?;
        }

        // 2. Compile constraints (populates witness_ops).
        self.compile_ir(program)?;

        // 3. Build the witness from the recorded op trace.
        self.fill_witness(inputs)
    }

    /// Build the witness vector for an already-compiled circuit by replaying
    /// the recorded `witness_ops` with concrete input values.
    ///
    /// This is the witness pass of `compile_ir_with_witness`, exposed
    /// separately so callers can drop the IR program (which the replay never
    /// reads) between constraint emission and witness generation. Must be
    /// called after `compile_ir` / `compile_instructions` on the same
    /// instance.
    pub fn fill_witness(
        &mut self,
        inputs: &HashMap<String, FieldElement<F>>,
    ) -> Result<Vec<FieldElement<F>>, R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        // 3. Allocate the witness vector.
        let mut witness = vec![FieldElement::<F>::zero(); self.cs.num_variables()];
        witness[0] = FieldElement::<F>::one();

        // 3a. Fill inputs. With early validation skipped, a missing input or
        //     unbound signal must surface as an error here, not an index panic.
        for name in self.public_inputs.iter().chain(self.witnesses.iter()) {
            let var = self
                .bindings
                .get(name)
                .ok_or_else(|| R1CSError::EvalError(format!("unbound input signal `{name}`")))?;
            let val = inputs
                .get(name)
                .ok_or_else(|| R1CSError::EvalError(format!("missing input `{name}`")))?;
            witness[var.index()] = *val;
        }

        // 3b. Replay witness ops (which may have been filtered by optimize_r1cs).
        // Take the Artik cache out for the duration of the replay so each
        // `ArtikCall` can borrow it mutably without conflicting with the
        // immutable borrow of `witness_ops`; it is restored afterward.
        let mut artik_memo = self.artik_memo.take();
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
                WitnessOp::ArtikCall {
                    outputs,
                    inputs,
                    program_bytes,
                } => {
                    crate::witness::dispatch_artik_call::<F>(
                        outputs,
                        inputs,
                        program_bytes,
                        &mut witness,
                        artik_memo.as_mut(),
                    )
                    .map_err(|e| R1CSError::EvalError(format!("{e}")))?;
                }
            }
        }
        self.artik_memo = artik_memo;

        // 3c. Post-fixup: fill substituted-away wires from substitution map.
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
