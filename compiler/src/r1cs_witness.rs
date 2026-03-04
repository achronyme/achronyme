use memory::FieldElement;
use std::collections::HashMap;

use crate::r1cs_backend::R1CSCompiler;
use crate::r1cs_error::R1CSError;
use crate::witness_gen::{fill_poseidon_witness, WitnessOp};

use ir::types::IrProgram;

/// Witness generation methods for R1CSCompiler.
impl R1CSCompiler {
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
    /// let prog = IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
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
        program: &IrProgram,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<Vec<FieldElement>, R1CSError> {
        // 1. Evaluate IR — early validation
        let _ssa_values = ir::eval::evaluate(program, inputs)
            .map_err(|e| R1CSError::EvalError(format!("{e}")))?;

        // 2. Compile constraints (populates witness_ops)
        self.compile_ir(program)?;

        // 3. Build witness vector
        let mut witness = vec![FieldElement::ZERO; self.cs.num_variables()];
        witness[0] = FieldElement::ONE;

        // 3a. Fill inputs
        for name in &self.public_inputs {
            witness[self.bindings[name].index()] = inputs[name];
        }
        for name in &self.witnesses {
            witness[self.bindings[name].index()] = inputs[name];
        }

        // 3b. Replay witness ops
        for op in &self.witness_ops {
            match op {
                WitnessOp::AssignLC { target, lc } => {
                    witness[target.index()] = lc.evaluate(&witness);
                }
                WitnessOp::Multiply { target, a, b } => {
                    witness[target.index()] = a.evaluate(&witness).mul(&b.evaluate(&witness));
                }
                WitnessOp::Inverse { target, operand } => {
                    let val = operand.evaluate(&witness);
                    witness[target.index()] = val.inv().ok_or_else(|| {
                        R1CSError::EvalError(format!("division by zero at wire {}", target.index()))
                    })?;
                }
                WitnessOp::BitExtract {
                    target,
                    source,
                    bit_index,
                } => {
                    let val = source.evaluate(&witness);
                    let limbs = val.to_canonical();
                    let li = (*bit_index / 64) as usize;
                    let bp = *bit_index % 64;
                    let bit = if li < 4 { (limbs[li] >> bp) & 1 } else { 0 };
                    witness[target.index()] = FieldElement::from_u64(bit);
                }
                WitnessOp::IsZero {
                    diff,
                    target_inv,
                    target_result,
                } => {
                    let d = diff.evaluate(&witness);
                    if d.is_zero() {
                        witness[target_inv.index()] = FieldElement::ZERO;
                        witness[target_result.index()] = FieldElement::ONE;
                    } else {
                        witness[target_inv.index()] = d
                            .inv()
                            .ok_or_else(|| R1CSError::EvalError("IsZero inverse failed".into()))?;
                        witness[target_result.index()] = FieldElement::ZERO;
                    }
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

        Ok(witness)
    }
}
