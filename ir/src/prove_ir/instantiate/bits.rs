//! Bit-level + indexing helpers on [`Instantiator`].
//!
//! Two concerns share this file because both compose the same set of
//! IR primitives (`Decompose`, `Const`, `Mul`, `Add`):
//!
//! - **Bitwise expansion** — [`emit_decompose_bits`], [`emit_recompose`],
//!   [`emit_bitwise_binop`], [`emit_bitnot`], [`emit_shift_right`],
//!   [`emit_shift_left`]. Drive the `BitAnd` / `BitOr` / `BitXor` /
//!   `BitNot` / `ShiftL` / `ShiftR` arms of [`super::exprs::emit_expr`].
//! - **Indexing utilities** — [`extract_const_index`],
//!   [`ensure_array_slot`], [`extract_const_u32`], [`resolve_const_u32`].
//!   Used by `LetIndexed` / `WitnessHintIndexed` / array-index lowering
//!   to fold compile-time-known indices into env updates.
//!
//! All methods are `pub(super)`.

use memory::{FieldBackend, FieldElement};

use super::utils::fe_to_u64;
use super::{BitwiseOp, InstEnvValue, Instantiator};
use crate::prove_ir::types::CircuitExpr;
use crate::types::{Instruction, SsaVar};
use ir_forge::ProveIrError;

impl<F: FieldBackend> Instantiator<F> {
    // -------------------------------------------------------------------
    // Bitwise operation expansion
    // -------------------------------------------------------------------

    /// Decompose a value into `num_bits` individual bit variables.
    /// Returns the vector of bit SsaVars (LSB first).
    pub(super) fn emit_decompose_bits(
        &mut self,
        operand: SsaVar,
        num_bits: u32,
    ) -> Result<Vec<SsaVar>, ProveIrError> {
        let result = self.program.fresh_var();
        let mut bit_vars = Vec::with_capacity(num_bits as usize);
        for _ in 0..num_bits {
            bit_vars.push(self.program.fresh_var());
        }
        self.push_inst(Instruction::Decompose {
            result,
            bit_results: bit_vars.clone(),
            operand,
            num_bits,
        });
        Ok(bit_vars)
    }

    /// Recompose bits (LSB first) back into a single field element: Σ bit_i * 2^i
    pub(super) fn emit_recompose(&mut self, bits: &[SsaVar]) -> Result<SsaVar, ProveIrError> {
        if bits.is_empty() {
            return Ok(self.emit_const(FieldElement::<F>::zero()));
        }

        let mut acc = bits[0]; // bit_0 * 2^0 = bit_0
        let mut power_of_two = FieldElement::<F>::from_u64(2);

        for &bit in &bits[1..] {
            // coeff = 2^i
            let coeff_var = self.emit_const(power_of_two);
            // term = bit * 2^i
            let term = self.program.fresh_var();
            self.push_inst(Instruction::Mul {
                result: term,
                lhs: bit,
                rhs: coeff_var,
            });
            // acc = acc + term
            let new_acc = self.program.fresh_var();
            self.push_inst(Instruction::Add {
                result: new_acc,
                lhs: acc,
                rhs: term,
            });
            acc = new_acc;
            power_of_two = power_of_two.add(&power_of_two); // 2^(i+1)
        }

        Ok(acc)
    }

    /// Emit a bitwise binary operation (AND, OR, XOR).
    pub(super) fn emit_bitwise_binop(
        &mut self,
        lhs: SsaVar,
        rhs: SsaVar,
        num_bits: u32,
        op: BitwiseOp,
    ) -> Result<SsaVar, ProveIrError> {
        let bits_l = self.emit_decompose_bits(lhs, num_bits)?;
        let bits_r = self.emit_decompose_bits(rhs, num_bits)?;

        let mut result_bits = Vec::with_capacity(num_bits as usize);
        for i in 0..num_bits as usize {
            let bit = match op {
                BitwiseOp::And => {
                    // AND: a * b
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: v,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    v
                }
                BitwiseOp::Or => {
                    // OR: a + b - a*b
                    let ab = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: ab,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let sum = self.program.fresh_var();
                    self.push_inst(Instruction::Add {
                        result: sum,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Sub {
                        result: v,
                        lhs: sum,
                        rhs: ab,
                    });
                    v
                }
                BitwiseOp::Xor => {
                    // XOR: a + b - 2*a*b
                    let ab = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: ab,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let two = self.emit_const(FieldElement::<F>::from_u64(2));
                    let two_ab = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: two_ab,
                        lhs: two,
                        rhs: ab,
                    });
                    let sum = self.program.fresh_var();
                    self.push_inst(Instruction::Add {
                        result: sum,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Sub {
                        result: v,
                        lhs: sum,
                        rhs: two_ab,
                    });
                    v
                }
            };
            result_bits.push(bit);
        }

        self.emit_recompose(&result_bits)
    }

    /// Emit bitwise NOT: decompose, flip each bit (1 - bit), recompose.
    pub(super) fn emit_bitnot(
        &mut self,
        operand: SsaVar,
        num_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        let bits = self.emit_decompose_bits(operand, num_bits)?;
        let one = self.emit_const(FieldElement::<F>::one());

        let mut result_bits = Vec::with_capacity(num_bits as usize);
        for &bit in &bits {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Sub {
                result: v,
                lhs: one,
                rhs: bit,
            });
            result_bits.push(v);
        }

        self.emit_recompose(&result_bits)
    }

    /// Emit right shift: decompose, take bits[shift..], recompose.
    pub(super) fn emit_shift_right(
        &mut self,
        operand: SsaVar,
        shift: u32,
        num_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        if shift >= num_bits {
            return Ok(self.emit_const(FieldElement::<F>::zero()));
        }
        let bits = self.emit_decompose_bits(operand, num_bits)?;
        // Right shift: drop the lowest `shift` bits
        let shifted_bits = &bits[shift as usize..];
        self.emit_recompose(shifted_bits)
    }

    /// Emit left shift: decompose, prepend `shift` zero bits, recompose.
    pub(super) fn emit_shift_left(
        &mut self,
        operand: SsaVar,
        shift: u32,
        num_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        if shift >= num_bits {
            return Ok(self.emit_const(FieldElement::<F>::zero()));
        }
        let bits = self.emit_decompose_bits(operand, num_bits)?;
        // Left shift: prepend `shift` zeros, truncate to num_bits
        let zero = self.emit_const(FieldElement::<F>::zero());
        let mut shifted_bits: Vec<SsaVar> = vec![zero; shift as usize];
        let remaining = (num_bits - shift) as usize;
        shifted_bits.extend_from_slice(&bits[..remaining.min(bits.len())]);
        self.emit_recompose(&shifted_bits)
    }

    /// Try to extract a constant usize from the SSA variable, using the
    /// O(1) const_values cache (populated by emit_const).
    pub(super) fn extract_const_index(&self, var: SsaVar) -> Option<usize> {
        let value = self.const_value_of(var)?;
        let limbs = value.to_canonical();
        if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
            usize::try_from(limbs[0]).ok()
        } else {
            None
        }
    }

    /// Ensure an array exists in the env and has at least `idx + 1` slots.
    /// Creates the array lazily if it doesn't exist, and extends it with
    /// placeholder variables if needed.
    pub(super) fn ensure_array_slot(&mut self, array: &str, idx: usize, var: SsaVar) {
        match self.env.get_mut(array) {
            Some(InstEnvValue::Array(arr)) => {
                // Extend if needed
                while arr.len() <= idx {
                    let placeholder = self.program.fresh_var();
                    arr.push(placeholder);
                }
                arr[idx] = var;
            }
            Some(InstEnvValue::Scalar(_)) => {
                // Name collision — don't overwrite scalar
            }
            None => {
                // Create array lazily
                let mut arr = Vec::with_capacity(idx + 1);
                for _ in 0..idx {
                    let placeholder = self.program.fresh_var();
                    arr.push(placeholder);
                }
                arr.push(var);
                self.env.insert(array.to_string(), InstEnvValue::Array(arr));
            }
        }
    }

    /// Extract a constant u32 from an emitted variable, with a descriptive error.
    pub(super) fn extract_const_u32(
        &self,
        var: SsaVar,
        context: &str,
    ) -> Result<u32, ProveIrError> {
        self.extract_const_index(var)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| ProveIrError::UnsupportedOperation {
                description: format!("{context} must be a compile-time constant"),
                span: None,
            })
    }

    /// Resolve a circuit expression to a u32 constant, trying eval_const_expr
    /// first (for captures) then falling back to emit + extract.
    pub(super) fn resolve_const_u32(
        &mut self,
        expr: &CircuitExpr,
        context: &str,
    ) -> Result<u32, ProveIrError> {
        // Try constant evaluation first (handles captures and arithmetic)
        if let Ok(fe) = self.eval_const_expr(expr) {
            let val = fe_to_u64(&fe, context)?;
            return u32::try_from(val).map_err(|_| ProveIrError::UnsupportedOperation {
                description: format!("{context} too large for u32"),
                span: None,
            });
        }
        // Fall back to emit + extract
        let var = self.emit_expr(expr)?;
        self.extract_const_u32(var, context)
    }
}
