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
//!   [`ensure_array_slot`].
//!   Used by `LetIndexed` / `WitnessHintIndexed` / array-index lowering
//!   to fold compile-time-known indices into env updates.
//!
//! All methods are `pub(super)`.

use memory::{FieldBackend, FieldElement};

use super::{BitwiseOp, InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use ir_core::{Instruction, SsaVar};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
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
        let result = self.fresh_var();
        let mut bit_vars = Vec::with_capacity(num_bits as usize);
        for _ in 0..num_bits {
            bit_vars.push(self.fresh_var());
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
            let term = self.fresh_var();
            self.push_inst(Instruction::Mul {
                result: term,
                lhs: bit,
                rhs: coeff_var,
            });
            // acc = acc + term
            let new_acc = self.fresh_var();
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
    ///
    /// `lhs_bits` and `rhs_bits` are the **operand decompose widths**
    /// — each operand must fit in its own width — and may differ.
    /// The result-bit count is `min(lhs_bits, rhs_bits)` for AND
    /// (higher bits AND with 0 are 0) and `max(lhs_bits, rhs_bits)`
    /// for OR/XOR (higher bits in the wider operand pass through with
    /// the missing side padded as 0).
    ///
    /// Conflating the two widths under a single `num_bits` was the
    /// pre-fix bug behind `var_postdecl_padding_e2e`: `(64) & 1`
    /// inferred result width = 1 = `min(7, 1)`, which forced
    /// `Decompose(64, 1)` and tripped a range-check failure during
    /// witness eval. Using the wider width as a single `num_bits`
    /// inflates the chain and triggers a Lysis perform_split hoist,
    /// breaking AssertEq's RHS register binding across iterations.
    /// Plumbing the widths separately is the only sound shape.
    pub(super) fn emit_bitwise_binop(
        &mut self,
        lhs: SsaVar,
        rhs: SsaVar,
        lhs_bits: u32,
        rhs_bits: u32,
        op: BitwiseOp,
    ) -> Result<SsaVar, ProveIrError> {
        let bits_l = self.emit_decompose_bits(lhs, lhs_bits)?;
        let bits_r = self.emit_decompose_bits(rhs, rhs_bits)?;

        let n_pairs = match op {
            BitwiseOp::And => lhs_bits.min(rhs_bits) as usize,
            BitwiseOp::Or | BitwiseOp::Xor => lhs_bits.max(rhs_bits) as usize,
        };

        // Pad the shorter operand with zero bits so OR/XOR can iterate
        // over the wider range without out-of-bounds. AND truncates to
        // the shorter side anyway, so the padding never gets read for
        // that op.
        let zero_lazy = |this: &mut Self| this.emit_const(FieldElement::<F>::zero());
        let mut result_bits = Vec::with_capacity(n_pairs);
        for i in 0..n_pairs {
            let l_bit = if i < bits_l.len() {
                bits_l[i]
            } else {
                zero_lazy(self)
            };
            let r_bit = if i < bits_r.len() {
                bits_r[i]
            } else {
                zero_lazy(self)
            };
            let bit = match op {
                BitwiseOp::And => {
                    // AND: a * b
                    let v = self.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: v,
                        lhs: l_bit,
                        rhs: r_bit,
                    });
                    v
                }
                BitwiseOp::Or => {
                    // OR: a + b - a*b
                    let ab = self.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: ab,
                        lhs: l_bit,
                        rhs: r_bit,
                    });
                    let sum = self.fresh_var();
                    self.push_inst(Instruction::Add {
                        result: sum,
                        lhs: l_bit,
                        rhs: r_bit,
                    });
                    let v = self.fresh_var();
                    self.push_inst(Instruction::Sub {
                        result: v,
                        lhs: sum,
                        rhs: ab,
                    });
                    v
                }
                BitwiseOp::Xor => {
                    // XOR: a + b - 2*a*b
                    let ab = self.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: ab,
                        lhs: l_bit,
                        rhs: r_bit,
                    });
                    let two = self.emit_const(FieldElement::<F>::from_u64(2));
                    let two_ab = self.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: two_ab,
                        lhs: two,
                        rhs: ab,
                    });
                    let sum = self.fresh_var();
                    self.push_inst(Instruction::Add {
                        result: sum,
                        lhs: l_bit,
                        rhs: r_bit,
                    });
                    let v = self.fresh_var();
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
            let v = self.fresh_var();
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
        // Pre-allocate placeholder vars first so we don't hold a mutable
        // borrow on `self.env` while calling `self.fresh_var()` (which
        // also takes `&mut self`). The original `while arr.len() <= idx`
        // loop runs `idx + 1 - arr.len()` times when extending — so we
        // need that many placeholders to make `arr[idx] = var` safe.
        let needed_placeholders = match self.env.get(array) {
            Some(InstEnvValue::Array(arr)) => (idx + 1).saturating_sub(arr.len()),
            None => 0, // None branch creates the array fresh below.
            Some(InstEnvValue::Scalar(_)) => 0,
        };
        let mut placeholders = Vec::with_capacity(needed_placeholders);
        for _ in 0..needed_placeholders {
            placeholders.push(self.fresh_var());
        }

        match self.env.get_mut(array) {
            Some(InstEnvValue::Array(arr)) => {
                // Extend with the pre-allocated placeholders, then
                // overwrite the target slot with the caller's var.
                arr.extend(placeholders);
                arr[idx] = var;
            }
            Some(InstEnvValue::Scalar(_)) => {
                // Name collision — don't overwrite scalar
            }
            None => {
                // Create array lazily
                let mut arr = Vec::with_capacity(idx + 1);
                for _ in 0..idx {
                    let placeholder = self.fresh_var();
                    arr.push(placeholder);
                }
                arr.push(var);
                self.env.insert(array.to_string(), InstEnvValue::Array(arr));
            }
        }
    }
}
