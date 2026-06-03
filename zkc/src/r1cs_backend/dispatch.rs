use super::*;

impl<F: FieldBackend> constraints::ConstraintBackend<F> for R1CSCompiler<F> {
    type Error = R1CSError;

    fn compile_instruction(
        &mut self,
        ir_idx: usize,
        inst: &IrInstruction<F>,
    ) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        let constraints_before = self.cs.num_constraints();

        match inst {
            IrInstruction::Const { result, value } => {
                self.cache_lc(*result, LinearCombination::from_constant(*value));
            }
            IrInstruction::Input {
                result,
                name,
                visibility,
            } => {
                let var = match visibility {
                    IrVisibility::Public => {
                        let v = self.cs.alloc_input();
                        if self.track_input_metadata {
                            self.bindings.insert(name.clone(), v);
                            self.public_inputs.push(name.clone());
                        }
                        v
                    }
                    IrVisibility::Witness => {
                        let v = self.cs.alloc_witness();
                        if self.track_input_metadata {
                            self.bindings.insert(name.clone(), v);
                            self.witnesses.push(name.clone());
                        }
                        v
                    }
                };
                self.cache_lc(*result, LinearCombination::from_variable(var));
            }
            IrInstruction::Add { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.auto_materialize(a + b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Sub { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.auto_materialize(a - b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Neg { result, operand } => {
                let lc = self.lookup_lc(operand)?;
                self.cache_lc(*result, lc * FieldElement::<F>::one().neg());
            }
            IrInstruction::Mul { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.multiply_lcs(&a, &b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Div { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let out = self.divide_lcs(&a, &b)?;
                self.cache_lc(*result, out);
            }
            IrInstruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let cond_lc = self.lookup_lc(cond)?;
                let then_lc = self.lookup_lc(if_true)?;
                let else_lc = self.lookup_lc(if_false)?;

                // Skip boolean enforcement if cond is proven boolean or already enforced
                if !self.proven_boolean.contains(cond) && self.bool_enforced.insert(*cond) {
                    BC_MUX_COND.fetch_add(1, Ordering::Relaxed);
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    let one_minus_cond = one - cond_lc.clone();
                    self.cs
                        .enforce(cond_lc.clone(), one_minus_cond, LinearCombination::zero());
                }

                // MUX: result = cond * (then - else) + else
                let diff = then_lc - else_lc.clone();
                let selected = self.multiply_lcs(&cond_lc, &diff);
                self.cache_lc(*result, selected + else_lc);
            }
            IrInstruction::AssertEq {
                result, lhs, rhs, ..
            } => {
                let lhs_was_used = self.is_ssa_used(*lhs);
                let a = self.lookup_lc_untracked(lhs)?;
                let b = self.lookup_lc(rhs)?;
                if self.forward_assert_eq_collapse
                    && !lhs_was_used
                    && a.as_single_variable()
                        .map(|var| var.index() > self.cs.num_pub_inputs())
                        .unwrap_or(false)
                {
                    self.cache_lc(*lhs, b.clone());
                } else {
                    self.mark_ssa_used(*lhs);
                    self.cs.enforce_equal(a, b.clone());
                }
                self.cache_lc(*result, b);
            }
            IrInstruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                let lc = self.lookup_lc(operand)?;
                // Boolean decomposition: x = sum(b_i * 2^i), each b_i boolean
                // Cost: bits boolean constraints + 1 sum equality = bits+1 total
                let mut sum = LinearCombination::zero();
                let two = FieldElement::<F>::from_u64(2);
                let mut coeff = FieldElement::<F>::one();
                for i in 0..*bits {
                    let bit_var = self.cs.alloc_witness();
                    // b_i * (1 - b_i) = 0  (enforces b_i ∈ {0, 1})
                    BC_RANGE_CHECK.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        LinearCombination::from_variable(bit_var),
                        LinearCombination::from_constant(FieldElement::<F>::one())
                            - LinearCombination::from_variable(bit_var),
                        LinearCombination::zero(),
                    );
                    sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                    coeff = coeff.mul(&two);
                    self.push_witness_op(WitnessOp::BitExtract {
                        target: bit_var,
                        source: lc.clone(),
                        bit_index: i,
                    });
                }
                self.cs.enforce_equal(lc.clone(), sum);
                // Record proven bound for IsLt/IsLe optimization
                self.range_bounds.insert(*operand, *bits);
                self.cache_lc(*result, lc);
            }
            IrInstruction::Not { result, operand } => {
                let op_lc = self.lookup_lc(operand)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                // Skip boolean enforcement if proven boolean or already enforced
                if !self.proven_boolean.contains(operand) && self.bool_enforced.insert(*operand) {
                    BC_NOT.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        op_lc.clone(),
                        one.clone() - op_lc.clone(),
                        LinearCombination::zero(),
                    );
                }
                // result = 1 - op
                self.cache_lc(*result, one - op_lc);
            }
            IrInstruction::And { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                if !self.proven_boolean.contains(lhs) && self.bool_enforced.insert(*lhs) {
                    BC_AND_LHS.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        a.clone(),
                        one.clone() - a.clone(),
                        LinearCombination::zero(),
                    );
                }
                if !self.proven_boolean.contains(rhs) && self.bool_enforced.insert(*rhs) {
                    BC_AND_RHS.fetch_add(1, Ordering::Relaxed);
                    self.cs
                        .enforce(b.clone(), one - b.clone(), LinearCombination::zero());
                }
                // result = a * b
                let out = self.multiply_lcs(&a, &b);
                self.cache_lc(*result, out);
            }
            IrInstruction::Or { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                if !self.proven_boolean.contains(lhs) && self.bool_enforced.insert(*lhs) {
                    BC_OR_LHS.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        a.clone(),
                        one.clone() - a.clone(),
                        LinearCombination::zero(),
                    );
                }
                if !self.proven_boolean.contains(rhs) && self.bool_enforced.insert(*rhs) {
                    BC_OR_RHS.fetch_add(1, Ordering::Relaxed);
                    self.cs
                        .enforce(b.clone(), one - b.clone(), LinearCombination::zero());
                }
                // result = a + b - a*b
                let product = self.multiply_lcs(&a, &b);
                self.cache_lc(*result, a + b - product);
            }
            IrInstruction::IsEq { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let diff = a - b;
                // IsZero gadget: alloc inv + eq_result
                // enforce: diff * inv = 1 - eq_result
                // enforce: diff * eq_result = 0
                let inv_var = self.cs.alloc_witness();
                let eq_var = self.cs.alloc_witness();
                self.push_witness_op(WitnessOp::IsZero {
                    diff: diff.clone(),
                    target_inv: inv_var,
                    target_result: eq_var,
                });
                let inv_lc = LinearCombination::from_variable(inv_var);
                let eq_lc = LinearCombination::from_variable(eq_var);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cs.enforce(diff.clone(), inv_lc, one - eq_lc.clone());
                self.cs
                    .enforce(diff, eq_lc.clone(), LinearCombination::zero());
                self.cache_lc(*result, eq_lc);
            }
            IrInstruction::IsNeq { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let diff = a - b;
                // IsZero gadget then negate
                let inv_var = self.cs.alloc_witness();
                let eq_var = self.cs.alloc_witness();
                self.push_witness_op(WitnessOp::IsZero {
                    diff: diff.clone(),
                    target_inv: inv_var,
                    target_result: eq_var,
                });
                let inv_lc = LinearCombination::from_variable(inv_var);
                let eq_lc = LinearCombination::from_variable(eq_var);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cs
                    .enforce(diff.clone(), inv_lc, one.clone() - eq_lc.clone());
                self.cs
                    .enforce(diff, eq_lc.clone(), LinearCombination::zero());
                // neq = 1 - eq
                self.cache_lc(*result, one - eq_lc);
            }
            IrInstruction::IsLt { result, lhs, rhs } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let bound_a = self.range_bounds.get(lhs).copied();
                let bound_b = self.range_bounds.get(rhs).copied();
                let default_bits = self.default_range_bits();

                let effective_bits = match (bound_a, bound_b) {
                    (Some(ba), Some(bb)) => ba.max(bb),
                    _ => {
                        if bound_a.is_none() {
                            self.enforce_default_range(&a);
                        }
                        if bound_b.is_none() {
                            self.enforce_default_range(&b);
                        }
                        default_bits
                    }
                };

                let offset =
                    power_of_two_generic::<F>(effective_bits).sub(&FieldElement::<F>::one());
                let diff = b - a + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                self.cache_lc(*result, lt_lc);
            }
            IrInstruction::IsLe { result, lhs, rhs } => {
                // a <= b  ≡  !(b < a)  ≡  1 - IsLt(b, a)
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let bound_a = self.range_bounds.get(lhs).copied();
                let bound_b = self.range_bounds.get(rhs).copied();
                let default_bits = self.default_range_bits();

                let effective_bits = match (bound_a, bound_b) {
                    (Some(ba), Some(bb)) => ba.max(bb),
                    _ => {
                        if bound_a.is_none() {
                            self.enforce_default_range(&a);
                        }
                        if bound_b.is_none() {
                            self.enforce_default_range(&b);
                        }
                        default_bits
                    }
                };

                let offset =
                    power_of_two_generic::<F>(effective_bits).sub(&FieldElement::<F>::one());
                let diff = a - b + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cache_lc(*result, one - lt_lc);
            }
            IrInstruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let offset = power_of_two_generic::<F>(*bitwidth).sub(&FieldElement::<F>::one());
                let diff = b - a + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                self.cache_lc(*result, lt_lc);
            }
            IrInstruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let a = self.lookup_lc(lhs)?;
                let b = self.lookup_lc(rhs)?;
                let offset = power_of_two_generic::<F>(*bitwidth).sub(&FieldElement::<F>::one());
                let diff = a - b + LinearCombination::from_constant(offset);
                let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                self.cache_lc(*result, one - lt_lc);
            }
            IrInstruction::Assert {
                result, operand, ..
            } => {
                let op_lc = self.lookup_lc(operand)?;
                let one = LinearCombination::from_constant(FieldElement::<F>::one());
                // Skip boolean enforcement if proven boolean or already enforced
                if !self.proven_boolean.contains(operand) && self.bool_enforced.insert(*operand) {
                    BC_ASSERT.fetch_add(1, Ordering::Relaxed);
                    self.cs.enforce(
                        op_lc.clone(),
                        one.clone() - op_lc.clone(),
                        LinearCombination::zero(),
                    );
                }
                // Enforce op == 1
                self.cs.enforce_equal(op_lc.clone(), one);
                self.cache_lc(*result, op_lc);
            }
            IrInstruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let left_lc = self.lookup_lc(left)?;
                let right_lc = self.lookup_lc(right)?;

                let left_var = self.materialize_lc(&left_lc);
                let right_var = self.materialize_lc(&right_lc);

                if self.poseidon_params.is_none() {
                    self.poseidon_params = Some(F::default_poseidon_t3());
                }
                let params = self.poseidon_params.as_ref().unwrap();

                let internal_start = self.cs.num_variables();
                let hash_var = constraints::poseidon::poseidon_hash_circuit(
                    &mut self.cs,
                    params,
                    left_var,
                    right_var,
                );
                let internal_count = self.cs.num_variables() - internal_start;

                self.push_witness_op(WitnessOp::PoseidonHash {
                    left: left_var,
                    right: right_var,
                    output: hash_var,
                    internal_start,
                    internal_count,
                });

                self.cache_lc(*result, LinearCombination::from_variable(hash_var));
            }
            IrInstruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let lc = self.lookup_lc(operand)?;
                // Materialize source to avoid cloning large LC num_bits times.
                let src_var = self.materialize_lc(&lc);
                let src_lc = LinearCombination::from_variable(src_var);

                // Same as RangeCheck but also registers each bit in self.lc_map.
                let mut sum = LinearCombination::zero();
                let two = FieldElement::<F>::from_u64(2);
                let mut coeff = FieldElement::<F>::one();
                for (i, bit_ssa) in bit_results.iter().enumerate() {
                    let bit_var = self.cs.alloc_witness();
                    // b_i * (1 - b_i) = 0
                    BC_DECOMPOSE.fetch_add(1, Ordering::Relaxed);
                    if *num_bits == 1 {
                        BC_DECOMPOSE_1BIT.fetch_add(1, Ordering::Relaxed);
                    }
                    self.cs.enforce(
                        LinearCombination::from_variable(bit_var),
                        LinearCombination::from_constant(FieldElement::<F>::one())
                            - LinearCombination::from_variable(bit_var),
                        LinearCombination::zero(),
                    );
                    // Track as bool-enforced so Mux/And/Or won't emit duplicate enforcement
                    self.bool_enforced.insert(*bit_ssa);
                    sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                    coeff = coeff.mul(&two);
                    self.push_witness_op(WitnessOp::BitExtract {
                        target: bit_var,
                        source: src_lc.clone(),
                        bit_index: i as u32,
                    });
                    // Register each bit in lc_map so subsequent instructions can use it
                    self.cache_lc(*bit_ssa, LinearCombination::from_variable(bit_var));
                }
                self.cs.enforce_equal(src_lc, sum);
                self.range_bounds.insert(*operand, *num_bits);
                self.cache_lc(*result, lc);
            }
            IrInstruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                self.compile_int_div(*result, *lhs, *rhs, *max_bits)?;
            }
            IrInstruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                self.compile_int_mod(*result, *lhs, *rhs, *max_bits)?;
            }
            IrInstruction::WitnessCall(call) => {
                // Each output is a fresh witness wire — no
                // constraints are emitted here. The prover's
                // witness generator replays the Artik program
                // against `inputs` at witness-gen time to fill
                // the wires.
                let mut input_vars: Vec<Variable> = Vec::with_capacity(call.inputs.len());
                for v in &call.inputs {
                    let lc = self.lookup_lc(v)?;
                    input_vars.push(self.materialize_lc(&lc));
                }
                let mut output_vars: Vec<Variable> = Vec::with_capacity(call.outputs.len());
                for out_ssa in &call.outputs {
                    let out_var = self.cs.alloc_witness();
                    output_vars.push(out_var);
                    self.cache_lc(*out_ssa, LinearCombination::from_variable(out_var));
                }
                let interned = self.intern_artik_program(&call.program_bytes);
                self.push_witness_op(WitnessOp::ArtikCall {
                    outputs: output_vars,
                    inputs: input_vars,
                    program_bytes: interned,
                });
            }
        }

        // Record which IR instruction generated each new constraint, when
        // the compiler was constructed in tracking mode.
        if self.track_constraint_origins {
            let constraints_after = self.cs.num_constraints();
            let result_var = inst.result_var();
            for _ in constraints_before..constraints_after {
                self.constraint_origins.push(ConstraintOrigin {
                    ir_index: ir_idx,
                    result_var,
                });
            }
        }

        Ok(())
    }
}
