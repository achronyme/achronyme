use super::*;

impl<F: FieldBackend> R1CSCompiler<F> {
    pub(super) fn compile_int_div(
        &mut self,
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        max_bits: u32,
    ) -> Result<(), R1CSError> {
        let cache_key = (lhs, rhs, max_bits);
        if let Some((cached_q, _)) = self.divmod_cache.get(&cache_key) {
            // Reuse cached quotient from a previous divmod on same operands
            self.cache_lc(result, cached_q.clone());
        } else {
            let a_lc = self.lookup_lc(&lhs)?;
            let b_lc = self.lookup_lc(&rhs)?;

            let q_var = self.cs.alloc_witness();
            let r_var = self.cs.alloc_witness();

            let lhs_var = self.materialize_lc(&a_lc);
            let rhs_var = self.materialize_lc(&b_lc);
            self.push_witness_op(WitnessOp::IntDivMod {
                q: q_var,
                r: r_var,
                lhs: lhs_var,
                rhs: rhs_var,
            });

            let q_lc = LinearCombination::from_variable(q_var);
            let r_lc = LinearCombination::from_variable(r_var);

            let bq = self.multiply_lcs(&b_lc, &q_lc);
            self.cs.enforce_equal(bq + r_lc.clone(), a_lc);

            self.enforce_n_range(&q_lc, max_bits);
            self.enforce_n_range(&r_lc, max_bits);

            let one = LinearCombination::from_constant(FieldElement::<F>::one());
            let b_minus_r_minus_1 = b_lc.clone() - r_lc.clone() - one;
            self.enforce_n_range(&b_minus_r_minus_1, max_bits);

            self.divmod_cache.insert(cache_key, (q_lc.clone(), r_lc));
            self.cache_lc(result, q_lc);
        }
        Ok(())
    }

    pub(super) fn compile_int_mod(
        &mut self,
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        max_bits: u32,
    ) -> Result<(), R1CSError> {
        let cache_key = (lhs, rhs, max_bits);
        if let Some((_, cached_r)) = self.divmod_cache.get(&cache_key) {
            // Reuse cached remainder from a previous divmod on same operands
            self.cache_lc(result, cached_r.clone());
        } else {
            let a_lc = self.lookup_lc(&lhs)?;
            let b_lc = self.lookup_lc(&rhs)?;

            let q_var = self.cs.alloc_witness();
            let r_var = self.cs.alloc_witness();

            let lhs_var = self.materialize_lc(&a_lc);
            let rhs_var = self.materialize_lc(&b_lc);
            self.push_witness_op(WitnessOp::IntDivMod {
                q: q_var,
                r: r_var,
                lhs: lhs_var,
                rhs: rhs_var,
            });

            let q_lc = LinearCombination::from_variable(q_var);
            let r_lc = LinearCombination::from_variable(r_var);

            let bq = self.multiply_lcs(&b_lc, &q_lc);
            self.cs.enforce_equal(bq + r_lc.clone(), a_lc);

            self.enforce_n_range(&q_lc, max_bits);
            self.enforce_n_range(&r_lc, max_bits);

            let one = LinearCombination::from_constant(FieldElement::<F>::one());
            let b_minus_r_minus_1 = b_lc.clone() - r_lc.clone() - one;
            self.enforce_n_range(&b_minus_r_minus_1, max_bits);

            self.divmod_cache.insert(cache_key, (q_lc, r_lc.clone()));
            self.cache_lc(result, r_lc);
        }
        Ok(())
    }
}
