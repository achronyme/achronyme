use constraints::plonkish::{CellRef, PlonkishError};
use constraints::PoseidonParamsProvider;
use memory::{FieldBackend, FieldElement};

use super::compiler::PlonkishCompiler;
use super::types::{PlonkVal, PlonkWitnessOp};

impl<F: FieldBackend> PlonkishCompiler<F> {
    #[allow(clippy::needless_range_loop)]
    pub(super) fn emit_poseidon(
        &mut self,
        left: CellRef,
        right: CellRef,
    ) -> Result<CellRef, PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
        if self.poseidon_params.is_none() {
            self.poseidon_params = Some(F::default_poseidon_t3());
        }
        let params = self.poseidon_params.clone().unwrap();

        let zero_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::<F>::zero()))?;
        let mut state = [zero_cell, left, right];

        let total_rounds = params.r_f + params.r_p;
        let half_f = params.r_f / 2;

        for r in 0..total_rounds {
            // Add round constants
            for i in 0..params.t {
                let rc = params.round_constants[r * params.t + i];
                if !rc.is_zero() {
                    let rc_cell = self.materialize_val(&PlonkVal::Constant(rc))?;
                    // state[i] = state[i]*1 + rc
                    let row = self.alloc_row();
                    self.system
                        .set(self.col_s_arith, row, FieldElement::<F>::one());
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row,
                        },
                        FieldElement::<F>::one(),
                    );
                    self.wire(
                        state[i],
                        CellRef {
                            column: self.col_a,
                            row,
                        },
                    );
                    self.wire(
                        rc_cell,
                        CellRef {
                            column: self.col_c,
                            row,
                        },
                    );
                    self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                    state[i] = CellRef {
                        column: self.col_d,
                        row,
                    };
                }
            }

            // S-box
            if r < half_f || r >= half_f + params.r_p {
                for i in 0..params.t {
                    state[i] = self.emit_sbox(state[i]);
                }
            } else {
                state[0] = self.emit_sbox(state[0]);
            }

            // MDS
            let old = state;
            for i in 0..params.t {
                let m0 = self.materialize_val(&PlonkVal::Constant(params.mds[i][0]))?;
                let prod0 = self.emit_arith_row(m0, old[0], None);
                let m1 = self.materialize_val(&PlonkVal::Constant(params.mds[i][1]))?;
                let prod1 = self.emit_arith_row(m1, old[1], None);
                let m2 = self.materialize_val(&PlonkVal::Constant(params.mds[i][2]))?;
                let prod2 = self.emit_arith_row(m2, old[2], None);
                // sum01 = prod0*1 + prod1
                let sum01_row = self.alloc_row();
                self.system
                    .set(self.col_s_arith, sum01_row, FieldElement::<F>::one());
                self.constrain_constant(
                    CellRef {
                        column: self.col_b,
                        row: sum01_row,
                    },
                    FieldElement::<F>::one(),
                );
                self.wire(
                    prod0,
                    CellRef {
                        column: self.col_a,
                        row: sum01_row,
                    },
                );
                self.wire(
                    prod1,
                    CellRef {
                        column: self.col_c,
                        row: sum01_row,
                    },
                );
                self.witness_ops
                    .push(PlonkWitnessOp::ArithRow { row: sum01_row });
                let sum01 = CellRef {
                    column: self.col_d,
                    row: sum01_row,
                };
                // sum_all = sum01*1 + prod2
                let sum_all_row = self.alloc_row();
                self.system
                    .set(self.col_s_arith, sum_all_row, FieldElement::<F>::one());
                self.constrain_constant(
                    CellRef {
                        column: self.col_b,
                        row: sum_all_row,
                    },
                    FieldElement::<F>::one(),
                );
                self.wire(
                    sum01,
                    CellRef {
                        column: self.col_a,
                        row: sum_all_row,
                    },
                );
                self.wire(
                    prod2,
                    CellRef {
                        column: self.col_c,
                        row: sum_all_row,
                    },
                );
                self.witness_ops
                    .push(PlonkWitnessOp::ArithRow { row: sum_all_row });
                state[i] = CellRef {
                    column: self.col_d,
                    row: sum_all_row,
                };
            }
        }

        // Output = state[0] (circomlibjs convention)
        Ok(state[0])
    }

    fn emit_sbox(&mut self, x: CellRef) -> CellRef {
        let x2 = self.emit_arith_row(x, x, None);
        let x4 = self.emit_arith_row(x2, x2, None);
        self.emit_arith_row(x4, x, None)
    }
}
