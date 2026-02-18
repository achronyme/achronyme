use std::collections::HashMap;

use constraints::plonkish::{
    Assignments, CellRef, Column, Expression, LookupTable, PlonkishError, PlonkishSystem,
};
use constraints::poseidon::PoseidonParams;
use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar, Visibility as IrVisibility};
use memory::FieldElement;

// ============================================================================
// PlonkVal — lazy representation of SSA values in Plonkish
// ============================================================================

#[derive(Debug, Clone)]
pub enum PlonkVal {
    Cell(CellRef),
    Constant(FieldElement),
    DeferredAdd(Box<PlonkVal>, Box<PlonkVal>),
    DeferredSub(Box<PlonkVal>, Box<PlonkVal>),
    DeferredNeg(Box<PlonkVal>),
}

impl PlonkVal {
    fn constant_value(&self) -> Option<FieldElement> {
        match self {
            PlonkVal::Constant(v) => Some(*v),
            _ => None,
        }
    }
}

// ============================================================================
// PlonkWitnessOp — trace for witness generation
// ============================================================================

#[derive(Debug, Clone)]
pub enum PlonkWitnessOp {
    /// Assign a named input value to a cell.
    AssignInput { cell: CellRef, name: String },
    /// Copy value from `from` cell to `to` cell.
    CopyValue { from: CellRef, to: CellRef },
    /// Set a cell to a constant value.
    SetConstant { cell: CellRef, value: FieldElement },
    /// Compute d = a*b + c for a given row.
    ArithRow { row: usize },
    /// Compute b = 1/a for a given row (a is already in col_a).
    InverseRow { row: usize },
}

// ============================================================================
// PlonkishCompiler
// ============================================================================

pub struct PlonkishCompiler {
    pub system: PlonkishSystem,
    // Standard column refs
    pub col_s_arith: Column,
    pub col_s_range: Column,
    pub col_constant: Column,
    pub col_a: Column,
    pub col_b: Column,
    pub col_c: Column,
    pub col_d: Column,
    pub col_instance: Column,
    // SSA → PlonkVal mapping
    val_map: HashMap<SsaVar, PlonkVal>,
    // Named inputs
    pub bindings: HashMap<String, CellRef>,
    pub public_inputs: Vec<String>,
    pub witnesses: Vec<String>,
    instance_row: usize,
    current_row: usize,
    // Witness ops trace
    pub witness_ops: Vec<PlonkWitnessOp>,
    // Poseidon params (lazy)
    poseidon_params: Option<PoseidonParams>,
    // Range table bits already created
    range_tables: HashMap<u32, usize>,
}

impl PlonkishCompiler {
    pub fn new() -> Self {
        let mut system = PlonkishSystem::new(1024);

        let col_s_arith = system.alloc_fixed();
        let col_s_range = system.alloc_fixed();
        let col_constant = system.alloc_fixed();
        let col_a = system.alloc_advice();
        let col_b = system.alloc_advice();
        let col_c = system.alloc_advice();
        let col_d = system.alloc_advice();
        let col_instance = system.alloc_instance();

        // Gate: s_arith * (a * b + c - d) = 0
        let poly = Expression::cell(col_s_arith, 0).mul(
            Expression::cell(col_a, 0)
                .mul(Expression::cell(col_b, 0))
                .add(Expression::cell(col_c, 0))
                .sub(Expression::cell(col_d, 0)),
        );
        system.register_gate("arithmetic", poly);

        Self {
            system,
            col_s_arith,
            col_s_range,
            col_constant,
            col_a,
            col_b,
            col_c,
            col_d,
            col_instance,
            val_map: HashMap::new(),
            bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
            instance_row: 0,
            current_row: 0,
            witness_ops: Vec::new(),
            poseidon_params: None,
            range_tables: HashMap::new(),
        }
    }

    /// Compile an SSA IR program into a Plonkish constraint system.
    pub fn compile_ir(&mut self, program: &IrProgram) -> Result<(), PlonkishError> {
        for inst in &program.instructions {
            match inst {
                IrInstruction::Const { result, value } => {
                    self.val_map.insert(*result, PlonkVal::Constant(*value));
                }
                IrInstruction::Input {
                    result,
                    name,
                    visibility,
                } => match visibility {
                    IrVisibility::Public => {
                        let cell = CellRef {
                            column: self.col_instance,
                            row: self.instance_row,
                        };
                        self.instance_row += 1;
                        self.bindings.insert(name.clone(), cell);
                        self.public_inputs.push(name.clone());
                        self.witness_ops.push(PlonkWitnessOp::AssignInput {
                            cell,
                            name: name.clone(),
                        });
                        self.val_map.insert(*result, PlonkVal::Cell(cell));
                    }
                    IrVisibility::Witness => {
                        let row = self.alloc_row();
                        let cell = CellRef {
                            column: self.col_a,
                            row,
                        };
                        self.bindings.insert(name.clone(), cell);
                        self.witnesses.push(name.clone());
                        self.witness_ops.push(PlonkWitnessOp::AssignInput {
                            cell,
                            name: name.clone(),
                        });
                        self.val_map.insert(*result, PlonkVal::Cell(cell));
                    }
                },
                IrInstruction::Add { result, lhs, rhs } => {
                    let a = self.val_map[lhs].clone();
                    let b = self.val_map[rhs].clone();
                    if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.add(&bv)));
                    } else {
                        self.val_map.insert(
                            *result,
                            PlonkVal::DeferredAdd(Box::new(a), Box::new(b)),
                        );
                    }
                }
                IrInstruction::Sub { result, lhs, rhs } => {
                    let a = self.val_map[lhs].clone();
                    let b = self.val_map[rhs].clone();
                    if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.sub(&bv)));
                    } else {
                        self.val_map.insert(
                            *result,
                            PlonkVal::DeferredSub(Box::new(a), Box::new(b)),
                        );
                    }
                }
                IrInstruction::Neg { result, operand } => {
                    let v = self.val_map[operand].clone();
                    if let Some(cv) = v.constant_value() {
                        self.val_map.insert(*result, PlonkVal::Constant(cv.neg()));
                    } else {
                        self.val_map
                            .insert(*result, PlonkVal::DeferredNeg(Box::new(v)));
                    }
                }
                IrInstruction::Mul { result, lhs, rhs } => {
                    let a = self.val_map[lhs].clone();
                    let b = self.val_map[rhs].clone();
                    if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.mul(&bv)));
                    } else {
                        let a_cell = self.materialize_val(&a);
                        let b_cell = self.materialize_val(&b);
                        let d_cell = self.emit_arith_row(a_cell, b_cell, None);
                        self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                    }
                }
                IrInstruction::Div { result, lhs, rhs } => {
                    let a_val = self.val_map[lhs].clone();
                    let b_val = self.val_map[rhs].clone();
                    if let (Some(av), Some(bv)) = (a_val.constant_value(), b_val.constant_value())
                    {
                        if let Some(inv) = bv.inv() {
                            self.val_map
                                .insert(*result, PlonkVal::Constant(av.mul(&inv)));
                        } else {
                            return Err(PlonkishError::MissingInput("division by zero".into()));
                        }
                    } else {
                        let num_cell = self.materialize_val(&a_val);
                        let den_cell = self.materialize_val(&b_val);
                        let d_cell = self.emit_div(num_cell, den_cell);
                        self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                    }
                }
                IrInstruction::Mux {
                    result,
                    cond,
                    if_true,
                    if_false,
                } => {
                    let cond_val = self.val_map[cond].clone();
                    let t_val = self.val_map[if_true].clone();
                    let f_val = self.val_map[if_false].clone();
                    let cond_cell = self.materialize_val(&cond_val);
                    let t_cell = self.materialize_val(&t_val);
                    let f_cell = self.materialize_val(&f_val);
                    let d_cell = self.emit_mux(cond_cell, t_cell, f_cell);
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
                IrInstruction::AssertEq { result, lhs, rhs } => {
                    let a = self.val_map[lhs].clone();
                    let b = self.val_map[rhs].clone();
                    let a_cell = self.materialize_val(&a);
                    let b_cell = self.materialize_val(&b);
                    self.system.add_copy(a_cell, b_cell);
                    self.val_map.insert(*result, PlonkVal::Cell(b_cell));
                }
                IrInstruction::PoseidonHash {
                    result,
                    left,
                    right,
                } => {
                    let left_val = self.val_map[left].clone();
                    let right_val = self.val_map[right].clone();
                    let left_cell = self.materialize_val(&left_val);
                    let right_cell = self.materialize_val(&right_val);
                    let d_cell = self.emit_poseidon(left_cell, right_cell);
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
                IrInstruction::RangeCheck {
                    result,
                    operand,
                    bits,
                } => {
                    let op_val = self.val_map[operand].clone();
                    let op_cell = self.materialize_val(&op_val);
                    self.emit_range_check(op_cell, *bits);
                    self.val_map.insert(*result, PlonkVal::Cell(op_cell));
                }
            }
        }

        // Finalize: set num_rows to cover both circuit rows and lookup tables
        let mut final_rows = self.current_row;
        for table in &self.system.lookup_tables {
            final_rows = final_rows.max(table.values.len());
        }
        self.system.num_rows = final_rows;
        self.system.assignments.ensure_rows(self.system.num_rows);

        Ok(())
    }

    /// Number of arithmetic rows used by the circuit (excluding table/padding rows).
    pub fn num_circuit_rows(&self) -> usize {
        self.current_row
    }

    // ========================================================================
    // Row allocation
    // ========================================================================

    fn alloc_row(&mut self) -> usize {
        let row = self.current_row;
        self.current_row += 1;
        if self.current_row > self.system.num_rows {
            self.system.num_rows = self.current_row;
            self.system.assignments.ensure_rows(self.current_row);
        }
        row
    }

    // ========================================================================
    // Wiring: copy value + add copy constraint
    // ========================================================================

    /// Wire a source cell's value to a destination cell.
    /// Records both a witness copy-value op and a verification copy constraint.
    fn wire(&mut self, from: CellRef, to: CellRef) {
        self.witness_ops
            .push(PlonkWitnessOp::CopyValue { from, to });
        self.system.add_copy(from, to);
    }

    // ========================================================================
    // Materialization: PlonkVal → CellRef
    // ========================================================================

    fn materialize_val(&mut self, val: &PlonkVal) -> CellRef {
        match val {
            PlonkVal::Cell(cell) => *cell,
            PlonkVal::Constant(fe) => {
                // Row: 0 * 0 + fe = fe → gate: s*(0*0 + fe - fe) = 0
                let row = self.alloc_row();
                self.system.set(self.col_s_arith, row, FieldElement::ONE);
                self.system.set(self.col_constant, row, *fe);
                self.witness_ops.push(PlonkWitnessOp::SetConstant {
                    cell: CellRef {
                        column: self.col_c,
                        row,
                    },
                    value: *fe,
                });
                self.witness_ops
                    .push(PlonkWitnessOp::ArithRow { row });
                CellRef {
                    column: self.col_d,
                    row,
                }
            }
            PlonkVal::DeferredAdd(a, b) => {
                let a_cell = self.materialize_val(a);
                let b_cell = self.materialize_val(b);
                // d = a*1 + b
                let row = self.alloc_row();
                self.system.set(self.col_s_arith, row, FieldElement::ONE);
                self.witness_ops.push(PlonkWitnessOp::SetConstant {
                    cell: CellRef {
                        column: self.col_b,
                        row,
                    },
                    value: FieldElement::ONE,
                });
                self.wire(
                    a_cell,
                    CellRef {
                        column: self.col_a,
                        row,
                    },
                );
                self.wire(
                    b_cell,
                    CellRef {
                        column: self.col_c,
                        row,
                    },
                );
                self.witness_ops
                    .push(PlonkWitnessOp::ArithRow { row });
                CellRef {
                    column: self.col_d,
                    row,
                }
            }
            PlonkVal::DeferredSub(a, b) => {
                let a_cell = self.materialize_val(a);
                let b_cell = self.materialize_val(b);
                // d = a - b = a*1 + (-b)
                // Negate b first
                let neg_b = self.negate_cell(b_cell);
                let row = self.alloc_row();
                self.system.set(self.col_s_arith, row, FieldElement::ONE);
                self.witness_ops.push(PlonkWitnessOp::SetConstant {
                    cell: CellRef {
                        column: self.col_b,
                        row,
                    },
                    value: FieldElement::ONE,
                });
                self.wire(
                    a_cell,
                    CellRef {
                        column: self.col_a,
                        row,
                    },
                );
                self.wire(
                    neg_b,
                    CellRef {
                        column: self.col_c,
                        row,
                    },
                );
                self.witness_ops
                    .push(PlonkWitnessOp::ArithRow { row });
                CellRef {
                    column: self.col_d,
                    row,
                }
            }
            PlonkVal::DeferredNeg(inner) => {
                let inner_cell = self.materialize_val(inner);
                self.negate_cell(inner_cell)
            }
        }
    }

    /// d = a * (-1) + 0 = -a
    fn negate_cell(&mut self, cell: CellRef) -> CellRef {
        let row = self.alloc_row();
        self.system.set(self.col_s_arith, row, FieldElement::ONE);
        self.wire(
            cell,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.witness_ops.push(PlonkWitnessOp::SetConstant {
            cell: CellRef {
                column: self.col_b,
                row,
            },
            value: FieldElement::ONE.neg(),
        });
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row });
        CellRef {
            column: self.col_d,
            row,
        }
    }

    // ========================================================================
    // Arithmetic row: d = a*b + c
    // ========================================================================

    fn emit_arith_row(
        &mut self,
        a_cell: CellRef,
        b_cell: CellRef,
        c_cell: Option<CellRef>,
    ) -> CellRef {
        let row = self.alloc_row();
        self.system.set(self.col_s_arith, row, FieldElement::ONE);
        self.wire(
            a_cell,
            CellRef {
                column: self.col_a,
                row,
            },
        );
        self.wire(
            b_cell,
            CellRef {
                column: self.col_b,
                row,
            },
        );
        if let Some(cc) = c_cell {
            self.wire(
                cc,
                CellRef {
                    column: self.col_c,
                    row,
                },
            );
        }
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row });
        CellRef {
            column: self.col_d,
            row,
        }
    }

    // ========================================================================
    // Division: 2 rows
    // ========================================================================

    fn emit_div(&mut self, num: CellRef, den: CellRef) -> CellRef {
        // Row 1: den * inv = 1
        let inv_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, inv_row, FieldElement::ONE);
        self.wire(
            den,
            CellRef {
                column: self.col_a,
                row: inv_row,
            },
        );
        // b = inv (filled by InverseRow)
        // d = 1 (set as constant)
        self.witness_ops.push(PlonkWitnessOp::SetConstant {
            cell: CellRef {
                column: self.col_d,
                row: inv_row,
            },
            value: FieldElement::ONE,
        });
        self.witness_ops
            .push(PlonkWitnessOp::InverseRow { row: inv_row });
        let inv_cell = CellRef {
            column: self.col_b,
            row: inv_row,
        };

        // Row 2: num * inv + 0 = result
        self.emit_arith_row(num, inv_cell, None)
    }

    // ========================================================================
    // MUX: boolean check + subtraction + selection
    // ========================================================================

    fn emit_mux(&mut self, cond: CellRef, t: CellRef, f: CellRef) -> CellRef {
        // Row 1: cond^2 = cond (boolean enforcement)
        // Gate: s*(a*b+c-d)=0 → s*(cond*cond+0-cond)=0 → cond^2=cond
        let bool_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, bool_row, FieldElement::ONE);
        self.wire(
            cond,
            CellRef {
                column: self.col_a,
                row: bool_row,
            },
        );
        self.wire(
            cond,
            CellRef {
                column: self.col_b,
                row: bool_row,
            },
        );
        self.wire(
            cond,
            CellRef {
                column: self.col_d,
                row: bool_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: bool_row });

        // diff = t - f
        let neg_f = self.negate_cell(f);
        let diff_row = self.alloc_row();
        self.system
            .set(self.col_s_arith, diff_row, FieldElement::ONE);
        self.witness_ops.push(PlonkWitnessOp::SetConstant {
            cell: CellRef {
                column: self.col_b,
                row: diff_row,
            },
            value: FieldElement::ONE,
        });
        self.wire(
            t,
            CellRef {
                column: self.col_a,
                row: diff_row,
            },
        );
        self.wire(
            neg_f,
            CellRef {
                column: self.col_c,
                row: diff_row,
            },
        );
        self.witness_ops
            .push(PlonkWitnessOp::ArithRow { row: diff_row });
        let diff = CellRef {
            column: self.col_d,
            row: diff_row,
        };

        // result = cond * diff + f
        self.emit_arith_row(cond, diff, Some(f))
    }

    // ========================================================================
    // Poseidon
    // ========================================================================

    fn emit_poseidon(&mut self, left: CellRef, right: CellRef) -> CellRef {
        if self.poseidon_params.is_none() {
            self.poseidon_params = Some(PoseidonParams::bn254_t3());
        }
        let params = self.poseidon_params.clone().unwrap();

        let zero_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ZERO));
        let mut state = [zero_cell, left, right];

        let total_rounds = params.r_f + params.r_p;
        let half_f = params.r_f / 2;

        for r in 0..total_rounds {
            // Add round constants
            for i in 0..params.t {
                let rc = params.round_constants[r * params.t + i];
                if !rc.is_zero() {
                    let rc_cell = self.materialize_val(&PlonkVal::Constant(rc));
                    // state[i] = state[i]*1 + rc
                    let row = self.alloc_row();
                    self.system.set(self.col_s_arith, row, FieldElement::ONE);
                    self.witness_ops.push(PlonkWitnessOp::SetConstant {
                        cell: CellRef {
                            column: self.col_b,
                            row,
                        },
                        value: FieldElement::ONE,
                    });
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
                    self.witness_ops
                        .push(PlonkWitnessOp::ArithRow { row });
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
                let m0 = self.materialize_val(&PlonkVal::Constant(params.mds[i][0]));
                let prod0 = self.emit_arith_row(m0, old[0], None);
                let m1 = self.materialize_val(&PlonkVal::Constant(params.mds[i][1]));
                let prod1 = self.emit_arith_row(m1, old[1], None);
                let m2 = self.materialize_val(&PlonkVal::Constant(params.mds[i][2]));
                let prod2 = self.emit_arith_row(m2, old[2], None);
                // sum01 = prod0*1 + prod1
                let sum01_row = self.alloc_row();
                self.system
                    .set(self.col_s_arith, sum01_row, FieldElement::ONE);
                self.witness_ops.push(PlonkWitnessOp::SetConstant {
                    cell: CellRef {
                        column: self.col_b,
                        row: sum01_row,
                    },
                    value: FieldElement::ONE,
                });
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
                    .set(self.col_s_arith, sum_all_row, FieldElement::ONE);
                self.witness_ops.push(PlonkWitnessOp::SetConstant {
                    cell: CellRef {
                        column: self.col_b,
                        row: sum_all_row,
                    },
                    value: FieldElement::ONE,
                });
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

        // Output = state[1]
        state[1]
    }

    fn emit_sbox(&mut self, x: CellRef) -> CellRef {
        let x2 = self.emit_arith_row(x, x, None);
        let x4 = self.emit_arith_row(x2, x2, None);
        self.emit_arith_row(x4, x, None)
    }

    // ========================================================================
    // Range check: 1 lookup row
    // ========================================================================

    fn emit_range_check(&mut self, operand: CellRef, bits: u32) {
        self.ensure_range_table(bits);

        let row = self.alloc_row();
        self.system.set(self.col_s_range, row, FieldElement::ONE);
        self.wire(
            operand,
            CellRef {
                column: self.col_a,
                row,
            },
        );
    }

    fn ensure_range_table(&mut self, bits: u32) {
        if self.range_tables.contains_key(&bits) {
            return;
        }

        let table_col = self.system.alloc_fixed();
        let table_size = 1usize << bits;

        if table_size > self.system.num_rows {
            self.system.num_rows = table_size;
            self.system.assignments.ensure_rows(table_size);
        }

        let mut values = Vec::with_capacity(table_size);
        for i in 0..table_size {
            let val = FieldElement::from_u64(i as u64);
            self.system.set(table_col, i, val);
            values.push(val);
        }

        self.system.lookup_tables.push(LookupTable {
            name: format!("range_{bits}"),
            column: table_col,
            values,
        });

        self.system.register_lookup(
            &format!("range_{bits}"),
            vec![Expression::cell(self.col_s_range, 0)
                .mul(Expression::cell(self.col_a, 0))],
            vec![Expression::cell(table_col, 0)],
        );

        let idx = self.system.lookup_tables.len() - 1;
        self.range_tables.insert(bits, idx);
    }
}

// ============================================================================
// PlonkishWitnessGenerator
// ============================================================================

pub struct PlonkishWitnessGenerator {
    ops: Vec<PlonkWitnessOp>,
    col_a: Column,
    col_b: Column,
    col_c: Column,
    col_d: Column,
}

impl PlonkishWitnessGenerator {
    pub fn from_compiler(compiler: &PlonkishCompiler) -> Self {
        Self {
            ops: compiler.witness_ops.clone(),
            col_a: compiler.col_a,
            col_b: compiler.col_b,
            col_c: compiler.col_c,
            col_d: compiler.col_d,
        }
    }

    pub fn generate(
        &self,
        inputs: &HashMap<String, FieldElement>,
        assignments: &mut Assignments,
    ) -> Result<(), PlonkishError> {
        for op in &self.ops {
            match op {
                PlonkWitnessOp::AssignInput { cell, name } => {
                    let val = inputs
                        .get(name)
                        .ok_or_else(|| PlonkishError::MissingInput(name.clone()))?;
                    assignments.set(cell.column, cell.row, *val);
                }
                PlonkWitnessOp::CopyValue { from, to } => {
                    let val = assignments.get(from.column, from.row);
                    assignments.set(to.column, to.row, val);
                }
                PlonkWitnessOp::SetConstant { cell, value } => {
                    assignments.set(cell.column, cell.row, *value);
                }
                PlonkWitnessOp::ArithRow { row } => {
                    let a_val = assignments.get(self.col_a, *row);
                    let b_val = assignments.get(self.col_b, *row);
                    let c_val = assignments.get(self.col_c, *row);
                    let d_val = a_val.mul(&b_val).add(&c_val);
                    assignments.set(self.col_d, *row, d_val);
                }
                PlonkWitnessOp::InverseRow { row } => {
                    let a_val = assignments.get(self.col_a, *row);
                    if let Some(inv) = a_val.inv() {
                        assignments.set(self.col_b, *row, inv);
                        // d = a * inv + 0 = 1
                        assignments.set(self.col_d, *row, FieldElement::ONE);
                    }
                }
            }
        }

        Ok(())
    }
}
