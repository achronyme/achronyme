use std::collections::{HashMap, HashSet};

use constraints::plonkish::{CellRef, Column, Expression, PlonkishError, PlonkishSystem};
use constraints::poseidon::PoseidonParams;
use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar, Visibility as IrVisibility};
use memory::FieldElement;

use super::types::{PlonkVal, PlonkWitnessOp};
use super::witness::PlonkishWitnessGenerator;

// ============================================================================
// PlonkishCompiler
// ============================================================================

pub struct PlonkishCompiler {
    pub system: PlonkishSystem,
    // Standard column refs
    pub col_s_arith: Column,
    pub col_constant: Column,
    pub col_zero: Column,
    pub col_a: Column,
    pub col_b: Column,
    pub col_c: Column,
    pub col_d: Column,
    pub col_instance: Column,
    // SSA → PlonkVal mapping
    pub(super) val_map: HashMap<SsaVar, PlonkVal>,
    // Named inputs
    pub bindings: HashMap<String, CellRef>,
    pub public_inputs: Vec<String>,
    pub witnesses: Vec<String>,
    pub(super) instance_row: usize,
    pub(super) current_row: usize,
    // Witness ops trace
    pub witness_ops: Vec<PlonkWitnessOp>,
    // Poseidon params (lazy)
    pub(super) poseidon_params: Option<PoseidonParams>,
    // Range table bits already created (maps bits → lookup_table index)
    pub(super) range_tables: HashMap<u32, usize>,
    // Per-bit-width range selector columns
    pub range_selectors: HashMap<u32, Column>,
    // SSA variables proven to be boolean by bool_prop analysis
    pub(super) proven_boolean: HashSet<SsaVar>,
}

impl Default for PlonkishCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PlonkishCompiler {
    pub fn new() -> Self {
        let mut system = PlonkishSystem::new(1024);

        let col_s_arith = system.alloc_fixed();
        let col_constant = system.alloc_fixed();
        let col_zero = system.alloc_fixed(); // Always zero (default), used for zero constraints
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
            col_constant,
            col_zero,
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
            range_selectors: HashMap::new(),
            proven_boolean: HashSet::new(),
        }
    }

    /// Set the proven-boolean set from bool_prop analysis.
    pub fn set_proven_boolean(&mut self, set: HashSet<SsaVar>) {
        self.proven_boolean = set;
    }

    /// Look up an SSA variable, returning an error instead of panicking.
    pub(super) fn lookup_val(&self, var: &SsaVar) -> Result<PlonkVal, PlonkishError> {
        self.val_map
            .get(var)
            .cloned()
            .ok_or_else(|| PlonkishError::MissingInput(format!("undefined SSA variable {:?}", var)))
    }

    /// Compile an SSA IR program into a Plonkish constraint system.
    pub fn compile_ir(&mut self, program: &IrProgram) -> Result<(), PlonkishError> {
        // Track proven bit-width bounds from RangeCheck for IsLt/IsLe optimization
        let mut range_bounds: HashMap<SsaVar, u32> = HashMap::new();

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
                    let a = self.lookup_val(lhs)?;
                    let b = self.lookup_val(rhs)?;
                    if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.add(&bv)));
                    } else {
                        self.val_map
                            .insert(*result, PlonkVal::DeferredAdd(Box::new(a), Box::new(b)));
                    }
                }
                IrInstruction::Sub { result, lhs, rhs } => {
                    let a = self.lookup_val(lhs)?;
                    let b = self.lookup_val(rhs)?;
                    if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.sub(&bv)));
                    } else {
                        self.val_map
                            .insert(*result, PlonkVal::DeferredSub(Box::new(a), Box::new(b)));
                    }
                }
                IrInstruction::Neg { result, operand } => {
                    let v = self.lookup_val(operand)?;
                    if let Some(cv) = v.constant_value() {
                        self.val_map.insert(*result, PlonkVal::Constant(cv.neg()));
                    } else {
                        self.val_map
                            .insert(*result, PlonkVal::DeferredNeg(Box::new(v)));
                    }
                }
                IrInstruction::Mul { result, lhs, rhs } => {
                    let a = self.lookup_val(lhs)?;
                    let b = self.lookup_val(rhs)?;
                    if let (Some(av), Some(bv)) = (a.constant_value(), b.constant_value()) {
                        self.val_map
                            .insert(*result, PlonkVal::Constant(av.mul(&bv)));
                    } else {
                        let a_cell = self.materialize_val(&a)?;
                        let b_cell = self.materialize_val(&b)?;
                        let d_cell = self.emit_arith_row(a_cell, b_cell, None);
                        self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                    }
                }
                IrInstruction::Div { result, lhs, rhs } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    if let (Some(av), Some(bv)) = (a_val.constant_value(), b_val.constant_value()) {
                        if let Some(inv) = bv.inv() {
                            self.val_map
                                .insert(*result, PlonkVal::Constant(av.mul(&inv)));
                        } else {
                            return Err(PlonkishError::MissingInput("division by zero".into()));
                        }
                    } else {
                        let num_cell = self.materialize_val(&a_val)?;
                        let den_cell = self.materialize_val(&b_val)?;
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
                    let cond_val = self.lookup_val(cond)?;
                    let t_val = self.lookup_val(if_true)?;
                    let f_val = self.lookup_val(if_false)?;
                    let cond_cell = self.materialize_val(&cond_val)?;
                    let t_cell = self.materialize_val(&t_val)?;
                    let f_cell = self.materialize_val(&f_val)?;
                    let d_cell = self.emit_mux(cond_cell, t_cell, f_cell);
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
                IrInstruction::AssertEq {
                    result, lhs, rhs, ..
                } => {
                    let a = self.lookup_val(lhs)?;
                    let b = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a)?;
                    let b_cell = self.materialize_val(&b)?;
                    self.system.add_copy(a_cell, b_cell);
                    self.val_map.insert(*result, PlonkVal::Cell(b_cell));
                }
                IrInstruction::PoseidonHash {
                    result,
                    left,
                    right,
                } => {
                    let left_val = self.lookup_val(left)?;
                    let right_val = self.lookup_val(right)?;
                    let left_cell = self.materialize_val(&left_val)?;
                    let right_cell = self.materialize_val(&right_val)?;
                    let d_cell = self.emit_poseidon(left_cell, right_cell)?;
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
                IrInstruction::RangeCheck {
                    result,
                    operand,
                    bits,
                } => {
                    let op_val = self.lookup_val(operand)?;
                    let op_cell = self.materialize_val(&op_val)?;
                    self.emit_range_check(op_cell, *bits)?;
                    // Record proven bound for IsLt/IsLe optimization
                    range_bounds.insert(*operand, *bits);
                    self.val_map.insert(*result, PlonkVal::Cell(op_cell));
                }
                IrInstruction::Not { result, operand } => {
                    let op_val = self.lookup_val(operand)?;
                    let op_cell = self.materialize_val(&op_val)?;
                    if !self.proven_boolean.contains(operand) {
                        self.emit_bool_check(op_cell);
                    }
                    // result = 1 - op: d = op * (-1) + 1
                    let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ONE))?;
                    let neg_op = self.negate_cell(op_cell);
                    let row = self.alloc_row();
                    self.system.set(self.col_s_arith, row, FieldElement::ONE);
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row,
                        },
                        FieldElement::ONE,
                    );
                    self.wire(
                        neg_op,
                        CellRef {
                            column: self.col_a,
                            row,
                        },
                    );
                    self.wire(
                        one_cell,
                        CellRef {
                            column: self.col_c,
                            row,
                        },
                    );
                    self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                    self.val_map.insert(
                        *result,
                        PlonkVal::Cell(CellRef {
                            column: self.col_d,
                            row,
                        }),
                    );
                }
                IrInstruction::And { result, lhs, rhs } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    if !self.proven_boolean.contains(lhs) {
                        self.emit_bool_check(a_cell);
                    }
                    if !self.proven_boolean.contains(rhs) {
                        self.emit_bool_check(b_cell);
                    }
                    // result = a * b
                    let d_cell = self.emit_arith_row(a_cell, b_cell, None);
                    self.val_map.insert(*result, PlonkVal::Cell(d_cell));
                }
                IrInstruction::Or { result, lhs, rhs } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    if !self.proven_boolean.contains(lhs) {
                        self.emit_bool_check(a_cell);
                    }
                    if !self.proven_boolean.contains(rhs) {
                        self.emit_bool_check(b_cell);
                    }
                    // result = a + b - a*b
                    let product = self.emit_arith_row(a_cell, b_cell, None);
                    let neg_product = self.negate_cell(product);
                    // sum = a*1 + b
                    let sum_row = self.alloc_row();
                    self.system
                        .set(self.col_s_arith, sum_row, FieldElement::ONE);
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row: sum_row,
                        },
                        FieldElement::ONE,
                    );
                    self.wire(
                        a_cell,
                        CellRef {
                            column: self.col_a,
                            row: sum_row,
                        },
                    );
                    self.wire(
                        b_cell,
                        CellRef {
                            column: self.col_c,
                            row: sum_row,
                        },
                    );
                    self.witness_ops
                        .push(PlonkWitnessOp::ArithRow { row: sum_row });
                    let sum_cell = CellRef {
                        column: self.col_d,
                        row: sum_row,
                    };
                    // result = sum*1 + neg_product
                    let result_row = self.alloc_row();
                    self.system
                        .set(self.col_s_arith, result_row, FieldElement::ONE);
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row: result_row,
                        },
                        FieldElement::ONE,
                    );
                    self.wire(
                        sum_cell,
                        CellRef {
                            column: self.col_a,
                            row: result_row,
                        },
                    );
                    self.wire(
                        neg_product,
                        CellRef {
                            column: self.col_c,
                            row: result_row,
                        },
                    );
                    self.witness_ops
                        .push(PlonkWitnessOp::ArithRow { row: result_row });
                    self.val_map.insert(
                        *result,
                        PlonkVal::Cell(CellRef {
                            column: self.col_d,
                            row: result_row,
                        }),
                    );
                }
                IrInstruction::IsEq { result, lhs, rhs } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    let eq_cell = self.emit_is_zero(a_cell, b_cell)?;
                    self.val_map.insert(*result, PlonkVal::Cell(eq_cell));
                }
                IrInstruction::IsNeq { result, lhs, rhs } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    let eq_cell = self.emit_is_zero(a_cell, b_cell)?;
                    // neq = 1 - eq
                    let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ONE))?;
                    let neg_eq = self.negate_cell(eq_cell);
                    let row = self.alloc_row();
                    self.system.set(self.col_s_arith, row, FieldElement::ONE);
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row,
                        },
                        FieldElement::ONE,
                    );
                    self.wire(
                        one_cell,
                        CellRef {
                            column: self.col_a,
                            row,
                        },
                    );
                    self.wire(
                        neg_eq,
                        CellRef {
                            column: self.col_c,
                            row,
                        },
                    );
                    self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                    self.val_map.insert(
                        *result,
                        PlonkVal::Cell(CellRef {
                            column: self.col_d,
                            row,
                        }),
                    );
                }
                IrInstruction::IsLt { result, lhs, rhs } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    let bound_a = range_bounds.get(lhs).copied();
                    let bound_b = range_bounds.get(rhs).copied();
                    let bound = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => Some(ba.max(bb)),
                        _ => None,
                    };
                    let lt_cell = self.emit_is_lt_bounded(a_cell, b_cell, bound)?;
                    self.val_map.insert(*result, PlonkVal::Cell(lt_cell));
                }
                IrInstruction::IsLe { result, lhs, rhs } => {
                    // a <= b ≡ !(b < a) ≡ 1 - IsLt(b, a)
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    let bound_a = range_bounds.get(lhs).copied();
                    let bound_b = range_bounds.get(rhs).copied();
                    let bound = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => Some(ba.max(bb)),
                        _ => None,
                    };
                    let lt_cell = self.emit_is_lt_bounded(b_cell, a_cell, bound)?;
                    // 1 - lt
                    let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ONE))?;
                    let neg_lt = self.negate_cell(lt_cell);
                    let row = self.alloc_row();
                    self.system.set(self.col_s_arith, row, FieldElement::ONE);
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row,
                        },
                        FieldElement::ONE,
                    );
                    self.wire(
                        one_cell,
                        CellRef {
                            column: self.col_a,
                            row,
                        },
                    );
                    self.wire(
                        neg_lt,
                        CellRef {
                            column: self.col_c,
                            row,
                        },
                    );
                    self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                    self.val_map.insert(
                        *result,
                        PlonkVal::Cell(CellRef {
                            column: self.col_d,
                            row,
                        }),
                    );
                }
                IrInstruction::IsLtBounded {
                    result,
                    lhs,
                    rhs,
                    bitwidth,
                } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    let lt_cell = self.emit_is_lt_bounded(a_cell, b_cell, Some(*bitwidth))?;
                    self.val_map.insert(*result, PlonkVal::Cell(lt_cell));
                }
                IrInstruction::IsLeBounded {
                    result,
                    lhs,
                    rhs,
                    bitwidth,
                } => {
                    let a_val = self.lookup_val(lhs)?;
                    let b_val = self.lookup_val(rhs)?;
                    let a_cell = self.materialize_val(&a_val)?;
                    let b_cell = self.materialize_val(&b_val)?;
                    let lt_cell = self.emit_is_lt_bounded(b_cell, a_cell, Some(*bitwidth))?;
                    // 1 - lt
                    let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ONE))?;
                    let neg_lt = self.negate_cell(lt_cell);
                    let row = self.alloc_row();
                    self.system.set(self.col_s_arith, row, FieldElement::ONE);
                    self.constrain_constant(
                        CellRef {
                            column: self.col_b,
                            row,
                        },
                        FieldElement::ONE,
                    );
                    self.wire(
                        one_cell,
                        CellRef {
                            column: self.col_a,
                            row,
                        },
                    );
                    self.wire(
                        neg_lt,
                        CellRef {
                            column: self.col_c,
                            row,
                        },
                    );
                    self.witness_ops.push(PlonkWitnessOp::ArithRow { row });
                    self.val_map.insert(
                        *result,
                        PlonkVal::Cell(CellRef {
                            column: self.col_d,
                            row,
                        }),
                    );
                }
                IrInstruction::Assert { result, operand } => {
                    let op_val = self.lookup_val(operand)?;
                    let op_cell = self.materialize_val(&op_val)?;
                    if !self.proven_boolean.contains(operand) {
                        self.emit_bool_check(op_cell);
                    }
                    // Enforce op == 1 via copy constraint to a materialized 1
                    let one_cell = self.materialize_val(&PlonkVal::Constant(FieldElement::ONE))?;
                    self.system.add_copy(op_cell, one_cell);
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

        // B4 fix: pad lookup table fixed columns by duplicating the last valid
        // entry instead of leaving zeros. Zero-filled lookup columns are a
        // soundness attack vector — a (0, 0) tuple validates f(0)=0 for any
        // table (cf. Plonky2 CVE GHSA-hj49-h7fq-px5h).
        let table_padding: Vec<(Column, usize, FieldElement)> = self
            .system
            .lookup_tables
            .iter()
            .filter_map(|table| {
                let table_len = table.values.len();
                if table_len > 0 && table_len < self.system.num_rows {
                    Some((table.column, table_len, table.values[table_len - 1]))
                } else {
                    None
                }
            })
            .collect();
        for (col, start, last_val) in table_padding {
            for row in start..self.system.num_rows {
                self.system.assignments.set(col, row, last_val);
            }
        }

        Ok(())
    }

    /// Compile an SSA IR program and generate a witness in a single pass.
    ///
    /// 1. Evaluates the IR with concrete inputs for early validation.
    /// 2. Compiles IR → Plonkish constraints.
    /// 3. Generates the witness by replaying ops into assignments.
    pub fn compile_ir_with_witness(
        &mut self,
        program: &IrProgram,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<(), PlonkishError> {
        // 1. Evaluate IR — early validation
        let _ssa_values = ir::eval::evaluate(program, inputs)
            .map_err(|e| PlonkishError::MissingInput(format!("evaluation error: {e}")))?;

        // 2. Compile constraints
        self.compile_ir(program)?;

        // 3. Generate witness
        let wg = PlonkishWitnessGenerator::from_compiler(self);
        wg.generate(inputs, &mut self.system.assignments)?;

        Ok(())
    }

    /// Number of arithmetic rows used by the circuit (excluding table/padding rows).
    pub fn num_circuit_rows(&self) -> usize {
        self.current_row
    }

    /// Return the bit-widths of all range tables created during compilation.
    pub fn range_tables_bits(&self) -> Vec<u32> {
        let mut bits: Vec<u32> = self.range_tables.keys().copied().collect();
        bits.sort();
        bits
    }
}
