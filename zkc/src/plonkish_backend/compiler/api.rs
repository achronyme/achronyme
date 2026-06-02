use std::collections::{HashMap, HashSet};

use constraints::plonkish::{Column, Expression, PlonkishError, PlonkishSystem};
use constraints::PoseidonParamsProvider;
use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar};
use memory::{FieldBackend, FieldElement};

use super::super::types::PlonkVal;
use super::super::witness::PlonkishWitnessGenerator;
use super::PlonkishCompiler;

impl<F: FieldBackend> Default for PlonkishCompiler<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> PlonkishCompiler<F> {
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
            range_bounds: HashMap::new(),
        }
    }

    /// Set the proven-boolean set from bool_prop analysis.
    pub fn set_proven_boolean(&mut self, set: HashSet<SsaVar>) {
        self.proven_boolean = set;
    }

    /// Look up an SSA variable, returning an error instead of panicking.
    pub(super) fn lookup_val(&self, var: &SsaVar) -> Result<PlonkVal<F>, PlonkishError> {
        self.val_map
            .get(var)
            .cloned()
            .ok_or_else(|| PlonkishError::MissingInput(format!("undefined SSA variable {:?}", var)))
    }

    /// Compile an SSA IR program into a Plonkish constraint system.
    pub fn compile_ir(&mut self, program: &IrProgram<F>) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
        self.range_bounds.clear();
        <Self as constraints::ConstraintBackend<F>>::compile_ir(self, program)?;
        self.finalize_lookup_tables();
        Ok(())
    }

    /// Streaming counterpart of [`compile_ir`](Self::compile_ir): consume
    /// owned instructions from any [`IntoIterator`] source so each
    /// `Instruction<F>` drops the moment its constraints are emitted.
    ///
    /// Lookup-table finalization runs at the end, matching the
    /// [`compile_ir`](Self::compile_ir) contract.
    pub fn compile_instructions<I>(&mut self, instructions: I) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
        I: IntoIterator<Item = IrInstruction<F>>,
    {
        self.range_bounds.clear();
        <Self as constraints::ConstraintBackend<F>>::compile_instructions(self, instructions)?;
        self.finalize_lookup_tables();
        Ok(())
    }

    /// Pad lookup tables and finalize `num_rows`. Called once per
    /// `compile_ir` after every instruction has been emitted.
    fn finalize_lookup_tables(&mut self) {
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
        let table_padding: Vec<(Column, usize, FieldElement<F>)> = self
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
    }

    /// Compile an SSA IR program and generate a witness in a single pass.
    ///
    /// 1. Evaluates the IR with concrete inputs for early validation.
    /// 2. Compiles IR → Plonkish constraints.
    /// 3. Generates the witness by replaying ops into assignments.
    pub fn compile_ir_with_witness(
        &mut self,
        program: &IrProgram<F>,
        inputs: &HashMap<String, FieldElement<F>>,
    ) -> Result<(), PlonkishError>
    where
        F: PoseidonParamsProvider,
    {
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
