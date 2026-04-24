//! Public entry points for ProveIR instantiation.
//!
//! [`ProveIR::instantiate`] and [`ProveIR::instantiate_with_outputs`]
//! are the two ways a caller kicks off instantiation. Both build a
//! fresh [`IrProgram`], wrap it in a [`LegacySink`], hand a borrowed
//! [`Instantiator`] to the body walk, and return the populated
//! program when the walk completes. The pre-trait pipeline lived
//! directly on `Instantiator.program`; commit 2.2 of Phase 3.C.6
//! routes everything through [`InstrSink`] without changing the
//! caller-visible behaviour.
//!
//! `instantiate_with_outputs` differs only in step 2: for every
//! [`InputDecl`] whose name appears in `output_names`, it records the
//! element-level SSA vars in [`Instantiator::output_pub_vars`] so that
//! downstream `WitnessHint` / `Let` nodes reuse the public wire
//! instead of creating a duplicate witness wire. This is exclusively
//! for the Circom frontend, where `signal output` signals must appear
//! on the public R1CS boundary.

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use super::{InstEnvValue, Instantiator, LegacySink};
use crate::error::ProveIrError;
use crate::types::ProveIR;
use ir_core::{IrProgram, SsaVar, Visibility};

impl ProveIR {
    /// Instantiate this template with concrete capture values, producing a flat IrProgram.
    ///
    /// The resulting IrProgram is compatible with the existing optimize → R1CS/Plonkish
    /// pipeline (same format as `IrLowering::lower_circuit()`).
    pub fn instantiate<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<IrProgram<F>, ProveIrError> {
        let mut program = IrProgram::<F>::new();
        run_instantiate(self, captures, &mut program, None)?;
        Ok(program)
    }

    /// Instantiate with public output support (Circom frontend).
    ///
    /// Output signals in Circom are always public R1CS wires. When the body
    /// encounters a `WitnessHint` or `Let` for an output signal, it reuses
    /// the public wire instead of creating a separate witness wire. This
    /// avoids duplicate wires and ensures constraints reference the public wire
    /// directly.
    ///
    /// `output_names` contains the base names of output signals (e.g. `{"c", "out"}`).
    pub fn instantiate_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<IrProgram<F>, ProveIrError> {
        if output_names.is_empty() {
            return self.instantiate(captures);
        }
        let mut program = IrProgram::<F>::new();
        run_instantiate(self, captures, &mut program, Some(output_names))?;
        Ok(program)
    }
}

/// Shared body of both entry points. Builds an `Instantiator` around
/// a [`LegacySink`] borrowing the caller's `program`, runs validate +
/// declare + emit, and lets the sink drop at scope end so the program
/// is once again exclusively borrowed by the caller for the return.
fn run_instantiate<F: FieldBackend>(
    prove_ir: &ProveIR,
    captures: &HashMap<String, FieldElement<F>>,
    program: &mut IrProgram<F>,
    output_names: Option<&HashSet<String>>,
) -> Result<(), ProveIrError> {
    let sink = LegacySink::new(program);
    let mut inst = Instantiator {
        sink: Box::new(sink),
        env: HashMap::new(),
        captures: captures.clone(),
        current_span: None,
        output_pub_vars: HashMap::new(),
        const_cache: HashMap::new(),
        const_values: HashMap::new(),
    };

    // 1. Validate all required captures are provided
    inst.validate_captures(prove_ir)?;

    // 2. Declare public inputs. For Circom-frontend callers (output_names
    //    is Some), record element-level SSA vars for outputs so body
    //    nodes reuse them instead of creating duplicate witness wires.
    for input in &prove_ir.public_inputs {
        inst.declare_input(input, Visibility::Public)?;

        if let Some(outputs) = output_names {
            if outputs.contains(&input.name) {
                match &input.array_size {
                    Some(array_size) => {
                        let size = inst.resolve_array_size(array_size)?;
                        for i in 0..size {
                            let elem_name = format!("{}_{i}", input.name);
                            if let Some(InstEnvValue::Scalar(v)) = inst.env.get(&elem_name) {
                                inst.output_pub_vars.insert(elem_name, *v);
                            }
                        }
                    }
                    None => {
                        if let Some(InstEnvValue::Scalar(v)) = inst.env.get(&input.name) {
                            inst.output_pub_vars.insert(input.name.clone(), *v);
                        }
                    }
                }
            }
        }
    }

    // 3. Declare witness inputs
    for input in &prove_ir.witness_inputs {
        inst.declare_input(input, Visibility::Witness)?;
    }

    // 4. Declare captures as circuit inputs or inline constants
    for cap in &prove_ir.captures {
        inst.declare_capture(cap)?;
    }

    // 4b. Reconstruct array env entries from capture_arrays.
    //     Individual element captures (path_0, path_1) were declared above;
    //     now assemble them into InstEnvValue::Array so array-consuming
    //     constructs (e.g. merkle_verify) can resolve the array by name.
    for arr in &prove_ir.capture_arrays {
        let elem_vars: Vec<SsaVar> = (0..arr.size)
            .map(|i| {
                let elem_name = format!("{}_{i}", arr.name);
                match inst.env.get(&elem_name) {
                    Some(InstEnvValue::Scalar(v)) => Ok(*v),
                    _ => Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "missing array element capture `{elem_name}` for array `{}`",
                            arr.name
                        ),
                        span: None,
                    }),
                }
            })
            .collect::<Result<_, _>>()?;
        inst.env
            .insert(arr.name.clone(), InstEnvValue::Array(elem_vars));
    }

    // 5. Emit all body nodes
    for node in &prove_ir.body {
        inst.emit_node(node)?;
    }

    // `inst` (and the LegacySink it owns) drops here, releasing the
    // borrow on `program`. Caller returns the populated program.
    Ok(())
}
