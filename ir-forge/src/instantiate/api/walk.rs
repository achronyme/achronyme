use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};
use rustc_hash::FxHashMap;

use ir_core::{IrProgram, SsaVar, Visibility};

use super::super::{InstEnvValue, Instantiator, InstrSink};
use crate::error::ProveIrError;
use crate::extended::ExtendedInstruction;
use crate::extended_program::ExtendedIrProgram;
use crate::types::ProveIR;

/// Shared body of all four entry points. Builds an `Instantiator`
/// holding the caller-provided `sink`, runs validate + declare +
/// emit, and lets the sink drop at scope end so the caller's
/// borrowed program (or body+metadata pair) is once again
/// exclusively borrowed for assembly into the return value.
pub(super) fn run_walk<'a, F: FieldBackend>(
    prove_ir: &ProveIR,
    captures: &HashMap<String, FieldElement<F>>,
    sink: Box<dyn InstrSink<F> + 'a>,
    output_names: Option<&HashSet<String>>,
) -> Result<(), ProveIrError> {
    let mut inst = Instantiator {
        sink,
        env: FxHashMap::default(),
        captures: captures
            .iter()
            .map(|(name, value)| (name.clone(), *value))
            .collect(),
        current_span: None,
        output_pub_vars: FxHashMap::default(),
        const_cache: FxHashMap::default(),
        const_values: FxHashMap::default(),
        component_bodies: prove_ir
            .component_bodies
            .iter()
            .map(|(key, body)| (key.clone(), body.clone()))
            .collect(),
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

    // `inst` (and the sink it owns) drops here, releasing the
    // borrow on the caller's program / body+metadata.
    Ok(())
}

/// Assemble the `ExtendedSink`'s output (a body Vec + a metadata
/// IrProgram skeleton) into a single [`ExtendedIrProgram<F>`].
pub(super) fn assemble_extended<F: FieldBackend>(
    body: Vec<ExtendedInstruction<F>>,
    metadata: IrProgram<F>,
) -> ExtendedIrProgram<F> {
    ExtendedIrProgram {
        body,
        next_var: metadata.next_var,
        var_names: metadata.var_names,
        var_types: metadata.var_types,
        input_spans: metadata.input_spans,
        var_spans: metadata.var_spans,
    }
}
