//! Default `CircomWitnessHandler` used by `ach run` / `ach prove`.
//!
//! Phase 4.4 wiring: the compiler records every `.circom` library
//! it encounters into `compiler.circom_library_registry` keyed by
//! a `library_id`. The CLI moves that registry into this handler
//! struct and injects it into the VM before `vm.interpret()` runs.
//! At runtime the VM's `CallCircomTemplate` opcode resolves
//! `handle.library_id → Arc<CircomLibrary>` here and delegates to
//! `circom::evaluate_template_witness` for the actual witness.

use std::collections::HashMap;
use std::sync::Arc;

use memory::{Bn254Fr, CircomHandle, FieldElement};
use vm::{CircomCallError, CircomCallResult, CircomOutputValue, CircomWitnessHandler};

use circom::library::{evaluate_template_witness, TemplateOutputValue};
use circom::CircomLibrary;

/// In-process circom witness handler. Owns the same `Arc<CircomLibrary>`
/// instances the compiler allocated at compile time so the library
/// ids embedded in every `CircomHandle` always resolve.
pub struct DefaultCircomWitnessHandler {
    libraries: Vec<Arc<CircomLibrary>>,
}

impl DefaultCircomWitnessHandler {
    /// Build from the compiler's library registry.
    pub fn new(libraries: Vec<Arc<CircomLibrary>>) -> Self {
        Self { libraries }
    }

    /// Return the number of registered libraries — used by tests.
    #[allow(dead_code)]
    pub fn library_count(&self) -> usize {
        self.libraries.len()
    }
}

impl CircomWitnessHandler for DefaultCircomWitnessHandler {
    fn invoke(
        &self,
        handle: &CircomHandle,
        signal_inputs: &[FieldElement],
    ) -> Result<CircomCallResult, CircomCallError> {
        let lib = self
            .libraries
            .get(handle.library_id as usize)
            .ok_or(CircomCallError::UnknownLibraryId(handle.library_id))?;

        // Look up the template entry so we know the declared input
        // signal names (positional inputs from the compiler are
        // one-to-one with the library's declared order).
        let entry = lib.template(&handle.template_name).ok_or_else(|| {
            CircomCallError::WitnessEvaluation(format!(
                "template `{}` no longer present in library id {} \
                 (compiler/runtime registry mismatch)",
                handle.template_name, handle.library_id
            ))
        })?;

        if entry.inputs.len() != signal_inputs.len() {
            return Err(CircomCallError::InvalidSignalInput {
                index: 0,
                reason: format!(
                    "expected {} signal input(s) for circom template `{}`, got {}",
                    entry.inputs.len(),
                    handle.template_name,
                    signal_inputs.len()
                ),
            });
        }

        // Build the name-keyed HashMap the library evaluator expects.
        let mut map: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        for (i, input_sig) in entry.inputs.iter().enumerate() {
            if !input_sig.is_scalar() {
                return Err(CircomCallError::InvalidSignalInput {
                    index: i,
                    reason: format!(
                        "circom template `{}` declares array-valued signal input \
                         `{}`; VM-mode calls only support scalar signal inputs \
                         (Phase 4 limitation)",
                        handle.template_name, input_sig.name
                    ),
                });
            }
            map.insert(input_sig.name.clone(), signal_inputs[i]);
        }

        // Dispatch to the real witness evaluator.
        let raw_outputs = evaluate_template_witness::<Bn254Fr>(
            lib,
            &handle.template_name,
            &handle.template_args,
            &map,
        )
        .map_err(|e| CircomCallError::WitnessEvaluation(e.to_string()))?;

        // Convert circom-local TemplateOutputValue → vm-local CircomOutputValue.
        let mut outputs = HashMap::with_capacity(raw_outputs.len());
        for (name, out) in raw_outputs {
            let converted = match out {
                TemplateOutputValue::Scalar(v) => CircomOutputValue::Scalar(v),
                TemplateOutputValue::Array { dims, values } => {
                    CircomOutputValue::Array { dims, values }
                }
            };
            outputs.insert(name, converted);
        }

        Ok(CircomCallResult { outputs })
    }
}
