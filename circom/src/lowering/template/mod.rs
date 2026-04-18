//! Template lowering: Circom template → complete ProveIR.
//!
//! Orchestrates signal extraction, environment setup, and body lowering
//! to produce a fully-formed `ProveIR` from a Circom `TemplateDef`.
//!
//! ## Submodules
//!
//! - [`lower`] — `lower_template_with_captures`, the library-mode entry
//!   point that runs the full pipeline against an explicit captures map.
//!   Re-exported as a public crate function.
//! - [`captures`] — capture classification: walks the lowered body to
//!   tag each template parameter as `StructureOnly` / `CircuitInput` /
//!   `Both`. Used internally by `lower`.
//! - [`tests`] — test suite (only compiled under `#[cfg(test)]`).
//!
//! The thin [`lower_template`] entry below adapts a `MainComponent` to
//! the captures + public-signals shape that [`lower::lower_template_with_captures`]
//! consumes.

mod captures;
mod lower;

use std::collections::{HashMap, HashSet};

use ir::prove_ir::types::{FieldConst, ProveIR};

use crate::ast::{CircomProgram, MainComponent, TemplateDef};

use super::error::LoweringError;

pub use lower::lower_template_with_captures;

/// Result of lowering a Circom template, including output signal metadata.
#[derive(Debug)]
pub struct LowerTemplateResult {
    pub prove_ir: ProveIR,
    /// Names of output signals (always public in R1CS).
    /// Used by the instantiator to emit post-body AssertEq constraints
    /// tying public output wires to their body-computed values.
    pub output_names: HashSet<String>,
}

/// Lower a Circom template definition to a ProveIR circuit template.
///
/// The `program` provides access to all template and function definitions
/// for component inlining and function call resolution.
/// The `main_component` determines which input signals are public vs witness.
pub fn lower_template(
    template: &TemplateDef,
    main: Option<&MainComponent>,
    program: &CircomProgram,
) -> Result<LowerTemplateResult, LoweringError> {
    // Extract captures from the main component's template args —
    // this is the only information lower_template_with_captures needs
    // from `main`, aside from the public_signals set.
    let mut captures: HashMap<String, FieldConst> = HashMap::new();
    if let Some(main_comp) = main {
        for (i, param) in template.params.iter().enumerate() {
            if let Some(arg) = main_comp.template_args.get(i) {
                if let Some(val) = super::utils::const_eval_u64(arg) {
                    captures.insert(param.clone(), FieldConst::from_u64(val));
                }
            }
        }
    }
    let public_signals: Vec<String> = main.map(|m| m.public_signals.clone()).unwrap_or_default();

    lower_template_with_captures(template, &captures, &public_signals, program)
}

#[cfg(test)]
mod tests;
