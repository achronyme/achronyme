//! Template lowering: Circom template → complete ProveIR.
//!
//! Orchestrates signal extraction, environment setup, and body lowering
//! to produce a fully-formed `ProveIR` from a Circom `TemplateDef`.

mod captures;

use std::collections::{HashMap, HashSet};

use ir::prove_ir::types::{FieldConst, ProveIR};

use crate::ast::{CircomProgram, MainComponent, TemplateDef};

use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::statements::lower_stmts;
use captures::classify_captures;

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

/// Library-mode entry point: lower a template directly against a
/// caller-supplied captures map and public-signals list, without
/// requiring a synthetic [`MainComponent`].
///
/// This is what the off-circuit witness evaluator uses when
/// an `.ach` file calls an imported Circom template in VM mode —
/// there's no `component main` in sight and synthesizing a fake
/// AST just to thread captures through the old entry point would
/// fabricate spans and truncate non-`u64` values. Passing captures
/// directly keeps everything honest.
pub fn lower_template_with_captures(
    template: &TemplateDef,
    captures: &HashMap<String, FieldConst>,
    public_signals: &[String],
    program: &CircomProgram,
) -> Result<LowerTemplateResult, LoweringError> {
    let mut ctx = LoweringContext::from_program(program);
    for (name, &val) in captures {
        ctx.param_values.insert(name.clone(), val);
    }

    // Pre-evaluate compile-time var declarations in a single pass.
    // Scalars (e.g., `var nout = nbits(...)`) and arrays (e.g., `var C[n] = POSEIDON_C(t)`)
    // are computed together so that later vars can reference earlier ones
    // (e.g., `var nRoundsP = N_ROUNDS_P[t - 2]`).
    let precomputed =
        super::utils::precompute_all(&template.body.stmts, &ctx.param_values, &ctx.functions);

    // 1. Extract signal layout (with pre-computed vars for dimension resolution)
    let layout = super::signals::extract_signal_layout_with_captures(
        template,
        captures,
        public_signals,
        &precomputed.scalars,
    )?;

    // Add pre-computed vars to param_values so they're available during body lowering
    for (name, val) in &precomputed.scalars {
        ctx.param_values.insert(name.clone(), *val);
    }

    // 2. Build lowering environment
    let mut env = LoweringEnv::new();

    // Input signals → env.inputs
    for input in &layout.public_inputs {
        env.inputs.insert(input.name.clone());
    }
    for input in &layout.witness_inputs {
        env.inputs.insert(input.name.clone());
    }

    // Output signals → env.locals (they'll be assigned in the body)
    for out in &layout.outputs {
        env.locals.insert(out.name.clone());
    }

    // Intermediate signals → env.locals
    for inter in &layout.intermediates {
        env.locals.insert(inter.name.clone());
    }

    // Template parameters → env.captures
    for param in &template.params {
        env.captures.insert(param.clone());
    }

    // Inject pre-computed array vars into the environment
    for (name, val) in precomputed.arrays {
        env.known_array_values.insert(name, val);
    }

    // 3. Lower body statements
    let body = lower_stmts(&template.body.stmts, &mut env, &mut ctx)?;

    // 4. Classify captures
    let captures = classify_captures(&template.params, &body);

    // 5. Convert output signals to public input declarations and collect names.
    //    In Circom, all `signal output` are public wires in the R1CS.
    let output_names: HashSet<String> = layout.outputs.iter().map(|o| o.name.clone()).collect();
    let mut all_public = layout.public_inputs;
    for out in &layout.outputs {
        all_public.push(out.to_input_decl());
    }

    // 6. Assemble ProveIR
    Ok(LowerTemplateResult {
        prove_ir: ProveIR {
            name: Some(template.name.clone()),
            public_inputs: all_public,
            witness_inputs: layout.witness_inputs,
            captures,
            body,
            capture_arrays: Vec::new(),
        },
        output_names,
    })
}



#[cfg(test)]
mod tests;
