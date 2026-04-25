//! Library-mode entry point for template lowering.
//!
//! [`lower_template_with_captures`] runs the full lowering pipeline
//! against a caller-supplied captures map and public-signal list — the
//! [`super::lower_template`] wrapper above just turns a `MainComponent`
//! into those two arguments before delegating here.

use std::collections::{HashMap, HashSet};

use ir_forge::types::{FieldConst, ProveIR};

use super::captures::classify_captures;
use super::LowerTemplateResult;
use crate::ast::{CircomProgram, TemplateDef};
use crate::lowering::context::LoweringContext;
use crate::lowering::env::{Frontend, LoweringEnv};
use crate::lowering::error::LoweringError;
use crate::lowering::statements::lower_stmts;
use crate::lowering::{signals, utils};

/// Library-mode entry point: lower a template directly against a
/// caller-supplied captures map and public-signals list, without
/// requiring a synthetic [`crate::ast::MainComponent`].
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
    lower_template_with_captures_and_frontend(
        template,
        captures,
        public_signals,
        program,
        Frontend::Legacy,
    )
}

/// Frontend-aware variant of [`lower_template_with_captures`]. Used by
/// the Lysis-targeting compilation path so the loop classifier sees
/// `Frontend::Lysis` and keeps loop-var-indexed signal-write loops
/// rolled.
pub fn lower_template_with_captures_and_frontend(
    template: &TemplateDef,
    captures: &HashMap<String, FieldConst>,
    public_signals: &[String],
    program: &CircomProgram,
    frontend: Frontend,
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
        utils::precompute_all(&template.body.stmts, &ctx.param_values, &ctx.functions);

    // 1. Extract signal layout (with pre-computed vars for dimension resolution)
    let layout = signals::extract_signal_layout_with_captures(
        template,
        captures,
        public_signals,
        &precomputed.scalars,
    )?;

    // Add pre-computed vars to param_values so they're available during body lowering.
    // Also inject into env.known_constants so that `Expr::Ident` lowering folds
    // them to `CircuitExpr::Const` — except for vars that are reassigned later
    // in the body (accumulators like `lc1 += ...`), which would produce wrong
    // values if folded. Template params and `var X; X = <const>;` patterns both
    // flow through here; the latter is needed for circomlib SHA256's
    // `var nBlocks; ...; nBlocks = (nBits+64)\512+1; paddedIn[nBlocks*512-k-1]`.
    let reassigned = super::super::components::find_reassigned_vars(&template.body.stmts);
    for (name, val) in &precomputed.scalars {
        ctx.param_values.insert(name.clone(), *val);
    }

    // 2. Build lowering environment
    let mut env = LoweringEnv::with_frontend(frontend);

    // Input signals → env.inputs. Array-valued inputs (e.g.
    // `signal input hin[256]`) additionally register their length
    // in `env.arrays` so call-site shape inference (Artik lift) and
    // `env.resolve_array_element(name, i)` can find them.
    for input in &layout.public_inputs {
        env.inputs.insert(input.name.clone());
        if let Some(ir_forge::types::ArraySize::Literal(len)) = &input.array_size {
            env.register_array(input.name.clone(), *len);
        }
    }
    for input in &layout.witness_inputs {
        env.inputs.insert(input.name.clone());
        if let Some(ir_forge::types::ArraySize::Literal(len)) = &input.array_size {
            env.register_array(input.name.clone(), *len);
        }
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

    // Inject pre-computed scalar vars into `known_constants` for identifier
    // folding. Skip reassigned vars (accumulators) to preserve correctness.
    for (name, val) in &precomputed.scalars {
        if !reassigned.contains(name) {
            env.known_constants.insert(name.clone(), *val);
        }
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
