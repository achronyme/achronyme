//! Template lowering: Circom template → complete ProveIR.
//!
//! Orchestrates signal extraction, environment setup, and body lowering
//! to produce a fully-formed `ProveIR` from a Circom `TemplateDef`.

use std::collections::{HashMap, HashSet};

use ir::prove_ir::types::{
    CaptureDef, CaptureUsage, CircuitExpr, CircuitNode, FieldConst, ForRange, ProveIR,
};

use crate::ast::{CircomProgram, MainComponent, TemplateDef};

/// Result of lowering a Circom template, including output signal metadata.
#[derive(Debug)]
pub struct LowerTemplateResult {
    pub prove_ir: ProveIR,
    /// Names of output signals (always public in R1CS).
    /// Used by the instantiator to emit post-body AssertEq constraints
    /// tying public output wires to their body-computed values.
    pub output_names: HashSet<String>,
}

use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::statements::lower_stmts;

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

/// Classify template parameter captures based on how they are used in the body.
///
/// - **StructureOnly**: only in loop bounds (`ForRange::WithCapture`) or
///   `Pow` exponents — affects circuit shape, not constraint values.
/// - **CircuitInput**: only in constraint expressions (`CircuitExpr::Capture`).
/// - **Both**: used in both structural and constraint positions.
fn classify_captures(params: &[String], body: &[CircuitNode]) -> Vec<CaptureDef> {
    let mut structural: HashSet<&str> = HashSet::new();
    let mut circuit: HashSet<&str> = HashSet::new();

    for node in body {
        collect_capture_usage(node, &mut structural, &mut circuit);
    }

    let param_set: HashSet<&str> = params.iter().map(|s| s.as_str()).collect();
    let mut captures = Vec::new();

    for param in params {
        if !param_set.contains(param.as_str()) {
            continue;
        }
        let in_struct = structural.contains(param.as_str());
        let in_circuit = circuit.contains(param.as_str());

        if !in_struct && !in_circuit {
            // Capture is declared but never referenced — still include it
            // as StructureOnly (no-op at instantiation).
            captures.push(CaptureDef {
                name: param.clone(),
                usage: CaptureUsage::StructureOnly,
            });
        } else {
            let usage = match (in_struct, in_circuit) {
                (true, true) => CaptureUsage::Both,
                (true, false) => CaptureUsage::StructureOnly,
                (false, true) => CaptureUsage::CircuitInput,
                (false, false) => unreachable!(
                    "capture appears in scan but is used in neither structure nor circuit"
                ),
            };
            captures.push(CaptureDef {
                name: param.clone(),
                usage,
            });
        }
    }

    captures
}

/// Walk a CircuitNode, recording which captures appear in structural vs
/// circuit positions.
fn collect_capture_usage<'a>(
    node: &'a CircuitNode,
    structural: &mut HashSet<&'a str>,
    circuit: &mut HashSet<&'a str>,
) {
    match node {
        CircuitNode::Let { value, .. } => collect_expr_captures(value, circuit),
        CircuitNode::LetArray { elements, .. } => {
            for e in elements {
                collect_expr_captures(e, circuit);
            }
        }
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            collect_expr_captures(lhs, circuit);
            collect_expr_captures(rhs, circuit);
        }
        CircuitNode::Assert { expr, .. } => collect_expr_captures(expr, circuit),
        CircuitNode::For { range, body, .. } => {
            // Loop bound captures are structural
            match range {
                ForRange::WithCapture { end_capture, .. } => {
                    structural.insert(end_capture.as_str());
                }
                ForRange::WithExpr { end_expr, .. } => {
                    // Captures in loop bound expressions are structural
                    collect_expr_captures(end_expr, structural);
                }
                ForRange::Literal { .. } | ForRange::Array(_) => {}
            }
            for n in body {
                collect_capture_usage(n, structural, circuit);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            collect_expr_captures(cond, circuit);
            for n in then_body {
                collect_capture_usage(n, structural, circuit);
            }
            for n in else_body {
                collect_capture_usage(n, structural, circuit);
            }
        }
        CircuitNode::Expr { expr, .. } => collect_expr_captures(expr, circuit),
        CircuitNode::Decompose { value, .. } => collect_expr_captures(value, circuit),
        CircuitNode::WitnessHint { hint, .. } => collect_expr_captures(hint, circuit),
        CircuitNode::LetIndexed { index, value, .. } => {
            collect_expr_captures(index, circuit);
            collect_expr_captures(value, circuit);
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            collect_expr_captures(index, circuit);
            collect_expr_captures(hint, circuit);
        }
    }
}

/// Collect all `Capture(name)` references in a circuit expression.
fn collect_expr_captures<'a>(expr: &'a CircuitExpr, captures: &mut HashSet<&'a str>) {
    match expr {
        CircuitExpr::Capture(name) => {
            captures.insert(name.as_str());
        }
        CircuitExpr::BinOp { lhs, rhs, .. }
        | CircuitExpr::Comparison { lhs, rhs, .. }
        | CircuitExpr::BoolOp { lhs, rhs, .. }
        | CircuitExpr::IntDiv { lhs, rhs, .. }
        | CircuitExpr::IntMod { lhs, rhs, .. } => {
            collect_expr_captures(lhs, captures);
            collect_expr_captures(rhs, captures);
        }
        CircuitExpr::UnaryOp { operand, .. } => collect_expr_captures(operand, captures),
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            collect_expr_captures(cond, captures);
            collect_expr_captures(if_true, captures);
            collect_expr_captures(if_false, captures);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            collect_expr_captures(left, captures);
            collect_expr_captures(right, captures);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args {
                collect_expr_captures(a, captures);
            }
        }
        CircuitExpr::RangeCheck { value, .. } => collect_expr_captures(value, captures),
        CircuitExpr::MerkleVerify { root, leaf, .. } => {
            collect_expr_captures(root, captures);
            collect_expr_captures(leaf, captures);
        }
        CircuitExpr::ArrayIndex { index, .. } => collect_expr_captures(index, captures),
        CircuitExpr::Pow { base, .. } => collect_expr_captures(base, captures),
        CircuitExpr::BitAnd { lhs, rhs, .. }
        | CircuitExpr::BitOr { lhs, rhs, .. }
        | CircuitExpr::BitXor { lhs, rhs, .. } => {
            collect_expr_captures(lhs, captures);
            collect_expr_captures(rhs, captures);
        }
        CircuitExpr::BitNot { operand, .. } => {
            collect_expr_captures(operand, captures);
        }
        CircuitExpr::ShiftR { operand, shift, .. } | CircuitExpr::ShiftL { operand, shift, .. } => {
            collect_expr_captures(operand, captures);
            collect_expr_captures(shift, captures);
        }
        // Leaf nodes with no captures
        CircuitExpr::Const(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => {}
    }
}

#[cfg(test)]
mod tests;
