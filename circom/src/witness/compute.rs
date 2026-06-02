use std::collections::HashMap;

use ir_forge::types::mangle::mangle_nodes;
use ir_forge::types::{CircuitExpr, CircuitNode, ForRange, ProveIR};
use memory::{FieldBackend, FieldElement, FieldFamily, PrimeId};

use super::error::WitnessError;
use super::eval::{eval_const_expr_u64, eval_hint, eval_hint_u64};

/// Compute all witness hint values from a ProveIR body.
///
/// Takes user-provided inputs and evaluates `WitnessHint` expressions
/// in order, building up a map of signal_name → FieldElement.
/// Later hints can reference earlier-computed values.
///
/// Returns `Err` if a Circom `assert()` fails during witness computation.
pub fn compute_witness_hints<F: FieldBackend>(
    prove_ir: &ProveIR,
    inputs: &HashMap<String, FieldElement<F>>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessError> {
    compute_witness_hints_with_captures(prove_ir, inputs, &HashMap::new())
}

/// Compute witness hints with capture values (template parameters).
///
/// Captures are needed to resolve For loop bounds like `for i < n`
/// where `n` is a template parameter.
///
/// Returns `Err` if a Circom `assert()` fails during witness computation.
pub fn compute_witness_hints_with_captures<F: FieldBackend>(
    prove_ir: &ProveIR,
    inputs: &HashMap<String, FieldElement<F>>,
    captures: &HashMap<String, u64>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessError> {
    let mut env: HashMap<String, FieldElement<F>> = inputs.clone();
    // Seed env with capture values so expressions like `1 << n` can
    // evaluate when `n` is a template parameter / capture.
    for (name, val) in captures {
        env.entry(name.clone())
            .or_insert_with(|| FieldElement::<F>::from_u64(*val));
    }
    collect_hints_recursive(
        &prove_ir.body,
        &mut env,
        captures,
        &prove_ir.component_bodies,
    )?;
    Ok(env)
}

fn collect_hints_recursive<F: FieldBackend>(
    nodes: &[CircuitNode],
    env: &mut HashMap<String, FieldElement<F>>,
    captures: &HashMap<String, u64>,
    comp_bodies: &HashMap<String, Vec<CircuitNode>>,
) -> Result<(), WitnessError> {
    for node in nodes {
        match node {
            CircuitNode::WitnessHint { name, hint, .. } => {
                if let Some(val) = eval_hint(hint, env) {
                    env.insert(name.clone(), val);
                }
            }
            CircuitNode::WitnessHintIndexed {
                array, index, hint, ..
            } => {
                if let (Some(idx), Some(val)) = (eval_hint_u64(index, env), eval_hint(hint, env)) {
                    let elem_name = format!("{array}_{idx}");
                    env.insert(elem_name, val);
                }
            }
            CircuitNode::Let { name, value, .. } => {
                if let Some(val) = eval_hint(value, env) {
                    env.insert(name.clone(), val);
                }
            }
            CircuitNode::LetIndexed {
                array,
                index,
                value,
                ..
            } => {
                if let (Some(idx), Some(val)) = (eval_hint_u64(index, env), eval_hint(value, env)) {
                    let elem_name = format!("{array}_{idx}");
                    env.insert(elem_name, val);
                }
            }
            CircuitNode::For {
                var, range, body, ..
            } => {
                let (start, end) = match range {
                    ForRange::Literal { start, end } => (Some(*start), Some(*end)),
                    ForRange::WithCapture { start, end_capture } => {
                        (Some(*start), captures.get(end_capture).copied())
                    }
                    ForRange::WithExpr { start, end_expr } => {
                        let end_val = eval_const_expr_u64(end_expr, captures);
                        (Some(*start), end_val)
                    }
                    ForRange::Array(_) => (None, None),
                };
                if let (Some(start), Some(end)) = (start, end) {
                    for i in start..end {
                        env.insert(var.clone(), FieldElement::<F>::from_u64(i));
                        collect_hints_recursive(body, env, captures, comp_bodies)?;
                    }
                } else {
                    collect_hints_recursive(body, env, captures, comp_bodies)?;
                }
            }
            CircuitNode::If {
                cond,
                then_body,
                else_body,
                ..
            } => {
                if let Some(val) = eval_hint(cond, env) {
                    if val != FieldElement::<F>::zero() {
                        collect_hints_recursive(then_body, env, captures, comp_bodies)?;
                    } else {
                        collect_hints_recursive(else_body, env, captures, comp_bodies)?;
                    }
                } else {
                    collect_hints_recursive(then_body, env, captures, comp_bodies)?;
                    collect_hints_recursive(else_body, env, captures, comp_bodies)?;
                }
            }
            CircuitNode::Assert { expr, message, .. } => {
                if let Some(val) = eval_hint(expr, env) {
                    if val == FieldElement::<F>::zero() {
                        let msg = message
                            .as_deref()
                            .unwrap_or("circom assert() failed during witness computation");
                        return Err(WitnessError {
                            message: msg.to_string(),
                        });
                    }
                }
            }
            CircuitNode::WitnessCall {
                output_bindings,
                input_signals,
                program_bytes,
                ..
            } => {
                // Resolve input signals from env. If any aren't yet
                // computed, skip this call (later passes may fill them
                // in). For the main SHA-256 lift this is unreachable in
                // practice — the lift's input_signals are sub-template
                // outputs that always precede the call in the body.
                let mut signal_vec: Vec<FieldElement<F>> = Vec::with_capacity(input_signals.len());
                let mut all_resolved = true;
                for expr in input_signals {
                    match eval_hint(expr, env) {
                        Some(v) => signal_vec.push(v),
                        None => {
                            all_resolved = false;
                            break;
                        }
                    }
                }
                if !all_resolved {
                    continue;
                }

                let family = artik_family_for::<F>().ok_or_else(|| WitnessError {
                    message: format!(
                        "no Artik field-family binding for backend {:?}",
                        F::PRIME_ID
                    ),
                })?;
                let program =
                    artik::bytecode::decode(program_bytes, Some(family)).map_err(|e| {
                        WitnessError {
                            message: format!("Artik decode failed: {e:?}"),
                        }
                    })?;

                let mut slot_vec: Vec<FieldElement<F>> =
                    vec![FieldElement::<F>::zero(); output_bindings.len()];
                let mut ctx = artik::ArtikContext::<F>::new(&signal_vec, &mut slot_vec);
                artik::execute(&program, &mut ctx).map_err(|e| WitnessError {
                    message: format!("Artik execute failed: {e:?}"),
                })?;

                for (name, val) in output_bindings.iter().zip(slot_vec.iter()) {
                    env.insert(name.clone(), *val);
                }
            }
            CircuitNode::LetArray { name, elements, .. } => {
                // Compile-time array alias (e.g. `var outCalc[256] = sha256compression(...)`).
                // The lift emits `LetArray { name, elements: [Var(artik_out_0), ...] }` so
                // later `ArrayIndex { array: name, index: i }` references can resolve through
                // to the underlying outputs. Without this, alias arrays produced by Artik
                // (or any compile-time array binding) never materialize in env, breaking
                // hint propagation through templates that wrap their outputs in a `var`.
                for (i, elem) in elements.iter().enumerate() {
                    if let Some(val) = eval_hint(elem, env) {
                        env.insert(format!("{name}_{i}"), val);
                    }
                }
            }
            CircuitNode::ComponentCall {
                body_key,
                comp_name,
                param_subs,
                ..
            } => {
                // A deferred component instance. Its internal hint
                // nodes live in the shared body, not here; expand it
                // with the same canonical mangle the instantiator
                // uses so the witness values are identical to an
                // inlined copy. Transient — one mangled body resident
                // per call.
                let body = comp_bodies.get(body_key).ok_or_else(|| WitnessError {
                    message: format!("ComponentCall references unknown body key `{body_key}`"),
                })?;
                let subs: HashMap<String, CircuitExpr> = param_subs.iter().cloned().collect();
                let mangled = mangle_nodes(body, comp_name, &subs);
                collect_hints_recursive(&mangled, env, captures, comp_bodies)?;
            }
            // No witness hints to collect — these emit constraints
            // only, declare slots, or are evaluated structurally.
            CircuitNode::AssertEq { .. }
            | CircuitNode::Expr { .. }
            | CircuitNode::Decompose { .. }
            | CircuitNode::WitnessArrayDecl { .. } => {}
        }
    }
    Ok(())
}

/// Map the field backend to its Artik header family. Mirrors
/// `ir::eval::witness_family` (kept local to avoid a `circom → ir`
/// dependency).
fn artik_family_for<F: FieldBackend>() -> Option<FieldFamily> {
    match F::PRIME_ID {
        PrimeId::Bn254 | PrimeId::Bls12_381 => Some(FieldFamily::BnLike256),
        _ => None,
    }
}
