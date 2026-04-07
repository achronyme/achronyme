//! Component wiring state machine.
//!
//! Tracks pending components whose input signals haven't been fully wired yet.
//! When all inputs are wired, the component body is inlined into the circuit.
//!
//! ## Protocol
//!
//! 1. **Declaration**: `component c = Template(args)` creates a `PendingComponent`
//!    with the set of expected input signals (extracted from the template definition).
//!    If the template has no inputs, it's inlined immediately — no pending entry.
//!
//! 2. **Wiring**: Each `c.signal <== expr` marks that signal as wired.
//!    - Scalar wiring (`c.in <== x`): signal name added to `wired_signals`.
//!    - Indexed wiring (`c.in[i] <== x`): sets `has_indexed_wirings = true`.
//!      These can't trigger inline because we don't know when the array is
//!      fully wired.
//!
//! 3. **Trigger**: When `wired_signals ⊇ input_signals` (all inputs wired),
//!    the component body is inlined via `inline_component_body_with_arrays`.
//!    Indexed wirings skip this check — they're flushed instead.
//!
//! 4. **Flush**: Before any substitution that reads a component output,
//!    `flush_indexed_pending` inlines all components with `has_indexed_wirings`.
//!    This ensures outputs are available before they're referenced.
//!
//! 5. **Cleanup**: At the end of a statement block, `lower_stmts_with_pending`
//!    inlines any remaining pending components (partial wiring or no-input).

use std::collections::{HashMap, HashSet};

use ir::prove_ir::types::{CircuitExpr, CircuitNode, FieldConst};

use super::super::const_fold::try_fold_const;

use crate::ast::{self, Expr};

use super::super::components::inline_component_body_with_const_inputs;
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::utils::{extract_ident_name, EvalValue};
use super::targets::resolve_component_array_name;

/// A pending component whose input signals haven't all been wired yet.
pub(super) struct PendingComponent<'a> {
    pub template: &'a ast::TemplateDef,
    pub template_args: Vec<CircuitExpr>,
    /// Array template args (param_name → compile-time array value).
    pub array_args: HashMap<String, EvalValue>,
    pub input_signals: HashSet<String>,
    pub wired_signals: HashSet<String>,
    /// True if any input was wired via indexed assignment (comp.signal[i]).
    /// Such components can't trigger inline from wiring completion alone —
    /// they need explicit flushing before their outputs are referenced.
    pub has_indexed_wirings: bool,
    /// Signal inputs wired to compile-time constants.
    /// When the component body is inlined, these are injected into the
    /// sub-template's `known_constants` so the lowerer emits `Const`
    /// instead of `Input`, enabling full constant propagation through
    /// Montgomery/MUX operations (Pedersen: 88→13 constraints).
    pub const_wired: HashMap<String, FieldConst>,
}

/// Flush pending components whose inputs were wired via indexed
/// assignments (`comp.signal[i]`). These can't trigger eagerly because
/// we don't know when the array is fully wired, so we flush before
/// the next substitution statement (which might reference their outputs).
pub(super) fn flush_indexed_pending<'a>(
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    env: &mut LoweringEnv,
) -> Result<(), LoweringError> {
    let to_flush: Vec<String> = pending
        .iter()
        .filter(|(_, c)| c.has_indexed_wirings)
        .map(|(name, _)| name.clone())
        .collect();
    for comp_name in &to_flush {
        if let Some(comp) = pending.remove(comp_name) {
            let mut const_inputs = comp.const_wired.clone();
            extract_const_inputs_from_nodes(comp_name, nodes, &mut const_inputs);
            let body = inline_component_body_with_const_inputs(
                comp_name,
                comp.template,
                &comp.template_args,
                &comp.array_args,
                &const_inputs,
                ctx,
                &comp.template.span,
            )?;
            propagate_const_nodes(&body, env);
            nodes.extend(body);
        }
    }
    Ok(())
}

/// Inline a specific pending component by name.
///
/// Used by the value-scan flush: when a substitution's value expression
/// references a pending component's output (e.g., `windows[0].out8[0]`),
/// that component must be inlined first so its output `Let` bindings
/// exist before the `Var` reference.
pub(super) fn flush_specific_component<'a>(
    comp_name: &str,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    env: &mut LoweringEnv,
) -> Result<(), LoweringError> {
    if let Some(comp) = pending.remove(comp_name) {
        // Build const_inputs by merging explicit const_wired with constants
        // extracted from already-emitted Let/WitnessHint nodes for this component.
        // This handles indexed wirings (e.g., comp.base[0] <== Const) where
        // the element name "base_0" isn't tracked during wiring.
        let mut const_inputs = comp.const_wired.clone();
        extract_const_inputs_from_nodes(comp_name, nodes, &mut const_inputs);
        let body = inline_component_body_with_const_inputs(
            comp_name,
            comp.template,
            &comp.template_args,
            &comp.array_args,
            &const_inputs,
            ctx,
            &comp.template.span,
        )?;
        propagate_const_nodes(&body, env);
        nodes.extend(body);
    }
    Ok(())
}

/// Scan existing nodes for Let/LetIndexed/WitnessHint/WitnessHintIndexed
/// with name `comp_name.signal_name` and constant values.
/// Extracts `signal_name → FieldConst` pairs.
///
/// For indexed nodes (e.g., `LetIndexed { array: "comp.base", index: Const(0), value: Const(fc) }`),
/// the element name is constructed as `base_0`.
pub(super) fn extract_const_inputs_from_nodes(
    comp_name: &str,
    nodes: &[CircuitNode],
    const_inputs: &mut HashMap<String, FieldConst>,
) {
    let prefix = format!("{comp_name}.");
    for node in nodes {
        match node {
            CircuitNode::Let { name, value, .. } => {
                if let Some(signal) = name.strip_prefix(&prefix) {
                    if let Some(fc) = try_fold_const(value) {
                        const_inputs.insert(signal.to_string(), fc);
                    }
                }
            }
            CircuitNode::LetIndexed {
                array,
                index,
                value,
                ..
            } => {
                if let Some(signal_base) = array.strip_prefix(&prefix) {
                    if let (Some(idx_fc), Some(val_fc)) =
                        (try_fold_const(index), try_fold_const(value))
                    {
                        if let Some(idx) = idx_fc.to_u64() {
                            const_inputs.insert(format!("{signal_base}_{idx}"), val_fc);
                        }
                    }
                }
            }
            CircuitNode::WitnessHint { name, hint, .. } => {
                if let Some(signal) = name.strip_prefix(&prefix) {
                    if let Some(fc) = try_fold_const(hint) {
                        const_inputs.insert(signal.to_string(), fc);
                    }
                }
            }
            CircuitNode::WitnessHintIndexed {
                array, index, hint, ..
            } => {
                if let Some(signal_base) = array.strip_prefix(&prefix) {
                    if let (Some(idx_fc), Some(val_fc)) =
                        (try_fold_const(index), try_fold_const(hint))
                    {
                        if let Some(idx) = idx_fc.to_u64() {
                            const_inputs.insert(format!("{signal_base}_{idx}"), val_fc);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Scan a value expression for references to pending component outputs.
///
/// Walks the AST recursively looking for `DotAccess` patterns whose object
/// resolves to a pending component name. Returns the names of referenced
/// pending components (deduplicated).
///
/// This enables demand-driven flushing: a component is inlined only when
/// its output is actually needed, not based on heuristic "fully wired" checks.
pub(super) fn collect_value_component_refs(
    expr: &Expr,
    pending: &HashMap<String, PendingComponent>,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Vec<String> {
    let mut refs = Vec::new();
    let all_constants = ctx.all_constants(env);
    collect_refs_recursive(expr, pending, &all_constants, &mut refs);
    refs
}

fn collect_refs_recursive(
    expr: &Expr,
    pending: &HashMap<String, PendingComponent>,
    constants: &HashMap<String, FieldConst>,
    refs: &mut Vec<String>,
) {
    match expr {
        Expr::DotAccess { object, .. } => {
            // comp.signal or comp[i].signal
            let comp_name = extract_ident_name(object)
                .or_else(|| resolve_component_array_name(object, constants));
            if let Some(name) = comp_name {
                if pending.contains_key(&name) && !refs.contains(&name) {
                    refs.push(name);
                }
            }
            // Also recurse into the object (handles nested Index chains)
            collect_refs_recursive(object, pending, constants, refs);
        }
        Expr::Index { object, index, .. } => {
            collect_refs_recursive(object, pending, constants, refs);
            collect_refs_recursive(index, pending, constants, refs);
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_refs_recursive(lhs, pending, constants, refs);
            collect_refs_recursive(rhs, pending, constants, refs);
        }
        Expr::UnaryOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            collect_refs_recursive(operand, pending, constants, refs);
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            collect_refs_recursive(condition, pending, constants, refs);
            collect_refs_recursive(if_true, pending, constants, refs);
            collect_refs_recursive(if_false, pending, constants, refs);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_refs_recursive(arg, pending, constants, refs);
            }
        }
        Expr::Tuple { elements, .. } => {
            for elem in elements {
                collect_refs_recursive(elem, pending, constants, refs);
            }
        }
        // Leaf nodes: Ident, Number, HexNumber, etc. — no component references
        _ => {}
    }
}

/// If this substitution wires a component input, mark it as wired.
/// When all inputs are wired, inline the component body.
///
/// `wired_value` is the lowered expression being assigned. When it's
/// `Const(fc)`, we record it in the component's `const_wired` map so
/// the sub-template can use the constant during lowering.
///
/// For indexed wirings (`comp.signal[i] <== expr`), the wiring is
/// tracked but the base signal name counts as wired (since the array
/// will be fully wired across multiple indexed assignments).
pub(super) fn maybe_trigger_inline<'a>(
    target: &Expr,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    wired_value: Option<&CircuitExpr>,
) -> Result<(), LoweringError> {
    let is_indexed = matches!(target, Expr::Index { .. });
    if let Some((comp_name, signal_name)) = extract_component_wiring_with_env(target, env, ctx) {
        if let Some(comp) = pending.get_mut(&comp_name) {
            // Track constant wired values for propagation into sub-template
            if let Some(CircuitExpr::Const(fc)) = wired_value {
                comp.const_wired.insert(signal_name.clone(), *fc);
            }
            comp.wired_signals.insert(signal_name);
            if is_indexed {
                comp.has_indexed_wirings = true;
            }
            // Don't trigger inline from the first indexed wiring to an
            // array — wait until the next non-wiring statement forces a
            // flush, or until all non-array inputs are also wired.
            if comp.has_indexed_wirings {
                return Ok(());
            }
            if comp.wired_signals.is_superset(&comp.input_signals) {
                let comp = pending.remove(&comp_name).expect(
                    "pending component disappeared between get_mut and remove; \
                     this is a bug in the wiring state machine",
                );
                let mut const_inputs = comp.const_wired.clone();
                extract_const_inputs_from_nodes(&comp_name, nodes, &mut const_inputs);
                let body = inline_component_body_with_const_inputs(
                    &comp_name,
                    comp.template,
                    &comp.template_args,
                    &comp.array_args,
                    &const_inputs,
                    ctx,
                    span,
                )?;
                propagate_const_nodes(&body, env);
                nodes.extend(body);
            }
        }
    }
    Ok(())
}

/// Check if a substitution target is a component signal wiring.
/// Handles `comp.signal`, `comp.signal[i]`, `comp[i].signal`,
/// and `comp[i][j].signal` (2D component arrays).
/// Returns `(component_name, signal_name)` if so.
pub(super) fn extract_component_wiring_with_env(
    target: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<(String, String)> {
    // Build combined constants for index resolution
    let all_constants = ctx.all_constants(env);

    match target {
        // comp.signal <== expr  OR  comp[i].signal <== expr  OR  comp[i][j].signal <== expr
        Expr::DotAccess { object, field, .. } => {
            // Simple: comp.signal
            if let Some(obj) = extract_ident_name(object) {
                return Some((obj, field.clone()));
            }
            // Component array (1D or multi-dim): comp[i].signal, comp[i][j].signal
            if let Some(comp_name) = resolve_component_array_name(object, &all_constants) {
                return Some((comp_name, field.clone()));
            }
            None
        }
        // Index patterns: comp.signal[i], comp.signal[i][j], comp[i].signal[j]
        Expr::Index { object, .. } => {
            // Unwrap Index chain to find the DotAccess inside
            let mut cur = object.as_ref();
            loop {
                match cur {
                    Expr::DotAccess {
                        object: da_obj,
                        field,
                        ..
                    } => {
                        if let Some(obj) = extract_ident_name(da_obj) {
                            return Some((obj, field.clone()));
                        }
                        if let Some(comp) = resolve_component_array_name(da_obj, &all_constants) {
                            return Some((comp, field.clone()));
                        }
                        return None;
                    }
                    Expr::Index { object: inner, .. } => {
                        cur = inner.as_ref();
                    }
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}

/// Scan inlined circuit nodes for `Let` and `WitnessHint` with constant
/// values, and add them to `env.known_constants`.
///
/// This enables constant propagation ACROSS component boundaries: after
/// inlining Edwards2Montgomery with constant inputs, its output signals
/// (e.g., `e2m.out_0`) become known constants in the parent scope, so
/// subsequent components (Window4, MontgomeryDouble) can also fold.
pub(super) fn propagate_const_nodes(nodes: &[CircuitNode], env: &mut LoweringEnv) {
    for node in nodes {
        match node {
            CircuitNode::Let { name, value, .. } => {
                if let Some(fc) = try_fold_const(value) {
                    env.known_constants.insert(name.clone(), fc);
                }
            }
            CircuitNode::LetIndexed {
                array,
                index,
                value,
                ..
            } => {
                if let (Some(idx_fc), Some(val_fc)) = (try_fold_const(index), try_fold_const(value))
                {
                    if let Some(idx) = idx_fc.to_u64() {
                        env.known_constants.insert(format!("{array}_{idx}"), val_fc);
                    }
                }
            }
            CircuitNode::WitnessHint { name, hint, .. } => {
                if let Some(fc) = try_fold_const(hint) {
                    env.known_constants.insert(name.clone(), fc);
                }
            }
            CircuitNode::WitnessHintIndexed {
                array, index, hint, ..
            } => {
                if let (Some(idx_fc), Some(val_fc)) = (try_fold_const(index), try_fold_const(hint))
                {
                    if let Some(idx) = idx_fc.to_u64() {
                        env.known_constants.insert(format!("{array}_{idx}"), val_fc);
                    }
                }
            }
            _ => {}
        }
    }
}
