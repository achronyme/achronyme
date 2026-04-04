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

use ir::prove_ir::types::CircuitExpr;

use crate::ast::{self, Expr};

use super::super::components::inline_component_body_with_arrays;
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::utils::{extract_ident_name, EvalValue};
use super::targets::resolve_component_array_name;
use ir::prove_ir::types::CircuitNode;

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
}

/// Flush pending components whose inputs were wired via indexed
/// assignments (`comp.signal[i]`). These can't trigger eagerly because
/// we don't know when the array is fully wired, so we flush before
/// the next substitution statement (which might reference their outputs).
pub(super) fn flush_indexed_pending<'a>(
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    let to_flush: Vec<String> = pending
        .iter()
        .filter(|(_, c)| c.has_indexed_wirings)
        .map(|(name, _)| name.clone())
        .collect();
    for comp_name in &to_flush {
        if let Some(comp) = pending.remove(comp_name) {
            let body = inline_component_body_with_arrays(
                comp_name,
                comp.template,
                &comp.template_args,
                &comp.array_args,
                ctx,
                &comp.template.span,
            )?;
            nodes.extend(body);
        }
    }
    Ok(())
}

/// If this substitution wires a component input, mark it as wired.
/// When all inputs are wired, inline the component body.
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
    env: &LoweringEnv,
) -> Result<(), LoweringError> {
    let is_indexed = matches!(target, Expr::Index { .. });
    if let Some((comp_name, signal_name)) = extract_component_wiring_with_env(target, env, ctx) {
        if let Some(comp) = pending.get_mut(&comp_name) {
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
                let body = inline_component_body_with_arrays(
                    &comp_name,
                    comp.template,
                    &comp.template_args,
                    &comp.array_args,
                    ctx,
                    span,
                )?;
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
    let mut all_constants = ctx.param_values.clone();
    for (k, &v) in &env.known_constants {
        all_constants.insert(k.clone(), v);
    }

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
