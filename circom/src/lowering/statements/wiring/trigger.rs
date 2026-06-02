use super::*;

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
pub(in super::super) fn maybe_trigger_inline<'a>(
    target: &Expr,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    wired_value: Option<&CircuitExpr>,
) -> Result<(), LoweringError> {
    let is_indexed = matches!(target, Expr::Index { .. });
    let Some((comp_name, signal_name)) = extract_component_wiring_with_env(target, env, ctx) else {
        return Ok(());
    };
    let Some(comp) = pending.get_mut(&comp_name) else {
        return Ok(());
    };
    comp.mark_wired(signal_name, wired_value, is_indexed);
    if !comp.is_ready_to_inline() {
        return Ok(());
    }
    let comp = pending.remove(&comp_name).expect(
        "pending component disappeared between get_mut and remove; \
         this is a bug in the wiring state machine",
    );
    comp.inline_into(&comp_name, nodes, ctx, env, span)
}

/// Check if a substitution target is a component signal wiring.
/// Handles `comp.signal`, `comp.signal[i]`, `comp[i].signal`,
/// and `comp[i][j].signal` (2D component arrays).
/// Returns `(component_name, signal_name)` if so.
pub(in super::super) fn extract_component_wiring_with_env(
    target: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<(String, String)> {
    match target {
        // comp.signal <== expr  OR  comp[i].signal <== expr  OR  comp[i][j].signal <== expr
        Expr::DotAccess { object, field, .. } => {
            // Simple: comp.signal
            if let Some(obj) = extract_ident_name(object) {
                return Some((obj, field.clone()));
            }
            // Component array (1D or multi-dim): comp[i].signal, comp[i][j].signal
            if let Some(comp_name) = resolve_component_array_name_ctx(object, ctx, env) {
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
                        if let Some(comp) = resolve_component_array_name_ctx(da_obj, ctx, env) {
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
