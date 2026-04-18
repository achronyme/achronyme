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
//! 2. **Wiring**: Each `c.signal <== expr` calls `mark_wired` on the
//!    pending entry. The component holds a [`WiringState`] enum:
//!    - Scalar wiring (`c.in <== x`): adds to the wired set, stays
//!      in `AllScalar`.
//!    - Indexed wiring (`c.in[i] <== x`): adds to the wired set and
//!      transitions to `PartialIndexed`. The transition is monotonic
//!      — `PartialIndexed` never reverts.
//!
//! 3. **Trigger**: After every `mark_wired`, callers check
//!    `is_ready_to_inline()`. It returns `true` iff the state is
//!    still `AllScalar` and the wired set covers `input_signals`.
//!    `PartialIndexed` always returns `false` — those components are
//!    inlined via flush, not trigger.
//!
//! 4. **Demand-driven flush**: Before a substitution that references a
//!    component output, [`collect_value_component_refs`] walks the read
//!    side of the statement and emits a list of pending components the
//!    value depends on; [`flush_specific_component`] inlines exactly
//!    those. This replaces an older bulk-flush approach that could
//!    inline components before their inputs were fully wired.
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

/// Wiring progress for a pending component.
///
/// Two-state machine. The transition `AllScalar → PartialIndexed` is
/// monotonic — once an indexed wiring (`comp.signal[i] <== expr`) is
/// recorded, the trigger path is permanently disabled and the
/// component must be flushed explicitly before its outputs are
/// referenced. Encoding this as an enum (rather than a `wired:
/// HashSet + has_indexed: bool` pair) makes the "forgot to set
/// has_indexed" class of bug unrepresentable.
pub(super) enum WiringState {
    /// All wirings so far are scalar. The trigger path is live: the
    /// component will inline as soon as `wired ⊇ input_signals`.
    AllScalar { wired: HashSet<String> },
    /// At least one wiring was indexed. The trigger path is dead;
    /// the component must be flushed (demand-driven from
    /// `flush_specific_component` or from the cleanup loop at end of
    /// block) before its outputs are referenced.
    PartialIndexed { wired: HashSet<String> },
}

impl WiringState {
    fn new() -> Self {
        Self::AllScalar {
            wired: HashSet::new(),
        }
    }

    /// Record a wiring. Transitions `AllScalar → PartialIndexed` on
    /// the first indexed wiring; subsequent indexed wirings stay in
    /// `PartialIndexed`. The signal name is added to `wired` in
    /// either case.
    fn mark(&mut self, signal: String, is_indexed: bool) {
        match self {
            Self::AllScalar { wired } => {
                wired.insert(signal);
                if is_indexed {
                    let wired = std::mem::take(wired);
                    *self = Self::PartialIndexed { wired };
                }
            }
            Self::PartialIndexed { wired } => {
                wired.insert(signal);
            }
        }
    }

    /// True iff `wired ⊇ inputs` AND no indexed wiring has been
    /// recorded. `PartialIndexed` always returns false — those
    /// components are inlined via flush, not trigger.
    fn is_ready(&self, inputs: &HashSet<String>) -> bool {
        match self {
            Self::AllScalar { wired } => wired.is_superset(inputs),
            Self::PartialIndexed { .. } => false,
        }
    }
}

/// A pending component whose input signals haven't all been wired yet.
///
/// All fields are private — callers interact through `new`,
/// `mark_wired`, `is_ready_to_inline`, and `inline_into`. This keeps
/// the wiring state machine + const-propagation bookkeeping in a
/// single module so future protocol changes only touch this file.
pub(super) struct PendingComponent<'a> {
    template: &'a ast::TemplateDef,
    template_args: Vec<CircuitExpr>,
    /// Array template args (param_name → compile-time array value).
    array_args: HashMap<String, EvalValue>,
    input_signals: HashSet<String>,
    /// Wiring progress (which signals are wired + whether any wiring
    /// was indexed).
    state: WiringState,
    /// Signal inputs wired to compile-time constants.
    /// When the component body is inlined, these are injected into the
    /// sub-template's `known_constants` so the lowerer emits `Const`
    /// instead of `Input`, enabling full constant propagation through
    /// Montgomery/MUX operations (Pedersen: 88→13 constraints).
    const_wired: HashMap<String, FieldConst>,
}

impl<'a> PendingComponent<'a> {
    /// Build a pending component with no wirings recorded yet.
    ///
    /// Caller must ensure `input_signals` is non-empty — components
    /// with zero inputs are inlined immediately at declaration and
    /// never enter the pending map.
    pub(super) fn new(
        template: &'a ast::TemplateDef,
        template_args: Vec<CircuitExpr>,
        array_args: HashMap<String, EvalValue>,
        input_signals: HashSet<String>,
    ) -> Self {
        Self {
            template,
            template_args,
            array_args,
            input_signals,
            state: WiringState::new(),
            const_wired: HashMap::new(),
        }
    }

    /// Record that an input signal has been wired.
    ///
    /// `is_indexed` is `true` for `comp.signal[i] <== expr` wirings;
    /// such wirings disable the scalar trigger path because the array
    /// isn't fully wired after a single element. The component must
    /// be flushed explicitly before its outputs are referenced.
    ///
    /// When `value` is a `Const`, the constant is recorded in
    /// `const_wired` for sub-template constant propagation.
    pub(super) fn mark_wired(
        &mut self,
        signal: String,
        value: Option<&CircuitExpr>,
        is_indexed: bool,
    ) {
        if let Some(CircuitExpr::Const(fc)) = value {
            self.const_wired.insert(signal.clone(), *fc);
        }
        self.state.mark(signal, is_indexed);
    }

    /// Returns `true` when all declared inputs have been wired AND
    /// no indexed wirings have been recorded — the two conditions
    /// the trigger path requires before inlining the component body.
    pub(super) fn is_ready_to_inline(&self) -> bool {
        self.state.is_ready(&self.input_signals)
    }

    /// Span of the template declaration. Used by flush + cleanup
    /// callers that don't have a wiring-statement span to attribute
    /// inline errors to.
    pub(super) fn template_span(&self) -> &diagnostics::Span {
        &self.template.span
    }

    /// Inline this pending component's body into `nodes`, propagating
    /// constants into `env`.
    ///
    /// Merges `const_wired` (recorded during `mark_wired`) with any
    /// constants found in already-emitted `Let`/`WitnessHint` nodes
    /// for this component (the indexed-wiring path stores constants
    /// in nodes rather than in `const_wired`).
    ///
    /// `span` is used for error attribution. Callers triggered from a
    /// wiring statement pass that statement's span; cleanup paths pass
    /// the template declaration's span.
    pub(super) fn inline_into(
        &self,
        comp_name: &str,
        nodes: &mut Vec<CircuitNode>,
        ctx: &mut LoweringContext<'a>,
        env: &mut LoweringEnv,
        span: &diagnostics::Span,
    ) -> Result<(), LoweringError> {
        let mut const_inputs = self.const_wired.clone();
        extract_const_inputs_from_nodes(comp_name, nodes, &mut const_inputs);
        let body = inline_component_body_with_const_inputs(
            comp_name,
            self.template,
            &self.template_args,
            &self.array_args,
            &const_inputs,
            ctx,
            span,
        )?;
        propagate_const_nodes(&body, env);
        nodes.extend(body);
        Ok(())
    }
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
        let span = comp.template_span().clone();
        comp.inline_into(comp_name, nodes, ctx, env, &span)?;
    }
    Ok(())
}

/// Scan existing nodes for Let/LetIndexed/WitnessHint/WitnessHintIndexed
/// with name `comp_name.signal_name` and constant values.
/// Extracts `signal_name → FieldConst` pairs.
///
/// For indexed nodes (e.g., `LetIndexed { array: "comp.base", index: Const(0), value: Const(fc) }`),
/// the element name is constructed as `base_0`.
fn extract_const_inputs_from_nodes(
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
fn propagate_const_nodes(nodes: &[CircuitNode], env: &mut LoweringEnv) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Block, TemplateDef, TemplateModifiers};
    use diagnostics::Span;
    use ir::prove_ir::types::FieldConst;

    fn dummy_span() -> Span {
        Span {
            byte_start: 0,
            byte_end: 0,
            line_start: 1,
            col_start: 1,
            line_end: 1,
            col_end: 1,
        }
    }

    fn dummy_template() -> TemplateDef {
        TemplateDef {
            name: "T".into(),
            params: vec![],
            modifiers: TemplateModifiers::default(),
            body: Block {
                stmts: vec![],
                span: dummy_span(),
            },
            span: dummy_span(),
        }
    }

    fn pending_with_inputs<'a>(template: &'a TemplateDef, inputs: &[&str]) -> PendingComponent<'a> {
        let input_signals: HashSet<String> = inputs.iter().map(|s| s.to_string()).collect();
        PendingComponent::new(template, vec![], HashMap::new(), input_signals)
    }

    #[test]
    fn new_initializes_to_all_scalar_empty() {
        let tmpl = dummy_template();
        let comp = pending_with_inputs(&tmpl, &["a", "b"]);
        assert!(matches!(&comp.state, WiringState::AllScalar { wired } if wired.is_empty()));
        assert!(comp.const_wired.is_empty());
        assert!(!comp.is_ready_to_inline());
    }

    #[test]
    fn scalar_only_path_reaches_ready_when_all_inputs_wired() {
        let tmpl = dummy_template();
        let mut comp = pending_with_inputs(&tmpl, &["a", "b"]);
        comp.mark_wired("a".into(), None, false);
        assert!(!comp.is_ready_to_inline());
        comp.mark_wired("b".into(), None, false);
        assert!(comp.is_ready_to_inline());
        assert!(matches!(comp.state, WiringState::AllScalar { .. }));
    }

    #[test]
    fn extra_scalar_wirings_beyond_inputs_still_ready() {
        let tmpl = dummy_template();
        let mut comp = pending_with_inputs(&tmpl, &["a"]);
        comp.mark_wired("a".into(), None, false);
        comp.mark_wired("extra".into(), None, false);
        assert!(comp.is_ready_to_inline());
    }

    #[test]
    fn indexed_wiring_disables_trigger_even_with_full_coverage() {
        let tmpl = dummy_template();
        let mut comp = pending_with_inputs(&tmpl, &["a", "b"]);
        comp.mark_wired("a".into(), None, true);
        comp.mark_wired("b".into(), None, false);
        assert!(!comp.is_ready_to_inline());
        assert!(matches!(comp.state, WiringState::PartialIndexed { .. }));
    }

    #[test]
    fn indexed_then_scalar_stays_partial_indexed() {
        let tmpl = dummy_template();
        let mut comp = pending_with_inputs(&tmpl, &["a", "b", "c"]);
        comp.mark_wired("a".into(), None, true);
        assert!(matches!(comp.state, WiringState::PartialIndexed { .. }));
        // Subsequent scalar wirings cannot revert the state.
        comp.mark_wired("b".into(), None, false);
        comp.mark_wired("c".into(), None, false);
        assert!(matches!(comp.state, WiringState::PartialIndexed { .. }));
        assert!(!comp.is_ready_to_inline());
    }

    #[test]
    fn const_value_is_recorded_in_const_wired() {
        let tmpl = dummy_template();
        let mut comp = pending_with_inputs(&tmpl, &["a"]);
        let fc = FieldConst::from_u64(42);
        comp.mark_wired("a".into(), Some(&CircuitExpr::Const(fc)), false);
        assert_eq!(comp.const_wired.get("a"), Some(&fc));
    }

    #[test]
    fn non_const_value_does_not_populate_const_wired() {
        let tmpl = dummy_template();
        let mut comp = pending_with_inputs(&tmpl, &["a"]);
        comp.mark_wired("a".into(), Some(&CircuitExpr::Var("x".into())), false);
        assert!(comp.const_wired.is_empty());
    }

    #[test]
    fn template_span_returns_template_declaration_span() {
        let tmpl = dummy_template();
        let comp = pending_with_inputs(&tmpl, &["a"]);
        assert_eq!(comp.template_span(), &tmpl.span);
    }
}
