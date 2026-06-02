use super::*;

/// Wiring progress for a pending component.
///
/// Two-state machine. The transition `AllScalar → PartialIndexed` is
/// monotonic — once an indexed wiring (`comp.signal[i] <== expr`) is
/// recorded, the trigger path is permanently disabled and the
/// component must be flushed explicitly before its outputs are
/// referenced. Encoding this as an enum (rather than a `wired:
/// HashSet + has_indexed: bool` pair) makes the "forgot to set
/// has_indexed" class of bug unrepresentable.
pub(in super::super) enum WiringState {
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
pub(in super::super) struct PendingComponent<'a> {
    template: &'a ast::TemplateDef,
    template_args: Vec<CircuitExpr>,
    /// Array template args (param_name → compile-time array value).
    array_args: HashMap<String, EvalValue>,
    input_signals: HashSet<String>,
    /// Wiring progress (which signals are wired + whether any wiring
    /// was indexed).
    pub(super) state: WiringState,
    /// Signal inputs wired to compile-time constants.
    ///
    /// Two key shapes:
    /// - Scalar wiring `comp.signal <== const_expr` records `signal → fc`.
    /// - Indexed wiring `comp.signal[idx] <== const_expr` records
    ///   `format!("{signal}_{idx}") → fc` (matching the layout that
    ///   `inline_component_body_*` reads via `env.known_constants`).
    ///
    /// When the component body is inlined, these are injected into the
    /// sub-template's `known_constants` so the lowerer emits `Const`
    /// instead of `Input`, enabling full constant propagation through
    /// Montgomery/MUX operations (Pedersen: 88→13 constraints).
    pub(super) const_wired: HashMap<String, FieldConst>,
}

impl<'a> PendingComponent<'a> {
    /// Build a pending component with no wirings recorded yet.
    ///
    /// Caller must ensure `input_signals` is non-empty — components
    /// with zero inputs are inlined immediately at declaration and
    /// never enter the pending map.
    pub(in super::super) fn new(
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
    /// For scalar wirings only, when `value` is a `Const`, the constant
    /// is recorded in `const_wired` for sub-template constant
    /// propagation. For indexed wirings the per-element constant is
    /// recorded separately via `record_indexed_const`, since the
    /// resolved index isn't part of the base signal name.
    pub(in super::super) fn mark_wired(
        &mut self,
        signal: String,
        value: Option<&CircuitExpr>,
        is_indexed: bool,
    ) {
        if !is_indexed {
            if let Some(CircuitExpr::Const(fc)) = value {
                self.const_wired.insert(signal.clone(), *fc);
            }
        }
        self.state.mark(signal, is_indexed);
    }

    /// Record a constant indexed wiring: `comp.signal_base[idx] <== fc`.
    ///
    /// Stored as `format!("{signal_base}_{idx}") → fc` so that
    /// `inline_component_body_with_const_inputs` can inject it into the
    /// sub-template's `known_constants` under the same key the indexed
    /// signal lookup uses.
    pub(in super::super) fn record_indexed_const(
        &mut self,
        signal_base: &str,
        idx: u64,
        fc: FieldConst,
    ) {
        self.const_wired.insert(format!("{signal_base}_{idx}"), fc);
    }

    /// Returns `true` when all declared inputs have been wired AND
    /// no indexed wirings have been recorded — the two conditions
    /// the trigger path requires before inlining the component body.
    pub(in super::super) fn is_ready_to_inline(&self) -> bool {
        self.state.is_ready(&self.input_signals)
    }

    /// Span of the template declaration. Used by flush + cleanup
    /// callers that don't have a wiring-statement span to attribute
    /// inline errors to.
    pub(in super::super) fn template_span(&self) -> &diagnostics::Span {
        &self.template.span
    }

    /// Inline this pending component's body into `nodes`, propagating
    /// constants into `env`.
    ///
    /// `const_wired` is the authoritative source of constant input
    /// values: scalar wirings populate it via `mark_wired`, indexed
    /// constant wirings via `record_indexed_const`. The substitution
    /// lowerer also stamps the corresponding `Let`/`LetIndexed` nodes
    /// into the parent vec, but those are for downstream consumers,
    /// not for re-discovery here.
    ///
    /// `span` is used for error attribution. Callers triggered from a
    /// wiring statement pass that statement's span; cleanup paths pass
    /// the template declaration's span.
    pub(in super::super) fn inline_into(
        &self,
        comp_name: &str,
        nodes: &mut Vec<CircuitNode>,
        ctx: &mut LoweringContext<'a>,
        env: &mut LoweringEnv,
        span: &diagnostics::Span,
    ) -> Result<(), LoweringError> {
        let body = inline_component_body_with_const_inputs(
            comp_name,
            self.template,
            &self.template_args,
            &self.array_args,
            &self.const_wired,
            ctx,
            span,
        )?;
        // Constant-output propagation lifts a component's constant
        // outputs into the parent env so downstream constraints that
        // consume them see `Const` rather than `Var`. The eager path
        // scans the freshly inlined (already mangled) nodes. A body
        // promoted to a single deferred `ComponentCall` has no inlined
        // nodes here; instead the constant outputs that scan would have
        // produced were captured once at cache time (unmangled,
        // body-walk order) and are replayed with this instance's mangle
        // prefix — yielding exactly the names and values the eager scan
        // would have inserted, so emitted constraints are identical
        // whether the body was inlined or deferred.
        match body.as_slice() {
            [CircuitNode::ComponentCall { body_key, .. }] => {
                if let Some(sig) = ctx.body_const_outputs.get(body_key.as_str()) {
                    let lifts: Vec<(String, FieldConst)> = sig
                        .iter()
                        .map(|(name, fc)| (mangle_name(comp_name, name), *fc))
                        .collect();
                    for (name, fc) in &lifts {
                        env.known_constants.insert(name.clone(), *fc);
                    }
                    // The signature preserves body-walk order with
                    // duplicates, so a later write to the same name
                    // shadows an earlier one — exactly as the eager
                    // scan's sequence of map inserts would. The
                    // post-replay invariant is therefore that every
                    // key holds its *last* signature value, not that
                    // every (possibly shadowed) entry is present.
                    debug_assert!(
                        {
                            let mut last: HashMap<&String, &FieldConst> = HashMap::new();
                            for (n, fc) in &lifts {
                                last.insert(n, fc);
                            }
                            last.iter()
                                .all(|(n, fc)| env.known_constants.get(n.as_str()) == Some(*fc))
                        },
                        "deferred const-output replay incomplete: a mangled \
                         output key is missing or holds the wrong (non-last) \
                         value after injection"
                    );
                }
            }
            _ => propagate_const_nodes(&body, env),
        }
        // R1″ flush tracking: `nodes[start..end]` after this `extend`
        // is exactly the inlined body. The for-loop unroller, when
        // capturing iter 0 for memoization, uses these ranges to
        // separate component flushes (scope cleanup that fires at
        // iter 0 because that's the first time outer-scope inputs
        // are wired) from the loop body's own work.
        let start = nodes.len();
        nodes.extend(body);
        let end = nodes.len();
        ctx.flush_tracker.record(start, end);
        Ok(())
    }
}
