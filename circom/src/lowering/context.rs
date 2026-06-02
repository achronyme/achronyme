//! Program-level lowering context.
//!
//! `LoweringContext` holds template and function definitions from the
//! parsed `CircomProgram`, enabling component instantiation (template
//! inlining) and function call inlining during lowering.

use std::collections::{HashMap, HashSet};

use ir_forge::types::{CircuitNode, FieldConst};

use crate::ast::{CircomProgram, Definition, FunctionDef, TemplateDef};

/// Maximum inlining depth to prevent infinite recursion from mutually
/// recursive templates or functions.
pub const MAX_INLINE_DEPTH: usize = 64;

/// Program-level context for template and function resolution.
///
/// Passed through the lowering pipeline so that component instantiations
/// can resolve their target template and function calls can be inlined.
pub struct LoweringContext<'a> {
    /// All template definitions, keyed by name.
    pub templates: HashMap<&'a str, &'a TemplateDef>,
    /// All function definitions, keyed by name.
    pub functions: HashMap<&'a str, &'a FunctionDef>,
    /// Current inlining depth (incremented on each component/function inline).
    pub inline_depth: usize,
    /// Template parameter values for the main template (e.g., n=3).
    /// Used to resolve component array sizes and unroll loops at lowering time.
    pub param_values: HashMap<String, FieldConst>,
    /// Bus type names declared in the program (for error detection).
    pub bus_names: HashSet<&'a str>,
    /// Counter for generating unique anonymous component names.
    anon_counter: usize,
    /// Cache of lowered template bodies (before mangling).
    ///
    /// Key: `template_name` for parameterless templates, or
    /// `template_name:param=val:...` for parameterized ones.
    /// Only entries with empty `const_inputs` and `array_args` are cached,
    /// since those guarantee identical lowered output.
    pub body_cache: HashMap<String, Vec<CircuitNode>>,
    /// Shared, unmangled template bodies promoted out of the parent
    /// body so a repeatedly-instantiated component is stored once and
    /// referenced by a small [`CircuitNode::ComponentCall`] per
    /// instance. Populated lazily on the first body-cache hit for a
    /// key (only keys an emitted `ComponentCall` references survive);
    /// transferred into `ProveIR::component_bodies` at end of
    /// lowering. Subset of [`Self::body_cache`].
    pub component_bodies: HashMap<String, Vec<CircuitNode>>,
    /// Per cached body, the constant outputs its eager inlining would
    /// have lifted into the parent env, captured once (in body-walk
    /// order, unmangled names) at the cache-miss that populated
    /// [`Self::body_cache`]. A deferred `ComponentCall` skips the
    /// per-instance scan of inlined nodes, so each hit replays this
    /// signature with the instance's mangle prefix instead — keeping
    /// emitted constraints identical to inlining while still deferring
    /// the body. Empty for bodies with no constant outputs (then the
    /// replay is a no-op and a hit behaves exactly like the
    /// no-constant-output case). Keyed like [`Self::body_cache`].
    pub body_const_outputs: HashMap<String, Vec<(String, FieldConst)>>,
    /// Side-channel for [`CircuitNode`]s produced during expression
    /// lowering that must land in the enclosing body *before* the
    /// statement whose expression emitted them. Populated by the
    /// Artik witness-call lift pass when it replaces E212; flushed
    /// by every statement-level lowering call before it pushes its
    /// own node.
    pub pending_nodes: Vec<CircuitNode>,
    /// R1″ for-loop body memoization: optional tracker that records
    /// the `[start, end)` ranges of `nodes` covered by pending-component
    /// flushes (i.e. emissions produced by `PendingComponent::inline_into`).
    /// When enabled, the for-loop unroller can subtract these ranges
    /// from an iteration's emission to obtain the "body-only" IR — the
    /// part that is uniform across iters and therefore memoizable.
    pub flush_tracker: FlushTracker,
    /// memoized unroll: when `Some((var_name, token))`, the
    /// expression lowering treats `Ident(var_name)` as the placeholder
    /// `CircuitExpr::LoopVar(token)` instead of either a const fold
    /// or an `env.resolve` lookup. The for-loop memoization unroller
    /// sets this around the iter-0 capture window so the loop variable
    /// flows through indexing/arithmetic as a symbolic node; the
    /// captured slice is then cloned + `substitute_loop_var`'d for each
    /// remaining iteration. Default `None` — outside the capture window
    /// the legacy unroll path drives the loop var through
    /// `env.known_constants` exactly as before, so existing behaviour
    /// is byte-identical.
    pub placeholder_loop_var: Option<(String, u32)>,
}

/// Records the IR-emission ranges produced by pending-component
/// flushes during a window of lowering. See `LoweringContext::flush_tracker`.
///
/// Disabled by default; the for-loop unroller turns it on around an
/// iteration capture and reads the recorded ranges back. Each entry is
/// a `(start, end)` half-open interval over the `nodes: Vec<CircuitNode>`
/// passed to `PendingComponent::inline_into` — the slice
/// `nodes[start..end]` is exactly the inlined component body.
///
/// Multiple flushes during the same window stack into `ranges` in the
/// order they fired. Empty flushes (`start == end`) are skipped.
#[derive(Default)]
pub struct FlushTracker {
    enabled: bool,
    ranges: Vec<(usize, usize)>,
}

impl FlushTracker {
    /// Turn on recording. Clears any previously recorded ranges.
    pub fn enable(&mut self) {
        self.enabled = true;
        self.ranges.clear();
    }

    /// Turn off recording and return the accumulated ranges, in the
    /// order they fired.
    pub fn take(&mut self) -> Vec<(usize, usize)> {
        self.enabled = false;
        std::mem::take(&mut self.ranges)
    }

    /// Record a flush range. No-op if recording is disabled or the
    /// range is empty.
    pub fn record(&mut self, start: usize, end: usize) {
        if self.enabled && start < end {
            self.ranges.push((start, end));
        }
    }

    /// `true` iff recording is currently turned on.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl<'a> LoweringContext<'a> {
    /// Build a context from a parsed Circom program.
    pub fn from_program(program: &'a CircomProgram) -> Self {
        let mut templates = HashMap::new();
        let mut functions = HashMap::new();
        let mut bus_names = HashSet::new();
        for def in &program.definitions {
            match def {
                Definition::Template(t) => {
                    templates.insert(t.name.as_str(), t);
                }
                Definition::Function(f) => {
                    functions.insert(f.name.as_str(), f);
                }
                Definition::Bus(b) => {
                    bus_names.insert(b.name.as_str());
                }
            }
        }
        Self {
            templates,
            functions,
            inline_depth: 0,
            param_values: HashMap::new(),
            bus_names,
            anon_counter: 0,
            body_cache: HashMap::new(),
            component_bodies: HashMap::new(),
            body_const_outputs: HashMap::new(),
            pending_nodes: Vec::new(),
            flush_tracker: FlushTracker::default(),
            placeholder_loop_var: None,
        }
    }

    /// Drain [`Self::pending_nodes`] into the caller's body. Call this
    /// from every statement-level lowering site, after lowering the
    /// statement's expressions and before pushing the statement's own
    /// node, so any witness-call side effects land in emission order.
    pub fn flush_pending_nodes(&mut self, nodes: &mut Vec<CircuitNode>) {
        if !self.pending_nodes.is_empty() {
            nodes.append(&mut self.pending_nodes);
        }
    }

    /// Generate a unique ID for an anonymous component.
    pub fn next_anon_id(&mut self) -> usize {
        let id = self.anon_counter;
        self.anon_counter += 1;
        id
    }

    /// Build a combined constants map from `param_values` and `env.known_constants`.
    ///
    /// Used by lowering functions that need to iterate over all constants or pass
    /// to expression evaluation. Prefer [`resolve_constant`] for single lookups.
    pub fn all_constants(&self, env: &super::env::LoweringEnv) -> HashMap<String, FieldConst> {
        let mut all = HashMap::with_capacity(
            self.param_values.len() + env.known_constants.len() + env.bound_const_vars.len(),
        );
        for (k, &v) in &self.param_values {
            all.insert(k.clone(), v);
        }
        for (k, &v) in &env.known_constants {
            all.entry(k.clone()).or_insert(v);
        }
        for (k, &v) in &env.bound_const_vars {
            all.entry(k.clone()).or_insert(v);
        }
        all
    }

    /// Look up a single constant by name without creating a merged HashMap.
    ///
    /// Checks `param_values` first (template params, precomputed vars),
    /// then `env.known_constants` (signals with known values). This avoids
    /// the allocation overhead of [`all_constants`] for simple lookups.
    ///
    /// **2-source.** Deliberately omits `env.bound_const_vars`. Use this
    /// only where a `bound_const_vars`-only name must NOT resolve (e.g.
    /// the index-fold fast path, which falls back to the full
    /// [`all_constants`] path on a miss so completeness is preserved).
    /// Where a miss has NO fallback and the result propagates into
    /// emitted constraints, use [`resolve_constant_with_bound`] instead.
    #[inline]
    pub fn resolve_constant(
        &self,
        name: &str,
        env: &super::env::LoweringEnv,
    ) -> Option<FieldConst> {
        self.param_values
            .get(name)
            .or_else(|| env.known_constants.get(name))
            .copied()
    }

    /// Look up a single constant by name across **all three** sources in
    /// the exact first-wins precedence of [`all_constants`]:
    /// `param_values > env.known_constants > env.bound_const_vars`
    /// (proven equivalent — `all_constants` inserts `param_values`
    /// unconditionally then `or_insert`s the other two in that order).
    ///
    /// Use this as the O(1) replacement for `all_constants().get(name)`
    /// on hot paths where a miss has no fallback and the resolved value
    /// propagates into emitted constraints (so dropping
    /// `bound_const_vars`, as [`resolve_constant`] would, is unsound).
    #[inline]
    pub fn resolve_constant_with_bound(
        &self,
        name: &str,
        env: &super::env::LoweringEnv,
    ) -> Option<FieldConst> {
        self.param_values
            .get(name)
            .or_else(|| env.known_constants.get(name))
            .or_else(|| env.bound_const_vars.get(name))
            .copied()
    }

    /// Create an empty context (for testing).
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            templates: HashMap::new(),
            functions: HashMap::new(),
            inline_depth: 0,
            body_cache: HashMap::new(),
            component_bodies: HashMap::new(),
            body_const_outputs: HashMap::new(),
            param_values: HashMap::new(),
            bus_names: HashSet::new(),
            anon_counter: 0,
            pending_nodes: Vec::new(),
            flush_tracker: FlushTracker::default(),
            placeholder_loop_var: None,
        }
    }

    /// If `name` matches the active R1″ memoization placeholder, return
    /// its token. The lowering paths that resolve identifiers (`Ident`,
    /// component-array index folding) consult this before the legacy
    /// const-fold / env-resolve chain to keep the loop variable
    /// symbolic during iter-0 capture.
    #[inline]
    pub fn placeholder_token_for(&self, name: &str) -> Option<u32> {
        match self.placeholder_loop_var.as_ref() {
            Some((var, token)) if var == name => Some(*token),
            _ => None,
        }
    }

    /// If `expr` is `Ident(name)` where `name` matches the active
    /// memoization placeholder, return the corresponding placeholder
    /// substring (e.g. `"$LV7$"`) suitable for embedding in component-
    /// array name mangling like `format!("{base}_{segment}")`. Returns
    /// `None` otherwise — the caller should fall back to the legacy
    /// numeric resolution path.
    ///
    /// Only handles the bare `Ident` form, not `Ident ± const`. The
    /// `is_memoizable` classifier in `lower_for_loop` is responsible
    /// for refusing to memoize loops whose component-array indices use
    /// shapes this method does not cover.
    pub fn placeholder_index_segment(&self, expr: &crate::ast::Expr) -> Option<String> {
        let (var, token) = self.placeholder_loop_var.as_ref()?;
        if let crate::ast::Expr::Ident { name, .. } = expr {
            if name == var {
                return Some(super::loop_var_subst::loop_var_placeholder(*token));
            }
        }
        None
    }

    /// `true` iff the active R1″ memoization placeholder loop variable
    /// appears anywhere inside `expr` — recursively walking through
    /// every sub-expression position. Used by index-lowering paths to
    /// decide whether the const-fold fast path is safe (no placeholder
    /// → fold; placeholder present → fall through to symbolic so the
    /// loop var stays as `LoopVar(token)` until late substitution).
    ///
    /// Returns `false` whenever `placeholder_loop_var` is `None`, so
    /// the predicate is a no-op outside the iter-0 capture window and
    /// preserves byte-for-byte legacy behaviour.
    ///
    /// Scope-blind by design: a `var i = …` shadow inside the body
    /// would falsely trigger the predicate, but the `is_memoizable`
    /// classifier in `lower_for_loop` rejects any body containing a
    /// bare-`Ident` substitution-assign upstream
    /// (`body_has_state_carrying_var_mutation` in
    /// `statements/loops.rs`), so shadowing cannot reach this path.
    /// If that gate ever loosens, this predicate becomes unsound.
    pub fn placeholder_appears_in(&self, expr: &crate::ast::Expr) -> bool {
        let Some((var, _)) = self.placeholder_loop_var.as_ref() else {
            return false;
        };
        expr_contains_ident(expr, var)
    }
}

fn expr_contains_ident(expr: &crate::ast::Expr, target: &str) -> bool {
    use crate::ast::Expr;
    match expr {
        Expr::Ident { name, .. } => name == target,
        Expr::BinOp { lhs, rhs, .. } => {
            expr_contains_ident(lhs, target) || expr_contains_ident(rhs, target)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_contains_ident(operand, target),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_contains_ident(condition, target)
                || expr_contains_ident(if_true, target)
                || expr_contains_ident(if_false, target)
        }
        Expr::Call { callee, args, .. } => {
            expr_contains_ident(callee, target)
                || args.iter().any(|a| expr_contains_ident(a, target))
        }
        Expr::AnonComponent {
            callee,
            template_args,
            signal_args,
            ..
        } => {
            expr_contains_ident(callee, target)
                || template_args.iter().any(|a| expr_contains_ident(a, target))
                || signal_args
                    .iter()
                    .any(|a| expr_contains_ident(&a.value, target))
        }
        Expr::Index { object, index, .. } => {
            expr_contains_ident(object, target) || expr_contains_ident(index, target)
        }
        Expr::DotAccess { object, .. } => expr_contains_ident(object, target),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(|e| expr_contains_ident(e, target))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
}

#[cfg(test)]
mod tests;
