//! [`ConstraintCollector`] — single-pass walker over a Circom template
//! body that records every fact the [`super::template::check_template`]
//! orchestrator needs to emit E100/E101/E102/W101/W102/W103.
//!
//! All public surface (struct, fields, `new`, `walk_stmts`) is
//! `pub(super)`; the per-statement walker stays private to this file.

use std::collections::{HashMap, HashSet};

use diagnostics::Span;

use super::expr_helpers::{
    collect_signal_refs, expr_signal_degree, extract_signal_names, is_quadratic_safe,
};
use crate::ast::*;

pub(super) struct ConstraintCollector {
    /// Signals assigned via `<--`, mapped to their assignment span.
    pub(super) unconstrained_assigns: HashMap<String, Span>,
    /// Signals that appear in `===` constraint expressions.
    pub(super) constrained_signals: HashSet<String>,
    /// Input/output signal declarations with their spans (for W101).
    pub(super) declared_signals: HashMap<String, (SignalType, Span)>,
    /// All signal assignments (name → list of spans) for E101 double-assignment detection.
    pub(super) signal_assignments: HashMap<String, Vec<Span>>,
    /// `<--` assignments where the RHS is quadratic-safe (W102).
    pub(super) quadratic_safe_hints: Vec<(String, Span)>,
    /// `===` or `<==` constraints with non-quadratic degree (E102).
    pub(super) non_quadratic_constraints: Vec<(Span, u32)>,
    /// Names declared via `var` in this template body (any nesting).
    /// Used by [`Self::expand_var_refs`] to recognise compile-time
    /// accumulators on the constraint side and harvest the signals
    /// they aggregate over.
    pub(super) var_names: HashSet<String>,
    /// For each `var` name, the set of identifiers referenced by any
    /// of its assignment RHSs (declaration init, plain `=`, compound
    /// `+=` / `*=` / etc.). Populated as the walker visits each
    /// assignment; the closure to *only signal names* happens later
    /// in [`Self::expand_var_refs`].
    pub(super) var_signal_deps: HashMap<String, HashSet<String>>,
}

impl ConstraintCollector {
    pub(super) fn new() -> Self {
        Self {
            unconstrained_assigns: HashMap::new(),
            constrained_signals: HashSet::new(),
            declared_signals: HashMap::new(),
            signal_assignments: HashMap::new(),
            quadratic_safe_hints: Vec::new(),
            non_quadratic_constraints: Vec::new(),
            var_names: HashSet::new(),
            var_signal_deps: HashMap::new(),
        }
    }

    /// Record every identifier referenced in `expr` as a dependency of
    /// the var named `var_name`. Idempotent — repeated visits to the
    /// same var (loop-body re-assignment) accumulate.
    fn record_var_deps(&mut self, var_name: &str, expr: &Expr) {
        let mut refs = HashSet::new();
        collect_signal_refs(expr, &mut refs);
        if !refs.is_empty() {
            self.var_signal_deps
                .entry(var_name.to_string())
                .or_default()
                .extend(refs);
        }
    }

    /// Closure pass that the per-template orchestrator runs after the
    /// statement walk. Two responsibilities:
    ///
    /// 1. **Transitive var-deps** — `var P` aggregating `var Q`
    ///    inherits Q's signal references. Iterates to fixpoint.
    /// 2. **Constraint-side expansion** — every name in
    ///    `constrained_signals` that is itself a var name brings in
    ///    its (now-closed) signal deps. After this, `constrained_
    ///    signals` covers signals that are pinned indirectly through
    ///    `var P[i] === expr` constraints (e.g. the polynomial-
    ///    fingerprint pattern in `BigMultNoCarry`'s bigint multiplier).
    ///
    /// The relaxation of E100 is bounded: a var only contributes
    /// signals if it actually has assignments referencing them. A
    /// declared-but-unassigned `var P[N];` adds nothing.
    ///
    /// **Branch fan-out** — assignments inside `if (cond) {...} else {...}`
    /// are unioned across both arms. The strict semantics would AND
    /// the deps (only signals appearing in both arms), which would
    /// catch the asymmetric case `if (c) { p = a; } else { p = b; }`
    /// where a single constraint on `p` only pins one of `a` or `b`
    /// at lower-time. This validator chooses the looser union
    /// semantics so the polynomial-fingerprint shape (which always
    /// fans the same signal across both arms in practice) clears
    /// cleanly; the asymmetric case is a known niche under-approximation.
    pub(super) fn expand_var_refs(&mut self) {
        // 1. Close var_signal_deps transitively.
        loop {
            let mut changed = false;
            let snapshot: Vec<(String, HashSet<String>)> = self
                .var_signal_deps
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (var_name, deps) in &snapshot {
                let mut additions: HashSet<String> = HashSet::new();
                for dep in deps {
                    if self.var_names.contains(dep) {
                        if let Some(inner) = self.var_signal_deps.get(dep) {
                            for inner_dep in inner {
                                if !deps.contains(inner_dep) {
                                    additions.insert(inner_dep.clone());
                                }
                            }
                        }
                    }
                }
                if !additions.is_empty() {
                    self.var_signal_deps
                        .entry(var_name.clone())
                        .or_default()
                        .extend(additions);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        // 2. Expand constrained_signals through any var ref it touches.
        let mut additions: HashSet<String> = HashSet::new();
        for name in &self.constrained_signals {
            if let Some(deps) = self.var_signal_deps.get(name) {
                additions.extend(deps.iter().cloned());
            }
        }
        self.constrained_signals.extend(additions);
    }

    pub(super) fn walk_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.walk_stmt(stmt);
        }
    }

    fn walk_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Substitution {
                target,
                value,
                op: AssignOp::SignalAssign,
                span,
            } => {
                // `target <-- expr` — every assigned signal is unconstrained
                // until proven otherwise. `extract_signal_names` returns a
                // `Vec` so tuple-destructured targets `(a, b) <-- expr;`
                // surface every assigned name (otherwise the second through
                // Nth signals would slip past E100 silently).
                let names = extract_signal_names(target);
                let safe = is_quadratic_safe(value);
                for name in names {
                    self.unconstrained_assigns
                        .entry(name.clone())
                        .or_insert_with(|| span.clone());
                    // E101: track signal assignment
                    self.signal_assignments
                        .entry(name.clone())
                        .or_default()
                        .push(span.clone());
                    // W102: check if expression is quadratic (could use <==)
                    if safe {
                        self.quadratic_safe_hints.push((name, span.clone()));
                    }
                }
            }
            Stmt::Substitution {
                target,
                value,
                op: AssignOp::RSignalAssign,
                span,
            } => {
                // `expr --> signal` — the signal being assigned is on the right (value side)
                let names = extract_signal_names(value);
                let safe = is_quadratic_safe(target);
                for name in names {
                    self.unconstrained_assigns
                        .entry(name.clone())
                        .or_insert_with(|| span.clone());
                    // E101: track signal assignment
                    self.signal_assignments
                        .entry(name.clone())
                        .or_default()
                        .push(span.clone());
                    // W102: check if expr (LHS) is quadratic (could use ==>)
                    if safe {
                        self.quadratic_safe_hints.push((name, span.clone()));
                    }
                }
            }
            Stmt::ConstraintEq { lhs, rhs, span } => {
                // `lhs === rhs` — collect all signal names referenced
                collect_signal_refs(lhs, &mut self.constrained_signals);
                collect_signal_refs(rhs, &mut self.constrained_signals);
                // E102: check that constraint degree ≤ 2
                let signal_set: HashSet<String> = self.declared_signals.keys().cloned().collect();
                let degree =
                    expr_signal_degree(lhs, &signal_set).max(expr_signal_degree(rhs, &signal_set));
                if degree > 2 {
                    self.non_quadratic_constraints.push((span.clone(), degree));
                }
            }
            Stmt::Substitution {
                op: AssignOp::ConstraintAssign,
                target,
                value,
                span,
            } => {
                // `target <== expr` — both target and expr are in constraints
                collect_signal_refs(target, &mut self.constrained_signals);
                collect_signal_refs(value, &mut self.constrained_signals);
                // E101: track signal assignment for every name on the LHS
                // (handles tuple-destructured `(a, b) <== ...`).
                for name in extract_signal_names(target) {
                    self.signal_assignments
                        .entry(name)
                        .or_default()
                        .push(span.clone());
                }
                // E102: check that constraint degree ≤ 2
                let signal_set: HashSet<String> = self.declared_signals.keys().cloned().collect();
                let degree = expr_signal_degree(value, &signal_set);
                if degree > 2 {
                    self.non_quadratic_constraints.push((span.clone(), degree));
                }
            }
            Stmt::Substitution {
                op: AssignOp::RConstraintAssign,
                target,
                value,
                span,
            } => {
                // `expr ==> target` — both sides are in constraints
                collect_signal_refs(target, &mut self.constrained_signals);
                collect_signal_refs(value, &mut self.constrained_signals);
                // E101: track signal assignment for every name in the
                // assigned position (target is on `value` side for reverse ops).
                for name in extract_signal_names(target) {
                    self.signal_assignments
                        .entry(name)
                        .or_default()
                        .push(span.clone());
                }
            }
            Stmt::SignalDecl {
                signal_type,
                declarations,
                init: Some((AssignOp::ConstraintAssign, value)),
                span,
                ..
            } => {
                // `signal c <== expr` — constrains the signal and all refs in expr
                for decl in declarations {
                    self.constrained_signals.insert(decl.name.clone());
                }
                collect_signal_refs(value, &mut self.constrained_signals);
                // Track the signal declaration
                for decl in declarations {
                    self.declared_signals
                        .entry(decl.name.clone())
                        .or_insert((*signal_type, span.clone()));
                    // E101: track signal assignment
                    self.signal_assignments
                        .entry(decl.name.clone())
                        .or_default()
                        .push(span.clone());
                }
                // E102: check that constraint degree ≤ 2
                let signal_set: HashSet<String> = self.declared_signals.keys().cloned().collect();
                let degree = expr_signal_degree(value, &signal_set);
                if degree > 2 {
                    self.non_quadratic_constraints.push((span.clone(), degree));
                }
            }
            Stmt::SignalDecl {
                signal_type,
                declarations,
                init: Some((AssignOp::SignalAssign, value)),
                span,
                ..
            } => {
                // `signal c <-- expr` — unconstrained inline init
                for decl in declarations {
                    self.declared_signals
                        .entry(decl.name.clone())
                        .or_insert((*signal_type, span.clone()));
                    // Track as unconstrained (fixes E100 for inline <-- init)
                    self.unconstrained_assigns
                        .entry(decl.name.clone())
                        .or_insert_with(|| span.clone());
                    // E101: track signal assignment
                    self.signal_assignments
                        .entry(decl.name.clone())
                        .or_default()
                        .push(span.clone());
                    // W102: check if expression is quadratic (could use <==)
                    if is_quadratic_safe(value) {
                        self.quadratic_safe_hints
                            .push((decl.name.clone(), span.clone()));
                    }
                }
            }
            Stmt::SignalDecl {
                signal_type,
                declarations,
                span,
                ..
            } => {
                // Track all signal declarations for W101
                for decl in declarations {
                    self.declared_signals
                        .entry(decl.name.clone())
                        .or_insert((*signal_type, span.clone()));
                }
            }
            Stmt::VarDecl { names, init, .. } => {
                // Register every declared `var` so the constraint-side
                // closure can recognise these names as compile-time
                // accumulators rather than signals. Multi-decl forms
                // (`var a, b;`) register each name; tuple-destructuring
                // (`var (a, b) = expr;`) does the same.
                for name in names {
                    self.var_names.insert(name.clone());
                }
                // If there is an init, every signal it references
                // becomes a dependency of every var being declared on
                // this line. For the common scalar case this collapses
                // to "name → refs(init)"; tuple destructure is rare
                // enough that fan-out is fine.
                if let Some(init_expr) = init {
                    for name in names {
                        self.record_var_deps(name, init_expr);
                    }
                }
            }
            Stmt::Substitution {
                target,
                value,
                op: AssignOp::Assign,
                ..
            } => {
                // Plain `=` assignment. The only kind that's of interest
                // here is one whose target's base name is a tracked
                // var: `P[i] = ...`, `P = ...`. extract_signal_names
                // returns the base names ("P" from "P[i]"), so a
                // var-typed target lands in var_names.
                for name in extract_signal_names(target) {
                    if self.var_names.contains(&name) {
                        self.record_var_deps(&name, value);
                    }
                }
            }
            Stmt::CompoundAssign { target, value, .. } => {
                // `P[i] += expr` etc. — same routing as plain assign
                // above; the LHS reads-and-writes the var, so the RHS
                // signals also become deps.
                for name in extract_signal_names(target) {
                    if self.var_names.contains(&name) {
                        self.record_var_deps(&name, value);
                    }
                }
            }
            // Recurse into nested blocks
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                self.walk_stmts(&then_body.stmts);
                if let Some(else_branch) = else_body {
                    match else_branch {
                        ElseBranch::Block(block) => self.walk_stmts(&block.stmts),
                        ElseBranch::IfElse(if_else) => self.walk_stmt(if_else),
                    }
                }
            }
            Stmt::For {
                init, step, body, ..
            } => {
                // Walk init + step so loop-local var declarations
                // register in `var_names`. Without this, `for (var i =
                // 0; ...; i++)` leaves `i` unknown to the var pass —
                // harmless for loop counters, but a `for (var sum = 0;
                // ...; sum += signal[k])` accumulator would be invisible.
                self.walk_stmt(init);
                self.walk_stmts(&body.stmts);
                self.walk_stmt(step);
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => self.walk_stmts(&body.stmts),
            Stmt::Block(block) => self.walk_stmts(&block.stmts),
            // All other statements don't affect constraint tracking
            _ => {}
        }
    }
}
