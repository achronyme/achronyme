//! [`ConstraintCollector`] — single-pass walker over a Circom template
//! body that records every fact the [`super::template::check_template`]
//! orchestrator needs to emit E100/E101/E102/W101/W102/W103.
//!
//! All public surface (struct, fields, `new`, `walk_stmts`) is
//! `pub(super)`; the per-statement walker stays private to this file.

use std::collections::{HashMap, HashSet};

use diagnostics::Span;

use crate::ast::*;
use super::expr_helpers::{
    collect_signal_refs, expr_signal_degree, extract_signal_name, is_quadratic_safe,
};

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
        }
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
                // `target <-- expr` — record as unconstrained
                if let Some(name) = extract_signal_name(target) {
                    self.unconstrained_assigns
                        .entry(name.clone())
                        .or_insert_with(|| span.clone());
                    // E101: track signal assignment
                    self.signal_assignments
                        .entry(name.clone())
                        .or_default()
                        .push(span.clone());
                    // W102: check if expression is quadratic (could use <==)
                    if is_quadratic_safe(value) {
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
                if let Some(name) = extract_signal_name(value) {
                    self.unconstrained_assigns
                        .entry(name.clone())
                        .or_insert_with(|| span.clone());
                    // E101: track signal assignment
                    self.signal_assignments
                        .entry(name.clone())
                        .or_default()
                        .push(span.clone());
                    // W102: check if expr (LHS) is quadratic (could use ==>)
                    if is_quadratic_safe(target) {
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
                // E101: track signal assignment
                if let Some(name) = extract_signal_name(target) {
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
                // E101: track signal assignment (target is on `value` side for reverse ops)
                if let Some(name) = extract_signal_name(target) {
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
            Stmt::For { body, .. } => self.walk_stmts(&body.stmts),
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => self.walk_stmts(&body.stmts),
            Stmt::Block(block) => self.walk_stmts(&block.stmts),
            // All other statements don't affect constraint tracking
            _ => {}
        }
    }
}
