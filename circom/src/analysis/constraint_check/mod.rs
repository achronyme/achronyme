//! Constraint pairing analysis for Circom templates.
//!
//! Ensures every signal assigned via `<--` (unconstrained) has at least one
//! corresponding `===` constraint that references it. A bare `<--` without
//! `===` is the #1 source of ZK vulnerabilities (under-constrained signals).
//!
//! # Algorithm
//!
//! Per template:
//! 1. Walk the body collecting two sets:
//!    - `unconstrained`: signals assigned via `<--` (with their spans)
//!    - `constrained`: signals referenced in `===` constraint expressions
//! 2. Any signal in `unconstrained` but not in `constrained` is an error.
//!
//! Signals assigned via `<==` are always safe (assign + constraint in one op)
//! and are not tracked.

use std::collections::{HashMap, HashSet};

use diagnostics::{Diagnostic, Span, SpanRange};

use crate::ast::*;

/// Result of constraint analysis on a single template.
#[derive(Debug)]
pub struct ConstraintReport {
    /// Template name.
    pub template_name: String,
    /// Diagnostics for under-constrained signals.
    pub diagnostics: Vec<Diagnostic>,
}

/// Analyze all templates in a program for under-constrained signals.
pub fn check_constraints(definitions: &[Definition]) -> Vec<ConstraintReport> {
    let mut reports = Vec::new();
    for def in definitions {
        if let Definition::Template(template) = def {
            let report = check_template(template);
            if !report.diagnostics.is_empty() {
                reports.push(report);
            }
        }
    }
    reports
}

fn check_template(template: &TemplateDef) -> ConstraintReport {
    let mut collector = ConstraintCollector::new();
    collector.walk_stmts(&template.body.stmts);

    let mut diagnostics = Vec::new();

    // Find unconstrained signals: assigned via <-- but never in ===
    for (name, assign_span) in &collector.unconstrained_assigns {
        if !collector.constrained_signals.contains(name) {
            let span_range = span_to_range(assign_span);

            let diag = Diagnostic::error(
                format!("signal `{name}` is assigned with `<--` but has no `===` constraint"),
                span_range,
            )
            .with_code("E100")
            .with_note(
                "under-constrained signals are the #1 source of ZK vulnerabilities".to_string(),
            )
            .with_note("use `<==` for automatic constraint, or add an explicit `===`".to_string());

            diagnostics.push(diag);
        }
    }

    // W103: signal assigned more than once (warning, not error).
    // This can be a false positive for signals assigned in different
    // branches of an if-else (e.g., `out <== a` in if, `out <== b` in else).
    // Circom's official compiler allows this pattern.
    for (name, spans) in &collector.signal_assignments {
        if spans.len() > 1 {
            let diag = Diagnostic::warning(
                format!("signal `{name}` is assigned more than once"),
                span_to_range(&spans[1]),
            )
            .with_code("W103")
            .with_note("first assignment was here".to_string())
            .with_note(
                "this is valid if assignments are in different branches of an if-else".to_string(),
            );
            diagnostics.push(diag);
        }
    }

    // W101: input/output signals that don't appear in any constraint.
    // This is a strong indicator of an under-constrained circuit.
    for (name, (sig_type, decl_span)) in &collector.declared_signals {
        match sig_type {
            SignalType::Input | SignalType::Output => {
                if !collector.constrained_signals.contains(name) {
                    let span_range = span_to_range(decl_span);
                    let kind = match sig_type {
                        SignalType::Input => "input",
                        SignalType::Output => "output",
                        SignalType::Intermediate => "intermediate",
                    };
                    let diag = Diagnostic::warning(
                        format!("{kind} signal `{name}` is not referenced in any constraint"),
                        span_range,
                    )
                    .with_code("W101")
                    .with_note(format!(
                        "a {kind} signal that doesn't participate in constraints \
                         cannot be verified — a malicious prover can set it to any value"
                    ));
                    diagnostics.push(diag);
                }
            }
            SignalType::Intermediate => {
                // Intermediates not in constraints are less concerning
                // (they might be used only in <-- hints)
            }
        }
    }

    // W102: <-- with a quadratic-safe expression (could use <==).
    // Mirrors circom 2.0.8+ behavior: the #1 source of under-constrained bugs
    // is using <-- where <== would have been appropriate.
    for (name, hint_span) in &collector.quadratic_safe_hints {
        let diag = Diagnostic::warning(
            format!(
                "signal `{name}` uses `<--` but the expression is quadratic — \
                 consider using `<==`"
            ),
            span_to_range(hint_span),
        )
        .with_code("W102")
        .with_note("`<--` only computes the witness value without adding a constraint".to_string())
        .with_note(
            "if the expression is representable as an R1CS constraint, `<==` is safer".to_string(),
        );
        diagnostics.push(diag);
    }

    // E102: non-quadratic constraint expression (degree > 2).
    // R1CS requires constraints of the form A*B + C = 0 where A, B, C are linear.
    for (eq_span, degree) in &collector.non_quadratic_constraints {
        let diag = Diagnostic::error(
            format!(
                "constraint expression has degree {degree} in signals, \
                 but R1CS requires degree ≤ 2"
            ),
            span_to_range(eq_span),
        )
        .with_code("E102")
        .with_note(
            "R1CS constraints must be quadratic: expressible as A*B + C = 0 \
             where A, B, C are linear combinations of signals"
                .to_string(),
        )
        .with_note("split the expression into intermediate signals to reduce degree".to_string());
        diagnostics.push(diag);
    }

    ConstraintReport {
        template_name: template.name.clone(),
        diagnostics,
    }
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

struct ConstraintCollector {
    /// Signals assigned via `<--`, mapped to their assignment span.
    unconstrained_assigns: HashMap<String, Span>,
    /// Signals that appear in `===` constraint expressions.
    constrained_signals: HashSet<String>,
    /// Input/output signal declarations with their spans (for W101).
    declared_signals: HashMap<String, (SignalType, Span)>,
    /// All signal assignments (name → list of spans) for E101 double-assignment detection.
    signal_assignments: HashMap<String, Vec<Span>>,
    /// `<--` assignments where the RHS is quadratic-safe (W102).
    quadratic_safe_hints: Vec<(String, Span)>,
    /// `===` or `<==` constraints with non-quadratic degree (E102).
    non_quadratic_constraints: Vec<(Span, u32)>,
}

impl ConstraintCollector {
    fn new() -> Self {
        Self {
            unconstrained_assigns: HashMap::new(),
            constrained_signals: HashSet::new(),
            declared_signals: HashMap::new(),
            signal_assignments: HashMap::new(),
            quadratic_safe_hints: Vec::new(),
            non_quadratic_constraints: Vec::new(),
        }
    }

    fn walk_stmts(&mut self, stmts: &[Stmt]) {
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

/// Extract the simple signal name from an expression target.
///
/// Handles: `x`, `x[i]`, `x[i][j]` — returns `"x"` in all cases.
/// Does NOT handle `c.out` (component access) since component outputs
/// are constrained by the component's own template.
fn extract_signal_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        Expr::Index { object, .. } => extract_signal_name(object),
        _ => None,
    }
}

/// Collect all simple identifier references from an expression.
///
/// This walks the entire expression tree and adds any `Ident` names
/// to the set, which represents signals that are involved in constraints.
fn collect_signal_refs(expr: &Expr, signals: &mut HashSet<String>) {
    match expr {
        Expr::Ident { name, .. } => {
            signals.insert(name.clone());
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_signal_refs(lhs, signals);
            collect_signal_refs(rhs, signals);
        }
        Expr::UnaryOp { operand, .. } => {
            collect_signal_refs(operand, signals);
        }
        Expr::PostfixOp { operand, .. } => {
            collect_signal_refs(operand, signals);
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            collect_signal_refs(condition, signals);
            collect_signal_refs(if_true, signals);
            collect_signal_refs(if_false, signals);
        }
        Expr::Call { callee, args, .. } => {
            collect_signal_refs(callee, signals);
            for arg in args {
                collect_signal_refs(arg, signals);
            }
        }
        Expr::Index { object, index, .. } => {
            collect_signal_refs(object, signals);
            collect_signal_refs(index, signals);
        }
        Expr::DotAccess { object, .. } => {
            collect_signal_refs(object, signals);
        }
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            for e in elements {
                collect_signal_refs(e, signals);
            }
        }
        Expr::ParallelOp { operand, .. } => {
            collect_signal_refs(operand, signals);
        }
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            for arg in template_args {
                collect_signal_refs(arg, signals);
            }
            for arg in signal_args {
                collect_signal_refs(&arg.value, signals);
            }
        }
        Expr::PrefixOp { operand, .. } => {
            collect_signal_refs(operand, signals);
        }
        // Leaf nodes with no sub-expressions
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => {}
    }
}

/// Convert a parser `Span` to a diagnostic `SpanRange`.
fn span_to_range(span: &Span) -> SpanRange {
    SpanRange::from_span(span)
}

// ---------------------------------------------------------------------------
// W102: quadratic-safe expression check
// ---------------------------------------------------------------------------

/// Returns `true` if the expression is "quadratic-safe" — built only from
/// field arithmetic (`+`, `-`, `*`), constants, and identifiers.
///
/// If an expression is quadratic-safe, it can potentially be used with `<==`
/// instead of `<--`, which is safer because `<==` adds a constraint.
///
/// Expressions containing division, modulo, shifts, comparisons, function
/// calls, or other non-algebraic operations are NOT quadratic-safe and
/// legitimately require `<--`.
fn is_quadratic_safe(expr: &Expr) -> bool {
    match expr {
        Expr::Number { .. } | Expr::HexNumber { .. } | Expr::Ident { .. } => true,
        Expr::BinOp { op, lhs, rhs, .. } => {
            matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul)
                && is_quadratic_safe(lhs)
                && is_quadratic_safe(rhs)
        }
        Expr::UnaryOp { op, operand, .. } => {
            matches!(op, UnaryOp::Neg) && is_quadratic_safe(operand)
        }
        // Everything else: division, shifts, comparisons, calls, ternary,
        // array access, etc. — these require <-- for off-circuit computation.
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// E102: algebraic degree computation
// ---------------------------------------------------------------------------

/// Compute the algebraic degree of an expression with respect to signals.
///
/// Signals (names in `signal_names`) have degree 1. Constants and variables
/// (not in `signal_names`) have degree 0. Operations compose degrees:
/// - `a + b` → `max(deg(a), deg(b))`
/// - `a * b` → `deg(a) + deg(b)`
/// - `a ** n` → `deg(a) * n` (conservatively high if n unknown)
///
/// R1CS constraints require degree ≤ 2.
fn expr_signal_degree(expr: &Expr, signal_names: &HashSet<String>) -> u32 {
    match expr {
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => 0,
        Expr::Ident { name, .. } => {
            if signal_names.contains(name) {
                1
            } else {
                0
            }
        }
        Expr::BinOp { op, lhs, rhs, .. } => {
            let dl = expr_signal_degree(lhs, signal_names);
            let dr = expr_signal_degree(rhs, signal_names);
            match op {
                BinOp::Add | BinOp::Sub => dl.max(dr),
                BinOp::Mul => dl + dr,
                BinOp::Div | BinOp::IntDiv | BinOp::Mod => {
                    // Division by a known value doesn't increase degree.
                    // Division by a signal is non-standard but treat conservatively.
                    if dr == 0 {
                        dl
                    } else {
                        dl + 1
                    }
                }
                BinOp::Pow => {
                    // x^n: if base has signals, degree grows multiplicatively.
                    // We can't always determine n statically, so be conservative.
                    if dl == 0 {
                        0
                    } else {
                        // Try to extract constant exponent
                        if let Some(n) = extract_const_u32(rhs) {
                            dl * n
                        } else {
                            // Unknown exponent with signal base → assume high degree
                            3
                        }
                    }
                }
                // Comparison, boolean, bitwise: these produce 0/1 values.
                // They don't directly increase algebraic degree of the result.
                _ => dl.max(dr),
            }
        }
        Expr::UnaryOp { operand, .. } => expr_signal_degree(operand, signal_names),
        Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            expr_signal_degree(operand, signal_names)
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let dc = expr_signal_degree(condition, signal_names);
            let dt = expr_signal_degree(if_true, signal_names);
            let df = expr_signal_degree(if_false, signal_names);
            dc.max(dt).max(df)
        }
        Expr::Call { args, .. } => {
            // Function calls: conservatively take max of argument degrees.
            args.iter()
                .map(|a| expr_signal_degree(a, signal_names))
                .max()
                .unwrap_or(0)
        }
        Expr::Index { object, .. } => expr_signal_degree(object, signal_names),
        Expr::DotAccess { object, .. } => expr_signal_degree(object, signal_names),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => elements
            .iter()
            .map(|e| expr_signal_degree(e, signal_names))
            .max()
            .unwrap_or(0),
        Expr::ParallelOp { operand, .. } => expr_signal_degree(operand, signal_names),
        Expr::AnonComponent { .. } => 0,
    }
}

/// Try to extract a small constant from a number literal expression.
fn extract_const_u32(expr: &Expr) -> Option<u32> {
    if let Expr::Number { value, .. } = expr {
        value.parse::<u32>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
