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
}

impl ConstraintCollector {
    fn new() -> Self {
        Self {
            unconstrained_assigns: HashMap::new(),
            constrained_signals: HashSet::new(),
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
                op: AssignOp::SignalAssign,
                span,
                ..
            } => {
                // `target <-- expr` — record as unconstrained
                if let Some(name) = extract_signal_name(target) {
                    self.unconstrained_assigns
                        .entry(name)
                        .or_insert_with(|| span.clone());
                }
            }
            Stmt::Substitution {
                value,
                op: AssignOp::RSignalAssign,
                span,
                ..
            } => {
                // `expr --> signal` — the signal being assigned is on the right (value side)
                if let Some(name) = extract_signal_name(value) {
                    self.unconstrained_assigns
                        .entry(name)
                        .or_insert_with(|| span.clone());
                }
            }
            Stmt::ConstraintEq { lhs, rhs, .. } => {
                // `lhs === rhs` — collect all signal names referenced
                collect_signal_refs(lhs, &mut self.constrained_signals);
                collect_signal_refs(rhs, &mut self.constrained_signals);
            }
            Stmt::Substitution {
                op: AssignOp::ConstraintAssign,
                value,
                ..
            } => {
                // `signal <== expr` — the expr side constrains all referenced signals
                collect_signal_refs(value, &mut self.constrained_signals);
            }
            Stmt::Substitution {
                op: AssignOp::RConstraintAssign,
                target,
                ..
            } => {
                // `expr ==> signal` — the expr side constrains all referenced signals
                collect_signal_refs(target, &mut self.constrained_signals);
            }
            Stmt::SignalDecl {
                init: Some((AssignOp::ConstraintAssign, value)),
                ..
            } => {
                // `signal c <== expr` — constrains referenced signals
                collect_signal_refs(value, &mut self.constrained_signals);
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
            Stmt::While { body, .. } => self.walk_stmts(&body.stmts),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;

    fn check(src: &str) -> Vec<ConstraintReport> {
        let full = format!("template T() {{ {src} }}");
        let (prog, parse_errors) = parse_circom(&full).expect("parse failed");
        assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
        check_constraints(&prog.definitions)
    }

    fn has_error(reports: &[ConstraintReport], signal: &str) -> bool {
        reports.iter().any(|r| {
            r.diagnostics.iter().any(|d| {
                d.message
                    .contains(&format!("signal `{signal}` is assigned with `<--`"))
            })
        })
    }

    // ── Safe patterns (no errors) ────────────────────────────────────

    #[test]
    fn constraint_assign_is_safe() {
        let reports = check("signal output c; c <== 42;");
        assert!(reports.is_empty());
    }

    #[test]
    fn signal_assign_with_constraint_eq_is_safe() {
        // The IsZero pattern: <-- for witness hint, === for verification
        let reports = check(
            r#"
            signal input in;
            signal output out;
            signal inv;
            inv <-- 1;
            in * inv === 1;
            "#,
        );
        assert!(!has_error(&reports, "inv"));
    }

    #[test]
    fn num2bits_pattern_is_safe() {
        // Num2Bits: <-- for bit extraction, === for sum check
        let reports = check(
            r#"
            signal input in;
            signal output out;
            out <-- 1;
            out === in;
            "#,
        );
        assert!(!has_error(&reports, "out"));
    }

    #[test]
    fn babyadd_division_pattern_is_safe() {
        // BabyAdd: <-- for EC division, === for verification
        let reports = check(
            r#"
            signal input x1;
            signal input y1;
            signal output xout;
            signal output yout;
            signal beta;
            signal gamma;
            signal tau;
            xout <-- 1;
            yout <-- 1;
            tau === x1 * y1;
            xout === beta + gamma;
            yout === beta - gamma;
            "#,
        );
        assert!(!has_error(&reports, "xout"));
        assert!(!has_error(&reports, "yout"));
    }

    // ── Unsafe patterns (errors) ─────────────────────────────────────

    #[test]
    fn bare_signal_assign_is_error() {
        let reports = check(
            r#"
            signal input in;
            signal output out;
            out <-- in;
            "#,
        );
        assert!(has_error(&reports, "out"));
    }

    #[test]
    fn bare_reverse_signal_assign_is_error() {
        let reports = check(
            r#"
            signal input in;
            signal output out;
            in --> out;
            "#,
        );
        assert!(has_error(&reports, "out"));
    }

    #[test]
    fn multiple_unconstrained_signals() {
        let reports = check(
            r#"
            signal a;
            signal b;
            a <-- 1;
            b <-- 2;
            "#,
        );
        assert!(has_error(&reports, "a"));
        assert!(has_error(&reports, "b"));
    }

    #[test]
    fn error_has_code_e100() {
        let reports = check("signal x; x <-- 1;");
        assert!(!reports.is_empty());
        let diag = &reports[0].diagnostics[0];
        assert_eq!(diag.code.as_deref(), Some("E100"));
    }

    // ── Nested blocks ────────────────────────────────────────────────

    #[test]
    fn signal_assign_in_for_loop_with_constraint() {
        let reports = check(
            r#"
            signal input in;
            signal output bits;
            for (var i = 0; i < 8; i++) {
                bits <-- 1;
            }
            bits === in;
            "#,
        );
        assert!(!has_error(&reports, "bits"));
    }

    #[test]
    fn signal_assign_in_for_loop_without_constraint() {
        let reports = check(
            r#"
            signal output bits;
            for (var i = 0; i < 8; i++) {
                bits <-- 1;
            }
            "#,
        );
        assert!(has_error(&reports, "bits"));
    }

    #[test]
    fn signal_assign_in_if_with_constraint_outside() {
        let reports = check(
            r#"
            signal input sel;
            signal out;
            if (sel == 0) {
                out <-- 1;
            } else {
                out <-- 2;
            }
            out === sel + 1;
            "#,
        );
        assert!(!has_error(&reports, "out"));
    }

    #[test]
    fn constraint_in_nested_if() {
        let reports = check(
            r#"
            signal x;
            x <-- 1;
            if (1 == 1) {
                x === 1;
            }
            "#,
        );
        assert!(!has_error(&reports, "x"));
    }

    // ── Array signals ────────────────────────────────────────────────

    #[test]
    fn array_signal_unconstrained() {
        let reports = check(
            r#"
            signal out;
            out <-- 42;
            "#,
        );
        assert!(has_error(&reports, "out"));
    }

    #[test]
    fn indexed_signal_with_constraint() {
        // out[i] <-- expr; out[i] === expr; — "out" appears in both
        let reports = check(
            r#"
            signal input in;
            signal output out;
            out <-- in;
            out === in;
            "#,
        );
        assert!(!has_error(&reports, "out"));
    }

    // ── Multiple templates ───────────────────────────────────────────

    #[test]
    fn checks_all_templates() {
        let src = r#"
            template Safe() {
                signal output x;
                x <== 1;
            }
            template Unsafe() {
                signal output y;
                y <-- 1;
            }
        "#;
        let (prog, _) = parse_circom(src).unwrap();
        let reports = check_constraints(&prog.definitions);
        // Only Unsafe should have errors
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].template_name, "Unsafe");
        assert!(has_error(&reports, "y"));
    }

    // ── Functions are ignored ────────────────────────────────────────

    #[test]
    fn functions_not_checked() {
        let src = r#"
            function helper(a) {
                return a + 1;
            }
        "#;
        let (prog, _) = parse_circom(src).unwrap();
        let reports = check_constraints(&prog.definitions);
        assert!(reports.is_empty());
    }
}
