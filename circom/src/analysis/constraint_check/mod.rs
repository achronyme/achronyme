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

mod collector;
mod expr_helpers;

use diagnostics::Diagnostic;

use crate::ast::*;
use collector::ConstraintCollector;
use expr_helpers::span_to_range;

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

#[cfg(test)]
mod tests;
