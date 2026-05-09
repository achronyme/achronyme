//! Per-template orchestrator. [`check_template`] runs the
//! [`super::collector::ConstraintCollector`] over a template body
//! and folds the recorded state into the five diagnostic categories
//! (E100, W101, W102, W103, E102).

use std::path::PathBuf;

use diagnostics::{Diagnostic, Span, SpanRange};

use super::collector::ConstraintCollector;
use super::expr_helpers::span_to_range;
use super::ConstraintReport;
use crate::ast::{SignalType, TemplateDef};

/// Build a `SpanRange` for a span that lives inside the given template,
/// attaching the template's source `.circom` file when known so the
/// diagnostic renderer prints `path/to/file.circom:line:col` instead of
/// a bare `line:col` (the latter is unactionable when an `include` chain
/// has pulled the offending template in from a vendored library).
fn span_to_range_in(span: &Span, source_file: &Option<PathBuf>) -> SpanRange {
    let mut sr = span_to_range(span);
    if let Some(f) = source_file {
        sr = sr.with_file(f.clone());
    }
    sr
}

/// Format a signal name for messages as `Template::name` so users can
/// disambiguate among the dozens of `out` / `in` signals that real
/// circomlib templates declare.
fn qualified(template: &TemplateDef, name: &str) -> String {
    format!("{}::{name}", template.name)
}

pub(super) fn check_template(template: &TemplateDef) -> ConstraintReport {
    let mut collector = ConstraintCollector::new();
    collector.walk_stmts(&template.body.stmts);

    let mut diagnostics = Vec::new();
    let source_file = &template.source_file;

    // Find unconstrained signals: assigned via <-- but never in ===
    for (name, assign_span) in &collector.unconstrained_assigns {
        if !collector.constrained_signals.contains(name) {
            let span_range = span_to_range_in(assign_span, source_file);
            let qname = qualified(template, name);

            let diag = Diagnostic::error(
                format!("signal `{qname}` is assigned with `<--` but has no `===` constraint"),
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
            let qname = qualified(template, name);
            let diag = Diagnostic::warning(
                format!("signal `{qname}` is assigned more than once"),
                span_to_range_in(&spans[1], source_file),
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
                    let span_range = span_to_range_in(decl_span, source_file);
                    let qname = qualified(template, name);
                    let kind = match sig_type {
                        SignalType::Input => "input",
                        SignalType::Output => "output",
                        SignalType::Intermediate => "intermediate",
                    };
                    let diag = Diagnostic::warning(
                        format!("{kind} signal `{qname}` is not referenced in any constraint"),
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
        let qname = qualified(template, name);
        let diag = Diagnostic::warning(
            format!(
                "signal `{qname}` uses `<--` but the expression is quadratic — \
                 consider using `<==`"
            ),
            span_to_range_in(hint_span, source_file),
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
                "constraint expression in template `{}` has degree {degree} in signals, \
                 but R1CS requires degree ≤ 2",
                template.name
            ),
            span_to_range_in(eq_span, source_file),
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
