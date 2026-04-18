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
//!
//! # Submodules
//!
//! - [`collector`] — single-pass walker that records every fact the
//!   per-template orchestrator needs (`pub(super)` API).
//! - [`expr_helpers`] — pure expression utilities (signal extraction,
//!   reference collection, quadratic-safe + algebraic-degree analysis).
//! - [`template`] — the per-template orchestrator that folds the
//!   collector's recorded state into E100/E101/E102/W101/W102/W103
//!   diagnostics.
//! - [`tests`] — test suite (only compiled under `#[cfg(test)]`).

mod collector;
mod expr_helpers;
mod template;

use diagnostics::Diagnostic;

use crate::ast::Definition;
use template::check_template;

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

#[cfg(test)]
mod tests;
