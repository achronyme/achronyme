//! Tests for constraint pairing analysis.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `constraint_check/mod.rs`.

mod basics;
mod e102;
mod lhs_targets;
mod poly_accumulators;
mod warnings;

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
            d.message.contains(&format!(
                "signal `{}::{signal}` is assigned with `<--`",
                r.template_name
            ))
        })
    })
}

fn has_warning(reports: &[ConstraintReport], signal: &str) -> bool {
    reports.iter().any(|r| {
        r.diagnostics.iter().any(|d| {
            d.severity == diagnostics::Severity::Warning
                && d.message.contains(signal)
                && d.code.as_deref() == Some("W101")
        })
    })
}

fn has_w102(reports: &[ConstraintReport], signal: &str) -> bool {
    reports.iter().any(|r| {
        r.diagnostics.iter().any(|d| {
            d.severity == diagnostics::Severity::Warning
                && d.code.as_deref() == Some("W102")
                && d.message.contains(signal)
        })
    })
}

fn has_e102(reports: &[ConstraintReport]) -> bool {
    reports.iter().any(|r| {
        r.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E102"))
    })
}
