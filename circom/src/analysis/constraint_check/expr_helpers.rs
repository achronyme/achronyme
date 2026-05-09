//! Pure expression helpers used by [`super::collector::ConstraintCollector`]
//! and [`super::template::check_template`].
//!
//! These walk Circom AST [`Expr`] nodes to:
//!
//! - extract every signal name from an assignment target
//!   ([`extract_signal_names`]),
//! - collect every identifier reference in a constraint expression
//!   ([`collect_signal_refs`]),
//! - convert a parser [`Span`] into a diagnostic [`SpanRange`]
//!   ([`span_to_range`]),
//! - decide whether an expression could legally use `<==` instead of `<--`
//!   ([`is_quadratic_safe`], drives W102),
//! - compute the algebraic degree of an expression w.r.t. a set of signals
//!   ([`expr_signal_degree`], drives E102).
//!
//! All helpers are `pub(super)` — they are not part of the analysis
//! pass's public API.

use std::collections::HashSet;

use diagnostics::{Span, SpanRange};

use crate::ast::*;

/// Extract every signal name being assigned to by an `<--` / `<==` /
/// `==>` / `-->` target expression.
///
/// Returns a `Vec` so tuple-destructured targets (`(a, b) <-- expr;`)
/// surface every assigned signal — `Option<String>` would silently drop
/// every name except the first and let an unconstrained `<--` slip
/// past E100. Handles:
///
/// - `x` → `["x"]`
/// - `x[i]`, `x[i][j]` → `["x"]` (index stripped — line/col disambiguates)
/// - `c.out`, `c[i].out`, `c.out[i]` → `["c.out"]` (component-access
///   targets get a qualified name so a `c.out <-- v;` without a paired
///   `===` is no longer silently accepted)
/// - `(a, b)` → `["a", "b"]` (recursive — nested tuples flatten)
///
/// Returns an empty `Vec` for shapes that aren't valid assignment
/// targets in any circom syntax (literals, calls, etc.).
pub(super) fn extract_signal_names(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Ident { name, .. } => vec![name.clone()],
        Expr::Index { object, .. } => extract_signal_names(object),
        Expr::DotAccess { object, field, .. } => extract_signal_names(object)
            .into_iter()
            .map(|base| format!("{base}.{field}"))
            .collect(),
        Expr::Tuple { elements, .. } => elements.iter().flat_map(extract_signal_names).collect(),
        _ => Vec::new(),
    }
}

/// Collect all simple identifier references from an expression.
///
/// This walks the entire expression tree and adds any `Ident` names
/// to the set, which represents signals that are involved in constraints.
pub(super) fn collect_signal_refs(expr: &Expr, signals: &mut HashSet<String>) {
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
            // Also register the qualified `c.out` form so a `c.out <-- v`
            // target (tracked under the qualified name) matches a paired
            // `c.out === expr` constraint here. Without this, every legal
            // sub-template-output handwritten constraint would E100 after
            // we start tracking DotAccess targets in `<--`.
            for name in extract_signal_names(expr) {
                signals.insert(name);
            }
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
pub(super) fn span_to_range(span: &Span) -> SpanRange {
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
pub(super) fn is_quadratic_safe(expr: &Expr) -> bool {
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
pub(super) fn expr_signal_degree(expr: &Expr, signal_names: &HashSet<String>) -> u32 {
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
