//! R1″ Phase 4: detect a top-level `if (loop_var <op> k) { ... } else { ... }`
//! pattern in a for-loop body.
//!
//! When a body contains exactly that shape, the body's emission is
//! uniform within `[start, boundary)` and uniform within
//! `[boundary, end)`, but differs between the two ranges. R1″
//! memoization captures both groups separately — one substituted
//! template for the lower range, one for the upper range.
//!
//! This module is pure AST analysis. It does not lower anything; the
//! actual two-capture partition is wired in Phase 6.

use crate::ast::{BinOp, Expr, Stmt};

use super::utils::const_eval_u64;

/// A detected branch-flip pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchFlip {
    /// The boundary value. Iterations split into:
    /// - `[start, boundary)` — the "lower range"
    /// - `[boundary, end)` — the "upper range"
    pub boundary: u64,
    /// `true`  ⇒ the *then-branch* lowers the lower range
    ///           (e.g. `if (i < k)` → then-body fires for i < k).
    /// `false` ⇒ the *then-branch* lowers the upper range
    ///           (e.g. `if (i >= k)` → then-body fires for i >= k).
    ///
    /// The else-branch always lowers the opposite range.
    pub then_covers_lower_range: bool,
}

/// Scan `stmts` for a top-level `if (loop_var <op> k) { ... } else { ... }`
/// where `<op>` is `<`, `<=`, `>`, or `>=`, and `k` is a compile-time
/// `u64` literal. Returns the FIRST match.
///
/// Conditions handled (every form maps to a single boundary):
/// | Condition       | boundary | then_covers_lower_range |
/// |-----------------|---------:|-------------------------|
/// | `loop_var < k`  | `k`      | true                    |
/// | `loop_var <= k` | `k + 1`  | true                    |
/// | `loop_var > k`  | `k + 1`  | false                   |
/// | `loop_var >= k` | `k`      | false                   |
/// | `k < loop_var`  | `k + 1`  | false (then = upper)    |
/// | `k <= loop_var` | `k`      | false                   |
/// | `k > loop_var`  | `k`      | true                    |
/// | `k >= loop_var` | `k + 1`  | true                    |
///
/// Returns `None` if:
/// - no top-level `IfElse` is present;
/// - the condition is not a `<`/`<=`/`>`/`>=` comparison;
/// - neither side of the comparison is the loop variable;
/// - the constant side does not const-evaluate to `u64`;
/// - the `else_body` is `None` (the partition needs both sides);
/// - `boundary + 1` overflows `u64` (saturated forms aren't useful here).
///
/// **Single-flip scope.** Multi-boundary patterns
/// (`if (i < 16) {...} else if (i < 32) {...}`) only return the
/// outermost boundary. Phase 4 explicitly targets the SHA-256
/// message-schedule shape (one if-else split). Multi-partition is
/// future work.
pub fn detect_branch_flip(stmts: &[Stmt], loop_var: &str) -> Option<BranchFlip> {
    for stmt in stmts {
        if let Stmt::IfElse {
            condition,
            else_body: Some(_),
            ..
        } = stmt
        {
            if let Some(flip) = analyze_cond(condition, loop_var) {
                return Some(flip);
            }
        }
    }
    None
}

fn analyze_cond(cond: &Expr, loop_var: &str) -> Option<BranchFlip> {
    let Expr::BinOp { op, lhs, rhs, .. } = cond else {
        return None;
    };

    // Pattern 1: `loop_var <op> const`
    if let Expr::Ident { name, .. } = lhs.as_ref() {
        if name == loop_var {
            let k = const_eval_u64(rhs)?;
            return match op {
                BinOp::Lt => Some(BranchFlip {
                    boundary: k,
                    then_covers_lower_range: true,
                }),
                BinOp::Le => Some(BranchFlip {
                    boundary: k.checked_add(1)?,
                    then_covers_lower_range: true,
                }),
                BinOp::Gt => Some(BranchFlip {
                    boundary: k.checked_add(1)?,
                    then_covers_lower_range: false,
                }),
                BinOp::Ge => Some(BranchFlip {
                    boundary: k,
                    then_covers_lower_range: false,
                }),
                _ => None,
            };
        }
    }

    // Pattern 2: `const <op> loop_var` (mirrored — algebraically
    // equivalent to swapping sides and inverting the operator).
    if let Expr::Ident { name, .. } = rhs.as_ref() {
        if name == loop_var {
            let k = const_eval_u64(lhs)?;
            return match op {
                // k < i  ≡  i > k  ⇒  boundary = k + 1, then = upper
                BinOp::Lt => Some(BranchFlip {
                    boundary: k.checked_add(1)?,
                    then_covers_lower_range: false,
                }),
                // k <= i ≡  i >= k ⇒  boundary = k, then = upper
                BinOp::Le => Some(BranchFlip {
                    boundary: k,
                    then_covers_lower_range: false,
                }),
                // k > i  ≡  i < k  ⇒  boundary = k, then = lower
                BinOp::Gt => Some(BranchFlip {
                    boundary: k,
                    then_covers_lower_range: true,
                }),
                // k >= i ≡  i <= k ⇒  boundary = k + 1, then = lower
                BinOp::Ge => Some(BranchFlip {
                    boundary: k.checked_add(1)?,
                    then_covers_lower_range: true,
                }),
                _ => None,
            };
        }
    }

    None
}
