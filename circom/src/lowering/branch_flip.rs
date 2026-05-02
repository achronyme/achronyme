//! Detect a top-level `if (loop_var <op> k) { ... } else { ... }`
//! pattern in a for-loop body.
//!
//! When a body contains exactly that shape, the body's emission is
//! uniform within `[start, boundary)` and uniform within
//! `[boundary, end)`, but differs between the two ranges. The
//! memoized unroll captures both groups separately — one
//! substituted template for the lower range, one for the upper
//! range.
//!
//! This module is pure AST analysis. It does not lower anything;
//! the actual two-capture partition lives in `loops.rs`.

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
/// outermost boundary. The detector targets the SHA-256
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;

    /// Wrap a body of statements in a loop and parse it; return the
    /// loop's body statements so the test can call
    /// `detect_branch_flip` against them.
    fn parse_loop_body(body_src: &str) -> Vec<Stmt> {
        let src =
            format!("template T() {{\n  for (var i = 0; i < 64; i++) {{\n{body_src}\n  }}\n}}\n");
        let (prog, errors) = parse_circom(&src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        let crate::ast::Definition::Template(t) = &prog.definitions[0] else {
            panic!("expected template");
        };
        let Stmt::For { body, .. } = &t.body.stmts[0] else {
            panic!("expected for-loop");
        };
        body.stmts.clone()
    }

    #[test]
    fn lt_loop_var_const_returns_lower_range() {
        let body = parse_loop_body("    if (i < 16) { var a = 0; } else { var b = 0; }");
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        assert_eq!(flip.boundary, 16);
        assert!(flip.then_covers_lower_range);
    }

    #[test]
    fn le_loop_var_const_offsets_boundary_by_one() {
        let body = parse_loop_body("    if (i <= 15) { var a = 0; } else { var b = 0; }");
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        // i <= 15 ≡ i < 16, so boundary = 16, then = lower.
        assert_eq!(flip.boundary, 16);
        assert!(flip.then_covers_lower_range);
    }

    #[test]
    fn gt_loop_var_const_makes_then_upper() {
        let body = parse_loop_body("    if (i > 15) { var a = 0; } else { var b = 0; }");
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        assert_eq!(flip.boundary, 16);
        assert!(!flip.then_covers_lower_range);
    }

    #[test]
    fn ge_loop_var_const_makes_then_upper() {
        let body = parse_loop_body("    if (i >= 16) { var a = 0; } else { var b = 0; }");
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        assert_eq!(flip.boundary, 16);
        assert!(!flip.then_covers_lower_range);
    }

    #[test]
    fn const_lt_loop_var_is_mirrored() {
        // `15 < i` ≡ `i > 15` ⇒ boundary = 16, then = upper.
        let body = parse_loop_body("    if (15 < i) { var a = 0; } else { var b = 0; }");
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        assert_eq!(flip.boundary, 16);
        assert!(!flip.then_covers_lower_range);
    }

    #[test]
    fn const_ge_loop_var_is_mirrored() {
        // `16 >= i` ≡ `i <= 16` ≡ `i < 17` ⇒ boundary = 17, then = lower.
        let body = parse_loop_body("    if (16 >= i) { var a = 0; } else { var b = 0; }");
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        assert_eq!(flip.boundary, 17);
        assert!(flip.then_covers_lower_range);
    }

    #[test]
    fn equality_does_not_count_as_branch_flip() {
        // `i == 5` partitions iters into a single point + everything else.
        // Not a useful boundary — the analysis returns None.
        let body = parse_loop_body("    if (i == 5) { var a = 0; } else { var b = 0; }");
        assert_eq!(detect_branch_flip(&body, "i"), None);
    }

    #[test]
    fn missing_else_is_not_a_flip() {
        // Without an else, there's only one branch shape; the
        // partition is degenerate (lower = then-body, upper = nothing).
        // Not what R1″ wants — the caller should treat this as uniform.
        let body = parse_loop_body("    if (i < 5) { var a = 0; }");
        assert_eq!(detect_branch_flip(&body, "i"), None);
    }

    #[test]
    fn cond_referencing_other_var_is_not_detected() {
        // `j < 16` does not reference the loop var `i` — analysis
        // returns None and the caller treats the body as uniform
        // (or unrolls in the legacy path if `j` happens to track the
        // loop var indirectly).
        let body =
            parse_loop_body("    var j = 5;\n    if (j < 16) { var a = 0; } else { var b = 0; }");
        assert_eq!(detect_branch_flip(&body, "i"), None);
    }

    #[test]
    fn empty_body_returns_none() {
        let body: Vec<Stmt> = Vec::new();
        assert_eq!(detect_branch_flip(&body, "i"), None);
    }

    #[test]
    fn first_top_level_if_wins() {
        // Two top-level branch-flips. We document the contract: the
        // first one in source order is returned. Multi-flip handling
        // is future work; for now SHA-256 has only one such loop.
        let body = parse_loop_body(
            "    if (i < 16) { var a = 0; } else { var b = 0; }\n\
             if (i < 32) { var c = 0; } else { var d = 0; }",
        );
        let flip = detect_branch_flip(&body, "i").expect("flip not detected");
        assert_eq!(flip.boundary, 16);
        assert!(flip.then_covers_lower_range);
    }

    #[test]
    fn sha256_message_schedule_pattern_yields_boundary_16() {
        // SHA-256's message-schedule loop:
        //   for (var t = 0; t < 64; t++) {
        //       if (t < 16) { ...simple input... }
        //       else { ...sigma rotation... }
        //   }
        // Should detect boundary = 16 with then = lower.
        let body = parse_loop_body(
            "    if (t < 16) { var simple = 0; } \
             else { var rotated = 0; }",
        );
        let flip = detect_branch_flip(&body, "t").expect("flip not detected");
        assert_eq!(flip.boundary, 16);
        assert!(flip.then_covers_lower_range);
    }
}
