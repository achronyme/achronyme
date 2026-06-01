use super::*;

/// A loop bound: literal constant, template parameter, or AST expression.
pub(super) enum LoopBound {
    Literal(u64),
    Capture(String),
    /// Expression bound (e.g., `n + 1`) — the AST Expr, lowered in lower_for_loop.
    Expr(Expr),
}

/// Result of parsing a for-loop condition: the bound plus the
/// iteration direction. Ascending loops match `i < N` / `i <= N`;
/// descending loops match `i != -1` (the canonical circomlib SMT
/// pattern, semantically equivalent to `i >= 0`).
pub(super) struct ParsedLoopCond {
    pub bound: LoopBound,
    pub is_descending: bool,
}

/// Extract the upper bound from a loop condition.
///
/// Ascending: `i < N` or `i <= N`. `N` can be a numeric literal or a
/// template parameter (capture). Returns `bound` as the
/// upper-exclusive end.
///
/// Descending: `i != -1`. Returns `bound = LoopBound::Literal(0)`
/// (lower-inclusive end) and `is_descending = true`. The unroll path
/// iterates the loop variable from `start` down to `0` inclusive.
/// Build `rhs + 1` as a fresh AST node so the loop classifier can lift
/// `i <= rhs` to the upper-exclusive form `i < rhs + 1` and let the
/// downstream `LoopBound::Expr` path evaluate it uniformly. The span
/// of the resulting expression points back at the original `rhs`.
pub(super) fn make_inclusive_to_exclusive(rhs: &Expr) -> Expr {
    let span = rhs.span().clone();
    Expr::BinOp {
        op: BinOp::Add,
        lhs: Box::new(rhs.clone()),
        rhs: Box::new(Expr::Number {
            value: "1".to_string(),
            span: span.clone(),
        }),
        span,
    }
}

pub(super) fn extract_loop_bound(
    condition: &Expr,
    var_name: &str,
    env: &LoweringEnv,
) -> Option<ParsedLoopCond> {
    match condition {
        Expr::BinOp { op, lhs, rhs, .. } => {
            // Check that LHS is the loop variable
            if let Expr::Ident { name, .. } = lhs.as_ref() {
                if name != var_name {
                    return None;
                }
            } else {
                return None;
            }

            // Descending shapes — recognise the canonical circomlib SMT
            // patterns. `bound` here is the lower-inclusive end of the
            // iteration; the unroll runs `(bound..=start).rev()`.
            //
            //   `i != -1` ≡ `i >= 0`   → bound = 0
            //   `i >= 0`               → bound = 0
            //   `i > -1`               → bound = 0
            //   `i > 0`                → bound = 1 (stops one before 0)
            //   `i >= N` (literal N)   → bound = N
            //   `i > N` (literal N)    → bound = N + 1
            let rhs_signed = crate::lowering::utils::const_eval_signed(rhs);
            match (op, rhs_signed) {
                (BinOp::Neq, Some(-1)) | (BinOp::Gt, Some(-1)) | (BinOp::Ge, Some(0)) => {
                    return Some(ParsedLoopCond {
                        bound: LoopBound::Literal(0),
                        is_descending: true,
                    });
                }
                (BinOp::Gt, Some(n)) if n >= 0 => {
                    return Some(ParsedLoopCond {
                        bound: LoopBound::Literal((n as u64) + 1),
                        is_descending: true,
                    });
                }
                (BinOp::Ge, Some(n)) if n > 0 => {
                    return Some(ParsedLoopCond {
                        bound: LoopBound::Literal(n as u64),
                        is_descending: true,
                    });
                }
                _ => {}
            }

            // Try literal constant first (ascending paths only)
            if let Some(bound) = const_eval_u64(rhs) {
                return match op {
                    BinOp::Lt => Some(ParsedLoopCond {
                        bound: LoopBound::Literal(bound),
                        is_descending: false,
                    }),
                    BinOp::Le => Some(ParsedLoopCond {
                        bound: LoopBound::Literal(bound + 1),
                        is_descending: false,
                    }),
                    _ => None,
                };
            }

            // Try template parameter (capture)
            if let Expr::Ident { name, .. } = rhs.as_ref() {
                if env.captures.contains(name) {
                    return match op {
                        BinOp::Lt => Some(ParsedLoopCond {
                            bound: LoopBound::Capture(name.clone()),
                            is_descending: false,
                        }),
                        // `i <= capture` becomes `i < capture + 1`. The
                        // `Capture` variant carries only the bare name,
                        // so the inclusive form rebinds through the
                        // `Expr` variant — which the downstream
                        // `resolve_bound_to_u64` / `LoopBound → ForRange`
                        // path already evaluates against bound captures.
                        BinOp::Le => Some(ParsedLoopCond {
                            bound: LoopBound::Expr(make_inclusive_to_exclusive(rhs.as_ref())),
                            is_descending: false,
                        }),
                        _ => None,
                    };
                }
            }

            // Expression bound (e.g., `i < n + 1` or `i <= n + m`).
            // `<=` rewrites to `<` over `rhs + 1` so the downstream
            // path sees a single exclusive-upper-bound representation
            // regardless of the source-level operator.
            match op {
                BinOp::Lt => Some(ParsedLoopCond {
                    bound: LoopBound::Expr(rhs.as_ref().clone()),
                    is_descending: false,
                }),
                BinOp::Le => Some(ParsedLoopCond {
                    bound: LoopBound::Expr(make_inclusive_to_exclusive(rhs.as_ref())),
                    is_descending: false,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Validate the loop step.
///
/// Returns `false` for ascending steps (`i++`, `i += 1`) and `true`
/// for descending steps (`i--`, `i -= 1`). The caller cross-checks
/// the direction against the condition shape.
pub(super) fn validate_loop_step(
    step: &Stmt,
    var_name: &str,
    span: &diagnostics::Span,
) -> Result<bool, LoweringError> {
    match step {
        // i++
        Stmt::Expr {
            expr:
                Expr::PostfixOp {
                    op: PostfixOp::Increment,
                    operand,
                    ..
                },
            ..
        } => {
            if let Expr::Ident { name, .. } = operand.as_ref() {
                if name == var_name {
                    return Ok(false);
                }
            }
            Err(LoweringError::new(
                format!("for loop step must increment `{var_name}`"),
                span,
            ))
        }
        // i--
        Stmt::Expr {
            expr:
                Expr::PostfixOp {
                    op: PostfixOp::Decrement,
                    operand,
                    ..
                },
            ..
        } => {
            if let Expr::Ident { name, .. } = operand.as_ref() {
                if name == var_name {
                    return Ok(true);
                }
            }
            Err(LoweringError::new(
                format!("for loop step must decrement `{var_name}`"),
                span,
            ))
        }
        // i += 1 or i -= 1
        Stmt::CompoundAssign {
            target, op, value, ..
        } => {
            if let Expr::Ident { name, .. } = target {
                if name == var_name {
                    if let Some(1) = const_eval_u64(value) {
                        match op {
                            CompoundOp::Add => return Ok(false),
                            CompoundOp::Sub => return Ok(true),
                            _ => {}
                        }
                    }
                }
            }
            Err(LoweringError::new(
                format!(
                    "for loop step must be `{var_name}++`, `{var_name}--`, \
                     `{var_name} += 1`, or `{var_name} -= 1`"
                ),
                span,
            ))
        }
        _ => Err(LoweringError::new(
            "for loop step must be `i++`, `i--`, `i += 1`, or `i -= 1` in circuit context",
            span,
        )),
    }
}
