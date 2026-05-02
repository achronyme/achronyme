//! `for` expression compilation.
//!
//! `compile_for_expr` is the dispatch point: it analyses the loop body
//! for mutable accumulators carried across iterations, then chooses
//! between the rolled `CircuitNode::For` path and one of two eager
//! unroll paths (literal range or array iteration). The carry-set
//! helpers at the bottom of the file are the per-iter SSA-rebind
//! detector — purely structural walks over the AST that decide whether
//! the rolled path is safe.
//!
//! See the doc-comment on `compile_for_expr` for the rolled-vs-unrolled
//! decision tree and the SSA-rebind rationale.

use std::collections::{BTreeSet, HashMap, HashSet};

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(super) fn compile_for_expr(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        /// Maximum number of iterations allowed for literal ranges.
        const MAX_LOOP_ITERATIONS: u64 = 1_000_000;

        // Carry-set detection: if the body re-assigns any mutable variable
        // declared *outside* this loop (and not redeclared / shadowed
        // inside), we must eager-unroll at lower time so each iteration's
        // SSA chain references the previous iteration's output. The default
        // path captures the body once with frozen SSA names, which would
        // silently drop the carry across iterations.
        //
        // Mirror of `circom/src/lowering/statements/loops.rs:body_writes_to_outer_scope_var`
        // adapted to the achronyme prove-block AST. Industry-standard pattern
        // — Noir, Leo, and Zokrates apply per-iteration SSA re-versioning
        // before emit; the canonical SSA representation of this construct is
        // a loop-header phi (Cytron et al. 1991) whose β-reduction over a
        // bounded literal range is the eager-unroll form (formally
        // equivalent for static ranges with no early exits).
        let carries = body_writes_to_outer_mut_var(body, &self.ssa_versions, var);

        let range = match iterable {
            ForIterable::Range { start, end } => {
                let iterations = end.saturating_sub(*start);
                if iterations > MAX_LOOP_ITERATIONS {
                    return Err(ProveIrError::RangeTooLarge {
                        iterations,
                        max: MAX_LOOP_ITERATIONS,
                        span: to_span(span),
                    });
                }
                ForRange::Literal {
                    start: *start,
                    end: *end,
                }
            }
            ForIterable::ExprRange { start, end } => {
                // Dynamic end bound: compile to WithCapture or WithExpr.
                // Simple capture name → WithCapture; expression → WithExpr.
                if let Expr::Ident { name, .. } = end.as_ref() {
                    if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Capture(_))) {
                        self.captured_names.insert(name.clone());
                        ForRange::WithCapture {
                            start: *start,
                            end_capture: name.clone(),
                        }
                    } else {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "dynamic loop bound `{name}` must be a captured variable \
                                 (from outer scope)"
                            ),
                            span: to_span(span),
                        });
                    }
                } else {
                    // Compile the end expression to a CircuitExpr
                    let end_circuit = self.compile_expr(end)?;
                    ForRange::WithExpr {
                        start: *start,
                        end_expr: Box::new(end_circuit),
                    }
                }
            }
            ForIterable::Expr(expr) => {
                // Must be an array identifier
                if let Expr::Ident { name, .. } = expr.as_ref() {
                    if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Array(_))) {
                        ForRange::Array(name.clone())
                    } else if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Capture(_)))
                    {
                        // Capture used as iterable — could be an array, defer to instantiation
                        ForRange::Array(name.clone())
                    } else {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "for loop iterable `{name}` must be an array or range \
                                 in circuits"
                            ),
                            span: to_span(span),
                        });
                    }
                } else {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "for loops in circuits require a literal range \
                                      (e.g., 0..5), a dynamic range (0..n), or an array"
                            .into(),
                        span: to_span(span),
                    });
                }
            }
        };

        // Carry-set + eager-unroll path: lower the body N times in place,
        // letting `ssa_versions` and `env` advance naturally per iteration.
        // Supported when the bound is statically resolvable at lower time
        // (literal range or array iteration where element names are
        // already in env). Dynamic-capture / expression bounds are
        // rejected — the same restriction Noir / Leo / Zokrates impose on
        // non-constant bounds in compiled circuits.
        if !carries.is_empty() {
            return match range {
                ForRange::Literal { start, end } => {
                    self.compile_for_eager_unroll(var, start, end, body, span)
                }
                ForRange::Array(arr_name) => {
                    self.compile_for_eager_unroll_array(var, &arr_name, body, span)
                }
                ForRange::WithCapture { .. } | ForRange::WithExpr { .. } => {
                    Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "for loop with mutable accumulator(s) {} requires a \
                             statically-known bound (literal range or array iteration); \
                             dynamic bounds (`0..n`) are not supported in this case. \
                             Use a literal bound or rewrite the loop without `mut` \
                             reassignment.",
                            format_carry_list(&carries)
                        ),
                        span: to_span(span),
                    })
                }
            };
        }

        // Save body, compile loop body into a separate buffer
        let saved_body = std::mem::take(&mut self.body);

        // Register loop var in env
        let saved_var = self.env.get(var).cloned();
        self.env
            .insert(var.to_string(), CompEnvValue::Scalar(var.to_string()));

        self.body = Vec::new();
        let _body_result = self.compile_block_as_expr(body)?;
        let loop_body = std::mem::take(&mut self.body);

        // Restore
        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }
        self.body = saved_body;

        // Emit the For node (preserved, unrolled during Phase B instantiation)
        self.body.push(CircuitNode::For {
            var: var.to_string(),
            range,
            body: loop_body,
            span: Some(SpanRange::from(span)),
        });

        // For loops don't produce a useful expression value in circuit context
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    /// Eager-unroll a `for` loop with literal bounds when the body
    /// carries mutable state across iterations. Lowers the body in place
    /// `end - start` times; each iteration calls `compile_block_as_expr`
    /// fresh, which advances `ssa_versions` and `env` so the next iter's
    /// `Var(name)` reads point at the previous iter's `Let("name$vK")`
    /// output. The natural SSA chain falls out of standard tree walking
    /// — same mechanism the circom Class A fix uses for var-accumulator
    /// escape.
    fn compile_for_eager_unroll(
        &mut self,
        var: &str,
        start: u64,
        end: u64,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let iterations = end.saturating_sub(start);
        const MAX_LOOP_ITERATIONS: u64 = 1_000_000;
        if iterations > MAX_LOOP_ITERATIONS {
            return Err(ProveIrError::RangeTooLarge {
                iterations,
                max: MAX_LOOP_ITERATIONS,
                span: to_span(span),
            });
        }

        // Save the loop var's prior binding (if any) so we can restore it
        // when the unroll exits — matches the rolled-loop scoping shape.
        let saved_var = self.env.get(var).cloned();

        for i in start..end {
            // Bind the loop var to the current const at lower time. Each
            // iteration emits its own Let so the inline body's `Var(var)`
            // reads resolve to a fresh const SSA at instantiate.
            self.body.push(CircuitNode::Let {
                name: var.to_string(),
                value: CircuitExpr::Const(FieldConst::from_u64(i)),
                span: Some(SpanRange::from(span)),
            });
            self.env
                .insert(var.to_string(), CompEnvValue::Scalar(var.to_string()));

            // Re-walk the source AST. ssa_versions advances on every
            // assignment to a mut var, so iter k+1 sees iter k's output
            // through env.
            let _result = self.compile_block_as_expr(body)?;
        }

        // Restore the loop var. Body-local mut decls (re-declared each
        // iter) are intentionally left in env at their last-iter binding;
        // post-loop reads of those names follow current rolled-loop
        // semantics (no scope reset).
        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }

        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    /// Eager-unroll counterpart of [`Self::compile_for_eager_unroll`] for
    /// array iteration (`for x in arr`). The element name list is
    /// already in env (populated by `compile_let` / `compile_mut_decl`
    /// when the array binding was lowered), so the iteration count is
    /// known statically here. Per iter, bind the loop var to one element
    /// name and re-walk the body.
    fn compile_for_eager_unroll_array(
        &mut self,
        var: &str,
        arr_name: &str,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let elem_names = match self.env.get(arr_name) {
            Some(CompEnvValue::Array(elems)) => elems.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "for loop iterable `{arr_name}` must be an array \
                         (eager-unroll path)"
                    ),
                    span: to_span(span),
                });
            }
        };

        let saved_var = self.env.get(var).cloned();

        for elem_name in &elem_names {
            // Bind the loop var to the current element's scalar name. No
            // intermediate Let needed — the element already lives in env
            // as a Scalar from the array's lowering, so a direct alias
            // entry suffices for the body's `Var(var)` reads.
            self.env
                .insert(var.to_string(), CompEnvValue::Scalar(elem_name.clone()));

            let _result = self.compile_block_as_expr(body)?;
        }

        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }

        Ok(CircuitExpr::Const(FieldConst::zero()))
    }
}

// ---------------------------------------------------------------------------
// Carry-set detection for `for` loops with mutable accumulators.
//
// Returns the deterministically-sorted list of mutable variable names
// declared *outside* the body that the body re-assigns. An empty result
// means the body is safe for the rolled-loop path; a non-empty result
// means `compile_for_expr` must eager-unroll at lower (literal range) or
// reject (dynamic range).
//
// Mirrors `circom/src/lowering/statements/loops.rs::body_writes_to_outer_scope_var`
// adapted to the achronyme prove-block AST (`achronyme_parser::ast::Stmt`,
// `Expr`, `Block`). The detection is the same two-phase shape:
//
//   1. Collect every name declared inside the body — recursively
//      descending into nested if/else, for, while, forever, block.
//   2. Walk every assignment in the body. A target whose name is (a) in
//      the outer `ssa_versions` map (declared with `mut` outside),
//      (b) not in the body's local declaration set, and (c) not the
//      loop variable, is a carry.
//
// The walk stays purely structural — no type-checking, no constant
// folding. An identifier-target lookup against `ssa_versions` is the
// authoritative "declared with mut in outer scope" predicate because
// `compile_mut_decl` is the only path that inserts into `ssa_versions`.
// ---------------------------------------------------------------------------

fn body_writes_to_outer_mut_var(
    body: &Block,
    ssa_versions: &HashMap<String, u32>,
    loop_var: &str,
) -> Vec<String> {
    let mut body_decls: HashSet<String> = HashSet::new();
    collect_block_decls(body, &mut body_decls);

    let mut out: BTreeSet<String> = BTreeSet::new();
    walk_block_writes(body, ssa_versions, &body_decls, loop_var, &mut out);
    out.into_iter().collect()
}

fn format_carry_list(carries: &[String]) -> String {
    let quoted: Vec<String> = carries.iter().map(|n| format!("`{n}`")).collect();
    quoted.join(", ")
}

/// Collect every binding name introduced inside this block — let, mut,
/// fn parameters, and any nested control-flow bodies. Used to mask
/// inner-shadowed names from the carry-set: if the loop body redeclares
/// `acc`, writes to that inner `acc` are not carries.
fn collect_block_decls(block: &Block, acc: &mut HashSet<String>) {
    for stmt in &block.stmts {
        collect_stmt_decls(stmt, acc);
    }
}

fn collect_stmt_decls(stmt: &Stmt, acc: &mut HashSet<String>) {
    match stmt {
        Stmt::LetDecl { name, value, .. } | Stmt::MutDecl { name, value, .. } => {
            acc.insert(name.clone());
            collect_expr_decls(value, acc);
        }
        Stmt::FnDecl {
            name, params, body, ..
        } => {
            acc.insert(name.clone());
            for p in params {
                acc.insert(p.name.clone());
            }
            collect_block_decls(body, acc);
        }
        Stmt::Assignment { value, .. } => collect_expr_decls(value, acc),
        Stmt::Print { value, .. } => collect_expr_decls(value, acc),
        Stmt::Return { value: Some(v), .. } => collect_expr_decls(v, acc),
        Stmt::Export { inner, .. } => collect_stmt_decls(inner, acc),
        Stmt::Expr(e) => collect_expr_decls(e, acc),
        // Top-level / module-level declarations and parse-error
        // placeholders carry no body-local binding semantics for our
        // purposes here.
        _ => {}
    }
}

fn collect_expr_decls(expr: &Expr, acc: &mut HashSet<String>) {
    match expr {
        Expr::If {
            then_block,
            else_branch,
            ..
        } => {
            collect_block_decls(then_block, acc);
            match else_branch {
                Some(ElseBranch::Block(b)) => collect_block_decls(b, acc),
                Some(ElseBranch::If(e)) => collect_expr_decls(e, acc),
                None => {}
            }
        }
        Expr::For { var, body, .. } => {
            // The inner loop's induction var is body-local relative to
            // *that* loop. For the outer-loop carry analysis, treat it
            // as introduced inside the body.
            acc.insert(var.clone());
            collect_block_decls(body, acc);
        }
        Expr::While { body, .. } | Expr::Forever { body, .. } => {
            collect_block_decls(body, acc);
        }
        Expr::Block { block, .. } => collect_block_decls(block, acc),
        Expr::FnExpr { params, body, .. } => {
            for p in params {
                acc.insert(p.name.clone());
            }
            collect_block_decls(body, acc);
        }
        // Other expression variants don't introduce bindings; their
        // sub-expressions are scanned only if they could host one of
        // the above (covered by the recursive variants).
        _ => {}
    }
}

fn walk_block_writes(
    block: &Block,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    for stmt in &block.stmts {
        walk_stmt_writes(stmt, ssa_versions, body_decls, loop_var, out);
    }
}

fn walk_stmt_writes(
    stmt: &Stmt,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    match stmt {
        // Indexed assignments (`arr[i] = ...`) are handled by a separate
        // lowering path (`compile_indexed_assignment`) that emits
        // `LetIndexed`, not SSA-versioned `Let`. They don't share the
        // per-iter SSA-rebind shape, so they are intentionally not
        // treated as carries here.
        Stmt::Assignment {
            target: Expr::Ident { name, .. },
            ..
        } if name != loop_var && ssa_versions.contains_key(name) && !body_decls.contains(name) => {
            out.insert(name.clone());
        }
        Stmt::Expr(e) => walk_expr_writes(e, ssa_versions, body_decls, loop_var, out),
        Stmt::Print { value, .. } => {
            walk_expr_writes(value, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::Return { value: Some(v), .. } => {
            walk_expr_writes(v, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => {
            walk_expr_writes(value, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::Export { inner, .. } => {
            walk_stmt_writes(inner, ssa_versions, body_decls, loop_var, out)
        }
        _ => {}
    }
}

fn walk_expr_writes(
    expr: &Expr,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    match expr {
        Expr::If {
            then_block,
            else_branch,
            ..
        } => {
            walk_block_writes(then_block, ssa_versions, body_decls, loop_var, out);
            match else_branch {
                Some(ElseBranch::Block(b)) => {
                    walk_block_writes(b, ssa_versions, body_decls, loop_var, out)
                }
                Some(ElseBranch::If(e)) => {
                    walk_expr_writes(e, ssa_versions, body_decls, loop_var, out)
                }
                None => {}
            }
        }
        Expr::For { body, .. } | Expr::While { body, .. } | Expr::Forever { body, .. } => {
            walk_block_writes(body, ssa_versions, body_decls, loop_var, out);
        }
        Expr::Block { block, .. } => {
            walk_block_writes(block, ssa_versions, body_decls, loop_var, out)
        }
        // Other expression variants don't host assignments directly.
        _ => {}
    }
}
