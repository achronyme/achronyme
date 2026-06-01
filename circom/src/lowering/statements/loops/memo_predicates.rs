use super::*;

pub(super) fn body_has_dot_access(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_dot_access)
}

pub(super) fn stmt_has_dot_access(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_has_dot_access(target) || expr_has_dot_access(value)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_has_dot_access(target) || expr_has_dot_access(value)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => expr_has_dot_access(lhs) || expr_has_dot_access(rhs),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_dot_access(condition)
                || then_body.stmts.iter().any(stmt_has_dot_access)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_dot_access),
                    Some(ElseBranch::IfElse(s)) => stmt_has_dot_access(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_dot_access),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_dot_access)
        }
        _ => false,
    }
}

pub(super) fn expr_has_dot_access(expr: &Expr) -> bool {
    match expr {
        Expr::DotAccess { .. } => true,
        Expr::Index { object, index, .. } => {
            expr_has_dot_access(object) || expr_has_dot_access(index)
        }
        Expr::BinOp { lhs, rhs, .. } => expr_has_dot_access(lhs) || expr_has_dot_access(rhs),
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_dot_access(operand),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_has_dot_access(condition)
                || expr_has_dot_access(if_true)
                || expr_has_dot_access(if_false)
        }
        Expr::Call { args, .. } => args.iter().any(expr_has_dot_access),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(expr_has_dot_access)
        }
        _ => false,
    }
}

pub(super) fn body_has_component_or_call(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_component_or_call)
}

pub(super) fn stmt_has_component_or_call(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::ComponentDecl { .. } => true,
        Stmt::Substitution { value, target, .. } => {
            // `comp[i] = T()` is parsed as Substitution; reject any
            // Substitution whose value is a Call (template instantiation
            // or function call).
            expr_contains_call(value) || expr_contains_call(target)
        }
        Stmt::CompoundAssign { value, .. } => expr_contains_call(value),
        Stmt::ConstraintEq { lhs, rhs, .. } => expr_contains_call(lhs) || expr_contains_call(rhs),
        Stmt::VarDecl { init, .. } => init.as_ref().is_some_and(expr_contains_call),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_contains_call(condition)
                || then_body.stmts.iter().any(stmt_has_component_or_call)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_component_or_call),
                    Some(ElseBranch::IfElse(s)) => stmt_has_component_or_call(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_component_or_call),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_component_or_call)
        }
        _ => false,
    }
}

pub(super) fn expr_contains_call(expr: &Expr) -> bool {
    expr_has_call(expr)
}

/// `true` iff the body has a state-carrying var mutation that is NOT
/// offset by an in-body reset of the same name.
///
/// A mutation is **state-carrying** when iter-N's value of a compile-
/// time `var` depends on iter-(N-1)'s value, which the memoization
/// replay model can't reconstruct (the captured iter-`start` body would
/// emit a snapshot of iter-`start`'s var values; replay just clones +
/// substitutes the placeholder, no per-iter recomputation). Examples:
///   - **Num2Bits's `lc1 += out[i] * e2`** — `lc1` accumulates without
///     a fresh reset in the body, so iter 0's final `lc1` value would
///     leak into iter 1.
///   - **Num2Bits's `e2 = e2 + e2`** — self-referential SubAssignIdent;
///     iter N's value is `2^N * iter_start_e2`, depends on prior iter.
///   - **MixS first-loop `lc += S[r*5+i]*in[i]`** — same shape as
///     Num2Bits's lc1: CompoundAssign with no in-body reset.
///
/// A mutation is **offset (safe)** when the same name has an earlier
/// non-self-referential `Substitution { Assign, Ident(name) }` in the
/// **same body**. Each iter starts fresh: the IR-level SSA shadowing
/// chain begins anew with the reset's `Let { name, value: <iter-
/// independent> }`, and subsequent CompoundAssigns build on top of
/// that reset rather than the prior iter's accumulator.
///
/// Mix's outer-i body is the canonical safe case:
/// ```text
///   lc = 0;                          // RESET (non-self-ref Subst on Ident)
///   for (j) { lc += M[j][i] * in[j]; }  // CompoundAssign in nested for
///   out[i] <== lc;                   // signal substitution (not flagged)
/// ```
/// `lc` has a CompoundAssign in the nested for, but `lc = 0` resets it
/// at the start of every outer iter, so the accumulator doesn't carry
/// across outer iters.
///
/// **Recursion semantics:**
///   - `IfElse` / `Block`: each branch starts with the current
///     `reset_names`. Resets inside a branch are scoped to that branch
///     and do NOT propagate to siblings (conservative — a reset only in
///     the `then` branch leaves `name` unsafe in the `else` branch).
///   - `For` / `While` / `DoWhile`: the nested body inherits the OUTER
///     reset_names. Resets inside the nested body apply only to that
///     body's own iters and do NOT propagate up.
///   - `CompoundAssign` whose target is not a bare `Ident` is rejected
///     uniformly (conservative; no current circuit hits this).
///
/// **Self-referential SubAssignIdent always state-carrying.**
/// `e2 = e2 + e2` is rejected even if `e2` is in `reset_names` from an
/// earlier reset in the same body. This is the conservative call:
/// loosening to "first SubAssignIdent counts as reset, subsequent
/// self-referential ones are safe under SSA shadowing" requires per-
/// stmt SSA tracking that's not worth the complexity for the MVP. No
/// real circuit hits the loosened pattern. If a future widening needs
/// it, the rule is local (this function) and the pattern is `lc = 0;
/// lc = lc + 1; …` — easy to extend.
///
/// **Signal substitutions excluded.** `out[i] <== …` / `out[i] <-- …`
/// target indexed signals (`Expr::Index`), not bare identifiers, and
/// route through `LetIndexed` / `WitnessHintIndexed` whose
/// `index: LoopVar(token)` substitutes uniformly.
///
/// Unit tests pinning the contract:
///   - `is_memoizable_rejects_num2bits_state_carrying_body` — Num2Bits
///     stays rejected (no in-body reset for lc1; e2 self-referential).
///   - `is_memoizable_rejects_inner_j_compoundassign_without_reset` —
///     Mix's inner-j body alone (CompoundAssign, no in-body reset).
///   - `is_memoizable_rejects_mixs_first_loop_compoundassign_without_reset`
///     — MixS's first-pass loop, structurally identical to inner-j.
///   - `is_memoizable_accepts_mix_outer_i_with_in_body_reset` —
///     positive pin for Mix's outer-i body (admit when reset is in
///     the same body).
pub(super) fn body_has_state_carrying_var_mutation(stmts: &[Stmt]) -> bool {
    let mut reset_names: HashSet<String> = HashSet::new();
    body_has_state_carrying_var_mutation_with_resets(stmts, &mut reset_names)
}

/// Recursive worker. `reset_names` is mutated in place to track names
/// reset by non-self-referential `Substitution { Assign, Ident, … }`
/// stmts seen so far in the current body's stmt sequence. Nested
/// scopes (IfElse branches, Block, For/While/DoWhile bodies) clone
/// `reset_names` so resets inside them don't propagate out.
pub(super) fn body_has_state_carrying_var_mutation_with_resets(
    stmts: &[Stmt],
    reset_names: &mut HashSet<String>,
) -> bool {
    for stmt in stmts {
        if stmt_carries_state(stmt, reset_names) {
            return true;
        }
        // Track non-self-referential SubAssignIdent as a reset for the
        // remainder of THIS body's stmt sequence.
        if let Stmt::Substitution {
            op: AssignOp::Assign,
            target: Expr::Ident { name, .. },
            value,
            ..
        } = stmt
        {
            if !expr_references_ident(value, name) {
                reset_names.insert(name.clone());
            }
        }
    }
    false
}

pub(super) fn stmt_carries_state(stmt: &Stmt, reset_names: &HashSet<String>) -> bool {
    match stmt {
        Stmt::CompoundAssign { target, .. } => match target {
            Expr::Ident { name, .. } => !reset_names.contains(name),
            _ => true,
        },
        Stmt::Substitution {
            op: AssignOp::Assign,
            target: Expr::Ident { name, .. },
            value,
            ..
        } => expr_references_ident(value, name),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            let mut then_resets = reset_names.clone();
            if body_has_state_carrying_var_mutation_with_resets(&then_body.stmts, &mut then_resets)
            {
                return true;
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    let mut else_resets = reset_names.clone();
                    body_has_state_carrying_var_mutation_with_resets(&b.stmts, &mut else_resets)
                }
                Some(ElseBranch::IfElse(s)) => stmt_carries_state(s, reset_names),
                None => false,
            }
        }
        Stmt::Block(b) => {
            let mut block_resets = reset_names.clone();
            body_has_state_carrying_var_mutation_with_resets(&b.stmts, &mut block_resets)
        }
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            let mut body_resets = reset_names.clone();
            body_has_state_carrying_var_mutation_with_resets(&body.stmts, &mut body_resets)
        }
        _ => false,
    }
}

// `expr_references_ident` is defined later in this module (originally
// added by `body_has_loop_var_dependent_var_decl`). It walks the AST
// exhaustively for occurrences of an `Expr::Ident { name }`, which is
// exactly the predicate Follow-up D needs to detect self-referential
// `Substitution { Assign, Ident(name), value: <contains Ident(name)> }`
// shapes (Num2Bits's `e2 = e2 + e2`).

/// Walk the body looking for `Expr::Call` patterns that lift to
/// Artik witness bytecode. We don't have a typed marker on the AST for
/// these (the lift happens during lowering, not parsing), so the
/// conservative rule is: any function call whose callee is a
/// recognised function name might lift. Until the lift pass exposes
/// a "this would emit a `WitnessCall`" predicate, refuse to memoize
/// any loop that contains a call whose name matches the witness-lift
/// shape (`__artik_*`), or — more conservatively — any function call
/// that doesn't trivially const-fold. SHA-256's round body has no
/// witness-lifted calls, so this gate is a no-op for the perf target.
///
/// **MVP**: we use the loosest practical check — any explicit
/// `Call`. Tightening (recognise pure compile-time calls and exempt
/// them) is a follow-up if it's needed to widen the memoizable set.
pub(super) fn body_has_witness_call(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_call)
}

pub(super) fn stmt_has_call(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution { value, .. } => expr_has_call(value),
        Stmt::CompoundAssign { value, .. } => expr_has_call(value),
        Stmt::ConstraintEq { lhs, rhs, .. } => expr_has_call(lhs) || expr_has_call(rhs),
        Stmt::VarDecl { init, .. } => init.as_ref().is_some_and(expr_has_call),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_call(condition)
                || then_body.stmts.iter().any(stmt_has_call)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_call),
                    Some(ElseBranch::IfElse(s)) => stmt_has_call(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_call),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_call)
        }
        _ => false,
    }
}

pub(super) fn expr_has_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call { .. } => true,
        Expr::BinOp { lhs, rhs, .. } => expr_has_call(lhs) || expr_has_call(rhs),
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_call(operand),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => expr_has_call(condition) || expr_has_call(if_true) || expr_has_call(if_false),
        Expr::Index { object, index, .. } => expr_has_call(object) || expr_has_call(index),
        Expr::DotAccess { object, .. } => expr_has_call(object),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(expr_has_call)
        }
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args.iter().any(expr_has_call)
                || signal_args.iter().any(|a| expr_has_call(&a.value))
        }
        _ => false,
    }
}

/// `true` iff the body declares a compile-time `var` whose initializer
/// references the loop variable. Replaying such a `var` from a
/// memoized iter-0 footprint would seed every replay iter with iter-0's
/// computed value, masking the per-iter recomputation.
pub(super) fn body_has_loop_var_dependent_var_decl(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var))
}

pub(super) fn stmt_has_loop_var_dependent_var_decl(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::VarDecl { init: Some(v), .. } => expr_references_ident(v, loop_var),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => {
                        stmt_has_loop_var_dependent_var_decl(s, loop_var)
                    }
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var)),
        _ => false,
    }
}

/// `true` iff the body contains a nested for/while/do-while whose
/// bound or condition references the outer loop var.
pub(super) fn body_has_nested_loop_with_loop_var_bound(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
}

pub(super) fn stmt_has_nested_loop_with_loop_var_bound(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::For {
            condition, body, ..
        } => {
            // Inner-loop bound mentions the outer loop var.
            expr_references_ident(condition, loop_var)
                || body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
        }
        Stmt::While {
            condition, body, ..
        }
        | Stmt::DoWhile {
            condition, body, ..
        } => {
            expr_references_ident(condition, loop_var)
                || body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => {
                        stmt_has_nested_loop_with_loop_var_bound(s, loop_var)
                    }
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var)),
        _ => false,
    }
}
