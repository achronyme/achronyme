use super::*;

/// `true` if the body contains a write (`=` or `+=`/`-=`/`*=`/...) to
/// a simple-identifier target whose name is bound in the enclosing
/// scope (`env.locals`) and is not declared inside this body.
///
/// Bug Class A trigger. The instantiator's `LoopUnrollMode::Symbolic`
/// path emits the body exactly once and propagates `var` updates
/// through the env. When the update RHS reads a `SymbolicArrayRead`,
/// arithmetic peephole simplification (`0 + x*1 → x`,
/// `0 + x → x`) can collapse the chain to the SymArrRead's
/// loop-local `result_var`. The env binding for the outer `var` then
/// holds a body-local SsaVar; any post-loop reference resolves to
/// that var outside its `LoopUnroll` scope and the walker rejects it
/// as undefined. Forcing eager unroll for these bodies routes them
/// through the Legacy path that materialises a fresh per-iteration
/// SSA chain in the outer scope, sidestepping the env-leak entirely.
///
/// Detection is local: walk the body once collecting body-local
/// `var` decl names, then scan for assignment/compound-assign
/// statements whose target is a simple identifier in `env.locals`
/// that wasn't declared inside the body. Signals (`<==`, `<--`,
/// `==>`, `-->`) are skipped because they don't propagate through
/// the env binding mechanism.
pub(super) fn body_writes_to_outer_scope_var(
    stmts: &[Stmt],
    env: &LoweringEnv,
    loop_var: &str,
) -> bool {
    let mut body_decls: HashSet<String> = HashSet::new();
    for s in stmts {
        collect_var_decls_in_stmt(s, &mut body_decls);
    }
    stmts
        .iter()
        .any(|s| stmt_writes_to_outer_var(s, env, &body_decls, loop_var))
}

pub(super) fn collect_var_decls_in_stmt(stmt: &Stmt, acc: &mut HashSet<String>) {
    match stmt {
        Stmt::VarDecl { names, .. } => {
            for n in names {
                acc.insert(n.clone());
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            for s in &then_body.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        collect_var_decls_in_stmt(s, acc);
                    }
                }
                Some(ElseBranch::IfElse(s)) => collect_var_decls_in_stmt(s, acc),
                None => {}
            }
        }
        Stmt::Block(b) => {
            for s in &b.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
        }
        Stmt::For { init, body, .. } => {
            collect_var_decls_in_stmt(init, acc);
            for s in &body.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            for s in &body.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
        }
        _ => {}
    }
}

pub(super) fn stmt_writes_to_outer_var(
    stmt: &Stmt,
    env: &LoweringEnv,
    body_decls: &HashSet<String>,
    loop_var: &str,
) -> bool {
    match stmt {
        Stmt::CompoundAssign { target, .. } => simple_ident_name(target)
            .map(|name| {
                name != loop_var && env.locals.contains(&name) && !body_decls.contains(&name)
            })
            .unwrap_or(false),
        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            ..
        } => simple_ident_name(target)
            .map(|name| {
                name != loop_var && env.locals.contains(&name) && !body_decls.contains(&name)
            })
            .unwrap_or(false),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var)),
                    Some(ElseBranch::IfElse(s)) => {
                        stmt_writes_to_outer_var(s, env, body_decls, loop_var)
                    }
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var)),
        _ => false,
    }
}

pub(super) fn simple_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// `true` if the body contains a signal/var write whose target is
/// `<comp>.<arr>[<idx>]...` (one or more `Index`-wrappings around a
/// `DotAccess`) where `<comp>` is bound in `env.locals` as a *scalar*
/// component (not in `env.component_arrays`) AND any index in the
/// chain references `loop_var`.
///
/// **Bug Class B trigger.** The instantiator's
/// `LoopUnrollMode::Symbolic` path emits a `SymbolicIndexedEffect`
/// for `comp.arr[i] <== ...` and immediately calls
/// `snapshot_array_slots("comp.arr")`, which fails because no
/// `WitnessArrayDecl` was emitted for sub-component input arrays at
/// component-decl lowering time (`statements/mod.rs::lower_component_decl`
/// only registers the names in `env.locals` / `env.arrays`, not in
/// the IR stream). Forcing eager unroll for these bodies routes the
/// writes through the const-index `LetIndexed` path, which lazily
/// allocates slots via `ensure_array_slot` and works fine.
///
/// Classifier-ordering invariant: this predicate must run AFTER
/// `body_has_component_array_ops` (line 1566) and
/// `body_references_known_arrays` (line 1569). SHA-256's nested
/// sub-component wirings (`sha256compression_0.hin[k] <== ...`)
/// match the syntactic shape post-unroll, but the post-unroll only
/// happens because the outer `for(i)` already eager-unrolled via
/// `ComponentArrayOps`. By the time this predicate could run on
/// SHA-256's inner loop, control has already taken a different
/// branch. Empirically verified by `bug_class_b_discriminate.rs`:
/// SHA-256(64) shows 3 SymIndEff total, all over `paddedIn` (parent-
/// owned), zero over sub-component arrays. Do not reorder this
/// predicate ahead of the higher-priority strategies.
pub(super) fn body_writes_to_subcomponent_array(
    stmts: &[Stmt],
    env: &LoweringEnv,
    loop_var: &str,
) -> bool {
    stmts
        .iter()
        .any(|s| stmt_writes_subcomp_array(s, env, loop_var))
}

pub(super) fn stmt_writes_subcomp_array(stmt: &Stmt, env: &LoweringEnv, loop_var: &str) -> bool {
    match stmt {
        // `<==`, `<--`, `=`: the syntactic LHS is the write destination.
        Stmt::Substitution {
            target,
            op: AssignOp::ConstraintAssign | AssignOp::SignalAssign | AssignOp::Assign,
            ..
        } => target_is_subcomp_array_with_loop_idx(target, env, loop_var),
        // `==>`, `-->`: the destination is on the RHS — `value` —
        // because lowering desugars `src ==> dest` to `dest <== src`.
        // The classifier runs before that swap, so the predicate must
        // mirror it here or sub-component writes through the reverse
        // form (e.g. `S[i] ==> compConstant.in[i]`) slip past the gate
        // and the loop stays rolled, hitting the symbolic-write path
        // at instantiate time with no array decl in scope.
        Stmt::Substitution {
            value,
            op: AssignOp::RConstraintAssign | AssignOp::RSignalAssign,
            ..
        } => target_is_subcomp_array_with_loop_idx(value, env, loop_var),
        Stmt::CompoundAssign { target, .. } => {
            target_is_subcomp_array_with_loop_idx(target, env, loop_var)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            target_is_subcomp_array_with_loop_idx(lhs, env, loop_var)
                || target_is_subcomp_array_with_loop_idx(rhs, env, loop_var)
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_writes_subcomp_array(s, env, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_writes_subcomp_array(s, env, loop_var)),
                    Some(ElseBranch::IfElse(s)) => stmt_writes_subcomp_array(s, env, loop_var),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_writes_subcomp_array(s, env, loop_var)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_writes_subcomp_array(s, env, loop_var)),
        _ => false,
    }
}

/// `true` if `expr` matches `<chain of Index>(DotAccess { Ident(c), f })`
/// where `c` is a scalar component (in `env.locals`, NOT in
/// `env.component_arrays`) and any of the indices along the chain
/// references `loop_var`.
pub(super) fn target_is_subcomp_array_with_loop_idx(
    expr: &Expr,
    env: &LoweringEnv,
    loop_var: &str,
) -> bool {
    let mut indices_have_loop_var = false;
    let mut cur = expr;
    loop {
        match cur {
            Expr::Index { object, index, .. } => {
                if expr_references_ident(index, loop_var) {
                    indices_have_loop_var = true;
                }
                cur = object;
            }
            Expr::DotAccess { object, .. } => match object.as_ref() {
                Expr::Ident { name, .. } => {
                    return indices_have_loop_var
                        && env.locals.contains(name)
                        && !env.component_arrays.contains(name);
                }
                _ => return false,
            },
            _ => return false,
        }
    }
}

/// `true` if the body contains any signal-level statement —
/// constraint/signal assignment, constraint-eq, signal-decl init,
/// or component-decl init. Walks into `IfElse`, nested `Block`, and
/// nested loop bodies (those loops get their own classification
/// when lowered, but a signal op *somewhere* in the tree means we
/// cannot leave the current loop rolled for Lysis Symbolic v1).
pub(super) fn body_has_any_signal_ops(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_any_signal_op)
}

pub(super) fn stmt_has_any_signal_op(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution {
            op:
                AssignOp::ConstraintAssign
                | AssignOp::SignalAssign
                | AssignOp::RConstraintAssign
                | AssignOp::RSignalAssign,
            ..
        } => true,
        Stmt::ConstraintEq { .. } => true,
        Stmt::SignalDecl {
            init: Some((AssignOp::ConstraintAssign | AssignOp::SignalAssign, _)),
            ..
        } => true,
        Stmt::ComponentDecl { init: Some(_), .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.stmts.iter().any(stmt_has_any_signal_op)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_any_signal_op),
                    Some(ElseBranch::IfElse(s)) => stmt_has_any_signal_op(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_any_signal_op),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_any_signal_op)
        }
        _ => false,
    }
}

/// `true` if the body contains any `arr[idx]` expression — as an
/// assignment target or anywhere inside an expression — whose
/// `idx` references `loop_var`. Covers reads (`in[i]`,
/// `comp.x[i]`), writes (`out[i] <== ...`), and mixed uses
/// (`sum += in[i] * K[i]`).
///
/// Walks into `IfElse`, nested `Block`, `CompoundAssign` and
/// `Substitution` RHS expressions. Does not descend into nested
/// `For` loops — those are classified separately when they are
/// lowered.
pub(super) fn body_has_loop_var_indexed_assignments(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_loop_var_dependent_index(s, loop_var))
}

pub(super) fn stmt_has_loop_var_dependent_index(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_has_loop_var_indexed(target, loop_var)
                || expr_has_loop_var_indexed(value, loop_var)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_has_loop_var_indexed(target, loop_var)
                || expr_has_loop_var_indexed(value, loop_var)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_has_loop_var_indexed(lhs, loop_var) || expr_has_loop_var_indexed(rhs, loop_var)
        }
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .is_some_and(|v| expr_has_loop_var_indexed(v, loop_var)),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_loop_var_indexed(condition, loop_var)
                || then_body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_loop_var_dependent_index(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => stmt_has_loop_var_dependent_index(s, loop_var),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
        // Descend into nested `for` / `while` / `do-while` bodies
        // keeping the same target `loop_var`. A nested loop's own
        // iterator is a different name, so references to the outer
        // `loop_var` inside the inner body are exactly what we need
        // to detect (e.g., BinSum's
        // `for (k) { for (j) { lin += in[j][k] * e2 } }`).
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
        _ => false,
    }
}

/// `true` if `expr` contains an `Expr::Index { index }` anywhere in
/// its subtree whose `index` references `loop_var`.
pub(super) fn expr_has_loop_var_indexed(expr: &Expr, loop_var: &str) -> bool {
    match expr {
        Expr::Index { object, index, .. } => {
            expr_references_ident(index, loop_var) || expr_has_loop_var_indexed(object, loop_var)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            expr_has_loop_var_indexed(lhs, loop_var) || expr_has_loop_var_indexed(rhs, loop_var)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_loop_var_indexed(operand, loop_var),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_has_loop_var_indexed(condition, loop_var)
                || expr_has_loop_var_indexed(if_true, loop_var)
                || expr_has_loop_var_indexed(if_false, loop_var)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_has_loop_var_indexed(a, loop_var)),
        Expr::DotAccess { object, .. } => expr_has_loop_var_indexed(object, loop_var),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => elements
            .iter()
            .any(|e| expr_has_loop_var_indexed(e, loop_var)),
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args
                .iter()
                .any(|a| expr_has_loop_var_indexed(a, loop_var))
                || signal_args
                    .iter()
                    .any(|a| expr_has_loop_var_indexed(&a.value, loop_var))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Ident { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
}

pub(super) fn expr_references_ident(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Ident { name: n, .. } => n == name,
        Expr::BinOp { lhs, rhs, .. } => {
            expr_references_ident(lhs, name) || expr_references_ident(rhs, name)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_references_ident(operand, name),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_references_ident(condition, name)
                || expr_references_ident(if_true, name)
                || expr_references_ident(if_false, name)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_references_ident(a, name)),
        Expr::Index { object, index, .. } => {
            expr_references_ident(object, name) || expr_references_ident(index, name)
        }
        Expr::DotAccess { object, .. } => expr_references_ident(object, name),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(|e| expr_references_ident(e, name))
        }
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args.iter().any(|a| expr_references_ident(a, name))
                || signal_args
                    .iter()
                    .any(|a| expr_references_ident(&a.value, name))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
}
