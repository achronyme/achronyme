//! Pure free-function helpers used across submodules.
//!
//! - [`eval_const_expr`] — fold an expression to a compile-time integer
//!   using the lift state's `const_locals` map. Returns `None` for
//!   anything signal- or runtime-dependent.
//! - [`extract_call_name`] — pull a bare identifier out of a call's
//!   `callee` expression.
//! - [`is_increment_on`] — shape check for `name++` / `++name`.
//! - [`stmts_are_mux_compatible`] / [`stmt_is_mux_compatible`] /
//!   [`expr_is_mux_compatible`] — pre-flight for the runtime mux pass:
//!   reject arms with `return`, array writes, witness writes, or
//!   non-scalar assignment targets.
//! - [`compound_to_binop`] — map a compound-assignment operator to the
//!   plain binary op the lift knows how to emit.

use std::collections::HashMap;

use artik::{ElemT, RegType};

use crate::ast::{BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt, UnaryOp};

use super::ConstInt;

/// Evaluate an expression to a compile-time integer. Used for loop
/// bounds and step amounts. Looks up identifiers in the provided
/// `const_locals` map; signals / runtime-valued locals return `None`.
pub(super) fn eval_const_expr(
    expr: &Expr,
    const_locals: &HashMap<String, ConstInt>,
) -> Option<ConstInt> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            ConstInt::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
        }
        Expr::Ident { name, .. } => const_locals.get(name).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = eval_const_expr(lhs, const_locals)?;
            let b = eval_const_expr(rhs, const_locals)?;
            match op {
                BinOp::Add => a.checked_add(b),
                BinOp::Sub => a.checked_sub(b),
                BinOp::Mul => a.checked_mul(b),
                // Comparisons return 1 / 0 so `if (i == 0) { ... }`
                // inside an unrolled loop folds correctly.
                BinOp::Eq => Some((a == b) as ConstInt),
                BinOp::Neq => Some((a != b) as ConstInt),
                BinOp::Lt => Some((a < b) as ConstInt),
                BinOp::Le => Some((a <= b) as ConstInt),
                BinOp::Gt => Some((a > b) as ConstInt),
                BinOp::Ge => Some((a >= b) as ConstInt),
                // Boolean connectives — both operands already folded to
                // ConstInt above (any non-zero value reads as true), so
                // the result is the usual integer logic-op. Circomlib's
                // shape-guard asserts like
                // `(n == 86 && k == 3) || (n == 64 && k == 4)` need
                // these to fold; without them the lift would treat the
                // predicate as runtime and bail.
                BinOp::And => Some(((a != 0) && (b != 0)) as ConstInt),
                BinOp::Or => Some(((a != 0) || (b != 0)) as ConstInt),
                _ => None,
            }
        }
        Expr::UnaryOp {
            op: UnaryOp::Neg,
            operand,
            ..
        } => eval_const_expr(operand, const_locals).and_then(ConstInt::checked_neg),
        _ => None,
    }
}

/// Extract the simple identifier from a call's `callee` expression.
/// Circom's function-call callees are always bare identifiers at the
/// lowering layer; anything more complex (method access, indexed
/// callable, etc.) bails out of the lift.
pub(super) fn extract_call_name(callee: &Expr) -> Option<String> {
    match callee {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Whether `expr` is the integer literal `1`. The literal-`1` base is
/// the discriminator between circom's field-precision power-of-two
/// (`1 << n`, lowered to `FPow2`) and a fixed-width bit-packing shift
/// (a signal / limb base shifted by a small amount, e.g. SHA-256's
/// `hin[..] << j`), which stays on the width-masked integer path.
pub(super) fn expr_is_one(expr: &Expr) -> bool {
    match expr {
        Expr::Number { value, .. } => value == "1",
        Expr::HexNumber { value, .. } => {
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            trimmed == "1"
        }
        _ => false,
    }
}

/// Recognize the shape `1 << <const k>` and return the shift amount
/// `k` if it fits in `0..=253`. Used by the IntDiv / Mod lift to detect
/// a compile-time-power-of-2 divisor without going through
/// `eval_const_expr` (which can't represent values exceeding `i64`,
/// such as `1 << 64`).
pub(super) fn match_one_shl_const(
    expr: &Expr,
    const_locals: &HashMap<String, ConstInt>,
) -> Option<u32> {
    let Expr::BinOp {
        op: BinOp::ShiftL,
        lhs,
        rhs,
        ..
    } = expr
    else {
        return None;
    };
    if !expr_is_one(lhs.as_ref()) {
        return None;
    }
    let k = eval_const_expr(rhs, const_locals)?;
    if !(0..=253).contains(&k) {
        return None;
    }
    Some(k as u32)
}

/// Is `expr` an increment on the named variable (`name++` or `++name`)?
pub(super) fn is_increment_on(expr: &Expr, name: &str) -> bool {
    let (op, operand) = match expr {
        Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => (op, operand),
        _ => return false,
    };
    if !matches!(op, PostfixOp::Increment) {
        return false;
    }
    matches!(operand.as_ref(), Expr::Ident { name: n, .. } if n == name)
}

/// Is `expr` a decrement on the named variable (`name--` or `--name`)?
pub(super) fn is_decrement_on(expr: &Expr, name: &str) -> bool {
    let (op, operand) = match expr {
        Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => (op, operand),
        _ => return false,
    };
    if !matches!(op, PostfixOp::Decrement) {
        return false;
    }
    matches!(operand.as_ref(), Expr::Ident { name: n, .. } if n == name)
}

/// Are all of `stmts` safe to lift under the mux scheme (both arms
/// executing unconditionally at runtime)?
pub(super) fn stmts_are_mux_compatible(stmts: &[Stmt]) -> bool {
    stmts.iter().all(stmt_is_mux_compatible)
}

/// Shape check for a single branch statement. The mux scheme runs
/// both arms of an if/else at runtime and picks the output of the
/// "taken" arm via field arithmetic, so only side-effect-free
/// statements are admissible:
/// - scalar `var` decls / `=` / compound-assign (no array writes),
/// - nested if/else (recursively checked),
/// - bare postfix/prefix side effects on pure expressions.
///
/// `return`, array stores, and tuple destructuring bail out of the mux
/// pass; the caller falls back to E212.
pub(super) fn stmt_is_mux_compatible(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::VarDecl {
            names,
            dimensions,
            init,
            ..
        } => {
            names.len() == 1
                && dimensions.is_empty()
                && init.as_ref().is_none_or(expr_is_mux_compatible)
        }
        Stmt::Substitution { target, value, .. } => {
            matches!(target, Expr::Ident { .. }) && expr_is_mux_compatible(value)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            matches!(target, Expr::Ident { .. }) && expr_is_mux_compatible(value)
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_is_mux_compatible(condition)
                && stmts_are_mux_compatible(&then_body.stmts)
                && match else_body {
                    Some(ElseBranch::Block(b)) => stmts_are_mux_compatible(&b.stmts),
                    Some(ElseBranch::IfElse(boxed)) => stmt_is_mux_compatible(boxed),
                    None => true,
                }
        }
        Stmt::Expr { expr, .. } => expr_is_mux_compatible(expr),
        _ => false,
    }
}

/// Is `expr` side-effect-free enough to evaluate on both arms of a
/// runtime mux? Calls bail out: a nested lift could still read
/// signals or emit work that's fine in isolation, but we keep the
/// MVP conservative and only admit pure register arithmetic.
fn expr_is_mux_compatible(expr: &Expr) -> bool {
    match expr {
        Expr::Number { .. } | Expr::HexNumber { .. } | Expr::Ident { .. } => true,
        Expr::BinOp { lhs, rhs, .. } => expr_is_mux_compatible(lhs) && expr_is_mux_compatible(rhs),
        Expr::UnaryOp { operand, .. } => expr_is_mux_compatible(operand),
        Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            expr_is_mux_compatible(operand)
        }
        Expr::Index { object, index, .. } => {
            // `arr[i]` reads from a pre-allocated array; both arms do
            // the read but only one result is selected.
            expr_is_mux_compatible(object) && expr_is_mux_compatible(index)
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_is_mux_compatible(condition)
                && expr_is_mux_compatible(if_true)
                && expr_is_mux_compatible(if_false)
        }
        // Function calls are opaque: an inlined callee may emit a
        // faulting opcode (e.g. `FIDiv` on a zero divisor inside a
        // `\` op) whose validity hinges on the runtime guard the
        // caller wrapped around the call. Mux execution runs both
        // arms, so the not-taken arm's call still executes its body
        // and can fault. Route calls through the branching lift,
        // which honours the guard.
        Expr::Call { .. } => false,
        _ => false,
    }
}

/// Collect the names of identifiers reassigned in `stmts`. Used by the
/// `while` lift to decide which scalars need slot-promotion across
/// loop iterations. Indexed assignments and array stores are
/// reported via `array_writes`; the `while` lift bails when those are
/// non-empty (heap arrays already persist across iterations, but
/// declaring a *new* array inside the body would re-allocate every
/// iteration and is rejected upstream).
pub(super) fn collect_mutated_scalars(stmts: &[Stmt]) -> MutationSummary {
    let mut summary = MutationSummary::default();
    for stmt in stmts {
        walk_stmt(stmt, &mut summary);
    }
    summary
}

#[derive(Default)]
pub(super) struct MutationSummary {
    /// Identifiers that appear as the target of `=`, `+=`, `++`, etc.
    pub scalars: std::collections::HashSet<String>,
    /// Identifiers used as the array side of `arr[i] = expr` or
    /// `arr[i] += expr` — the lift permits these inside `while`
    /// because Artik arrays are heap-resident.
    pub array_writes: std::collections::HashSet<String>,
    /// Set when the body re-declares an array via `var arr[N];`. The
    /// `while` lift rejects this — re-declaring an array each
    /// iteration would leak heap memory.
    pub declares_array: bool,
    /// Names introduced via a sized `var arr[N];` declaration. Lets
    /// the if/else slot merge tell array-typed targets apart from
    /// genuine scalars — `arr = call(...)` reads as a substitution
    /// against an `Ident` target syntactically, but the underlying
    /// shape is a heap rebind that doesn't need a slot.
    pub fresh_array_decls: std::collections::HashSet<String>,
    /// Set when the body emits a `<--` style witness write (currently
    /// not exposed inside circom function bodies, but kept so the
    /// detection grows cleanly if the AST adds the form).
    pub writes_witness: bool,
    /// Identifiers introduced via scalar `var x = ...;` — distinct
    /// from the pre-loop scope. The lift uses this to decide whether a
    /// reference inside the body refers to a fresh local or to one
    /// that needs slot promotion.
    pub fresh_decls: std::collections::HashSet<String>,
}

fn walk_stmt(stmt: &Stmt, out: &mut MutationSummary) {
    match stmt {
        Stmt::VarDecl {
            names, dimensions, ..
        } => {
            if !dimensions.is_empty() {
                out.declares_array = true;
                for name in names {
                    out.fresh_array_decls.insert(name.clone());
                }
            } else {
                for name in names {
                    out.fresh_decls.insert(name.clone());
                }
            }
        }
        Stmt::Substitution { target, .. } => {
            collect_assignment_target(target, out);
        }
        Stmt::CompoundAssign { target, .. } => {
            collect_assignment_target(target, out);
        }
        Stmt::Expr { expr, .. } => collect_side_effect_target(expr, out),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            for s in &then_body.stmts {
                walk_stmt(s, out);
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        walk_stmt(s, out);
                    }
                }
                Some(ElseBranch::IfElse(boxed)) => walk_stmt(boxed, out),
                None => {}
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            walk_stmt(init, out);
            walk_stmt(step, out);
            for s in &body.stmts {
                walk_stmt(s, out);
            }
        }
        Stmt::While { body, .. } => {
            for s in &body.stmts {
                walk_stmt(s, out);
            }
        }
        Stmt::Return { .. } | Stmt::Block(_) | Stmt::Assert { .. } | Stmt::Log { .. } => {}
        _ => {}
    }
}

fn collect_assignment_target(target: &Expr, out: &mut MutationSummary) {
    match target {
        Expr::Ident { name, .. } => {
            out.scalars.insert(name.clone());
        }
        Expr::Index { object, .. } => {
            if let Expr::Ident { name, .. } = object.as_ref() {
                out.array_writes.insert(name.clone());
            }
        }
        _ => {}
    }
}

fn collect_side_effect_target(expr: &Expr, out: &mut MutationSummary) {
    if let Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } = expr {
        if let Expr::Ident { name, .. } = operand.as_ref() {
            out.scalars.insert(name.clone());
        }
    }
}

/// Does any statement in `stmts` (recursively) execute a `return`?
/// The `if/else` lift needs this to decide whether the mux merge is
/// safe — a returning arm can't merge branchlessly, so the lift falls
/// back to a real conditional jump.
pub(super) fn stmts_have_return(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_return)
}

pub(super) fn stmt_has_return(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return { .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            stmts_have_return(&then_body.stmts)
                || match else_body {
                    Some(ElseBranch::Block(b)) => stmts_have_return(&b.stmts),
                    Some(ElseBranch::IfElse(boxed)) => stmt_has_return(boxed),
                    None => false,
                }
        }
        Stmt::For { body, .. } => stmts_have_return(&body.stmts),
        Stmt::While { body, .. } => stmts_have_return(&body.stmts),
        Stmt::Block(b) => stmts_have_return(&b.stmts),
        _ => false,
    }
}

/// Collect every `var arr[...]` declaration the body would otherwise
/// execute on each loop iteration. Walks recursively into if/else,
/// for, while, and block bodies. Used by the runtime-while lift to
/// hoist the allocations out of the loop body — without hoisting,
/// each iter emits a fresh `AllocArray` and the heap explodes
/// quadratically (256 iters × ~3 arrays × 200 cells crosses the
/// per-program memory cap).
pub(super) fn collect_array_decls<'a>(stmts: &'a [Stmt], out: &mut Vec<&'a Stmt>) {
    for s in stmts {
        collect_array_decls_in_stmt(s, out);
    }
}

fn collect_array_decls_in_stmt<'a>(stmt: &'a Stmt, out: &mut Vec<&'a Stmt>) {
    match stmt {
        Stmt::VarDecl { dimensions, .. } if !dimensions.is_empty() => out.push(stmt),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            collect_array_decls(&then_body.stmts, out);
            match else_body {
                Some(ElseBranch::Block(b)) => collect_array_decls(&b.stmts, out),
                Some(ElseBranch::IfElse(boxed)) => collect_array_decls_in_stmt(boxed, out),
                None => {}
            }
        }
        Stmt::For { body, .. } => collect_array_decls(&body.stmts, out),
        Stmt::While { body, .. } => collect_array_decls(&body.stmts, out),
        Stmt::Block(b) => collect_array_decls(&b.stmts, out),
        _ => {}
    }
}

/// Result of pre-scanning a function body to determine the shape
/// of its array returns. Reported to the nested-call lift so the
/// destination slot can be allocated at frame entry rather than
/// lazily inside a conditional arm.
pub(super) enum ArrayReturnScan {
    /// Every `return` in the body is array-shaped (either an
    /// `Expr::ArrayLit` or a bare `Expr::Ident` referencing a
    /// `var X[K]` declaration whose dim folds against the callee's
    /// param consts) and they all have the same length `n`.
    Fixed(u32),
    /// The body contains at least one `return` whose shape can't be
    /// resolved at lift time, or two array-shaped returns with
    /// disagreeing lengths. The nested-call lift must skip the
    /// array-slot fast path in this case.
    Other,
}

/// Pre-scan a function body for array-shaped returns. Walks
/// recursively into compound statements (`if/else`, `for`, `while`,
/// `do/while`, bare blocks). Two passes:
///
/// 1. Collect 1D `var X[K]` declarations across the whole body into
///    a `name → len` map. Circom hoists `var` to function scope, so
///    decls inside conditional arms are visible to returns in any
///    other arm. Multiple names with the same dim are fine; the
///    same name appearing twice with disagreeing dims is treated as
///    non-homogeneous and forces a bail.
/// 2. Walk each `return` and resolve its shape:
///    - `Expr::ArrayLit` → length is the literal cell count.
///    - `Expr::Ident` → look up in the dim map.
///    - anything else → bail.
///
/// All resolved lengths must agree on a single `n`; otherwise the
/// caller has to fall back to the legacy emit-per-return path,
/// which is still semantically buggy but unchanged from today.
pub(super) fn scan_array_returns(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
) -> ArrayReturnScan {
    let mut dim_map: HashMap<String, u32> = HashMap::new();
    let mut consistent = true;
    collect_array_dims(stmts, param_consts, &mut dim_map, &mut consistent);
    if !consistent {
        return ArrayReturnScan::Other;
    }

    let mut found: Option<u32> = None;
    let mut homogeneous = true;
    walk_returns(stmts, &dim_map, &mut found, &mut homogeneous);
    if !homogeneous {
        return ArrayReturnScan::Other;
    }
    let Some(n) = found else {
        return ArrayReturnScan::Other;
    };

    // A single `return` at the top level of the body lifts to exactly
    // one nested_result-setting site, and the handle it records is
    // the one whichever runtime path produces. The legacy emit-per-
    // return path is correct in that case, and the per-cell copy the
    // slot path emits would add hundreds of registers per call —
    // enough to push deep nested-call chains past the executor's
    // frame budget. Reserve the slot only when there are multiple
    // potential return sites (more than one `Stmt::Return`, or any
    // return nested inside a conditional or loop body where the lift
    // walks it more than once).
    let mut top_level_returns: u32 = 0;
    let mut nested_returns: u32 = 0;
    count_returns(stmts, true, &mut top_level_returns, &mut nested_returns);
    if nested_returns == 0 && top_level_returns <= 1 {
        return ArrayReturnScan::Other;
    }
    ArrayReturnScan::Fixed(n)
}

fn count_returns(stmts: &[Stmt], at_top_level: bool, top_level: &mut u32, nested: &mut u32) {
    for stmt in stmts {
        count_returns_in_stmt(stmt, at_top_level, top_level, nested);
    }
}

fn count_returns_in_stmt(stmt: &Stmt, at_top_level: bool, top_level: &mut u32, nested: &mut u32) {
    match stmt {
        Stmt::Return { .. } => {
            if at_top_level {
                *top_level += 1;
            } else {
                *nested += 1;
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            count_returns(&then_body.stmts, false, top_level, nested);
            match else_body {
                Some(ElseBranch::Block(b)) => count_returns(&b.stmts, false, top_level, nested),
                Some(ElseBranch::IfElse(boxed)) => {
                    count_returns_in_stmt(boxed, false, top_level, nested)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => count_returns(&body.stmts, false, top_level, nested),
        Stmt::While { body, .. } => count_returns(&body.stmts, false, top_level, nested),
        Stmt::DoWhile { body, .. } => count_returns(&body.stmts, false, top_level, nested),
        Stmt::Block(b) => count_returns(&b.stmts, at_top_level, top_level, nested),
        _ => {}
    }
}

fn collect_array_dims(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &mut HashMap<String, u32>,
    consistent: &mut bool,
) {
    for stmt in stmts {
        collect_array_dims_in_stmt(stmt, param_consts, dim_map, consistent);
        if !*consistent {
            return;
        }
    }
}

fn collect_array_dims_in_stmt(
    stmt: &Stmt,
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &mut HashMap<String, u32>,
    consistent: &mut bool,
) {
    match stmt {
        Stmt::VarDecl {
            names, dimensions, ..
        } if dimensions.len() == 1 && names.len() == 1 => {
            let name = &names[0];
            let len = match eval_const_expr(&dimensions[0], param_consts)
                .and_then(|v| u32::try_from(v).ok())
            {
                Some(v) => v,
                None => return,
            };
            match dim_map.get(name) {
                Some(prev) if *prev != len => *consistent = false,
                _ => {
                    dim_map.insert(name.clone(), len);
                }
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            collect_array_dims(&then_body.stmts, param_consts, dim_map, consistent);
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    collect_array_dims(&b.stmts, param_consts, dim_map, consistent)
                }
                Some(ElseBranch::IfElse(boxed)) => {
                    collect_array_dims_in_stmt(boxed, param_consts, dim_map, consistent)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => {
            collect_array_dims(&body.stmts, param_consts, dim_map, consistent)
        }
        Stmt::While { body, .. } => {
            collect_array_dims(&body.stmts, param_consts, dim_map, consistent)
        }
        Stmt::DoWhile { body, .. } => {
            collect_array_dims(&body.stmts, param_consts, dim_map, consistent)
        }
        Stmt::Block(b) => collect_array_dims(&b.stmts, param_consts, dim_map, consistent),
        _ => {}
    }
}

fn walk_returns(
    stmts: &[Stmt],
    dim_map: &HashMap<String, u32>,
    found: &mut Option<u32>,
    homogeneous: &mut bool,
) {
    for stmt in stmts {
        walk_returns_in_stmt(stmt, dim_map, found, homogeneous);
        if !*homogeneous {
            return;
        }
    }
}

fn walk_returns_in_stmt(
    stmt: &Stmt,
    dim_map: &HashMap<String, u32>,
    found: &mut Option<u32>,
    homogeneous: &mut bool,
) {
    match stmt {
        Stmt::Return { value, .. } => {
            let len_opt = match value {
                Expr::ArrayLit { elements, .. } => u32::try_from(elements.len()).ok(),
                Expr::Ident { name, .. } => dim_map.get(name).copied(),
                _ => None,
            };
            let len = match len_opt {
                Some(v) => v,
                None => {
                    *homogeneous = false;
                    return;
                }
            };
            match *found {
                None => *found = Some(len),
                Some(prev) if prev == len => {}
                Some(_) => *homogeneous = false,
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            walk_returns(&then_body.stmts, dim_map, found, homogeneous);
            match else_body {
                Some(ElseBranch::Block(b)) => walk_returns(&b.stmts, dim_map, found, homogeneous),
                Some(ElseBranch::IfElse(boxed)) => {
                    walk_returns_in_stmt(boxed, dim_map, found, homogeneous)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => walk_returns(&body.stmts, dim_map, found, homogeneous),
        Stmt::While { body, .. } => walk_returns(&body.stmts, dim_map, found, homogeneous),
        Stmt::DoWhile { body, .. } => walk_returns(&body.stmts, dim_map, found, homogeneous),
        Stmt::Block(b) => walk_returns(&b.stmts, dim_map, found, homogeneous),
        _ => {}
    }
}

/// Map a circom compound-assignment operator to the plain binary op
/// the lift knows how to emit. Returns `None` for unsupported shapes.
pub(super) fn compound_to_binop(op: CompoundOp) -> Option<BinOp> {
    match op {
        CompoundOp::Add => Some(BinOp::Add),
        CompoundOp::Sub => Some(BinOp::Sub),
        CompoundOp::Mul => Some(BinOp::Mul),
        CompoundOp::Div => Some(BinOp::Div),
        CompoundOp::ShiftL => Some(BinOp::ShiftL),
        CompoundOp::ShiftR => Some(BinOp::ShiftR),
        CompoundOp::BitAnd => Some(BinOp::BitAnd),
        CompoundOp::BitOr => Some(BinOp::BitOr),
        CompoundOp::BitXor => Some(BinOp::BitXor),
        _ => None,
    }
}

/// Return shape of a circom function, classified so the caller can
/// derive the register types a subprogram with this body exposes.
///
/// Arrays cross the subprogram `Call` / `Return` boundary as a single
/// handle into the program-global array store, so every array variant
/// collapses to one `Array(Field)` register at the ABI. The
/// dimensional detail kept here drives the call-site re-bundling (one
/// flat `LetArray` plus row-major strides for 2D), not the register
/// count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CalleeReturnShape {
    /// Every `return` yields a single field value.
    Scalar,
    /// Every `return` yields a 1D array of `len` field cells.
    Array(u32),
    /// Every `return` yields a `rows × cols` field array.
    Array2D(u32, u32),
    /// The shape is not statically resolvable: a runtime-dimensioned
    /// array, returns of disagreeing shape, a forwarded call result,
    /// or a return expression whose shape the classifier does not
    /// model. A subprogram cannot be reserved for such a body.
    Other,
}

impl CalleeReturnShape {
    /// Register types a subprogram with this return shape exposes.
    /// Scalars are one `Field`; every array variant is one
    /// `Array(Field)` handle. `Other` has no representable signature.
    pub(super) fn to_reg_types(self) -> Option<Vec<RegType>> {
        match self {
            Self::Scalar => Some(vec![RegType::Field]),
            Self::Array(_) | Self::Array2D(..) => Some(vec![RegType::Array(ElemT::Field)]),
            Self::Other => None,
        }
    }
}

/// Dimensions of a body-scoped `var X[..]` declaration that fold
/// against the callee's param consts.
#[derive(Clone, Copy)]
enum DeclDim {
    D1(u32),
    D2(u32, u32),
}

/// Classify what every `return` in `stmts` yields. Circom hoists
/// `var` declarations to function scope, so a `var X[K]` in any arm
/// is visible to a `return X;` in another; the first pass collects
/// those dimensions, the second resolves each `return` against them.
///
/// Unlike [`scan_array_returns`] there is no single-return special
/// case: a subprogram return is a real `Return` instruction regardless
/// of how many `return` sites the body has, so the return-count gate
/// that path needs does not apply here. Every `return` must resolve to
/// the same shape; any unresolved or disagreeing return yields
/// [`CalleeReturnShape::Other`].
pub(super) fn infer_callee_return_shape(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
) -> CalleeReturnShape {
    // `None` value = a name declared as an array whose dimension does
    // not fold against the param consts. Returning such a name is
    // unresolvable (the subprogram cannot reserve a fixed handle
    // shape), so it must classify as `Other` rather than fall through
    // to the scalar default.
    let mut dim_map: HashMap<String, Option<DeclDim>> = HashMap::new();
    let mut consistent = true;
    collect_return_dims(stmts, param_consts, &mut dim_map, &mut consistent);
    if !consistent {
        return CalleeReturnShape::Other;
    }

    let mut found: Option<CalleeReturnShape> = None;
    let mut ok = true;
    classify_returns(stmts, &dim_map, &mut found, &mut ok);
    if !ok {
        return CalleeReturnShape::Other;
    }
    found.unwrap_or(CalleeReturnShape::Other)
}

fn collect_return_dims(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &mut HashMap<String, Option<DeclDim>>,
    consistent: &mut bool,
) {
    for stmt in stmts {
        collect_return_dims_in_stmt(stmt, param_consts, dim_map, consistent);
        if !*consistent {
            return;
        }
    }
}

fn collect_return_dims_in_stmt(
    stmt: &Stmt,
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &mut HashMap<String, Option<DeclDim>>,
    consistent: &mut bool,
) {
    let fold = |e: &Expr| eval_const_expr(e, param_consts).and_then(|v| u32::try_from(v).ok());
    match stmt {
        Stmt::VarDecl {
            names, dimensions, ..
        } if names.len() == 1 && (dimensions.len() == 1 || dimensions.len() == 2) => {
            let name = &names[0];
            let dim: Option<DeclDim> = if dimensions.len() == 1 {
                fold(&dimensions[0]).map(DeclDim::D1)
            } else {
                match (fold(&dimensions[0]), fold(&dimensions[1])) {
                    (Some(r), Some(c)) => Some(DeclDim::D2(r, c)),
                    _ => None,
                }
            };
            match (dim_map.get(name), dim) {
                (Some(Some(DeclDim::D1(p))), Some(DeclDim::D1(n))) if *p != n => {
                    *consistent = false
                }
                (Some(Some(DeclDim::D2(pr, pc))), Some(DeclDim::D2(r, c)))
                    if (*pr, *pc) != (r, c) =>
                {
                    *consistent = false
                }
                (Some(Some(DeclDim::D1(_))), Some(DeclDim::D2(..)))
                | (Some(Some(DeclDim::D2(..))), Some(DeclDim::D1(_))) => *consistent = false,
                // A later unresolved decl of an already-array name keeps
                // it unresolvable; otherwise record this decl's dim
                // (resolved or not — `None` marks a runtime dimension).
                (Some(None), _) => {
                    dim_map.insert(name.clone(), None);
                }
                _ => {
                    dim_map.insert(name.clone(), dim);
                }
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            collect_return_dims(&then_body.stmts, param_consts, dim_map, consistent);
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    collect_return_dims(&b.stmts, param_consts, dim_map, consistent)
                }
                Some(ElseBranch::IfElse(boxed)) => {
                    collect_return_dims_in_stmt(boxed, param_consts, dim_map, consistent)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => {
            collect_return_dims(&body.stmts, param_consts, dim_map, consistent)
        }
        Stmt::While { body, .. } => {
            collect_return_dims(&body.stmts, param_consts, dim_map, consistent)
        }
        Stmt::DoWhile { body, .. } => {
            collect_return_dims(&body.stmts, param_consts, dim_map, consistent)
        }
        Stmt::Block(b) => collect_return_dims(&b.stmts, param_consts, dim_map, consistent),
        _ => {}
    }
}

fn classify_returns(
    stmts: &[Stmt],
    dim_map: &HashMap<String, Option<DeclDim>>,
    found: &mut Option<CalleeReturnShape>,
    ok: &mut bool,
) {
    for stmt in stmts {
        classify_returns_in_stmt(stmt, dim_map, found, ok);
        if !*ok {
            return;
        }
    }
}

fn classify_returns_in_stmt(
    stmt: &Stmt,
    dim_map: &HashMap<String, Option<DeclDim>>,
    found: &mut Option<CalleeReturnShape>,
    ok: &mut bool,
) {
    match stmt {
        Stmt::Return { value, .. } => {
            let shape = match classify_return_expr(value, dim_map) {
                Some(s) => s,
                None => {
                    *ok = false;
                    return;
                }
            };
            match *found {
                None => *found = Some(shape),
                Some(prev) if prev == shape => {}
                Some(_) => *ok = false,
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            classify_returns(&then_body.stmts, dim_map, found, ok);
            match else_body {
                Some(ElseBranch::Block(b)) => classify_returns(&b.stmts, dim_map, found, ok),
                Some(ElseBranch::IfElse(boxed)) => {
                    classify_returns_in_stmt(boxed, dim_map, found, ok)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => classify_returns(&body.stmts, dim_map, found, ok),
        Stmt::While { body, .. } => classify_returns(&body.stmts, dim_map, found, ok),
        Stmt::DoWhile { body, .. } => classify_returns(&body.stmts, dim_map, found, ok),
        Stmt::Block(b) => classify_returns(&b.stmts, dim_map, found, ok),
        _ => {}
    }
}

/// Resolve the shape of a single `return <expr>;`. `None` means the
/// shape is not modelled (the whole classification then yields
/// `Other`). A forwarded call result is deliberately unresolved here —
/// resolving it requires the callee registry, which the classifier
/// does not have.
fn classify_return_expr(
    value: &Expr,
    dim_map: &HashMap<String, Option<DeclDim>>,
) -> Option<CalleeReturnShape> {
    match value {
        Expr::ArrayLit { elements, .. } => {
            if elements.iter().any(|e| matches!(e, Expr::ArrayLit { .. })) {
                // Nested array literals would need per-row length
                // agreement to be a clean 2D shape; treat as unmodelled
                // rather than guess.
                return None;
            }
            u32::try_from(elements.len())
                .ok()
                .map(CalleeReturnShape::Array)
        }
        Expr::Ident { name, .. } => match dim_map.get(name) {
            Some(Some(DeclDim::D1(n))) => Some(CalleeReturnShape::Array(*n)),
            Some(Some(DeclDim::D2(r, c))) => Some(CalleeReturnShape::Array2D(*r, *c)),
            // Declared as an array but with a runtime dimension: the
            // subprogram cannot reserve a fixed handle shape.
            Some(None) => None,
            // No array declaration in scope: a scalar local / parameter.
            None => Some(CalleeReturnShape::Scalar),
        },
        Expr::Ternary {
            if_true, if_false, ..
        } => {
            let a = classify_return_expr(if_true, dim_map)?;
            let b = classify_return_expr(if_false, dim_map)?;
            (a == b).then_some(a)
        }
        // A forwarded call result resolves to the callee's shape, which
        // the classifier cannot see.
        Expr::Call { .. } => None,
        // Numbers, arithmetic, an indexed element read, and unary /
        // postfix forms all produce a single field value.
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::BinOp { .. }
        | Expr::UnaryOp { .. }
        | Expr::PostfixOp { .. }
        | Expr::PrefixOp { .. }
        | Expr::Index { .. } => Some(CalleeReturnShape::Scalar),
        _ => None,
    }
}

/// The array-dimension signature of a function body: every `var X[..]`
/// declaration's folded dimensions, concatenated in pre-order
/// source-traversal order. `None` if any dimension does not fold
/// against the param consts — a runtime array dimension means no
/// fixed-shape subprogram can be reserved for the body.
///
/// This is the subprogram specialization key. Two instantiations of
/// the same circom function whose array dimensions fold to the same
/// values share one subprogram; instantiations that differ in any
/// dimension get distinct ones. The traversal order is fixed
/// (statements in source order, `then` before `else`, recursing into
/// compound bodies), so a given body always produces the same `Vec`
/// and equality on it is a sound dedup key regardless of which call
/// site triggered the lift.
pub(super) fn compute_dim_signature(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
) -> Option<Vec<u32>> {
    let mut sig = Vec::new();
    let mut ok = true;
    collect_dim_signature(stmts, param_consts, &mut sig, &mut ok);
    ok.then_some(sig)
}

fn collect_dim_signature(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
    sig: &mut Vec<u32>,
    ok: &mut bool,
) {
    for stmt in stmts {
        collect_dim_signature_in_stmt(stmt, param_consts, sig, ok);
        if !*ok {
            return;
        }
    }
}

fn collect_dim_signature_in_stmt(
    stmt: &Stmt,
    param_consts: &HashMap<String, ConstInt>,
    sig: &mut Vec<u32>,
    ok: &mut bool,
) {
    match stmt {
        Stmt::VarDecl { dimensions, .. } if !dimensions.is_empty() => {
            for d in dimensions {
                match eval_const_expr(d, param_consts).and_then(|v| u32::try_from(v).ok()) {
                    Some(n) => sig.push(n),
                    None => {
                        *ok = false;
                        return;
                    }
                }
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            collect_dim_signature(&then_body.stmts, param_consts, sig, ok);
            if !*ok {
                return;
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    collect_dim_signature(&b.stmts, param_consts, sig, ok)
                }
                Some(ElseBranch::IfElse(boxed)) => {
                    collect_dim_signature_in_stmt(boxed, param_consts, sig, ok)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => collect_dim_signature(&body.stmts, param_consts, sig, ok),
        Stmt::While { body, .. } => collect_dim_signature(&body.stmts, param_consts, sig, ok),
        Stmt::DoWhile { body, .. } => collect_dim_signature(&body.stmts, param_consts, sig, ok),
        Stmt::Block(b) => collect_dim_signature(&b.stmts, param_consts, sig, ok),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Definition;
    use crate::parser::parse_circom;

    fn parse_body(body_src: &str) -> Vec<Stmt> {
        let src = format!("function probe(c, x, n, a, cond) {{ {body_src} }}");
        let (prog, errors) = parse_circom(&src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        match &prog.definitions[0] {
            Definition::Function(f) => f.body.stmts.clone(),
            _ => panic!("expected function"),
        }
    }

    fn shape(body_src: &str) -> CalleeReturnShape {
        infer_callee_return_shape(&parse_body(body_src), &HashMap::new())
    }

    fn shape_with(body_src: &str, consts: &[(&str, ConstInt)]) -> CalleeReturnShape {
        let map: HashMap<String, ConstInt> =
            consts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        infer_callee_return_shape(&parse_body(body_src), &map)
    }

    #[test]
    fn scalar_returns_classify_as_scalar() {
        assert_eq!(shape("return 1 + 2;"), CalleeReturnShape::Scalar);
        assert_eq!(shape("var x = 3; return x;"), CalleeReturnShape::Scalar);
        assert_eq!(shape("return a[0];"), CalleeReturnShape::Scalar);
    }

    #[test]
    fn array_literal_and_decl_returns_classify_as_array() {
        assert_eq!(shape("return [1, 2, 3];"), CalleeReturnShape::Array(3));
        assert_eq!(
            shape("var out[4]; return out;"),
            CalleeReturnShape::Array(4)
        );
    }

    #[test]
    fn array_decl_dim_folds_against_param_consts() {
        assert_eq!(
            shape_with("var out[n]; return out;", &[("n", 5)]),
            CalleeReturnShape::Array(5)
        );
    }

    #[test]
    fn two_dimensional_decl_returns_classify_as_array2d() {
        assert_eq!(
            shape("var m[2][3]; return m;"),
            CalleeReturnShape::Array2D(2, 3)
        );
    }

    #[test]
    fn return_count_does_not_force_other() {
        // A single top-level array return is `Other` for the inlining
        // path's slot heuristic; for a subprogram it is a real
        // `Return`, so it must classify cleanly.
        assert_eq!(
            shape("var out[2]; return out;"),
            CalleeReturnShape::Array(2)
        );
        assert_eq!(
            shape("if (c) { var out[2]; return out; } var r[2]; return r;"),
            CalleeReturnShape::Array(2)
        );
    }

    #[test]
    fn disagreeing_return_shapes_are_other() {
        assert_eq!(
            shape("if (c) { return 1; } var out[2]; return out;"),
            CalleeReturnShape::Other
        );
        assert_eq!(
            shape("if (c) { var a[2]; return a; } var b[3]; return b;"),
            CalleeReturnShape::Other
        );
    }

    #[test]
    fn forwarded_call_return_is_other() {
        assert_eq!(shape("return foo(x);"), CalleeReturnShape::Other);
    }

    #[test]
    fn runtime_dim_array_is_other() {
        // `n` is not in param_consts, so the dim does not fold.
        assert_eq!(shape("var out[n]; return out;"), CalleeReturnShape::Other);
    }

    #[test]
    fn scalar_ternary_returns_classify_as_scalar() {
        assert_eq!(
            shape("return cond == 0 ? 1 : x;"),
            CalleeReturnShape::Scalar
        );
    }

    fn dim_sig(body_src: &str) -> Option<Vec<u32>> {
        compute_dim_signature(&parse_body(body_src), &HashMap::new())
    }

    fn dim_sig_with(body_src: &str, consts: &[(&str, ConstInt)]) -> Option<Vec<u32>> {
        let map: HashMap<String, ConstInt> =
            consts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        compute_dim_signature(&parse_body(body_src), &map)
    }

    #[test]
    fn dim_signature_concatenates_in_source_order() {
        assert_eq!(
            dim_sig("var a[2]; var b[3]; var c[4]; return a;"),
            Some(vec![2, 3, 4])
        );
        // 2D decl contributes both dims in order.
        assert_eq!(
            dim_sig("var m[2][3]; var v[5]; return v;"),
            Some(vec![2, 3, 5])
        );
        // No array decls → empty (but resolvable) signature.
        assert_eq!(dim_sig("return x + 1;"), Some(vec![]));
    }

    #[test]
    fn dim_signature_traversal_is_then_before_else_and_recurses() {
        assert_eq!(
            dim_sig("if (c) { var t[1]; } else { var e[2]; } var tail[3]; return x;"),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            dim_sig("for (var i = 0; i < n; i++) { var loop_arr[7]; } return x;"),
            Some(vec![7])
        );
    }

    #[test]
    fn dim_signature_folds_against_param_consts() {
        assert_eq!(
            dim_sig_with("var a[n]; var b[m]; return a;", &[("n", 8), ("m", 16)]),
            Some(vec![8, 16])
        );
    }

    #[test]
    fn dim_signature_is_none_on_any_runtime_dim() {
        // `m` does not fold → whole signature is unresolvable.
        assert_eq!(
            dim_sig_with("var a[n]; var b[m]; return a;", &[("n", 8)]),
            None
        );
        assert_eq!(dim_sig("var a[2]; var b[k]; return a;"), None);
    }

    #[test]
    fn reg_type_collapse_is_one_handle_per_array() {
        assert_eq!(
            CalleeReturnShape::Scalar.to_reg_types(),
            Some(vec![RegType::Field])
        );
        assert_eq!(
            CalleeReturnShape::Array(7).to_reg_types(),
            Some(vec![RegType::Array(ElemT::Field)])
        );
        assert_eq!(
            CalleeReturnShape::Array2D(3, 4).to_reg_types(),
            Some(vec![RegType::Array(ElemT::Field)])
        );
        assert_eq!(CalleeReturnShape::Other.to_reg_types(), None);
    }
}
