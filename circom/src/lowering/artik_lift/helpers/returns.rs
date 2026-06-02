use std::collections::{HashMap, HashSet};

use artik::{ElemT, RegType};

use crate::ast::{ElseBranch, Expr, FunctionDef, Stmt};

use super::super::ConstInt;
use super::consts::{eval_const_expr, extract_call_name};

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
pub(in super::super) enum CalleeReturnShape {
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
    pub(in super::super) fn to_reg_types(self) -> Option<Vec<RegType>> {
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
pub(in super::super) fn infer_callee_return_shape(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
    functions: &HashMap<String, &FunctionDef>,
    visited: &mut HashSet<String>,
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
    classify_returns(
        stmts,
        param_consts,
        &dim_map,
        functions,
        visited,
        &mut found,
        &mut ok,
    );
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

#[allow(clippy::too_many_arguments)]
fn classify_returns(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &HashMap<String, Option<DeclDim>>,
    functions: &HashMap<String, &FunctionDef>,
    visited: &mut HashSet<String>,
    found: &mut Option<CalleeReturnShape>,
    ok: &mut bool,
) {
    for stmt in stmts {
        classify_returns_in_stmt(stmt, param_consts, dim_map, functions, visited, found, ok);
        if !*ok {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_returns_in_stmt(
    stmt: &Stmt,
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &HashMap<String, Option<DeclDim>>,
    functions: &HashMap<String, &FunctionDef>,
    visited: &mut HashSet<String>,
    found: &mut Option<CalleeReturnShape>,
    ok: &mut bool,
) {
    match stmt {
        Stmt::Return { value, .. } => {
            let shape = match classify_return_expr(value, param_consts, dim_map, functions, visited)
            {
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
            classify_returns(
                &then_body.stmts,
                param_consts,
                dim_map,
                functions,
                visited,
                found,
                ok,
            );
            match else_body {
                Some(ElseBranch::Block(b)) => classify_returns(
                    &b.stmts,
                    param_consts,
                    dim_map,
                    functions,
                    visited,
                    found,
                    ok,
                ),
                Some(ElseBranch::IfElse(boxed)) => classify_returns_in_stmt(
                    boxed,
                    param_consts,
                    dim_map,
                    functions,
                    visited,
                    found,
                    ok,
                ),
                None => {}
            }
        }
        Stmt::For { body, .. } => classify_returns(
            &body.stmts,
            param_consts,
            dim_map,
            functions,
            visited,
            found,
            ok,
        ),
        Stmt::While { body, .. } => classify_returns(
            &body.stmts,
            param_consts,
            dim_map,
            functions,
            visited,
            found,
            ok,
        ),
        Stmt::DoWhile { body, .. } => classify_returns(
            &body.stmts,
            param_consts,
            dim_map,
            functions,
            visited,
            found,
            ok,
        ),
        Stmt::Block(b) => classify_returns(
            &b.stmts,
            param_consts,
            dim_map,
            functions,
            visited,
            found,
            ok,
        ),
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
    param_consts: &HashMap<String, ConstInt>,
    dim_map: &HashMap<String, Option<DeclDim>>,
    functions: &HashMap<String, &FunctionDef>,
    visited: &mut HashSet<String>,
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
            let a = classify_return_expr(if_true, param_consts, dim_map, functions, visited)?;
            let b = classify_return_expr(if_false, param_consts, dim_map, functions, visited)?;
            (a == b).then_some(a)
        }
        // A forwarded call: `return f(args);`. The return shape is
        // whatever `f` returns, resolved by recursing into `f`'s body.
        // The `visited` set bounds the recursion — circom forbids
        // recursive functions, so a cycle here is malformed input and
        // declines cleanly instead of looping.
        Expr::Call { callee, args, .. } => {
            let name = extract_call_name(callee)?;
            let func = functions.get(name.as_str())?;
            if args.len() != func.params.len() {
                return None;
            }
            if !visited.insert(name.clone()) {
                return None;
            }
            // The forwarded callee's own return shape does not see the
            // caller's argument constants — a forwarded callee whose
            // shape depends on a caller-passed constant declines
            // (conservative; no shape is invented).
            let inner =
                infer_callee_return_shape(&func.body.stmts, &HashMap::new(), functions, visited);
            visited.remove(&name);
            match inner {
                CalleeReturnShape::Scalar => Some(CalleeReturnShape::Scalar),
                // The emission side packs a single result register for
                // `return <call>`; an array handle would be dropped.
                // Decline a forwarded array return so the gate never
                // reserves a subprogram whose return cannot be
                // delivered.
                CalleeReturnShape::Array(_)
                | CalleeReturnShape::Array2D(..)
                | CalleeReturnShape::Other => None,
            }
        }
        // A single-index read. `arr2d[row]` where `arr2d` is a 2D local
        // is a 1D row slice of `cols` cells — the emission side
        // (`emit_callee_return` / the non-subprogram row-slice path)
        // materializes exactly that. Only when the row index const-folds
        // into `0..rows` (the same guard `materialize_row_slice`
        // applies); a 2D local indexed by a non-folding row is *not* a
        // scalar, so the honest answer is unmodelled (`None` → `Other`,
        // the lift then declines to decomposition rather than reserving
        // a shape emission cannot deliver). A 1D-local element read, or
        // an index into a non-array / runtime-dim name, is a single
        // field value.
        Expr::Index { object, index, .. } => {
            if let Expr::Ident { name, .. } = object.as_ref() {
                if let Some(Some(DeclDim::D2(rows, cols))) = dim_map.get(name) {
                    let r = eval_const_expr(index, param_consts)?;
                    if (0..i64::from(*rows)).contains(&r) {
                        return Some(CalleeReturnShape::Array(*cols));
                    }
                    return None;
                }
            }
            Some(CalleeReturnShape::Scalar)
        }
        // Numbers, arithmetic, and unary / postfix forms all produce a
        // single field value.
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::BinOp { .. }
        | Expr::UnaryOp { .. }
        | Expr::PostfixOp { .. }
        | Expr::PrefixOp { .. } => Some(CalleeReturnShape::Scalar),
        _ => None,
    }
}
