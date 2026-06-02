use super::*;

/// Walk every `Expr` reachable from a `Program` and invoke `visit` for each.
/// Includes sub-expressions recursively so we can validate id uniqueness
/// across the whole AST.
fn walk_exprs(prog: &Program, mut visit: impl FnMut(&Expr)) {
    fn walk_stmt(stmt: &Stmt, visit: &mut dyn FnMut(&Expr)) {
        match stmt {
            Stmt::LetDecl { value, .. }
            | Stmt::MutDecl { value, .. }
            | Stmt::Expr(value)
            | Stmt::Print { value, .. } => walk_expr(value, visit),
            Stmt::Assignment { target, value, .. } => {
                walk_expr(target, visit);
                walk_expr(value, visit);
            }
            Stmt::Return { value, .. } => {
                if let Some(v) = value {
                    walk_expr(v, visit);
                }
            }
            Stmt::FnDecl { body, .. } | Stmt::CircuitDecl { body, .. } => walk_block(body, visit),
            Stmt::Export { inner, .. } => walk_stmt(inner, visit),
            Stmt::PublicDecl { .. }
            | Stmt::WitnessDecl { .. }
            | Stmt::Break { .. }
            | Stmt::Continue { .. }
            | Stmt::Import { .. }
            | Stmt::SelectiveImport { .. }
            | Stmt::ExportList { .. }
            | Stmt::ImportCircuit { .. }
            | Stmt::Error { .. } => {}
        }
    }

    fn walk_block(block: &Block, visit: &mut dyn FnMut(&Expr)) {
        for s in &block.stmts {
            walk_stmt(s, visit);
        }
    }

    fn walk_expr(expr: &Expr, visit: &mut dyn FnMut(&Expr)) {
        visit(expr);
        match expr {
            Expr::Number { .. }
            | Expr::FieldLit { .. }
            | Expr::BigIntLit { .. }
            | Expr::Bool { .. }
            | Expr::StringLit { .. }
            | Expr::Nil { .. }
            | Expr::Ident { .. }
            | Expr::StaticAccess { .. }
            | Expr::Error { .. } => {}
            Expr::BinOp { lhs, rhs, .. } => {
                walk_expr(lhs, visit);
                walk_expr(rhs, visit);
            }
            Expr::UnaryOp { operand, .. } => walk_expr(operand, visit),
            Expr::Call { callee, args, .. } => {
                walk_expr(callee, visit);
                for a in args {
                    walk_expr(&a.value, visit);
                }
            }
            Expr::Index { object, index, .. } => {
                walk_expr(object, visit);
                walk_expr(index, visit);
            }
            Expr::DotAccess { object, .. } => walk_expr(object, visit),
            Expr::If {
                condition,
                then_block,
                else_branch,
                ..
            } => {
                walk_expr(condition, visit);
                walk_block(then_block, visit);
                match else_branch {
                    Some(ElseBranch::Block(b)) => walk_block(b, visit),
                    Some(ElseBranch::If(e)) => walk_expr(e, visit),
                    None => {}
                }
            }
            Expr::For { body, iterable, .. } => {
                if let ForIterable::Expr(e) | ForIterable::ExprRange { end: e, .. } = iterable {
                    walk_expr(e, visit);
                }
                walk_block(body, visit);
            }
            Expr::While {
                condition, body, ..
            } => {
                walk_expr(condition, visit);
                walk_block(body, visit);
            }
            Expr::Forever { body, .. } => walk_block(body, visit),
            Expr::Block { block, .. } => walk_block(block, visit),
            Expr::FnExpr { body, .. } | Expr::Prove { body, .. } => walk_block(body, visit),
            Expr::Array { elements, .. } => {
                for e in elements {
                    walk_expr(e, visit);
                }
            }
            Expr::Map { pairs, .. } => {
                for (_, v) in pairs {
                    walk_expr(v, visit);
                }
            }
        }
    }

    for s in &prog.stmts {
        walk_stmt(s, &mut visit);
    }
}

#[test]
fn expr_id_synthetic_is_reserved_zero() {
    assert_eq!(ExprId::SYNTHETIC.as_u32(), 0);
    assert!(ExprId::SYNTHETIC.is_synthetic());
    assert!(!ExprId::from_raw(1).is_synthetic());
}

#[test]
fn expr_ids_are_unique_across_program() {
    let source = r#"
        let x = 1 + 2 * 3
        let y = [x, x + 1, foo(x, 2)]
        fn add(a, b) { a + b }
        let z = if x > 0 { add(x, y[0]) } else { -x }
    "#;
    let prog = parse_ok(source);
    let mut seen = std::collections::HashSet::new();
    walk_exprs(&prog, |e| {
        let id = e.id();
        assert!(
            !id.is_synthetic(),
            "parser must never allocate SYNTHETIC (0) to a real expression"
        );
        assert!(
            seen.insert(id),
            "duplicate ExprId {id:?} on expression {e:?}"
        );
    });
    assert!(!seen.is_empty(), "program produced no expressions");
}

#[test]
fn expr_ids_start_at_one_and_are_dense() {
    // A single literal produces one Expr and one id. That id should be 1
    // (the first allocation after SYNTHETIC(0)).
    let prog = parse_ok("42");
    let mut ids = Vec::new();
    walk_exprs(&prog, |e| ids.push(e.id().as_u32()));
    assert_eq!(ids, vec![1]);
}

#[test]
fn expr_ids_are_monotonically_allocated() {
    // Each subsequent parse_program starts fresh (ids reset per Parser),
    // but within one parse they are strictly increasing in allocation
    // order. The parse_program API doesn't let us inspect allocation
    // order directly, so we assert that ids within one program are
    // pairwise distinct and bounded by the total expression count.
    let prog = parse_ok("a + b * c - d");
    let mut count = 0usize;
    let mut max_id = 0u32;
    walk_exprs(&prog, |e| {
        count += 1;
        max_id = max_id.max(e.id().as_u32());
    });
    assert_eq!(count, 7, "expected 4 idents + 3 binops, got {count}");
    // Dense means max id equals count (since first id is 1).
    assert_eq!(max_id as usize, count);
}

#[test]
fn expr_id_accessor_matches_variant_field() {
    // Sanity-check that `Expr::id()` returns the same value as the
    // `id` field on every variant we construct.
    let prog = parse_ok("let x = foo.bar[0]");
    match &prog.stmts[0] {
        Stmt::LetDecl {
            value: Expr::Index { id, object, .. },
            ..
        } => {
            assert_ne!(id.as_u32(), 0);
            assert_eq!(prog.stmts[0].clone().let_value().id(), *id);
            match object.as_ref() {
                Expr::DotAccess { id: dot_id, .. } => assert_ne!(dot_id.as_u32(), 0),
                other => panic!("expected DotAccess inside Index, got {other:?}"),
            }
        }
        other => panic!("expected LetDecl wrapping Index, got {other:?}"),
    }
}

/// Helper for the accessor test — extract the value out of a let decl.
impl Stmt {
    #[cfg(test)]
    fn let_value(self) -> Expr {
        match self {
            Stmt::LetDecl { value, .. } => value,
            _ => panic!("not a LetDecl"),
        }
    }
}
