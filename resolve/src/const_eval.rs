//! Compile-time constant evaluation — Movimiento 2 Phase 5.
//!
//! A lightweight AST-level evaluator that resolves expressions to
//! integer constants when all operands are statically known. The
//! primary consumer is the VM-mode circom dispatcher: instead of
//! requiring `Expr::Number` literals for template arguments, it can
//! accept any expression whose `ExprId` appears in the
//! [`ResolvedProgram::const_values`] map.
//!
//! ## Scope
//!
//! The evaluator tracks `let` bindings whose RHS evaluates to a
//! constant. `mut` bindings, function parameters, and any expression
//! involving runtime values produce `None`. This is deliberately
//! conservative — it only folds what it can prove.

use std::collections::HashMap;

use achronyme_parser::ast::{BinOp, Block, ElseBranch, Expr, ForIterable, Stmt, UnaryOp};

use crate::annotate::AnnotationKey;
use crate::module_graph::{ModuleGraph, ModuleId};

// ---- Public types -------------------------------------------------------

/// Map from `(ModuleId, ExprId)` to the compile-time integer value of
/// that expression. Only populated for expressions the evaluator can
/// prove constant.
pub type ConstValues = HashMap<AnnotationKey, i64>;

// ---- Public entry point -------------------------------------------------

/// Evaluate all constant expressions across every module in the graph.
///
/// Returns a map from `(module_id, expr_id)` to the integer value for
/// every expression that can be proven constant at compile time. The
/// map is stored on [`ResolvedProgram`] and consumed by the VM
/// compiler's circom template dispatcher.
pub fn evaluate_constants(graph: &ModuleGraph) -> ConstValues {
    let mut result = ConstValues::new();
    for module in graph.iter() {
        let mut ctx = EvalCtx {
            module_id: module.id,
            scopes: vec![HashMap::new()],
            result: &mut result,
        };
        for stmt in &module.program.stmts {
            eval_stmt(&mut ctx, stmt);
        }
    }
    result
}

// ---- Internal context ---------------------------------------------------

struct EvalCtx<'a> {
    module_id: ModuleId,
    /// Stack of scopes, each mapping variable names to their known
    /// constant values. Pushed on block entry, popped on exit.
    scopes: Vec<HashMap<String, i64>>,
    /// Output map — accumulated across the whole program.
    result: &'a mut ConstValues,
}

impl EvalCtx<'_> {
    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn define(&mut self, name: &str, value: i64) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), value);
        }
    }

    fn lookup(&self, name: &str) -> Option<i64> {
        for scope in self.scopes.iter().rev() {
            if let Some(&v) = scope.get(name) {
                return Some(v);
            }
        }
        None
    }

    fn record(&mut self, expr: &Expr, value: i64) {
        self.result.insert((self.module_id, expr.id()), value);
    }
}

// ---- Statement walker ---------------------------------------------------

fn eval_stmt(ctx: &mut EvalCtx, stmt: &Stmt) {
    match stmt {
        Stmt::LetDecl { name, value, .. } => {
            if let Some(v) = try_eval(ctx, value) {
                ctx.define(name, v);
            }
            eval_expr_recursive(ctx, value);
        }
        Stmt::MutDecl { value, .. } => {
            eval_expr_recursive(ctx, value);
        }
        Stmt::Assignment { target, value, .. } => {
            // Assignments to mut vars invalidate const tracking.
            // We don't track mut values, so just walk for sub-exprs.
            eval_expr_recursive(ctx, target);
            eval_expr_recursive(ctx, value);
        }
        Stmt::FnDecl { body, .. } => {
            ctx.push_scope();
            eval_block(ctx, body);
            ctx.pop_scope();
        }
        Stmt::Print { value, .. } => eval_expr_recursive(ctx, value),
        Stmt::Return { value: Some(v), .. } => eval_expr_recursive(ctx, v),
        Stmt::Expr(e) => eval_expr_recursive(ctx, e),
        Stmt::Export { inner, .. } => eval_stmt(ctx, inner),
        _ => {}
    }
}

fn eval_block(ctx: &mut EvalCtx, block: &Block) {
    for stmt in &block.stmts {
        eval_stmt(ctx, stmt);
    }
}

fn eval_block_scoped(ctx: &mut EvalCtx, block: &Block) {
    ctx.push_scope();
    eval_block(ctx, block);
    ctx.pop_scope();
}

// ---- Expression walker + evaluator --------------------------------------

/// Walk an expression tree, recording const values for every
/// sub-expression that evaluates to a constant.
fn eval_expr_recursive(ctx: &mut EvalCtx, expr: &Expr) {
    // Try to evaluate this expression as a constant.
    if let Some(v) = try_eval(ctx, expr) {
        ctx.record(expr, v);
    }

    // Recurse into children regardless.
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
            eval_expr_recursive(ctx, lhs);
            eval_expr_recursive(ctx, rhs);
        }
        Expr::UnaryOp { operand, .. } => eval_expr_recursive(ctx, operand),
        Expr::Call { callee, args, .. } => {
            eval_expr_recursive(ctx, callee);
            for arg in args {
                eval_expr_recursive(ctx, &arg.value);
            }
        }
        Expr::Index { object, index, .. } => {
            eval_expr_recursive(ctx, object);
            eval_expr_recursive(ctx, index);
        }
        Expr::DotAccess { object, .. } => eval_expr_recursive(ctx, object),
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            eval_expr_recursive(ctx, condition);
            eval_block_scoped(ctx, then_block);
            match else_branch {
                Some(ElseBranch::Block(b)) => eval_block_scoped(ctx, b),
                Some(ElseBranch::If(e)) => eval_expr_recursive(ctx, e),
                None => {}
            }
        }
        Expr::For { iterable, body, .. } => {
            match iterable {
                ForIterable::Range { .. } => {}
                ForIterable::ExprRange { end, .. } => eval_expr_recursive(ctx, end),
                ForIterable::Expr(e) => eval_expr_recursive(ctx, e),
            }
            eval_block_scoped(ctx, body);
        }
        Expr::While {
            condition, body, ..
        } => {
            eval_expr_recursive(ctx, condition);
            eval_block_scoped(ctx, body);
        }
        Expr::Forever { body, .. } => eval_block_scoped(ctx, body),
        Expr::Block { block, .. } => eval_block_scoped(ctx, block),
        Expr::FnExpr { body, .. } => {
            ctx.push_scope();
            eval_block(ctx, body);
            ctx.pop_scope();
        }
        Expr::Prove { body, .. } => {
            ctx.push_scope();
            eval_block(ctx, body);
            ctx.pop_scope();
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                eval_expr_recursive(ctx, e);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                eval_expr_recursive(ctx, v);
            }
        }
    }
}

/// Try to evaluate an expression to a compile-time integer constant.
/// Returns `None` for anything that can't be proven constant.
fn try_eval(ctx: &EvalCtx, expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Number { value, .. } => value.parse::<i64>().ok(),
        Expr::Bool { value, .. } => Some(if *value { 1 } else { 0 }),
        Expr::Ident { name, .. } => ctx.lookup(name),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = try_eval(ctx, lhs)?;
            let r = try_eval(ctx, rhs)?;
            eval_binop(op.clone(), l, r)
        }
        Expr::UnaryOp { op, operand, .. } => {
            let v = try_eval(ctx, operand)?;
            eval_unaryop(op.clone(), v)
        }
        _ => None,
    }
}

fn eval_binop(op: BinOp, l: i64, r: i64) -> Option<i64> {
    match op {
        BinOp::Add => l.checked_add(r),
        BinOp::Sub => l.checked_sub(r),
        BinOp::Mul => l.checked_mul(r),
        BinOp::Div => {
            if r == 0 {
                None
            } else {
                l.checked_div(r)
            }
        }
        BinOp::Mod => {
            if r == 0 {
                None
            } else {
                Some(l % r)
            }
        }
        BinOp::Pow => {
            if r < 0 {
                None
            } else {
                i64_checked_pow(l, r as u64)
            }
        }
        BinOp::Eq => Some(if l == r { 1 } else { 0 }),
        BinOp::Neq => Some(if l != r { 1 } else { 0 }),
        BinOp::Lt => Some(if l < r { 1 } else { 0 }),
        BinOp::Le => Some(if l <= r { 1 } else { 0 }),
        BinOp::Gt => Some(if l > r { 1 } else { 0 }),
        BinOp::Ge => Some(if l >= r { 1 } else { 0 }),
        BinOp::And => Some(if l != 0 && r != 0 { 1 } else { 0 }),
        BinOp::Or => Some(if l != 0 || r != 0 { 1 } else { 0 }),
    }
}

fn eval_unaryop(op: UnaryOp, v: i64) -> Option<i64> {
    match op {
        UnaryOp::Neg => v.checked_neg(),
        UnaryOp::Not => Some(if v == 0 { 1 } else { 0 }),
    }
}

fn i64_checked_pow(base: i64, exp: u64) -> Option<i64> {
    if exp > 63 {
        return None;
    }
    let mut result: i64 = 1;
    for _ in 0..exp {
        result = result.checked_mul(base)?;
    }
    Some(result)
}

// ---- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_env(vars: &[(&str, i64)]) -> (EvalCtx<'static>, ConstValues) {
        // Leak the ConstValues so we can return both ctx and result.
        // Only for tests — the leaked map is tiny.
        let result = Box::leak(Box::new(ConstValues::new()));
        let mut scopes = vec![HashMap::new()];
        for &(name, val) in vars {
            scopes[0].insert(name.to_string(), val);
        }
        (
            EvalCtx {
                module_id: crate::module_graph::ModuleId::from_raw(0),
                scopes,
                result,
            },
            ConstValues::new(),
        )
    }

    fn zero_span() -> achronyme_parser::ast::Span {
        achronyme_parser::ast::Span {
            byte_start: 0,
            byte_end: 0,
            line_start: 0,
            col_start: 0,
            line_end: 0,
            col_end: 0,
        }
    }

    fn num(value: i64) -> Expr {
        use achronyme_parser::ast::ExprId;
        Expr::Number {
            id: ExprId::SYNTHETIC,
            value: value.to_string(),
            span: zero_span(),
        }
    }

    fn ident(name: &str) -> Expr {
        use achronyme_parser::ast::ExprId;
        Expr::Ident {
            id: ExprId::SYNTHETIC,
            name: name.to_string(),
            span: zero_span(),
        }
    }

    fn binop(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
        use achronyme_parser::ast::ExprId;
        Expr::BinOp {
            id: ExprId::SYNTHETIC,
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            span: zero_span(),
        }
    }

    fn unary(op: UnaryOp, operand: Expr) -> Expr {
        use achronyme_parser::ast::ExprId;
        Expr::UnaryOp {
            id: ExprId::SYNTHETIC,
            op,
            operand: Box::new(operand),
            span: zero_span(),
        }
    }

    #[test]
    fn number_literal() {
        let (ctx, _) = ctx_with_env(&[]);
        assert_eq!(try_eval(&ctx, &num(42)), Some(42));
    }

    #[test]
    fn negative_number() {
        let (ctx, _) = ctx_with_env(&[]);
        assert_eq!(try_eval(&ctx, &num(-7)), Some(-7));
    }

    #[test]
    fn ident_lookup() {
        let (ctx, _) = ctx_with_env(&[("n", 8)]);
        assert_eq!(try_eval(&ctx, &ident("n")), Some(8));
    }

    #[test]
    fn unknown_ident() {
        let (ctx, _) = ctx_with_env(&[]);
        assert_eq!(try_eval(&ctx, &ident("x")), None);
    }

    #[test]
    fn add() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = binop(BinOp::Add, num(3), num(4));
        assert_eq!(try_eval(&ctx, &e), Some(7));
    }

    #[test]
    fn sub() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = binop(BinOp::Sub, num(10), num(3));
        assert_eq!(try_eval(&ctx, &e), Some(7));
    }

    #[test]
    fn mul() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = binop(BinOp::Mul, num(6), num(7));
        assert_eq!(try_eval(&ctx, &e), Some(42));
    }

    #[test]
    fn div_by_zero() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = binop(BinOp::Div, num(10), num(0));
        assert_eq!(try_eval(&ctx, &e), None);
    }

    #[test]
    fn pow() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = binop(BinOp::Pow, num(2), num(10));
        assert_eq!(try_eval(&ctx, &e), Some(1024));
    }

    #[test]
    fn nested_binop_with_ident() {
        let (ctx, _) = ctx_with_env(&[("n", 4)]);
        let e = binop(BinOp::Mul, ident("n"), num(2));
        assert_eq!(try_eval(&ctx, &e), Some(8));
    }

    #[test]
    fn comparison() {
        let (ctx, _) = ctx_with_env(&[]);
        assert_eq!(try_eval(&ctx, &binop(BinOp::Lt, num(3), num(5))), Some(1));
        assert_eq!(try_eval(&ctx, &binop(BinOp::Gt, num(3), num(5))), Some(0));
    }

    #[test]
    fn negation() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = unary(UnaryOp::Neg, num(42));
        assert_eq!(try_eval(&ctx, &e), Some(-42));
    }

    #[test]
    fn not_op() {
        let (ctx, _) = ctx_with_env(&[]);
        assert_eq!(try_eval(&ctx, &unary(UnaryOp::Not, num(0))), Some(1));
        assert_eq!(try_eval(&ctx, &unary(UnaryOp::Not, num(5))), Some(0));
    }

    #[test]
    fn partial_unknown_returns_none() {
        let (ctx, _) = ctx_with_env(&[]);
        let e = binop(BinOp::Add, num(1), ident("unknown"));
        assert_eq!(try_eval(&ctx, &e), None);
    }
}
