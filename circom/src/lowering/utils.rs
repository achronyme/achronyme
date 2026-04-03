//! Shared lowering utilities.
//!
//! Helper functions used across multiple lowering modules (signals,
//! expressions, statements). These operate on the Circom AST and
//! don't depend on ProveIR types.

use std::collections::HashMap;

use crate::ast::{self, AssignOp, CompoundOp, ElseBranch, Expr, FunctionDef, PostfixOp, Stmt};

/// Extract a simple identifier name from an expression.
///
/// Returns `Some("x")` for `Expr::Ident { name: "x" }`, `None` for
/// anything more complex (index, dot access, etc.).
pub fn extract_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Try to evaluate a Circom AST expression as a constant u64.
///
/// Used for array dimensions, loop bounds, and power exponents that must
/// be compile-time constants.
pub fn const_eval_u64(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

/// Evaluate a Circom expression as u64 by substituting known parameter values.
///
/// Like `const_eval_u64` but also resolves identifiers from the param map.
/// Used for signal array dimensions and loop bounds that involve template params.
pub fn const_eval_with_params(expr: &Expr, params: &HashMap<String, u64>) -> Option<u64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(hex, 16).ok()
        }
        Expr::Ident { name, .. } => params.get(name.as_str()).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = const_eval_with_params(lhs, params)?;
            let r = const_eval_with_params(rhs, params)?;
            match op {
                ast::BinOp::Add => l.checked_add(r),
                ast::BinOp::Sub => l.checked_sub(r),
                ast::BinOp::Mul => l.checked_mul(r),
                ast::BinOp::Div | ast::BinOp::IntDiv => {
                    if r != 0 {
                        Some(l / r)
                    } else {
                        None
                    }
                }
                ast::BinOp::Mod => {
                    if r != 0 {
                        Some(l % r)
                    } else {
                        None
                    }
                }
                ast::BinOp::ShiftL => Some(l << (r & 63)),
                ast::BinOp::ShiftR => Some(l >> (r & 63)),
                ast::BinOp::Pow => Some(l.pow(r as u32)),
                _ => None,
            }
        }
        Expr::UnaryOp { op, operand, .. } => {
            let val = const_eval_with_params(operand, params)?;
            match op {
                ast::UnaryOp::Neg => Some(val.wrapping_neg()),
                _ => None,
            }
        }
        // Fall back to const_eval for literals
        _ => const_eval_u64(expr),
    }
}

/// Display symbol for a binary operator (for error messages).
pub fn binop_symbol(op: ast::BinOp) -> &'static str {
    match op {
        ast::BinOp::Add => "+",
        ast::BinOp::Sub => "-",
        ast::BinOp::Mul => "*",
        ast::BinOp::Div => "/",
        ast::BinOp::IntDiv => "\\",
        ast::BinOp::Mod => "%",
        ast::BinOp::Pow => "**",
        ast::BinOp::Eq => "==",
        ast::BinOp::Neq => "!=",
        ast::BinOp::Lt => "<",
        ast::BinOp::Le => "<=",
        ast::BinOp::Gt => ">",
        ast::BinOp::Ge => ">=",
        ast::BinOp::And => "&&",
        ast::BinOp::Or => "||",
        ast::BinOp::BitAnd => "&",
        ast::BinOp::BitOr => "|",
        ast::BinOp::BitXor => "^",
        ast::BinOp::ShiftL => "<<",
        ast::BinOp::ShiftR => ">>",
    }
}

// ---------------------------------------------------------------------------
// Compile-time function evaluation
// ---------------------------------------------------------------------------

/// Maximum loop iterations during compile-time function evaluation.
const MAX_EVAL_ITERATIONS: usize = 10_000;

/// Maximum recursion depth for compile-time evaluation.
const MAX_EVAL_DEPTH: usize = 64;

/// Result of evaluating a single statement.
enum StmtResult {
    /// Statement completed normally.
    Continue,
    /// A `return` statement was reached with the given value.
    Return(i64),
}

/// Evaluate a Circom function body at compile time with concrete i64 arguments.
///
/// Returns `Some(result)` if the function can be fully evaluated to a constant,
/// `None` if evaluation fails (non-constant data, array operations, or
/// non-terminating loops).
pub fn eval_function(
    func: &FunctionDef,
    args: &[i64],
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<i64> {
    if depth > MAX_EVAL_DEPTH {
        return None;
    }
    if args.len() != func.params.len() {
        return None;
    }

    let mut vars: HashMap<String, i64> = HashMap::new();
    for (param, &val) in func.params.iter().zip(args) {
        vars.insert(param.clone(), val);
    }

    match eval_stmts(&func.body.stmts, &mut vars, functions, depth)? {
        StmtResult::Return(val) => Some(val),
        StmtResult::Continue => None,
    }
}

/// Try to evaluate a function call at compile time.
///
/// Const-evaluates all arguments using `params`, then evaluates the function
/// body. Returns `Some(result)` only if everything resolves to constants.
pub fn try_eval_function_call(
    func: &FunctionDef,
    args: &[Expr],
    params: &HashMap<String, u64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<u64> {
    let vars: HashMap<String, i64> = params.iter().map(|(k, &v)| (k.clone(), v as i64)).collect();
    let arg_vals: Vec<i64> = args
        .iter()
        .map(|a| eval_expr_i64(a, &vars, functions, depth))
        .collect::<Option<_>>()?;
    eval_function(func, &arg_vals, functions, depth).map(|v| v as u64)
}

/// Evaluate a Circom expression as u64 with parameter substitution and
/// function call support.
///
/// Like `const_eval_with_params` but also handles `Call` expressions by
/// evaluating the called function at compile time.
pub fn const_eval_with_functions(
    expr: &Expr,
    params: &HashMap<String, u64>,
    functions: &HashMap<&str, &FunctionDef>,
) -> Option<u64> {
    let vars: HashMap<String, i64> = params.iter().map(|(k, &v)| (k.clone(), v as i64)).collect();
    eval_expr_i64(expr, &vars, functions, 0).map(|v| v as u64)
}

/// Pre-evaluate compile-time `var` declarations from a template body.
///
/// Scans statements for `var x = <const-expr>` (including function calls)
/// and returns a map of computed values. Used before signal layout extraction
/// so that dimensions like `signal output out[nbits(n)]` resolve correctly.
pub fn precompute_vars(
    stmts: &[Stmt],
    params: &HashMap<String, u64>,
    functions: &HashMap<&str, &FunctionDef>,
) -> HashMap<String, u64> {
    let mut known = params.clone();
    for stmt in stmts {
        if let Stmt::VarDecl {
            names,
            init: Some(expr),
            ..
        } = stmt
        {
            if names.len() == 1 {
                if let Some(val) = const_eval_with_functions(expr, &known, functions) {
                    known.insert(names[0].clone(), val);
                }
            }
        }
    }
    // Return only the NEW vars (exclude original params)
    known
        .into_iter()
        .filter(|(k, _)| !params.contains_key(k))
        .collect()
}

// ── Internal helpers ────────────────────────────────────────────

fn eval_stmts(
    stmts: &[Stmt],
    vars: &mut HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<StmtResult> {
    for stmt in stmts {
        match eval_stmt(stmt, vars, functions, depth)? {
            StmtResult::Continue => {}
            ret @ StmtResult::Return(_) => return Some(ret),
        }
    }
    Some(StmtResult::Continue)
}

fn eval_stmt(
    stmt: &Stmt,
    vars: &mut HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<StmtResult> {
    match stmt {
        Stmt::VarDecl { names, init, .. } => {
            let val = match init {
                Some(expr) => eval_expr_i64(expr, vars, functions, depth)?,
                None => 0,
            };
            for name in names {
                vars.insert(name.clone(), val);
            }
            Some(StmtResult::Continue)
        }

        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            value,
            ..
        } => {
            if let Expr::Ident { name, .. } = target {
                let val = eval_expr_i64(value, vars, functions, depth)?;
                vars.insert(name.clone(), val);
                Some(StmtResult::Continue)
            } else {
                None
            }
        }

        Stmt::CompoundAssign {
            target, op, value, ..
        } => {
            if let Expr::Ident { name, .. } = target {
                let current = *vars.get(name.as_str())?;
                let rhs = eval_expr_i64(value, vars, functions, depth)?;
                let result = apply_compound_op(current, *op, rhs)?;
                vars.insert(name.clone(), result);
                Some(StmtResult::Continue)
            } else {
                None
            }
        }

        Stmt::Expr { expr, .. } => {
            if let Expr::PostfixOp { op, operand, .. } = expr {
                if let Expr::Ident { name, .. } = operand.as_ref() {
                    let current = *vars.get(name.as_str())?;
                    match op {
                        PostfixOp::Increment => {
                            vars.insert(name.clone(), current + 1);
                        }
                        PostfixOp::Decrement => {
                            vars.insert(name.clone(), current - 1);
                        }
                    }
                    return Some(StmtResult::Continue);
                }
            }
            // Other expression statements — evaluate for side effects
            eval_expr_i64(expr, vars, functions, depth)?;
            Some(StmtResult::Continue)
        }

        Stmt::While {
            condition, body, ..
        } => {
            for _ in 0..MAX_EVAL_ITERATIONS {
                let cond = eval_expr_i64(condition, vars, functions, depth)?;
                if cond == 0 {
                    return Some(StmtResult::Continue);
                }
                match eval_stmts(&body.stmts, vars, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
            }
            None // non-terminating
        }

        Stmt::For {
            init,
            condition,
            step,
            body,
            ..
        } => {
            eval_stmt(init, vars, functions, depth)?;
            for _ in 0..MAX_EVAL_ITERATIONS {
                let cond = eval_expr_i64(condition, vars, functions, depth)?;
                if cond == 0 {
                    return Some(StmtResult::Continue);
                }
                match eval_stmts(&body.stmts, vars, functions, depth)? {
                    StmtResult::Continue => {}
                    ret @ StmtResult::Return(_) => return Some(ret),
                }
                eval_stmt(step, vars, functions, depth)?;
            }
            None
        }

        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            let cond = eval_expr_i64(condition, vars, functions, depth)?;
            if cond != 0 {
                eval_stmts(&then_body.stmts, vars, functions, depth)
            } else if let Some(branch) = else_body {
                match branch {
                    ElseBranch::Block(block) => eval_stmts(&block.stmts, vars, functions, depth),
                    ElseBranch::IfElse(stmt) => eval_stmt(stmt, vars, functions, depth),
                }
            } else {
                Some(StmtResult::Continue)
            }
        }

        Stmt::Return { value, .. } => {
            let val = eval_expr_i64(value, vars, functions, depth)?;
            Some(StmtResult::Return(val))
        }

        Stmt::Log { .. } | Stmt::Assert { .. } => Some(StmtResult::Continue),

        Stmt::Block(block) => eval_stmts(&block.stmts, vars, functions, depth),

        // Signal decls, component decls, constraint eqs — not evaluable
        _ => None,
    }
}

fn eval_expr_i64(
    expr: &Expr,
    vars: &HashMap<String, i64>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<i64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            i64::from_str_radix(hex, 16).ok()
        }
        Expr::Ident { name, .. } => vars.get(name.as_str()).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = eval_expr_i64(lhs, vars, functions, depth)?;
            let r = eval_expr_i64(rhs, vars, functions, depth)?;
            eval_binop_i64(l, *op, r)
        }
        Expr::UnaryOp { op, operand, .. } => {
            let val = eval_expr_i64(operand, vars, functions, depth)?;
            match op {
                ast::UnaryOp::Neg => Some(-val),
                ast::UnaryOp::Not => Some(if val == 0 { 1 } else { 0 }),
                ast::UnaryOp::BitNot => Some(!val),
            }
        }
        Expr::PostfixOp { operand, .. } => {
            // In expression context, return the current value (side effect
            // is handled by eval_stmt for statement-level postfix ops)
            if let Expr::Ident { name, .. } = operand.as_ref() {
                vars.get(name.as_str()).copied()
            } else {
                None
            }
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let cond = eval_expr_i64(condition, vars, functions, depth)?;
            if cond != 0 {
                eval_expr_i64(if_true, vars, functions, depth)
            } else {
                eval_expr_i64(if_false, vars, functions, depth)
            }
        }
        Expr::Call { callee, args, .. } => {
            let name = extract_ident_name(callee)?;
            let func = *functions.get(name.as_str())?;
            let arg_vals: Vec<i64> = args
                .iter()
                .map(|a| eval_expr_i64(a, vars, functions, depth))
                .collect::<Option<_>>()?;
            eval_function(func, &arg_vals, functions, depth + 1)
        }
        _ => None,
    }
}

fn eval_binop_i64(l: i64, op: ast::BinOp, r: i64) -> Option<i64> {
    match op {
        ast::BinOp::Add => Some(l.wrapping_add(r)),
        ast::BinOp::Sub => Some(l.wrapping_sub(r)),
        ast::BinOp::Mul => Some(l.wrapping_mul(r)),
        ast::BinOp::Div | ast::BinOp::IntDiv => {
            if r != 0 {
                Some(l / r)
            } else {
                None
            }
        }
        ast::BinOp::Mod => {
            if r != 0 {
                Some(l % r)
            } else {
                None
            }
        }
        ast::BinOp::Pow => Some(l.pow(r as u32)),
        ast::BinOp::Eq => Some(if l == r { 1 } else { 0 }),
        ast::BinOp::Neq => Some(if l != r { 1 } else { 0 }),
        ast::BinOp::Lt => Some(if l < r { 1 } else { 0 }),
        ast::BinOp::Le => Some(if l <= r { 1 } else { 0 }),
        ast::BinOp::Gt => Some(if l > r { 1 } else { 0 }),
        ast::BinOp::Ge => Some(if l >= r { 1 } else { 0 }),
        ast::BinOp::And => Some(if l != 0 && r != 0 { 1 } else { 0 }),
        ast::BinOp::Or => Some(if l != 0 || r != 0 { 1 } else { 0 }),
        ast::BinOp::BitAnd => Some(l & r),
        ast::BinOp::BitOr => Some(l | r),
        ast::BinOp::BitXor => Some(l ^ r),
        ast::BinOp::ShiftL => Some(l << (r & 63)),
        ast::BinOp::ShiftR => Some(l >> (r & 63)),
    }
}

fn apply_compound_op(current: i64, op: CompoundOp, rhs: i64) -> Option<i64> {
    match op {
        CompoundOp::Add => Some(current.wrapping_add(rhs)),
        CompoundOp::Sub => Some(current.wrapping_sub(rhs)),
        CompoundOp::Mul => Some(current.wrapping_mul(rhs)),
        CompoundOp::Div | CompoundOp::IntDiv => {
            if rhs != 0 {
                Some(current / rhs)
            } else {
                None
            }
        }
        CompoundOp::Mod => {
            if rhs != 0 {
                Some(current % rhs)
            } else {
                None
            }
        }
        CompoundOp::Pow => Some(current.pow(rhs as u32)),
        CompoundOp::ShiftL => Some(current << (rhs & 63)),
        CompoundOp::ShiftR => Some(current >> (rhs & 63)),
        CompoundOp::BitAnd => Some(current & rhs),
        CompoundOp::BitOr => Some(current | rhs),
        CompoundOp::BitXor => Some(current ^ rhs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;

    /// Parse a Circom expression inside a template var init.
    fn parse_expr(expr_src: &str) -> Expr {
        let src = format!("template T() {{ var _x = {expr_src}; }}");
        let (prog, errors) = parse_circom(&src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => match &t.body.stmts[0] {
                crate::ast::Stmt::VarDecl { init: Some(e), .. } => e.clone(),
                other => panic!("expected VarDecl, got {:?}", other),
            },
            _ => panic!("expected template"),
        }
    }

    #[test]
    fn const_eval_decimal() {
        assert_eq!(const_eval_u64(&parse_expr("42")), Some(42));
    }

    #[test]
    fn const_eval_hex() {
        assert_eq!(const_eval_u64(&parse_expr("0x10")), Some(16));
    }

    #[test]
    fn const_eval_non_const() {
        assert_eq!(const_eval_u64(&parse_expr("a + 1")), None);
    }

    #[test]
    fn extract_ident() {
        let expr = parse_expr("foo");
        assert_eq!(extract_ident_name(&expr), Some("foo".to_string()));
    }

    #[test]
    fn extract_ident_from_non_ident() {
        let expr = parse_expr("1 + 2");
        assert_eq!(extract_ident_name(&expr), None);
    }

    // ── eval_function tests ─────────────────────────────────────

    /// Helper: parse a complete Circom program and extract functions + templates.
    fn parse_program(src: &str) -> crate::ast::CircomProgram {
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        prog
    }

    /// Build a functions map from a parsed program.
    fn extract_functions(prog: &crate::ast::CircomProgram) -> HashMap<&str, &FunctionDef> {
        let mut fns = HashMap::new();
        for def in &prog.definitions {
            if let crate::ast::Definition::Function(f) = def {
                fns.insert(f.name.as_str(), f);
            }
        }
        fns
    }

    #[test]
    fn eval_simple_return() {
        let prog = parse_program("function double(x) { return x * 2; }");
        let fns = extract_functions(&prog);
        let f = fns["double"];
        assert_eq!(eval_function(f, &[5], &fns, 0), Some(10));
        assert_eq!(eval_function(f, &[0], &fns, 0), Some(0));
    }

    #[test]
    fn eval_nbits() {
        let prog = parse_program(
            r#"
            function nbits(a) {
                var n = 1;
                var r = 0;
                while (n - 1 < a) {
                    r++;
                    n *= 2;
                }
                return r;
            }
            "#,
        );
        let fns = extract_functions(&prog);
        let f = fns["nbits"];
        assert_eq!(eval_function(f, &[0], &fns, 0), Some(0));
        assert_eq!(eval_function(f, &[1], &fns, 0), Some(1));
        assert_eq!(eval_function(f, &[3], &fns, 0), Some(2));
        assert_eq!(eval_function(f, &[7], &fns, 0), Some(3));
        assert_eq!(eval_function(f, &[255], &fns, 0), Some(8));
    }

    #[test]
    fn eval_for_loop() {
        let prog = parse_program(
            r#"
            function factorial(n) {
                var result = 1;
                for (var i = 2; i <= n; i++) {
                    result *= i;
                }
                return result;
            }
            "#,
        );
        let fns = extract_functions(&prog);
        let f = fns["factorial"];
        assert_eq!(eval_function(f, &[1], &fns, 0), Some(1));
        assert_eq!(eval_function(f, &[5], &fns, 0), Some(120));
    }

    #[test]
    fn eval_if_else() {
        let prog = parse_program(
            r#"
            function abs_val(x) {
                if (x < 0) {
                    return 0 - x;
                } else {
                    return x;
                }
            }
            "#,
        );
        let fns = extract_functions(&prog);
        let f = fns["abs_val"];
        assert_eq!(eval_function(f, &[5], &fns, 0), Some(5));
        assert_eq!(eval_function(f, &[-3], &fns, 0), Some(3));
    }

    #[test]
    fn eval_nested_function_call() {
        let prog = parse_program(
            r#"
            function double(x) { return x * 2; }
            function quad(x) { return double(double(x)); }
            "#,
        );
        let fns = extract_functions(&prog);
        let f = fns["quad"];
        assert_eq!(eval_function(f, &[3], &fns, 0), Some(12));
    }

    #[test]
    fn eval_ternary() {
        let prog = parse_program("function pick(a) { return a > 0 ? a : 0; }");
        let fns = extract_functions(&prog);
        let f = fns["pick"];
        assert_eq!(eval_function(f, &[5], &fns, 0), Some(5));
        assert_eq!(eval_function(f, &[-1], &fns, 0), Some(0));
    }

    #[test]
    fn precompute_vars_with_function() {
        let prog = parse_program(
            r#"
            function nbits(a) {
                var n = 1;
                var r = 0;
                while (n - 1 < a) {
                    r++;
                    n *= 2;
                }
                return r;
            }
            template T(maxval) {
                var nb = nbits(maxval);
                signal input in;
                signal output out[nb];
            }
            component main {public [in]} = T(255);
            "#,
        );
        let fns = extract_functions(&prog);
        let mut params = HashMap::new();
        params.insert("maxval".to_string(), 255u64);

        let t = match &prog.definitions[1] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };
        let vars = precompute_vars(&t.body.stmts, &params, &fns);
        assert_eq!(vars.get("nb"), Some(&8u64));
    }
}
