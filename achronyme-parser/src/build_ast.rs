/// Converts pest `Pair<Rule>` trees into owned AST types.
///
/// This is the sole location that matches pest `Rule` variants for the circuit path.
use pest::iterators::Pair;
use pest::Parser;

use crate::ast::*;
use crate::{AchronymeParser, Rule};

/// Parse a complete program source into an AST `Program`.
pub fn parse_program(source: &str) -> Result<Program, String> {
    let pairs = AchronymeParser::parse(Rule::program, source)
        .map_err(|e| e.to_string())?;
    let program_pair = pairs.into_iter().next().unwrap();
    build_program(program_pair)
}

/// Parse a block source (including braces) into an AST `Block`.
pub fn parse_block(source: &str) -> Result<Block, String> {
    let pairs = AchronymeParser::parse(Rule::block, source)
        .map_err(|e| e.to_string())?;
    let block_pair = pairs.into_iter().next().unwrap();
    build_block(block_pair)
}

fn span_of(pair: &Pair<Rule>) -> Span {
    let (line, col) = pair.as_span().start_pos().line_col();
    Span { line, col }
}

fn build_program(pair: Pair<Rule>) -> Result<Program, String> {
    let mut stmts = Vec::new();
    for child in pair.into_inner() {
        if child.as_rule() == Rule::stmt {
            stmts.push(build_stmt(child)?);
        }
        // Skip EOI
    }
    Ok(Program { stmts })
}

fn build_stmt(pair: Pair<Rule>) -> Result<Stmt, String> {
    let inner = pair.into_inner().next().unwrap();
    let sp = span_of(&inner);
    match inner.as_rule() {
        Rule::let_decl => build_let_decl(inner),
        Rule::mut_decl => build_mut_decl(inner),
        Rule::assignment => build_assignment(inner),
        Rule::public_decl => build_public_decl(inner),
        Rule::witness_decl => build_witness_decl(inner),
        Rule::fn_decl => build_fn_decl(inner),
        Rule::print_stmt => build_print(inner),
        Rule::return_stmt => build_return(inner),
        Rule::break_stmt => Ok(Stmt::Break { span: sp }),
        Rule::continue_stmt => Ok(Stmt::Continue { span: sp }),
        _ => {
            // Expression statement
            let expr = build_expr(inner)?;
            Ok(Stmt::Expr(expr))
        }
    }
}

fn build_let_decl(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let value = build_expr(inner.next().unwrap())?;
    Ok(Stmt::LetDecl { name, value, span: sp })
}

fn build_mut_decl(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let value = build_expr(inner.next().unwrap())?;
    Ok(Stmt::MutDecl { name, value, span: sp })
}

fn build_assignment(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let target = build_expr(inner.next().unwrap())?;
    let value = build_expr(inner.next().unwrap())?;
    Ok(Stmt::Assignment { target, value, span: sp })
}

fn build_public_decl(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let names = build_input_decls(pair)?;
    Ok(Stmt::PublicDecl { names, span: sp })
}

fn build_witness_decl(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let names = build_input_decls(pair)?;
    Ok(Stmt::WitnessDecl { names, span: sp })
}

fn build_input_decls(pair: Pair<Rule>) -> Result<Vec<InputDecl>, String> {
    let mut decls = Vec::new();
    let mut inner = pair.into_inner().peekable();
    while let Some(child) = inner.next() {
        if child.as_rule() == Rule::identifier {
            let name = child.as_str().to_string();
            let array_size = if inner.peek().map(|p| p.as_rule()) == Some(Rule::array_size) {
                let size_pair = inner.next().unwrap();
                let s = size_pair.into_inner().next().unwrap().as_str();
                Some(s.parse::<usize>().map_err(|_| format!("invalid array size: {s}"))?)
            } else {
                None
            };
            decls.push(InputDecl { name, array_size });
        }
    }
    Ok(decls)
}

fn build_fn_decl(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();

    let mut params = Vec::new();
    let mut body = None;
    for child in inner {
        match child.as_rule() {
            Rule::param_list => {
                for param in child.into_inner() {
                    if param.as_rule() == Rule::identifier {
                        params.push(param.as_str().to_string());
                    }
                }
            }
            Rule::block => {
                body = Some(build_block(child)?);
            }
            _ => {}
        }
    }
    Ok(Stmt::FnDecl {
        name,
        params,
        body: body.unwrap(),
        span: sp,
    })
}

fn build_print(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let inner = pair.into_inner().next().unwrap();
    let value = build_expr(inner)?;
    Ok(Stmt::Print { value, span: sp })
}

fn build_return(pair: Pair<Rule>) -> Result<Stmt, String> {
    let sp = span_of(&pair);
    let value = pair.into_inner().next().map(|p| build_expr(p)).transpose()?;
    Ok(Stmt::Return { value, span: sp })
}

fn build_block(pair: Pair<Rule>) -> Result<Block, String> {
    let sp = span_of(&pair);
    let mut stmts = Vec::new();
    for child in pair.into_inner() {
        if child.as_rule() == Rule::stmt {
            stmts.push(build_stmt(child)?);
        }
    }
    Ok(Block { stmts, span: sp })
}

// ========================================================================
// Expressions
// ========================================================================

/// Build an expression from any expression-level rule.
fn build_expr(pair: Pair<Rule>) -> Result<Expr, String> {
    match pair.as_rule() {
        Rule::expr => {
            let inner = pair.into_inner().next().unwrap();
            build_expr(inner)
        }
        Rule::or_expr => build_binop_chain(pair, build_or_op),
        Rule::and_expr => build_binop_chain(pair, build_and_op),
        Rule::cmp_expr => build_binop_chain(pair, build_cmp_op),
        Rule::add_expr => build_binop_chain(pair, build_add_op),
        Rule::mul_expr => build_binop_chain(pair, build_mul_op),
        Rule::pow_expr => build_binop_chain(pair, build_pow_op),
        Rule::prefix_expr => build_prefix_expr(pair),
        Rule::postfix_expr => build_postfix_expr(pair),
        Rule::atom => build_atom(pair),
        // These can appear when an expression is used directly as a statement
        Rule::number | Rule::identifier | Rule::string | Rule::true_lit | Rule::false_lit
        | Rule::nil_lit | Rule::list_literal | Rule::map_literal | Rule::if_expr
        | Rule::while_expr | Rule::for_expr | Rule::forever_expr | Rule::prove_expr
        | Rule::fn_expr | Rule::block => build_atom_inner(pair),
        _ => Err(format!("unexpected expression rule: {:?}", pair.as_rule())),
    }
}

type OpParser = fn(&Pair<Rule>) -> Option<BinOp>;

/// Build a left-associative chain of binary operations.
/// The `op_parser` maps operator pairs to `BinOp`.
fn build_binop_chain(pair: Pair<Rule>, op_parser: OpParser) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut children = pair.into_inner();
    let first = children.next().unwrap();
    let mut result = build_expr(first)?;

    while let Some(op_pair) = children.next() {
        if let Some(op) = op_parser(&op_pair) {
            let rhs = build_expr(children.next().unwrap())?;
            result = Expr::BinOp {
                op,
                lhs: Box::new(result),
                rhs: Box::new(rhs),
                span: sp.clone(),
            };
        } else {
            // Single child (no operator), just unwrap
            return Err(format!("expected operator, got {:?}", op_pair.as_rule()));
        }
    }
    Ok(result)
}

fn build_or_op(pair: &Pair<Rule>) -> Option<BinOp> {
    if pair.as_rule() == Rule::or_op { Some(BinOp::Or) } else { None }
}

fn build_and_op(pair: &Pair<Rule>) -> Option<BinOp> {
    if pair.as_rule() == Rule::and_op { Some(BinOp::And) } else { None }
}

fn build_cmp_op(pair: &Pair<Rule>) -> Option<BinOp> {
    if pair.as_rule() == Rule::cmp_op {
        Some(match pair.as_str() {
            "==" => BinOp::Eq,
            "!=" => BinOp::Neq,
            "<" => BinOp::Lt,
            "<=" => BinOp::Le,
            ">" => BinOp::Gt,
            ">=" => BinOp::Ge,
            _ => return None,
        })
    } else {
        None
    }
}

fn build_add_op(pair: &Pair<Rule>) -> Option<BinOp> {
    if pair.as_rule() == Rule::add_op {
        Some(match pair.as_str() {
            "+" => BinOp::Add,
            "-" => BinOp::Sub,
            _ => return None,
        })
    } else {
        None
    }
}

fn build_mul_op(pair: &Pair<Rule>) -> Option<BinOp> {
    if pair.as_rule() == Rule::mul_op {
        Some(match pair.as_str() {
            "*" => BinOp::Mul,
            "/" => BinOp::Div,
            "%" => BinOp::Mod,
            _ => return None,
        })
    } else {
        None
    }
}

fn build_pow_op(pair: &Pair<Rule>) -> Option<BinOp> {
    if pair.as_rule() == Rule::pow_op { Some(BinOp::Pow) } else { None }
}

fn build_prefix_expr(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut ops = Vec::new();
    let mut operand = None;

    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::unary_op => {
                let op = match child.as_str() {
                    "-" => UnaryOp::Neg,
                    "!" => UnaryOp::Not,
                    s => return Err(format!("unknown unary operator: {s}")),
                };
                ops.push(op);
            }
            _ => {
                operand = Some(build_expr(child)?);
                break;
            }
        }
    }

    let mut result = operand.unwrap();
    // Apply operators in reverse order (innermost first)
    for op in ops.into_iter().rev() {
        result = Expr::UnaryOp {
            op,
            operand: Box::new(result),
            span: sp.clone(),
        };
    }
    Ok(result)
}

fn build_postfix_expr(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let atom = inner.next().unwrap();
    let mut result = build_expr(atom)?;

    for op in inner {
        match op.as_rule() {
            Rule::call_op => {
                let args: Vec<Expr> = op
                    .into_inner()
                    .map(build_expr)
                    .collect::<Result<_, _>>()?;
                result = Expr::Call {
                    callee: Box::new(result),
                    args,
                    span: sp.clone(),
                };
            }
            Rule::index_op => {
                let index_inner = op.into_inner().next().unwrap();
                if index_inner.as_rule() == Rule::identifier {
                    // Dot access: `.field`
                    result = Expr::DotAccess {
                        object: Box::new(result),
                        field: index_inner.as_str().to_string(),
                        span: sp.clone(),
                    };
                } else {
                    // Bracket index: `[expr]`
                    let index = build_expr(index_inner)?;
                    result = Expr::Index {
                        object: Box::new(result),
                        index: Box::new(index),
                        span: sp.clone(),
                    };
                }
            }
            _ => return Err(format!("unexpected postfix op: {:?}", op.as_rule())),
        }
    }
    Ok(result)
}

fn build_atom(pair: Pair<Rule>) -> Result<Expr, String> {
    let inner = pair.into_inner().next().unwrap();
    build_atom_inner(inner)
}

fn build_atom_inner(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    match pair.as_rule() {
        Rule::number => {
            Ok(Expr::Number {
                value: pair.as_str().to_string(),
                span: sp,
            })
        }
        Rule::identifier => {
            Ok(Expr::Ident {
                name: pair.as_str().to_string(),
                span: sp,
            })
        }
        Rule::string => {
            let inner_text = pair.into_inner().next().unwrap().as_str().to_string();
            Ok(Expr::StringLit {
                value: inner_text,
                span: sp,
            })
        }
        Rule::true_lit => Ok(Expr::Bool { value: true, span: sp }),
        Rule::false_lit => Ok(Expr::Bool { value: false, span: sp }),
        Rule::nil_lit => Ok(Expr::Nil { span: sp }),
        Rule::list_literal => {
            let elements: Vec<Expr> = pair
                .into_inner()
                .map(build_expr)
                .collect::<Result<_, _>>()?;
            Ok(Expr::Array { elements, span: sp })
        }
        Rule::map_literal => build_map(pair),
        Rule::if_expr => build_if(pair),
        Rule::while_expr => build_while(pair),
        Rule::for_expr => build_for(pair),
        Rule::forever_expr => {
            let body = build_block(pair.into_inner().next().unwrap())?;
            Ok(Expr::Forever { body, span: sp })
        }
        Rule::prove_expr => {
            let source = pair.as_str().to_string();
            let body = build_block(pair.into_inner().next().unwrap())?;
            Ok(Expr::Prove { body, source, span: sp })
        }
        Rule::fn_expr => build_fn_expr(pair),
        Rule::block => {
            let block = build_block(pair)?;
            Ok(Expr::Block(block))
        }
        Rule::expr => {
            // Parenthesized expression: `(expr)` — just unwrap
            build_expr(pair)
        }
        _ => Err(format!("unexpected atom rule: {:?}", pair.as_rule())),
    }
}

fn build_map(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut pairs_vec = Vec::new();
    for map_pair in pair.into_inner() {
        if map_pair.as_rule() == Rule::map_pair {
            let mut inner = map_pair.into_inner();
            let key_pair = inner.next().unwrap();
            let value = build_expr(inner.next().unwrap())?;
            let key = match key_pair.as_rule() {
                Rule::identifier => MapKey::Ident(key_pair.as_str().to_string()),
                Rule::string => {
                    let inner_text = key_pair.into_inner().next().unwrap().as_str().to_string();
                    MapKey::StringLit(inner_text)
                }
                _ => return Err(format!("unexpected map key: {:?}", key_pair.as_rule())),
            };
            pairs_vec.push((key, value));
        }
    }
    Ok(Expr::Map { pairs: pairs_vec, span: sp })
}

fn build_if(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let condition = Box::new(build_expr(inner.next().unwrap())?);
    let then_block = build_block(inner.next().unwrap())?;

    let else_branch = if let Some(else_part) = inner.next() {
        match else_part.as_rule() {
            Rule::block => Some(ElseBranch::Block(build_block(else_part)?)),
            Rule::if_expr => Some(ElseBranch::If(Box::new(build_if(else_part)?))),
            _ => return Err(format!("unexpected else branch: {:?}", else_part.as_rule())),
        }
    } else {
        None
    };

    Ok(Expr::If {
        condition,
        then_block,
        else_branch,
        span: sp,
    })
}

fn build_while(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let condition = Box::new(build_expr(inner.next().unwrap())?);
    let body = build_block(inner.next().unwrap())?;
    Ok(Expr::While { condition, body, span: sp })
}

fn build_for(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let var = inner.next().unwrap().as_str().to_string();
    let iterable_pair = inner.next().unwrap();
    let body = build_block(inner.next().unwrap())?;

    let iterable = if iterable_pair.as_rule() == Rule::range_expr {
        let mut range_inner = iterable_pair.into_inner();
        let start: u64 = range_inner
            .next()
            .unwrap()
            .as_str()
            .parse()
            .map_err(|e| format!("invalid range start: {e}"))?;
        let end: u64 = range_inner
            .next()
            .unwrap()
            .as_str()
            .parse()
            .map_err(|e| format!("invalid range end: {e}"))?;
        ForIterable::Range { start, end }
    } else {
        ForIterable::Expr(Box::new(build_expr(iterable_pair)?))
    };

    Ok(Expr::For { var, iterable, body, span: sp })
}

fn build_fn_expr(pair: Pair<Rule>) -> Result<Expr, String> {
    let sp = span_of(&pair);
    let mut inner = pair.into_inner();
    let mut name = None;
    let mut params = Vec::new();
    let mut body = None;

    for child in inner.by_ref() {
        match child.as_rule() {
            Rule::identifier => {
                name = Some(child.as_str().to_string());
            }
            Rule::param_list => {
                for param in child.into_inner() {
                    if param.as_rule() == Rule::identifier {
                        params.push(param.as_str().to_string());
                    }
                }
            }
            Rule::block => {
                body = Some(build_block(child)?);
            }
            _ => {}
        }
    }

    Ok(Expr::FnExpr {
        name,
        params,
        body: body.unwrap(),
        span: sp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_number() {
        let prog = parse_program("42").unwrap();
        assert_eq!(prog.stmts.len(), 1);
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Number { value, .. }) => assert_eq!(value, "42"),
            other => panic!("expected Number, got {other:?}"),
        }
    }

    #[test]
    fn parse_negative_number() {
        // `-7` at expression level is parsed as UnaryOp(Neg, Number("7"))
        // because prefix_expr captures the `-` before the number atom.
        let prog = parse_program("-7").unwrap();
        assert_eq!(prog.stmts.len(), 1);
        match &prog.stmts[0] {
            Stmt::Expr(Expr::UnaryOp { op, operand, .. }) => {
                assert_eq!(*op, UnaryOp::Neg);
                match operand.as_ref() {
                    Expr::Number { value, .. } => assert_eq!(value, "7"),
                    other => panic!("expected Number, got {other:?}"),
                }
            }
            other => panic!("expected UnaryOp(Neg), got {other:?}"),
        }
    }

    #[test]
    fn parse_let_decl() {
        let prog = parse_program("let x = 5").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { name, value, .. } => {
                assert_eq!(name, "x");
                match value {
                    Expr::Number { value: v, .. } => assert_eq!(v, "5"),
                    other => panic!("expected Number, got {other:?}"),
                }
            }
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_binary_add() {
        let prog = parse_program("a + b").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::BinOp { op, lhs, rhs, .. }) => {
                assert_eq!(*op, BinOp::Add);
                match lhs.as_ref() {
                    Expr::Ident { name, .. } => assert_eq!(name, "a"),
                    other => panic!("expected Ident, got {other:?}"),
                }
                match rhs.as_ref() {
                    Expr::Ident { name, .. } => assert_eq!(name, "b"),
                    other => panic!("expected Ident, got {other:?}"),
                }
            }
            other => panic!("expected BinOp, got {other:?}"),
        }
    }

    #[test]
    fn parse_function_call() {
        let prog = parse_program("foo(1, 2)").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Call { callee, args, .. }) => {
                match callee.as_ref() {
                    Expr::Ident { name, .. } => assert_eq!(name, "foo"),
                    other => panic!("expected Ident, got {other:?}"),
                }
                assert_eq!(args.len(), 2);
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn parse_array_literal() {
        let prog = parse_program("let arr = [1, 2, 3]").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { value, .. } => match value {
                Expr::Array { elements, .. } => assert_eq!(elements.len(), 3),
                other => panic!("expected Array, got {other:?}"),
            },
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_if_else() {
        let prog = parse_program("if x { 1 } else { 2 }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::If { else_branch, .. }) => {
                assert!(else_branch.is_some());
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn parse_for_range() {
        let prog = parse_program("for i in 0..5 { i }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::For { var, iterable, .. }) => {
                assert_eq!(var, "i");
                match iterable {
                    ForIterable::Range { start, end } => {
                        assert_eq!(*start, 0);
                        assert_eq!(*end, 5);
                    }
                    other => panic!("expected Range, got {other:?}"),
                }
            }
            other => panic!("expected For, got {other:?}"),
        }
    }

    #[test]
    fn parse_fn_decl() {
        let prog = parse_program("fn add(a, b) { a + b }").unwrap();
        match &prog.stmts[0] {
            Stmt::FnDecl { name, params, .. } => {
                assert_eq!(name, "add");
                assert_eq!(params, &["a", "b"]);
            }
            other => panic!("expected FnDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_public_witness_decl() {
        let prog = parse_program("public x, y\nwitness z[3]").unwrap();
        assert_eq!(prog.stmts.len(), 2);
        match &prog.stmts[0] {
            Stmt::PublicDecl { names, .. } => {
                assert_eq!(names.len(), 2);
                assert_eq!(names[0].name, "x");
                assert!(names[0].array_size.is_none());
                assert_eq!(names[1].name, "y");
            }
            other => panic!("expected PublicDecl, got {other:?}"),
        }
        match &prog.stmts[1] {
            Stmt::WitnessDecl { names, .. } => {
                assert_eq!(names.len(), 1);
                assert_eq!(names[0].name, "z");
                assert_eq!(names[0].array_size, Some(3));
            }
            other => panic!("expected WitnessDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_prove_block() {
        let prog = parse_program("prove { 1 + 2 }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Prove { source, .. }) => {
                assert!(source.contains("1 + 2"));
            }
            other => panic!("expected Prove, got {other:?}"),
        }
    }

    #[test]
    fn parse_unary_ops() {
        let prog = parse_program("-x").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::UnaryOp { op, .. }) => assert_eq!(*op, UnaryOp::Neg),
            other => panic!("expected UnaryOp, got {other:?}"),
        }
    }

    #[test]
    fn parse_index_access() {
        let prog = parse_program("arr[0]").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Index { .. }) => {}
            other => panic!("expected Index, got {other:?}"),
        }
    }

    #[test]
    fn parse_dot_access() {
        let prog = parse_program("obj.field").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::DotAccess { field, .. }) => assert_eq!(field, "field"),
            other => panic!("expected DotAccess, got {other:?}"),
        }
    }

    #[test]
    fn parse_map_literal() {
        let prog = parse_program(r#"{ key: 1, "str_key": 2 }"#).unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Map { pairs, .. }) => {
                assert_eq!(pairs.len(), 2);
            }
            // Could parse as block if no colon syntax — check
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn parse_block_source() {
        let block = parse_block("{ let x = 1; x + 2 }").unwrap();
        assert_eq!(block.stmts.len(), 2);
    }

    #[test]
    fn parse_precedence() {
        // a + b * c should parse as a + (b * c)
        let prog = parse_program("a + b * c").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::BinOp { op: BinOp::Add, rhs, .. }) => {
                match rhs.as_ref() {
                    Expr::BinOp { op: BinOp::Mul, .. } => {}
                    other => panic!("expected Mul on rhs, got {other:?}"),
                }
            }
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn parse_chained_comparison() {
        // a == b should work
        let prog = parse_program("a == b").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::BinOp { op: BinOp::Eq, .. }) => {}
            other => panic!("expected Eq, got {other:?}"),
        }
    }

    #[test]
    fn parse_logical_operators() {
        let prog = parse_program("a && b || c").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::BinOp { op: BinOp::Or, lhs, .. }) => {
                match lhs.as_ref() {
                    Expr::BinOp { op: BinOp::And, .. } => {}
                    other => panic!("expected And on lhs, got {other:?}"),
                }
            }
            other => panic!("expected Or, got {other:?}"),
        }
    }
}
