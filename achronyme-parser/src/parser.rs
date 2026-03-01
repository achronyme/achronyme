/// Recursive descent parser with Pratt expression parsing for Achronyme.
///
/// Drop-in replacement for `build_ast::parse_program` / `build_ast::parse_block`.
use crate::ast::*;
use crate::error::ParseError;
use crate::lexer::Lexer;
use crate::token::{Token, TokenKind};

/// Parse a complete source string into an AST Program.
///
/// ```
/// use achronyme_parser::parse_program;
///
/// let prog = parse_program("let x = 1 + 2").unwrap();
/// assert_eq!(prog.stmts.len(), 1);
/// ```
pub fn parse_program(source: &str) -> Result<Program, String> {
    let tokens = Lexer::tokenize(source).map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_program().map_err(|e| e.to_string())
}

/// Parse a block source (including braces) into an AST Block.
///
/// ```
/// use achronyme_parser::parse_program;
/// use achronyme_parser::ast::Stmt;
///
/// let prog = parse_program("public x\nwitness y\nassert_eq(x, y)").unwrap();
/// assert_eq!(prog.stmts.len(), 3);
/// assert!(matches!(&prog.stmts[0], Stmt::PublicDecl { .. }));
/// assert!(matches!(&prog.stmts[1], Stmt::WitnessDecl { .. }));
/// ```
/// Parse a complete source string, returning a structured [`ParseError`] on failure.
pub fn parse_program_with_errors(source: &str) -> Result<Program, ParseError> {
    let tokens = Lexer::tokenize(source)?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_program()
}

pub fn parse_block(source: &str) -> Result<Block, String> {
    let tokens = Lexer::tokenize(source).map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_block().map_err(|e| e.to_string())
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    source: String,
    /// Nesting depth: 0 = top-level, >0 = inside block/function.
    block_depth: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>, source: String) -> Self {
        Self {
            tokens,
            pos: 0,
            source,
            block_depth: 0,
        }
    }

    // ========================================================================
    // Token helpers
    // ========================================================================

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn at(&self, kind: &TokenKind) -> bool {
        self.peek_kind() == kind
    }

    fn advance(&mut self) -> &Token {
        let tok = &self.tokens[self.pos];
        if tok.kind != TokenKind::Eof {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, kind: &TokenKind) -> Result<&Token, ParseError> {
        if self.at(kind) {
            Ok(self.advance())
        } else {
            let tok = self.peek();
            Err(ParseError::new(
                format!(
                    "expected `{}`, found `{}`",
                    kind_name(kind),
                    tok_display(tok)
                ),
                tok.span.line,
                tok.span.col,
            ))
        }
    }

    fn span(&self) -> Span {
        self.peek().span.clone()
    }

    fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Peek at the token N positions ahead (0 = current).
    fn lookahead(&self, n: usize) -> &TokenKind {
        let idx = self.pos + n;
        if idx < self.tokens.len() {
            &self.tokens[idx].kind
        } else {
            &TokenKind::Eof
        }
    }

    // ========================================================================
    // Program / Block
    // ========================================================================

    fn do_parse_program(&mut self) -> Result<Program, ParseError> {
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
            self.eat(&TokenKind::Semicolon);
        }
        Ok(Program { stmts })
    }

    fn do_parse_block(&mut self) -> Result<Block, ParseError> {
        self.parse_block_inner()
    }

    fn parse_block_inner(&mut self) -> Result<Block, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::LBrace)?;
        self.block_depth += 1;
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
            self.eat(&TokenKind::Semicolon);
        }
        self.block_depth -= 1;
        self.expect(&TokenKind::RBrace)?;
        Ok(Block { stmts, span: sp })
    }

    // ========================================================================
    // Statements
    // ========================================================================

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek_kind() {
            TokenKind::Import => self.parse_import(),
            TokenKind::Export => self.parse_export(),
            TokenKind::Let => self.parse_let_decl(),
            TokenKind::Mut => self.parse_mut_decl(),
            TokenKind::Public => self.parse_public_decl(),
            TokenKind::Witness => self.parse_witness_decl(),
            TokenKind::Fn => {
                // fn as statement requires a name (fn_decl)
                // fn as expression may or may not have a name
                // Disambiguate: `fn <ident> (` → FnDecl statement
                if matches!(self.lookahead(1), TokenKind::Ident)
                    && matches!(self.lookahead(2), TokenKind::LParen)
                {
                    self.parse_fn_decl()
                } else {
                    // fn expression (anonymous or named used as value)
                    let expr = self.parse_expr()?;
                    self.try_parse_assignment(expr)
                }
            }
            TokenKind::Print => self.parse_print(),
            TokenKind::Return => self.parse_return(),
            TokenKind::Break => {
                let sp = self.span();
                self.advance();
                Ok(Stmt::Break { span: sp })
            }
            TokenKind::Continue => {
                let sp = self.span();
                self.advance();
                Ok(Stmt::Continue { span: sp })
            }
            _ => {
                let expr = self.parse_expr()?;
                self.try_parse_assignment(expr)
            }
        }
    }

    /// After parsing an expression, check if `=` follows to make it an assignment.
    fn try_parse_assignment(&mut self, expr: Expr) -> Result<Stmt, ParseError> {
        if self.at(&TokenKind::Assign) {
            let sp = expr.span().clone();
            self.advance();
            let value = self.parse_expr()?;
            Ok(Stmt::Assignment {
                target: expr,
                value,
                span: sp,
            })
        } else {
            Ok(Stmt::Expr(expr))
        }
    }

    fn parse_let_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `let`
        let name = self.expect_ident()?;
        let type_ann = self.try_parse_type_annotation()?;
        self.expect(&TokenKind::Assign)?;
        let value = self.parse_expr()?;
        Ok(Stmt::LetDecl {
            name,
            type_ann,
            value,
            span: sp,
        })
    }

    fn parse_mut_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `mut`
        let name = self.expect_ident()?;
        let type_ann = self.try_parse_type_annotation()?;
        self.expect(&TokenKind::Assign)?;
        let value = self.parse_expr()?;
        Ok(Stmt::MutDecl {
            name,
            type_ann,
            value,
            span: sp,
        })
    }

    fn parse_public_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `public`
        let names = self.parse_input_decl_list()?;
        Ok(Stmt::PublicDecl { names, span: sp })
    }

    fn parse_witness_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `witness`
        let names = self.parse_input_decl_list()?;
        Ok(Stmt::WitnessDecl { names, span: sp })
    }

    fn parse_input_decl_list(&mut self) -> Result<Vec<InputDecl>, ParseError> {
        let mut decls = Vec::new();
        decls.push(self.parse_input_decl()?);
        while self.eat(&TokenKind::Comma) {
            decls.push(self.parse_input_decl()?);
        }
        Ok(decls)
    }

    fn parse_input_decl(&mut self) -> Result<InputDecl, ParseError> {
        let name = self.expect_ident()?;
        let array_size = if self.eat(&TokenKind::LBracket) {
            let tok = self.expect(&TokenKind::Integer)?;
            let size: usize = tok.lexeme.parse().map_err(|_| {
                ParseError::new(
                    format!("invalid array size: {}", tok.lexeme),
                    tok.span.line,
                    tok.span.col,
                )
            })?;
            // Need to clone span info before expecting
            self.expect(&TokenKind::RBracket)?;
            Some(size)
        } else {
            None
        };
        let type_ann = self.try_parse_type_annotation()?;
        Ok(InputDecl {
            name,
            array_size,
            type_ann,
        })
    }

    fn parse_fn_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `fn`
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_param_list()?;
        self.expect(&TokenKind::RParen)?;
        let return_type = self.try_parse_return_type()?;
        let body = self.parse_block_inner()?;
        Ok(Stmt::FnDecl {
            name,
            params,
            return_type,
            body,
            span: sp,
        })
    }

    fn parse_import(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        if self.block_depth > 0 {
            return Err(ParseError::new(
                "import statements are only allowed at the top level",
                sp.line,
                sp.col,
            ));
        }
        self.advance(); // eat `import`
        let tok = self.peek().clone();
        if tok.kind != TokenKind::StringLit {
            return Err(ParseError::new(
                format!(
                    "expected string literal for import path, found `{}`",
                    tok_display(&tok)
                ),
                tok.span.line,
                tok.span.col,
            ));
        }
        let path = tok.lexeme.clone();
        self.advance();
        self.expect(&TokenKind::As)?;
        let alias = self.expect_ident()?;
        Ok(Stmt::Import {
            path,
            alias,
            span: sp,
        })
    }

    fn parse_export(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        if self.block_depth > 0 {
            return Err(ParseError::new(
                "export statements are only allowed at the top level",
                sp.line,
                sp.col,
            ));
        }
        self.advance(); // eat `export`
        let inner = match self.peek_kind() {
            TokenKind::Fn => {
                if matches!(self.lookahead(1), TokenKind::Ident)
                    && matches!(self.lookahead(2), TokenKind::LParen)
                {
                    self.parse_fn_decl()?
                } else {
                    let tok = self.peek();
                    return Err(ParseError::new(
                        "export only applies to named `fn` or `let` declarations",
                        tok.span.line,
                        tok.span.col,
                    ));
                }
            }
            TokenKind::Let => self.parse_let_decl()?,
            _ => {
                let tok = self.peek();
                return Err(ParseError::new(
                    format!(
                        "export only applies to `fn` or `let` declarations, found `{}`",
                        tok_display(tok)
                    ),
                    tok.span.line,
                    tok.span.col,
                ));
            }
        };
        Ok(Stmt::Export {
            inner: Box::new(inner),
            span: sp,
        })
    }

    fn parse_param_list(&mut self) -> Result<Vec<TypedParam>, ParseError> {
        let mut params = Vec::new();
        if !self.at(&TokenKind::RParen) {
            let name = self.expect_ident()?;
            let type_ann = self.try_parse_type_annotation()?;
            params.push(TypedParam { name, type_ann });
            while self.eat(&TokenKind::Comma) {
                let name = self.expect_ident()?;
                let type_ann = self.try_parse_type_annotation()?;
                params.push(TypedParam { name, type_ann });
            }
        }
        Ok(params)
    }

    fn parse_print(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `print`
        self.expect(&TokenKind::LParen)?;
        let value = self.parse_expr()?;
        self.expect(&TokenKind::RParen)?;
        Ok(Stmt::Print { value, span: sp })
    }

    fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `return`
                        // Return has an optional value. Value present if next token can start an expression
                        // and is NOT a statement-starting keyword or block closer.
        let value = if self.can_start_expr() {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Stmt::Return { value, span: sp })
    }

    /// Whether the current token can start an expression.
    fn can_start_expr(&self) -> bool {
        matches!(
            self.peek_kind(),
            TokenKind::Integer
                | TokenKind::StringLit
                | TokenKind::Ident
                | TokenKind::True
                | TokenKind::False
                | TokenKind::Nil
                | TokenKind::LParen
                | TokenKind::LBracket
                | TokenKind::LBrace
                | TokenKind::Minus
                | TokenKind::Not
                | TokenKind::If
                | TokenKind::While
                | TokenKind::For
                | TokenKind::Forever
                | TokenKind::Fn
                | TokenKind::Prove
        )
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        if tok.kind == TokenKind::Ident {
            self.advance();
            Ok(tok.lexeme)
        } else {
            Err(ParseError::new(
                format!("expected identifier, found `{}`", tok_display(&tok)),
                tok.span.line,
                tok.span.col,
            ))
        }
    }

    // ========================================================================
    // Type annotation helpers
    // ========================================================================

    /// Try to parse a type annotation (`: Type`). Returns `None` if no `:` is present.
    fn try_parse_type_annotation(&mut self) -> Result<Option<TypeAnnotation>, ParseError> {
        if !self.eat(&TokenKind::Colon) {
            return Ok(None);
        }
        let ann = self.parse_type()?;
        Ok(Some(ann))
    }

    /// Try to parse a return type annotation (`-> Type`). Returns `None` if no `->` is present.
    fn try_parse_return_type(&mut self) -> Result<Option<TypeAnnotation>, ParseError> {
        if !self.eat(&TokenKind::Arrow) {
            return Ok(None);
        }
        let ann = self.parse_type()?;
        Ok(Some(ann))
    }

    /// Parse a type: `Field`, `Bool`, `Field[N]`, or `Bool[N]`.
    fn parse_type(&mut self) -> Result<TypeAnnotation, ParseError> {
        let tok = self.peek().clone();
        if tok.kind != TokenKind::Ident {
            return Err(ParseError::new(
                format!(
                    "expected type (`Field` or `Bool`), found `{}`",
                    tok_display(&tok)
                ),
                tok.span.line,
                tok.span.col,
            ));
        }
        let base = tok.lexeme.as_str();
        if base != "Field" && base != "Bool" {
            return Err(ParseError::new(
                format!("expected type (`Field` or `Bool`), found `{base}`"),
                tok.span.line,
                tok.span.col,
            ));
        }
        self.advance();

        // Check for array syntax: `[N]`
        if self.eat(&TokenKind::LBracket) {
            let size_tok = self.expect(&TokenKind::Integer)?;
            let size: usize = size_tok.lexeme.parse().map_err(|_| {
                ParseError::new(
                    format!("invalid array size: {}", size_tok.lexeme),
                    size_tok.span.line,
                    size_tok.span.col,
                )
            })?;
            self.expect(&TokenKind::RBracket)?;
            return Ok(match base {
                "Field" => TypeAnnotation::FieldArray(size),
                "Bool" => TypeAnnotation::BoolArray(size),
                _ => unreachable!(),
            });
        }

        Ok(match base {
            "Field" => TypeAnnotation::Field,
            "Bool" => TypeAnnotation::Bool,
            _ => unreachable!(),
        })
    }

    // ========================================================================
    // Expressions — Pratt parser
    // ========================================================================

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_expr_bp(0)
    }

    fn parse_expr_bp(&mut self, min_bp: u8) -> Result<Expr, ParseError> {
        // Prefix
        let mut lhs = self.parse_prefix()?;

        // Infix / postfix loop
        loop {
            // Postfix: call, index, dot
            match self.peek_kind() {
                TokenKind::LParen => {
                    if 13 < min_bp {
                        break;
                    }
                    lhs = self.parse_call(lhs)?;
                    continue;
                }
                TokenKind::LBracket => {
                    if 13 < min_bp {
                        break;
                    }
                    lhs = self.parse_index(lhs)?;
                    continue;
                }
                TokenKind::Dot => {
                    if 13 < min_bp {
                        break;
                    }
                    lhs = self.parse_dot(lhs)?;
                    continue;
                }
                _ => {}
            }

            // Infix binary operators
            if let Some((l_bp, r_bp)) = infix_bp(self.peek_kind()) {
                if l_bp < min_bp {
                    break;
                }
                let op_tok = self.advance().clone();
                let was_cmp = is_comparison(&op_tok.kind);
                let op = token_to_binop(&op_tok.kind);
                let rhs = self.parse_expr_bp(r_bp)?;
                let sp = lhs.span().clone();
                lhs = Expr::BinOp {
                    op,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    span: sp,
                };
                // Reject chained comparisons: `a < b < c` is a silent bug
                if was_cmp && is_comparison(self.peek_kind()) {
                    let next = self.peek();
                    return Err(ParseError::new(
                        "comparison operators cannot be chained; use `&&` to combine: `a < b && b < c`",
                        next.span.line,
                        next.span.col,
                    ));
                }
                continue;
            }

            break;
        }

        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<Expr, ParseError> {
        match self.peek_kind() {
            TokenKind::Minus | TokenKind::Not => {
                let sp = self.span();
                let op_tok = self.advance().clone();
                let op = match op_tok.kind {
                    TokenKind::Minus => UnaryOp::Neg,
                    TokenKind::Not => UnaryOp::Not,
                    _ => unreachable!(),
                };
                let operand = self.parse_expr_bp(11)?; // prefix BP
                Ok(Expr::UnaryOp {
                    op,
                    operand: Box::new(operand),
                    span: sp,
                })
            }
            _ => self.parse_atom(),
        }
    }

    fn parse_atom(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        match self.peek_kind().clone() {
            TokenKind::Integer => {
                let tok = self.advance().clone();
                Ok(Expr::Number {
                    value: tok.lexeme,
                    span: sp,
                })
            }
            TokenKind::FieldLit => {
                let tok = self.advance().clone();
                let (value, radix) = if let Some(hex) = tok.lexeme.strip_prefix('x') {
                    (hex.to_string(), FieldRadix::Hex)
                } else if let Some(bin) = tok.lexeme.strip_prefix('b') {
                    (bin.to_string(), FieldRadix::Binary)
                } else {
                    (tok.lexeme, FieldRadix::Decimal)
                };
                Ok(Expr::FieldLit {
                    value,
                    radix,
                    span: sp,
                })
            }
            TokenKind::BigIntLit => {
                let tok = self.advance().clone();
                // Lexeme format: "256xFF00" or "512d42" or "256b1010"
                // Find the radix char position (first non-digit after start)
                let width_end = tok
                    .lexeme
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(tok.lexeme.len());
                let width: u16 = tok.lexeme[..width_end]
                    .parse()
                    .map_err(|_| ParseError::new("invalid BigInt width", sp.line, sp.col))?;
                let rest = &tok.lexeme[width_end..];
                let (value, radix) = if let Some(hex) = rest.strip_prefix('x') {
                    (hex.to_string(), BigIntRadix::Hex)
                } else if let Some(dec) = rest.strip_prefix('d') {
                    (dec.to_string(), BigIntRadix::Decimal)
                } else if let Some(bin) = rest.strip_prefix('b') {
                    (bin.to_string(), BigIntRadix::Binary)
                } else {
                    return Err(ParseError::new(
                        "invalid BigInt literal radix",
                        sp.line,
                        sp.col,
                    ));
                };
                Ok(Expr::BigIntLit {
                    value,
                    width,
                    radix,
                    span: sp,
                })
            }
            TokenKind::StringLit => {
                let tok = self.advance().clone();
                Ok(Expr::StringLit {
                    value: tok.lexeme,
                    span: sp,
                })
            }
            TokenKind::True => {
                self.advance();
                Ok(Expr::Bool {
                    value: true,
                    span: sp,
                })
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::Bool {
                    value: false,
                    span: sp,
                })
            }
            TokenKind::Nil => {
                self.advance();
                Ok(Expr::Nil { span: sp })
            }
            TokenKind::Ident => {
                let tok = self.advance().clone();
                Ok(Expr::Ident {
                    name: tok.lexeme,
                    span: sp,
                })
            }
            TokenKind::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(&TokenKind::RParen)?;
                Ok(expr)
            }
            TokenKind::LBracket => self.parse_array(),
            TokenKind::LBrace => self.parse_brace_expr(),
            TokenKind::If => self.parse_if(),
            TokenKind::While => self.parse_while(),
            TokenKind::For => self.parse_for(),
            TokenKind::Forever => self.parse_forever(),
            TokenKind::Fn => self.parse_fn_expr(),
            TokenKind::Prove => self.parse_prove(),
            _ => {
                let tok = self.peek();
                Err(ParseError::new(
                    format!("expected expression, found `{}`", tok_display(tok)),
                    tok.span.line,
                    tok.span.col,
                ))
            }
        }
    }

    // ========================================================================
    // Postfix helpers
    // ========================================================================

    fn parse_call(&mut self, callee: Expr) -> Result<Expr, ParseError> {
        let sp = callee.span().clone();
        self.advance(); // eat `(`
        let mut args = Vec::new();
        if !self.at(&TokenKind::RParen) {
            args.push(self.parse_expr()?);
            while self.eat(&TokenKind::Comma) {
                if self.at(&TokenKind::RParen) {
                    break; // trailing comma
                }
                args.push(self.parse_expr()?);
            }
        }
        self.expect(&TokenKind::RParen)?;
        Ok(Expr::Call {
            callee: Box::new(callee),
            args,
            span: sp,
        })
    }

    fn parse_index(&mut self, object: Expr) -> Result<Expr, ParseError> {
        let sp = object.span().clone();
        self.advance(); // eat `[`
        let index = self.parse_expr()?;
        self.expect(&TokenKind::RBracket)?;
        Ok(Expr::Index {
            object: Box::new(object),
            index: Box::new(index),
            span: sp,
        })
    }

    fn parse_dot(&mut self, object: Expr) -> Result<Expr, ParseError> {
        let sp = object.span().clone();
        self.advance(); // eat `.`
        let field = self.expect_ident()?;
        Ok(Expr::DotAccess {
            object: Box::new(object),
            field,
            span: sp,
        })
    }

    // ========================================================================
    // Compound expressions
    // ========================================================================

    fn parse_array(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `[`
        let mut elements = Vec::new();
        if !self.at(&TokenKind::RBracket) {
            elements.push(self.parse_expr()?);
            while self.eat(&TokenKind::Comma) {
                if self.at(&TokenKind::RBracket) {
                    break; // trailing comma
                }
                elements.push(self.parse_expr()?);
            }
        }
        self.expect(&TokenKind::RBracket)?;
        Ok(Expr::Array { elements, span: sp })
    }

    /// Disambiguate `{` — map literal vs block.
    /// Map: `{ ident: expr, ... }` or `{ "str": expr, ... }`
    /// Block: everything else
    fn parse_brace_expr(&mut self) -> Result<Expr, ParseError> {
        // LL-3 lookahead: `{ (ident|string) `:` → map
        if self.is_map_literal() {
            self.parse_map()
        } else {
            let block = self.parse_block_inner()?;
            Ok(Expr::Block(block))
        }
    }

    fn is_map_literal(&self) -> bool {
        // Current token is `{`
        // Check tokens[pos+1] is ident or string, and tokens[pos+2] is `:`
        match self.lookahead(1) {
            TokenKind::Ident | TokenKind::StringLit => {
                matches!(self.lookahead(2), TokenKind::Colon)
            }
            // `{}` is an empty map (matches pest grammar behavior)
            TokenKind::RBrace => true,
            _ => false,
        }
    }

    fn parse_map(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `{`
        let mut pairs = Vec::new();
        if !self.at(&TokenKind::RBrace) {
            pairs.push(self.parse_map_pair()?);
            while self.eat(&TokenKind::Comma) {
                if self.at(&TokenKind::RBrace) {
                    break; // trailing comma
                }
                pairs.push(self.parse_map_pair()?);
            }
        }
        self.expect(&TokenKind::RBrace)?;
        Ok(Expr::Map { pairs, span: sp })
    }

    fn parse_map_pair(&mut self) -> Result<(MapKey, Expr), ParseError> {
        let key = match self.peek_kind() {
            TokenKind::Ident => {
                let tok = self.advance().clone();
                MapKey::Ident(tok.lexeme)
            }
            TokenKind::StringLit => {
                let tok = self.advance().clone();
                MapKey::StringLit(tok.lexeme)
            }
            _ => {
                let tok = self.peek();
                return Err(ParseError::new(
                    format!(
                        "expected map key (identifier or string), found `{}`",
                        tok_display(tok)
                    ),
                    tok.span.line,
                    tok.span.col,
                ));
            }
        };
        self.expect(&TokenKind::Colon)?;
        let value = self.parse_expr()?;
        Ok((key, value))
    }

    fn parse_if(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `if`
        let condition = Box::new(self.parse_expr()?);
        let then_block = self.parse_block_inner()?;
        let else_branch = if self.eat(&TokenKind::Else) {
            if self.at(&TokenKind::If) {
                Some(ElseBranch::If(Box::new(self.parse_if()?)))
            } else {
                Some(ElseBranch::Block(self.parse_block_inner()?))
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

    fn parse_while(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `while`
        let condition = Box::new(self.parse_expr()?);
        let body = self.parse_block_inner()?;
        Ok(Expr::While {
            condition,
            body,
            span: sp,
        })
    }

    fn parse_for(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `for`
        let var = self.expect_ident()?;
        self.expect(&TokenKind::In)?;

        // Try range: `integer..integer`
        let iterable = if self.at(&TokenKind::Integer) && self.lookahead(1) == &TokenKind::DotDot {
            let start_tok = self.advance().clone();
            self.advance(); // eat `..`
            let end_tok = self.expect(&TokenKind::Integer)?;
            let start: u64 = start_tok.lexeme.parse().map_err(|e| {
                ParseError::new(
                    format!("invalid range start: {e}"),
                    start_tok.span.line,
                    start_tok.span.col,
                )
            })?;
            let end: u64 = end_tok.lexeme.parse().map_err(|e| {
                ParseError::new(
                    format!("invalid range end: {e}"),
                    end_tok.span.line,
                    end_tok.span.col,
                )
            })?;
            ForIterable::Range { start, end }
        } else {
            ForIterable::Expr(Box::new(self.parse_expr()?))
        };

        let body = self.parse_block_inner()?;
        Ok(Expr::For {
            var,
            iterable,
            body,
            span: sp,
        })
    }

    fn parse_forever(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `forever`
        let body = self.parse_block_inner()?;
        Ok(Expr::Forever { body, span: sp })
    }

    fn parse_fn_expr(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        self.advance(); // eat `fn`
        let name = if self.at(&TokenKind::Ident) {
            Some(self.expect_ident()?)
        } else {
            None
        };
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_param_list()?;
        self.expect(&TokenKind::RParen)?;
        let return_type = self.try_parse_return_type()?;
        let body = self.parse_block_inner()?;
        Ok(Expr::FnExpr {
            name,
            params,
            return_type,
            body,
            span: sp,
        })
    }

    fn parse_prove(&mut self) -> Result<Expr, ParseError> {
        let sp = self.span();
        let start = self.peek().byte_offset;
        self.advance(); // eat `prove`

        let body = self.parse_block_inner()?;

        // The closing `}` was the token just before current position
        let end = self.tokens[self.pos - 1].byte_offset + 1;
        let source_text = self.source[start..end].to_string();

        Ok(Expr::Prove {
            body,
            source: source_text,
            span: sp,
        })
    }
}

// ============================================================================
// Pratt precedence helpers
// ============================================================================

/// Returns (left_bp, right_bp) for infix operators. None if not infix.
fn is_comparison(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Eq
            | TokenKind::Neq
            | TokenKind::Lt
            | TokenKind::Le
            | TokenKind::Gt
            | TokenKind::Ge
    )
}

fn infix_bp(kind: &TokenKind) -> Option<(u8, u8)> {
    Some(match kind {
        TokenKind::Or => (1, 2),
        TokenKind::And => (3, 4),
        TokenKind::Eq
        | TokenKind::Neq
        | TokenKind::Lt
        | TokenKind::Le
        | TokenKind::Gt
        | TokenKind::Ge => (5, 6),
        TokenKind::Plus | TokenKind::Minus => (7, 8),
        TokenKind::Star | TokenKind::Slash | TokenKind::Percent => (9, 10),
        TokenKind::Caret => (12, 11), // right-associative
        _ => return None,
    })
}

fn token_to_binop(kind: &TokenKind) -> BinOp {
    match kind {
        TokenKind::Plus => BinOp::Add,
        TokenKind::Minus => BinOp::Sub,
        TokenKind::Star => BinOp::Mul,
        TokenKind::Slash => BinOp::Div,
        TokenKind::Percent => BinOp::Mod,
        TokenKind::Caret => BinOp::Pow,
        TokenKind::Eq => BinOp::Eq,
        TokenKind::Neq => BinOp::Neq,
        TokenKind::Lt => BinOp::Lt,
        TokenKind::Le => BinOp::Le,
        TokenKind::Gt => BinOp::Gt,
        TokenKind::Ge => BinOp::Ge,
        TokenKind::And => BinOp::And,
        TokenKind::Or => BinOp::Or,
        _ => unreachable!("not a binary operator: {kind:?}"),
    }
}

fn kind_name(kind: &TokenKind) -> &'static str {
    match kind {
        TokenKind::Integer => "integer",
        TokenKind::FieldLit => "field literal",
        TokenKind::BigIntLit => "bigint literal",
        TokenKind::StringLit => "string",
        TokenKind::Let => "let",
        TokenKind::Mut => "mut",
        TokenKind::If => "if",
        TokenKind::Else => "else",
        TokenKind::While => "while",
        TokenKind::For => "for",
        TokenKind::In => "in",
        TokenKind::Fn => "fn",
        TokenKind::Return => "return",
        TokenKind::Break => "break",
        TokenKind::Continue => "continue",
        TokenKind::Print => "print",
        TokenKind::Nil => "nil",
        TokenKind::True => "true",
        TokenKind::False => "false",
        TokenKind::Public => "public",
        TokenKind::Witness => "witness",
        TokenKind::Prove => "prove",
        TokenKind::Forever => "forever",
        TokenKind::Import => "import",
        TokenKind::Export => "export",
        TokenKind::As => "as",
        TokenKind::Ident => "identifier",
        TokenKind::Plus => "+",
        TokenKind::Minus => "-",
        TokenKind::Star => "*",
        TokenKind::Slash => "/",
        TokenKind::Percent => "%",
        TokenKind::Caret => "^",
        TokenKind::Eq => "==",
        TokenKind::Neq => "!=",
        TokenKind::Lt => "<",
        TokenKind::Le => "<=",
        TokenKind::Gt => ">",
        TokenKind::Ge => ">=",
        TokenKind::And => "&&",
        TokenKind::Or => "||",
        TokenKind::Not => "!",
        TokenKind::Assign => "=",
        TokenKind::Arrow => "->",
        TokenKind::DotDot => "..",
        TokenKind::Dot => ".",
        TokenKind::LParen => "(",
        TokenKind::RParen => ")",
        TokenKind::LBracket => "[",
        TokenKind::RBracket => "]",
        TokenKind::LBrace => "{",
        TokenKind::RBrace => "}",
        TokenKind::Comma => ",",
        TokenKind::Colon => ":",
        TokenKind::Semicolon => ";",
        TokenKind::Eof => "end of file",
    }
}

fn tok_display(tok: &Token) -> String {
    if tok.kind == TokenKind::Eof {
        "end of file".to_string()
    } else if tok.lexeme.is_empty() {
        kind_name(&tok.kind).to_string()
    } else {
        tok.lexeme.clone()
    }
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
            Stmt::FnDecl {
                name,
                params,
                return_type,
                ..
            } => {
                assert_eq!(name, "add");
                let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
                assert_eq!(names, &["a", "b"]);
                assert!(params.iter().all(|p| p.type_ann.is_none()));
                assert!(return_type.is_none());
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
    fn reject_chained_comparisons() {
        // P-03: comparison operators cannot be chained
        assert!(parse_program("a < b < c").is_err());
        assert!(parse_program("a == b == c").is_err());
        assert!(parse_program("a >= b <= c").is_err());
        // Single comparison is fine
        assert!(parse_program("a < b").is_ok());
        // Combining with && is fine
        assert!(parse_program("a < b && b < c").is_ok());
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
            Stmt::Expr(Expr::BinOp {
                op: BinOp::Add,
                rhs,
                ..
            }) => match rhs.as_ref() {
                Expr::BinOp { op: BinOp::Mul, .. } => {}
                other => panic!("expected Mul on rhs, got {other:?}"),
            },
            other => panic!("expected Add, got {other:?}"),
        }
    }

    #[test]
    fn parse_chained_comparison() {
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
            Stmt::Expr(Expr::BinOp {
                op: BinOp::Or, lhs, ..
            }) => match lhs.as_ref() {
                Expr::BinOp { op: BinOp::And, .. } => {}
                other => panic!("expected And on lhs, got {other:?}"),
            },
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn parse_right_assoc_pow() {
        // 2^3^4 should parse as 2^(3^4)
        let prog = parse_program("2^3^4").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::BinOp {
                op: BinOp::Pow,
                lhs,
                rhs,
                ..
            }) => {
                match lhs.as_ref() {
                    Expr::Number { value, .. } => assert_eq!(value, "2"),
                    other => panic!("expected Number(2), got {other:?}"),
                }
                match rhs.as_ref() {
                    Expr::BinOp { op: BinOp::Pow, .. } => {}
                    other => panic!("expected Pow on rhs, got {other:?}"),
                }
            }
            other => panic!("expected Pow, got {other:?}"),
        }
    }

    #[test]
    fn parse_neg_before_pow() {
        // -a^2 should parse as -(a^2)
        let prog = parse_program("-a^2").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::UnaryOp {
                op: UnaryOp::Neg,
                operand,
                ..
            }) => match operand.as_ref() {
                Expr::BinOp { op: BinOp::Pow, .. } => {}
                other => panic!("expected Pow inside Neg, got {other:?}"),
            },
            other => panic!("expected UnaryOp(Neg), got {other:?}"),
        }
    }

    #[test]
    fn parse_assignment() {
        let prog = parse_program("x = 5").unwrap();
        match &prog.stmts[0] {
            Stmt::Assignment { target, value, .. } => {
                match target {
                    Expr::Ident { name, .. } => assert_eq!(name, "x"),
                    other => panic!("expected Ident target, got {other:?}"),
                }
                match value {
                    Expr::Number { value: v, .. } => assert_eq!(v, "5"),
                    other => panic!("expected Number, got {other:?}"),
                }
            }
            other => panic!("expected Assignment, got {other:?}"),
        }
    }

    #[test]
    fn parse_empty_program() {
        let prog = parse_program("").unwrap();
        assert!(prog.stmts.is_empty());
    }

    #[test]
    fn parse_error_unexpected() {
        let err = parse_program(")").unwrap_err();
        assert!(err.contains("expected expression"));
    }

    #[test]
    fn parse_while_loop() {
        let prog = parse_program("while x { 1 }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::While { .. }) => {}
            other => panic!("expected While, got {other:?}"),
        }
    }

    #[test]
    fn parse_forever_loop() {
        let prog = parse_program("forever { 1 }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Forever { .. }) => {}
            other => panic!("expected Forever, got {other:?}"),
        }
    }

    #[test]
    fn parse_fn_expr_anonymous() {
        let prog = parse_program("fn(x) { x + 1 }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::FnExpr { name, params, .. }) => {
                assert!(name.is_none());
                let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
                assert_eq!(names, &["x"]);
            }
            other => panic!("expected FnExpr, got {other:?}"),
        }
    }

    #[test]
    fn parse_for_in_expr() {
        let prog = parse_program("for x in arr { x }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::For { var, iterable, .. }) => {
                assert_eq!(var, "x");
                match iterable {
                    ForIterable::Expr(e) => match e.as_ref() {
                        Expr::Ident { name, .. } => assert_eq!(name, "arr"),
                        other => panic!("expected Ident, got {other:?}"),
                    },
                    other => panic!("expected Expr iterable, got {other:?}"),
                }
            }
            other => panic!("expected For, got {other:?}"),
        }
    }

    #[test]
    fn parse_else_if() {
        let prog = parse_program("if a { 1 } else if b { 2 } else { 3 }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::If {
                else_branch: Some(ElseBranch::If(inner)),
                ..
            }) => match inner.as_ref() {
                Expr::If {
                    else_branch: Some(ElseBranch::Block(_)),
                    ..
                } => {}
                other => panic!("expected inner If with else block, got {other:?}"),
            },
            other => panic!("expected If with else-if, got {other:?}"),
        }
    }

    #[test]
    fn parse_mut_decl() {
        let prog = parse_program("mut x = 10").unwrap();
        match &prog.stmts[0] {
            Stmt::MutDecl { name, .. } => assert_eq!(name, "x"),
            other => panic!("expected MutDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_return_with_value() {
        let prog = parse_program("return 42").unwrap();
        match &prog.stmts[0] {
            Stmt::Return {
                value: Some(Expr::Number { value, .. }),
                ..
            } => {
                assert_eq!(value, "42");
            }
            other => panic!("expected Return with value, got {other:?}"),
        }
    }

    #[test]
    fn parse_return_without_value() {
        // `return` followed by `}` has no value
        let prog = parse_program("if true { return }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::If { then_block, .. }) => match &then_block.stmts[0] {
                Stmt::Return { value: None, .. } => {}
                other => panic!("expected Return without value, got {other:?}"),
            },
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn parse_nil() {
        let prog = parse_program("nil").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Nil { .. }) => {}
            other => panic!("expected Nil, got {other:?}"),
        }
    }

    #[test]
    fn parse_bool_true() {
        let prog = parse_program("true").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Bool { value: true, .. }) => {}
            other => panic!("expected Bool(true), got {other:?}"),
        }
    }

    #[test]
    fn parse_string() {
        let prog = parse_program(r#""hello""#).unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::StringLit { value, .. }) => assert_eq!(value, "hello"),
            other => panic!("expected StringLit, got {other:?}"),
        }
    }

    #[test]
    fn parse_not_operator() {
        let prog = parse_program("!x").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::UnaryOp {
                op: UnaryOp::Not, ..
            }) => {}
            other => panic!("expected Not, got {other:?}"),
        }
    }

    #[test]
    fn parse_semicolons() {
        let prog = parse_program("1; 2; 3").unwrap();
        assert_eq!(prog.stmts.len(), 3);
    }

    #[test]
    fn parse_nested_call() {
        let prog = parse_program("f(g(x))").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::Call { callee, args, .. }) => {
                match callee.as_ref() {
                    Expr::Ident { name, .. } => assert_eq!(name, "f"),
                    other => panic!("expected Ident, got {other:?}"),
                }
                assert_eq!(args.len(), 1);
                match &args[0] {
                    Expr::Call { .. } => {}
                    other => panic!("expected inner Call, got {other:?}"),
                }
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    // ========================================================================
    // Type annotation tests
    // ========================================================================

    #[test]
    fn parse_let_with_type() {
        let prog = parse_program("let x: Field = 5").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { name, type_ann, .. } => {
                assert_eq!(name, "x");
                assert_eq!(*type_ann, Some(TypeAnnotation::Field));
            }
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_let_with_bool_type() {
        let prog = parse_program("let ok: Bool = true").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { name, type_ann, .. } => {
                assert_eq!(name, "ok");
                assert_eq!(*type_ann, Some(TypeAnnotation::Bool));
            }
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_let_without_type() {
        let prog = parse_program("let x = 5").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { type_ann, .. } => {
                assert!(type_ann.is_none());
            }
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_mut_with_type() {
        let prog = parse_program("mut x: Field = 10").unwrap();
        match &prog.stmts[0] {
            Stmt::MutDecl { name, type_ann, .. } => {
                assert_eq!(name, "x");
                assert_eq!(*type_ann, Some(TypeAnnotation::Field));
            }
            other => panic!("expected MutDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_public_with_type() {
        let prog = parse_program("public x: Field").unwrap();
        match &prog.stmts[0] {
            Stmt::PublicDecl { names, .. } => {
                assert_eq!(names[0].name, "x");
                assert_eq!(names[0].type_ann, Some(TypeAnnotation::Field));
            }
            other => panic!("expected PublicDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_witness_with_type() {
        let prog = parse_program("witness flag: Bool").unwrap();
        match &prog.stmts[0] {
            Stmt::WitnessDecl { names, .. } => {
                assert_eq!(names[0].name, "flag");
                assert_eq!(names[0].type_ann, Some(TypeAnnotation::Bool));
            }
            other => panic!("expected WitnessDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_witness_array_with_type() {
        let prog = parse_program("witness path[3]: Field").unwrap();
        match &prog.stmts[0] {
            Stmt::WitnessDecl { names, .. } => {
                assert_eq!(names[0].name, "path");
                assert_eq!(names[0].array_size, Some(3));
                assert_eq!(names[0].type_ann, Some(TypeAnnotation::Field));
            }
            other => panic!("expected WitnessDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_public_without_type() {
        let prog = parse_program("public x").unwrap();
        match &prog.stmts[0] {
            Stmt::PublicDecl { names, .. } => {
                assert!(names[0].type_ann.is_none());
            }
            other => panic!("expected PublicDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_fn_with_typed_params() {
        let prog = parse_program("fn hash(a: Field, b: Field) -> Field { a + b }").unwrap();
        match &prog.stmts[0] {
            Stmt::FnDecl {
                name,
                params,
                return_type,
                ..
            } => {
                assert_eq!(name, "hash");
                assert_eq!(params.len(), 2);
                assert_eq!(params[0].name, "a");
                assert_eq!(params[0].type_ann, Some(TypeAnnotation::Field));
                assert_eq!(params[1].name, "b");
                assert_eq!(params[1].type_ann, Some(TypeAnnotation::Field));
                assert_eq!(*return_type, Some(TypeAnnotation::Field));
            }
            other => panic!("expected FnDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_fn_mixed_typed_untyped_params() {
        let prog = parse_program("fn f(a: Field, b) { a + b }").unwrap();
        match &prog.stmts[0] {
            Stmt::FnDecl {
                params,
                return_type,
                ..
            } => {
                assert_eq!(params[0].type_ann, Some(TypeAnnotation::Field));
                assert!(params[1].type_ann.is_none());
                assert!(return_type.is_none());
            }
            other => panic!("expected FnDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_fn_expr_with_return_type() {
        let prog = parse_program("fn(x: Bool) -> Bool { !x }").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::FnExpr {
                params,
                return_type,
                ..
            }) => {
                assert_eq!(params[0].name, "x");
                assert_eq!(params[0].type_ann, Some(TypeAnnotation::Bool));
                assert_eq!(*return_type, Some(TypeAnnotation::Bool));
            }
            other => panic!("expected FnExpr, got {other:?}"),
        }
    }

    #[test]
    fn parse_arrow_token() {
        // Ensure -> doesn't interfere with subtraction
        let prog = parse_program("a - b").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::BinOp { op: BinOp::Sub, .. }) => {}
            other => panic!("expected Sub, got {other:?}"),
        }
    }

    #[test]
    fn parse_negative_still_works() {
        // Ensure negation still works after lexer change
        let prog = parse_program("-5").unwrap();
        match &prog.stmts[0] {
            Stmt::Expr(Expr::UnaryOp {
                op: UnaryOp::Neg, ..
            }) => {}
            other => panic!("expected Neg, got {other:?}"),
        }
    }

    #[test]
    fn parse_type_annotation_array() {
        let prog = parse_program("let a: Field[4] = [1, 2, 3, 4]").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { type_ann, .. } => {
                assert_eq!(*type_ann, Some(TypeAnnotation::FieldArray(4)));
            }
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_type_annotation_bool_array() {
        let prog = parse_program("witness flags[2]: Bool[2]").unwrap();
        match &prog.stmts[0] {
            Stmt::WitnessDecl { names, .. } => {
                assert_eq!(names[0].type_ann, Some(TypeAnnotation::BoolArray(2)));
            }
            other => panic!("expected WitnessDecl, got {other:?}"),
        }
    }

    #[test]
    fn parse_invalid_type_annotation() {
        assert!(parse_program("let x: Integer = 5").is_err());
    }

    #[test]
    fn parse_multiple_public_with_types() {
        let prog = parse_program("public x: Field, y: Bool").unwrap();
        match &prog.stmts[0] {
            Stmt::PublicDecl { names, .. } => {
                assert_eq!(names.len(), 2);
                assert_eq!(names[0].type_ann, Some(TypeAnnotation::Field));
                assert_eq!(names[1].type_ann, Some(TypeAnnotation::Bool));
            }
            other => panic!("expected PublicDecl, got {other:?}"),
        }
    }

    #[test]
    fn field_and_bool_not_keywords() {
        // Field and Bool are NOT keywords, they can be used as identifiers
        let prog = parse_program("let Field = 5").unwrap();
        match &prog.stmts[0] {
            Stmt::LetDecl { name, .. } => assert_eq!(name, "Field"),
            other => panic!("expected LetDecl, got {other:?}"),
        }
    }

    // ====================================================================
    // Import / Export tests
    // ====================================================================

    #[test]
    fn parse_import_basic() {
        let prog = parse_program(r#"import "./utils.ach" as utils"#).unwrap();
        assert_eq!(prog.stmts.len(), 1);
        match &prog.stmts[0] {
            Stmt::Import { path, alias, .. } => {
                assert_eq!(path, "./utils.ach");
                assert_eq!(alias, "utils");
            }
            other => panic!("expected Import, got {other:?}"),
        }
    }

    #[test]
    fn parse_export_fn() {
        let prog = parse_program("export fn add(a, b) { a + b }").unwrap();
        assert_eq!(prog.stmts.len(), 1);
        match &prog.stmts[0] {
            Stmt::Export { inner, .. } => match inner.as_ref() {
                Stmt::FnDecl { name, params, .. } => {
                    assert_eq!(name, "add");
                    assert_eq!(params.len(), 2);
                }
                other => panic!("expected FnDecl inside Export, got {other:?}"),
            },
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[test]
    fn parse_export_let() {
        let prog = parse_program("export let PI = 3").unwrap();
        assert_eq!(prog.stmts.len(), 1);
        match &prog.stmts[0] {
            Stmt::Export { inner, .. } => match inner.as_ref() {
                Stmt::LetDecl { name, .. } => assert_eq!(name, "PI"),
                other => panic!("expected LetDecl inside Export, got {other:?}"),
            },
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[test]
    fn parse_export_mut_error() {
        // export mut should fail
        let result = parse_program("export mut x = 5");
        assert!(result.is_err());
    }

    #[test]
    fn parse_import_no_as_error() {
        // import without "as" should fail
        let result = parse_program(r#"import "./foo.ach""#);
        assert!(result.is_err());
    }

    #[test]
    fn import_export_as_are_keywords() {
        // import, export, and as are now keywords and cannot be used as variable names
        assert!(parse_program("let import = 5").is_err());
        assert!(parse_program("let export = 5").is_err());
        assert!(parse_program("let as = 5").is_err());
    }
}
