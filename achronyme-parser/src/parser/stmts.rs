use crate::ast::*;
use crate::error::ParseError;
use crate::token::TokenKind;

use super::core::Parser;
use super::tables::tok_display;

impl Parser {
    // ========================================================================
    // Statements
    // ========================================================================

    pub(super) fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
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
                Ok(Stmt::Break {
                    span: self.span_to_prev(&sp),
                })
            }
            TokenKind::Continue => {
                let sp = self.span();
                self.advance();
                Ok(Stmt::Continue {
                    span: self.span_to_prev(&sp),
                })
            }
            TokenKind::Circuit => self.parse_circuit_decl(),
            TokenKind::Prove => {
                // prove name(...) { ... } → desugar to let name = prove name(...) { ... }
                // prove(...) { ... } or prove { ... } → expression statement
                if matches!(self.lookahead(1), TokenKind::Ident)
                    && matches!(self.lookahead(2), TokenKind::LParen | TokenKind::LBrace)
                {
                    self.parse_prove_decl()
                } else {
                    let expr = self.parse_expr()?;
                    self.try_parse_assignment(expr)
                }
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
                span: self.span_to_prev(&sp),
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
            span: self.span_to_prev(&sp),
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
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_public_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `public`
        let names = self.parse_input_decl_list()?;
        Ok(Stmt::PublicDecl {
            names,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_witness_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `witness`
        let names = self.parse_input_decl_list()?;
        Ok(Stmt::WitnessDecl {
            names,
            span: self.span_to_prev(&sp),
        })
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
        // Parse inline array size: `name[N]` (old syntax, before type annotation)
        let inline_array_size = if self.eat(&TokenKind::LBracket) {
            let tok = self.expect(&TokenKind::Integer)?;
            let size: usize = tok.lexeme.parse().map_err(|_| {
                ParseError::new(
                    format!("invalid array size: {}", tok.lexeme),
                    tok.span.line_start,
                    tok.span.col_start,
                )
            })?;
            self.expect(&TokenKind::RBracket)?;
            Some(size)
        } else {
            None
        };
        let type_ann = self.try_parse_type_annotation()?;

        // Merge inline array_size into type annotation
        let type_ann = match (type_ann, inline_array_size) {
            (Some(mut ann), Some(size)) => {
                // If type_ann already has an array_size, inline takes precedence
                // (this is the `name[3]: Field` case → Field[3])
                if ann.array_size.is_none() {
                    ann.array_size = Some(size);
                }
                Some(ann)
            }
            (None, Some(size)) => {
                // No explicit type annotation but has inline array size
                // Default to Field[N]
                Some(TypeAnnotation::array(BaseType::Field, size))
            }
            (ann, None) => ann,
        };

        Ok(InputDecl { name, type_ann })
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
            span: self.span_to_prev(&sp),
        })
    }

    /// Parse `prove name(hash: Public) { ... }` at statement level.
    /// Desugars to `let name = prove name(hash: Public) { ... }`.
    fn parse_prove_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `prove`
        let name = self.expect_ident()?;
        let params = self.parse_prove_params()?;
        let body = self.parse_block_inner()?;
        let span = self.span_to_prev(&sp);

        Ok(Stmt::LetDecl {
            name: name.clone(),
            type_ann: None,
            value: Expr::Prove {
                name: Some(name),
                body,
                params,
                span: span.clone(),
            },
            span,
        })
    }

    /// Parse `circuit name(x: Public, y: Witness Field[3]) { body }`
    ///
    /// Also accepts old syntax `circuit name(public x, witness y[3]) { body }`
    /// for backward compatibility (emits W008 deprecation warning).
    fn parse_circuit_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `circuit`
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;

        let mut params = Vec::new();
        while !self.at(&TokenKind::RParen) {
            // Detect old syntax: `public name` or `witness name`
            // vs new syntax: `name: Type`
            let tok = self.peek().clone();
            if (tok.kind == TokenKind::Public || tok.kind == TokenKind::Witness)
                && matches!(self.lookahead(1), TokenKind::Ident)
            {
                // Old syntax: `public name` or `witness name[N]`
                let visibility = if tok.kind == TokenKind::Public {
                    Visibility::Public
                } else {
                    Visibility::Witness
                };
                self.advance(); // eat visibility keyword
                let param_name = self.expect_ident()?;

                let array_size = if self.at(&TokenKind::LBracket) {
                    self.advance();
                    let size_tok = self.peek().clone();
                    let size = size_tok.lexeme.parse::<usize>().map_err(|_| {
                        ParseError::new(
                            format!("expected array size, found `{}`", tok_display(&size_tok)),
                            size_tok.span.line_start,
                            size_tok.span.col_start,
                        )
                    })?;
                    self.advance();
                    self.expect(&TokenKind::RBracket)?;
                    Some(size)
                } else {
                    None
                };

                // Emit W008 deprecation warning
                let new_type = if let Some(n) = array_size {
                    format!("{visibility} Field[{n}]")
                } else {
                    format!("{visibility}")
                };
                self.errors.push(
                    crate::Diagnostic::warning(
                        format!(
                            "deprecated circuit param syntax: use `{param_name}: {new_type}` instead of `{} {param_name}{}`",
                            if visibility == Visibility::Public { "public" } else { "witness" },
                            if let Some(n) = array_size { format!("[{n}]") } else { String::new() },
                        ),
                        crate::diagnostic::SpanRange::from(&tok.span),
                    )
                    .with_code("W008"),
                );

                params.push(TypedParam {
                    name: param_name,
                    type_ann: Some(TypeAnnotation {
                        visibility: Some(visibility),
                        base: BaseType::Field, // old syntax had no type — default to Field
                        array_size,
                    }),
                });
            } else {
                // New syntax: `name: Type`
                let param_name = self.expect_ident()?;
                let type_ann = self.try_parse_type_annotation()?;
                params.push(TypedParam {
                    name: param_name,
                    type_ann,
                });
            }

            if self.at(&TokenKind::Comma) {
                self.advance();
            }
        }
        self.expect(&TokenKind::RParen)?;

        let body = self.parse_block_inner()?;

        Ok(Stmt::CircuitDecl {
            name,
            params,
            body,
            span: self.span_to_prev(&sp),
        })
    }

    /// Parse `import circuit "path" as name`
    fn parse_import_circuit(&mut self, sp: Span) -> Result<Stmt, ParseError> {
        self.advance(); // eat `circuit`

        let tok = self.peek().clone();
        if tok.kind != TokenKind::StringLit {
            return Err(ParseError::new(
                format!(
                    "expected string literal for circuit path, found `{}`",
                    tok_display(&tok)
                ),
                tok.span.line_start,
                tok.span.col_start,
            ));
        }
        let path = tok.lexeme.clone();
        self.advance();
        self.expect(&TokenKind::As)?;
        let alias = self.expect_ident()?;

        Ok(Stmt::ImportCircuit {
            path,
            alias,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_import(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        if self.block_depth > 0 {
            return Err(ParseError::new(
                "import statements are only allowed at the top level",
                sp.line_start,
                sp.col_start,
            ));
        }
        self.advance(); // eat `import`

        // Branch: circuit import `import circuit "path" as name`
        if self.at(&TokenKind::Circuit) {
            return self.parse_import_circuit(sp);
        }

        // Branch: selective import `import { x, y } from "path"`
        if self.at(&TokenKind::LBrace) {
            return self.parse_selective_import(sp);
        }

        let tok = self.peek().clone();
        if tok.kind != TokenKind::StringLit {
            return Err(ParseError::new(
                format!(
                    "expected string literal for import path, found `{}`",
                    tok_display(&tok)
                ),
                tok.span.line_start,
                tok.span.col_start,
            ));
        }
        let path = tok.lexeme.clone();
        self.advance();
        self.expect(&TokenKind::As)?;
        let alias = self.expect_ident()?;
        Ok(Stmt::Import {
            path,
            alias,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_selective_import(&mut self, sp: Span) -> Result<Stmt, ParseError> {
        self.advance(); // eat `{`

        // Parse comma-separated list of identifiers
        let mut names = Vec::new();
        if !self.at(&TokenKind::RBrace) {
            names.push(self.expect_ident()?);
            while self.eat(&TokenKind::Comma) {
                // Allow trailing comma
                if self.at(&TokenKind::RBrace) {
                    break;
                }
                names.push(self.expect_ident()?);
            }
        }

        if names.is_empty() {
            let tok = self.peek();
            return Err(ParseError::new(
                "empty import list — specify at least one name to import",
                tok.span.line_start,
                tok.span.col_start,
            ));
        }

        self.expect(&TokenKind::RBrace)?;

        // Expect contextual keyword `from` (parsed as Ident)
        let from_tok = self.peek().clone();
        if from_tok.kind == TokenKind::Ident && from_tok.lexeme == "from" {
            self.advance();
        } else {
            return Err(ParseError::new(
                format!(
                    "expected `from` after import list, found `{}` (hint: `import {{...}} from \"path\"`)",
                    tok_display(&from_tok)
                ),
                from_tok.span.line_start,
                from_tok.span.col_start,
            ));
        }

        // Parse the module path
        let path_tok = self.peek().clone();
        if path_tok.kind != TokenKind::StringLit {
            return Err(ParseError::new(
                format!(
                    "expected string literal for import path, found `{}`",
                    tok_display(&path_tok)
                ),
                path_tok.span.line_start,
                path_tok.span.col_start,
            ));
        }
        let path = path_tok.lexeme.clone();
        self.advance();

        Ok(Stmt::SelectiveImport {
            names,
            path,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_export(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        if self.block_depth > 0 {
            return Err(ParseError::new(
                "export statements are only allowed at the top level",
                sp.line_start,
                sp.col_start,
            ));
        }
        self.advance(); // eat `export`

        // Branch: export list `export { x, y }`
        if self.at(&TokenKind::LBrace) {
            return self.parse_export_list(sp);
        }

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
                        tok.span.line_start,
                        tok.span.col_start,
                    ));
                }
            }
            TokenKind::Let => self.parse_let_decl()?,
            _ => {
                let tok = self.peek();
                return Err(ParseError::new(
                    format!(
                        "export only applies to `fn`, `let` declarations, or `{{...}}` list, found `{}`",
                        tok_display(tok)
                    ),
                    tok.span.line_start,
                    tok.span.col_start,
                ));
            }
        };
        Ok(Stmt::Export {
            inner: Box::new(inner),
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_export_list(&mut self, sp: Span) -> Result<Stmt, ParseError> {
        self.advance(); // eat `{`

        let mut names = Vec::new();
        if !self.at(&TokenKind::RBrace) {
            names.push(self.expect_ident()?);
            while self.eat(&TokenKind::Comma) {
                // Allow trailing comma
                if self.at(&TokenKind::RBrace) {
                    break;
                }
                names.push(self.expect_ident()?);
            }
        }

        if names.is_empty() {
            let tok = self.peek();
            return Err(ParseError::new(
                "empty export list — specify at least one name to export",
                tok.span.line_start,
                tok.span.col_start,
            ));
        }

        self.expect(&TokenKind::RBrace)?;

        Ok(Stmt::ExportList {
            names,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_param_list(&mut self) -> Result<Vec<TypedParam>, ParseError> {
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
        Ok(Stmt::Print {
            value,
            span: self.span_to_prev(&sp),
        })
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
        Ok(Stmt::Return {
            value,
            span: self.span_to_prev(&sp),
        })
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

    pub(super) fn expect_ident(&mut self) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        if tok.kind == TokenKind::Ident {
            self.advance();
            Ok(tok.lexeme)
        } else {
            Err(ParseError::new(
                format!("expected identifier, found `{}`", tok_display(&tok)),
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }

    // ========================================================================
    // Type annotation helpers
    // ========================================================================

    /// Try to parse a type annotation (`: Type`). Returns `None` if no `:` is present.
    pub(super) fn try_parse_type_annotation(
        &mut self,
    ) -> Result<Option<TypeAnnotation>, ParseError> {
        if !self.eat(&TokenKind::Colon) {
            return Ok(None);
        }
        let ann = self.parse_type()?;
        Ok(Some(ann))
    }

    /// Try to parse a return type annotation (`-> Type`). Returns `None` if no `->` is present.
    pub(super) fn try_parse_return_type(&mut self) -> Result<Option<TypeAnnotation>, ParseError> {
        if !self.eat(&TokenKind::Arrow) {
            return Ok(None);
        }
        let ann = self.parse_type()?;
        Ok(Some(ann))
    }

    /// Parse a type: `Field`, `Bool`, `Field[N]`, `Bool[N]`,
    /// or visibility-prefixed: `Public`, `Witness`, `Public Field[3]`, etc.
    fn parse_type(&mut self) -> Result<TypeAnnotation, ParseError> {
        let tok = self.peek().clone();
        if tok.kind != TokenKind::Ident {
            return Err(ParseError::new(
                format!(
                    "expected type (`Field` or `Bool`), found `{}`",
                    tok_display(&tok)
                ),
                tok.span.line_start,
                tok.span.col_start,
            ));
        }

        // Check for visibility prefix
        let visibility = match tok.lexeme.as_str() {
            "Public" => {
                self.advance();
                Some(Visibility::Public)
            }
            "Witness" => {
                self.advance();
                Some(Visibility::Witness)
            }
            _ => None,
        };

        // After visibility, parse optional base type (defaults to Field)
        let (base, base_consumed) = if visibility.is_some() {
            // Peek to see if next token is a base type
            let next = self.peek().clone();
            if next.kind == TokenKind::Ident && (next.lexeme == "Field" || next.lexeme == "Bool") {
                let b = if next.lexeme == "Bool" {
                    BaseType::Bool
                } else {
                    BaseType::Field
                };
                self.advance();
                (b, true)
            } else {
                // Visibility alone → default to Field
                (BaseType::Field, false)
            }
        } else {
            // No visibility — must have a base type
            let base_str = tok.lexeme.as_str();
            if base_str != "Field" && base_str != "Bool" {
                let hint = match base_str.to_lowercase().as_str() {
                    "field" => " (did you mean `Field`?)",
                    "bool" | "boolean" => " (did you mean `Bool`?)",
                    "int" | "integer" | "number" | "u32" | "u64" | "i32" | "i64" => {
                        " (valid types are `Field`, `Bool`, `Field[N]`, `Bool[N]`)"
                    }
                    _ => " (valid types are `Field`, `Bool`, `Field[N]`, `Bool[N]`)",
                };
                return Err(ParseError::new(
                    format!("expected type, found `{base_str}`{hint}"),
                    tok.span.line_start,
                    tok.span.col_start,
                ));
            }
            let b = if base_str == "Bool" {
                BaseType::Bool
            } else {
                BaseType::Field
            };
            self.advance();
            (b, true)
        };

        // Check for array syntax: `[N]`
        // Only parse `[N]` if the base type was explicitly consumed, or if
        // visibility was consumed (so `Public[3]` = `Public Field[3]`)
        let array_size =
            if (base_consumed || visibility.is_some()) && self.eat(&TokenKind::LBracket) {
                let size_tok = self.expect(&TokenKind::Integer)?;
                let size: usize = size_tok.lexeme.parse().map_err(|_| {
                    ParseError::new(
                        format!("invalid array size: {}", size_tok.lexeme),
                        size_tok.span.line_start,
                        size_tok.span.col_start,
                    )
                })?;
                self.expect(&TokenKind::RBracket)?;
                Some(size)
            } else {
                None
            };

        Ok(TypeAnnotation {
            visibility,
            base,
            array_size,
        })
    }
}
