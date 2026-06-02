use crate::ast::*;
use crate::error::ParseError;
use crate::parser::core::Parser;
use crate::parser::tables::tok_display;
use crate::token::TokenKind;

impl Parser {
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

    pub(super) fn parse_import(&mut self) -> Result<Stmt, ParseError> {
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
                "empty import list - specify at least one name to import",
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

    pub(super) fn parse_export(&mut self) -> Result<Stmt, ParseError> {
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
                "empty export list - specify at least one name to export",
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
}
