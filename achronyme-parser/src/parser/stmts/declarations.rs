use crate::ast::*;
use crate::error::ParseError;
use crate::parser::core::Parser;
use crate::parser::tables::tok_display;
use crate::token::TokenKind;

impl Parser {
    pub(super) fn parse_let_decl(&mut self) -> Result<Stmt, ParseError> {
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

    pub(super) fn parse_mut_decl(&mut self) -> Result<Stmt, ParseError> {
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

    pub(super) fn parse_public_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `public`
        let names = self.parse_input_decl_list()?;
        Ok(Stmt::PublicDecl {
            names,
            span: self.span_to_prev(&sp),
        })
    }

    pub(super) fn parse_witness_decl(&mut self) -> Result<Stmt, ParseError> {
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
        let array_size = if self.eat(&TokenKind::LBracket) {
            let tok = self.expect(&TokenKind::Integer)?;
            let size: usize = tok.lexeme.parse().map_err(|_| {
                ParseError::new(
                    format!("invalid array size: {}", tok.lexeme),
                    tok.span.line_start,
                    tok.span.col_start,
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

    pub(super) fn parse_fn_decl(&mut self) -> Result<Stmt, ParseError> {
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
    pub(super) fn parse_prove_decl(&mut self) -> Result<Stmt, ParseError> {
        let sp = self.span();
        self.advance(); // eat `prove`
        let name = self.expect_ident()?;
        let params = self.parse_prove_params()?;
        let body = self.parse_block_inner()?;
        let span = self.span_to_prev(&sp);

        let id = self.alloc_expr_id();
        Ok(Stmt::LetDecl {
            name: name.clone(),
            type_ann: None,
            value: Expr::Prove {
                id,
                name: Some(name),
                body,
                params,
                span: span.clone(),
            },
            span,
        })
    }

    /// Parse `circuit name(root: Public, leaf: Witness, path: Witness Field[3]) { body }`
    pub(super) fn parse_circuit_decl(&mut self) -> Result<Stmt, ParseError> {
        use crate::ast::TypedParam;

        let sp = self.span();
        self.advance(); // eat `circuit`
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;

        let mut params = Vec::new();
        while !self.at(&TokenKind::RParen) {
            let tok = self.peek().clone();
            if tok.kind != TokenKind::Ident {
                return Err(ParseError::new(
                    format!("expected parameter name, found `{}`", tok_display(&tok)),
                    tok.span.line_start,
                    tok.span.col_start,
                ));
            }

            let param_name = self.expect_ident()?;
            self.expect(&TokenKind::Colon)?;
            let type_ann = self.parse_type()?;

            if type_ann.visibility.is_none() {
                return Err(ParseError::new(
                    format!(
                        "circuit parameter `{param_name}` requires `Public` or `Witness` annotation"
                    ),
                    tok.span.line_start,
                    tok.span.col_start,
                ));
            }

            params.push(TypedParam {
                name: param_name,
                type_ann: Some(type_ann),
            });

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

    pub(in crate::parser) fn parse_param_list(&mut self) -> Result<Vec<TypedParam>, ParseError> {
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
}
