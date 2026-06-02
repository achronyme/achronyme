use diagnostics::{ParseError, Span};

use crate::ast::*;
use crate::token::TokenKind;

use super::super::tables::tok_display;
use super::Parser;

impl Parser {
    pub(in crate::parser) fn do_parse_program(&mut self) -> Result<CircomProgram, ParseError> {
        let mut version = None;
        let mut custom_templates = false;
        let mut includes = Vec::new();
        let mut definitions = Vec::new();
        let mut main_component = None;

        // Parse pragmas
        while self.at(&TokenKind::Pragma) {
            let pragma = self.parse_pragma()?;
            match pragma {
                Pragma::Version(v) => version = Some(v),
                Pragma::CustomTemplates => custom_templates = true,
            }
        }

        // Parse includes
        while self.at(&TokenKind::Include) {
            includes.push(self.parse_include()?);
        }

        // Parse definitions and main component
        while !self.at(&TokenKind::Eof) {
            match self.peek_kind() {
                TokenKind::Template => {
                    definitions.push(Definition::Template(self.parse_template_def()?));
                }
                TokenKind::Function => {
                    definitions.push(Definition::Function(self.parse_function_def()?));
                }
                TokenKind::Bus => {
                    definitions.push(Definition::Bus(self.parse_bus_def()?));
                }
                TokenKind::Component => {
                    // Could be `component main ...`
                    if self.lookahead(1) == &TokenKind::MainKw {
                        main_component = Some(self.parse_main_component()?);
                    } else {
                        // Unexpected top-level component — error recovery
                        let err = ParseError::with_code(
                            "unexpected `component` at top level (did you mean `component main`?)",
                            "E306",
                            self.peek().span.line_start,
                            self.peek().span.col_start,
                        );
                        let abort = self.record_error(&err);
                        self.synchronize();
                        if abort {
                            break;
                        }
                    }
                }
                _ => {
                    let tok = self.peek();
                    let err = ParseError::with_code(
                        format!(
                            "expected `template`, `function`, `bus`, or `component main`, found {}",
                            tok_display(tok)
                        ),
                        "E306",
                        tok.span.line_start,
                        tok.span.col_start,
                    );
                    let abort = self.record_error(&err);
                    self.synchronize();
                    if abort {
                        break;
                    }
                }
            }
        }

        Ok(CircomProgram {
            version,
            custom_templates,
            includes,
            definitions,
            main_component,
        })
    }

    fn parse_pragma(&mut self) -> Result<Pragma, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Pragma)?;

        let tok = self.peek();
        match tok.lexeme.as_str() {
            "circom" => {
                self.advance();
                let version = self.parse_version(&sp)?;
                self.expect(&TokenKind::Semicolon)?;
                Ok(Pragma::Version(version))
            }
            "custom_templates" => {
                self.advance();
                self.expect(&TokenKind::Semicolon)?;
                Ok(Pragma::CustomTemplates)
            }
            _ => Err(ParseError::with_code(
                format!("unknown pragma `{}`", tok.lexeme),
                "E304",
                tok.span.line_start,
                tok.span.col_start,
            )),
        }
    }

    fn parse_version(&mut self, start: &Span) -> Result<Version, ParseError> {
        let major = self.expect_number()?;
        self.expect(&TokenKind::Dot)?;
        let minor = self.expect_number()?;
        self.expect(&TokenKind::Dot)?;
        let patch = self.expect_number()?;
        Ok(Version {
            major,
            minor,
            patch,
            span: self.span_to_prev(start),
        })
    }

    fn expect_number(&mut self) -> Result<u32, ParseError> {
        let tok = self.peek();
        if tok.kind == TokenKind::DecNumber {
            let val = tok.lexeme.parse::<u32>().map_err(|_| {
                ParseError::with_code(
                    format!("invalid version number `{}`", tok.lexeme),
                    "E305",
                    tok.span.line_start,
                    tok.span.col_start,
                )
            })?;
            self.advance();
            Ok(val)
        } else {
            Err(ParseError::with_code(
                format!("expected version number, found {}", tok_display(tok)),
                "E305",
                tok.span.line_start,
                tok.span.col_start,
            ))
        }
    }

    fn parse_include(&mut self) -> Result<Include, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Include)?;
        let tok = self.peek();
        if tok.kind != TokenKind::StringLit {
            return Err(ParseError::with_code(
                format!(
                    "expected string after `include`, found {}",
                    tok_display(tok)
                ),
                "E300",
                tok.span.line_start,
                tok.span.col_start,
            ));
        }
        let path = tok.lexeme.clone();
        self.advance();
        self.expect(&TokenKind::Semicolon)?;
        Ok(Include {
            path,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_template_def(&mut self) -> Result<TemplateDef, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Template)?;

        let mut modifiers = TemplateModifiers::default();

        // Parse optional modifiers: custom, parallel, extern_c (in any order)
        loop {
            match self.peek_kind() {
                TokenKind::Custom => {
                    self.advance();
                    modifiers.custom = true;
                }
                TokenKind::Parallel => {
                    self.advance();
                    modifiers.parallel = true;
                }
                // `extern_c` is not a keyword — it's an identifier (v2.2.3+)
                TokenKind::Ident if self.peek().lexeme == "extern_c" => {
                    self.advance();
                    modifiers.extern_c = true;
                }
                _ => break,
            }
        }

        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_ident_list()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block()?;

        Ok(TemplateDef {
            name,
            params,
            modifiers,
            body,
            span: self.span_to_prev(&sp),
            source_file: None,
        })
    }

    fn parse_function_def(&mut self) -> Result<FunctionDef, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Function)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_ident_list()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block()?;

        Ok(FunctionDef {
            name,
            params,
            body,
            span: self.span_to_prev(&sp),
            source_file: None,
        })
    }

    fn parse_bus_def(&mut self) -> Result<BusDef, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Bus)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let params = self.parse_ident_list()?;
        self.expect(&TokenKind::RParen)?;
        let body = self.parse_block()?;

        Ok(BusDef {
            name,
            params,
            body,
            span: self.span_to_prev(&sp),
            source_file: None,
        })
    }

    fn parse_main_component(&mut self) -> Result<MainComponent, ParseError> {
        let sp = self.span();
        self.expect(&TokenKind::Component)?;
        self.expect(&TokenKind::MainKw)?;

        // Optional {public [sig1, sig2]}
        let mut public_signals = Vec::new();
        if self.eat(&TokenKind::LBrace) {
            self.expect(&TokenKind::Public)?;
            self.expect(&TokenKind::LBracket)?;
            public_signals = self.parse_ident_list()?;
            self.expect(&TokenKind::RBracket)?;
            self.expect(&TokenKind::RBrace)?;
        }

        self.expect(&TokenKind::Assign)?;

        let template_name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let template_args = self.parse_expr_list()?;
        self.expect(&TokenKind::RParen)?;
        self.expect(&TokenKind::Semicolon)?;

        Ok(MainComponent {
            public_signals,
            template_name,
            template_args,
            span: self.span_to_prev(&sp),
        })
    }

    fn parse_ident_list(&mut self) -> Result<Vec<String>, ParseError> {
        let mut names = Vec::new();
        if !self.at(&TokenKind::RParen) && !self.at(&TokenKind::RBracket) {
            names.push(self.expect_ident()?);
            while self.eat(&TokenKind::Comma) {
                names.push(self.expect_ident()?);
            }
        }
        Ok(names)
    }
}

/// Internal pragma representation.
enum Pragma {
    Version(Version),
    CustomTemplates,
}
