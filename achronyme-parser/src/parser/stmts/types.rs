use crate::ast::*;
use crate::error::ParseError;
use crate::parser::core::Parser;
use crate::parser::tables::tok_display;
use crate::token::TokenKind;

impl Parser {
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
    pub(in crate::parser) fn try_parse_return_type(
        &mut self,
    ) -> Result<Option<TypeAnnotation>, ParseError> {
        if !self.eat(&TokenKind::Arrow) {
            return Ok(None);
        }
        let ann = self.parse_type()?;
        Ok(Some(ann))
    }

    /// Parse a type: `Field`, `Bool`, `Int`, `String`, `Field[N]`, `Bool[N]`, `Int[N]`, `String[N]`,
    /// or with visibility: `Public`, `Witness`, `Public Field[N]`, `Witness Bool`, etc.
    /// Note: `Int` and `String` cannot be used with visibility modifiers (VM-only types).
    pub(in crate::parser) fn parse_type(&mut self) -> Result<TypeAnnotation, ParseError> {
        use crate::ast::{BaseType, Visibility};

        let tok = self.peek().clone();
        if tok.kind != TokenKind::Ident {
            return Err(ParseError::new(
                format!(
                    "expected type (`Field`, `Bool`, `Int`, `String`, `Public`, or `Witness`), found `{}`",
                    tok_display(&tok)
                ),
                tok.span.line_start,
                tok.span.col_start,
            ));
        }

        let ident = tok.lexeme.as_str();

        // Check for visibility prefix (Public/Witness as contextual keywords)
        let visibility = match ident {
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

        // Parse base type. If visibility was given, base type is optional
        // (Public alone = Public Field).
        let base = if visibility.is_some() {
            let next = self.peek().clone();
            if next.kind == TokenKind::Ident {
                match next.lexeme.as_str() {
                    "Field" => {
                        self.advance();
                        BaseType::Field
                    }
                    "Bool" => {
                        self.advance();
                        BaseType::Bool
                    }
                    "Int" | "String" => {
                        return Err(ParseError::new(
                            format!(
                                "`{}` cannot be used with `{}` (only `Field` and `Bool` are valid in circuit context)",
                                next.lexeme,
                                if visibility == Some(Visibility::Public) {
                                    "Public"
                                } else {
                                    "Witness"
                                }
                            ),
                            next.span.line_start,
                            next.span.col_start,
                        ));
                    }
                    _ => BaseType::Field, // Visibility alone defaults to Field
                }
            } else {
                BaseType::Field
            }
        } else {
            // No visibility - must have a type name
            let base = match ident {
                "Field" => BaseType::Field,
                "Bool" => BaseType::Bool,
                "Int" => BaseType::Int,
                "String" => BaseType::String,
                _ => {
                    let hint = match ident.to_lowercase().as_str() {
                        "field" => " (did you mean `Field`?)",
                        "bool" | "boolean" => " (did you mean `Bool`?)",
                        "int" | "integer" | "number" | "u32" | "u64" | "i32" | "i64" => {
                            " (did you mean `Int`?)"
                        }
                        "string" | "str" => " (did you mean `String`?)",
                        _ => " (valid types are `Field`, `Bool`, `Int`, `String`, `Public`, `Witness`)",
                    };
                    return Err(ParseError::new(
                        format!("expected type, found `{ident}`{hint}"),
                        tok.span.line_start,
                        tok.span.col_start,
                    ));
                }
            };
            self.advance();
            base
        };

        // Check for array syntax: `[N]`
        let array_size = if self.eat(&TokenKind::LBracket) {
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

        Ok(TypeAnnotation::new(visibility, base, array_size))
    }
}
