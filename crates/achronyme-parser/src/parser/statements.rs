use pest::iterators::Pair;
use crate::ast::{AstNode, ImportItem};
use crate::parser::AstParser;
use crate::pest_parser::Rule;

impl AstParser {
    pub(super) fn build_ast_from_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let inner = pair.into_inner().next()
            .ok_or("Empty statement")?;

        match inner.as_rule() {
            Rule::import_statement => self.build_import_statement(inner),
            Rule::export_statement => self.build_export_statement(inner),
            Rule::let_statement => self.build_let_statement(inner),
            Rule::mut_statement => self.build_mut_statement(inner),
            Rule::type_alias_statement => self.build_type_alias_statement(inner),
            Rule::return_statement => self.build_return_statement(inner),
            Rule::yield_statement => self.build_yield_statement(inner),
            Rule::throw_stmt => self.build_throw_statement(inner),
            Rule::assignment => self.build_assignment(inner),
            Rule::expr => self.build_ast_from_expr(inner),
            _ => Err(format!("Unexpected statement rule: {:?}", inner.as_rule()))
        }
    }

    pub(super) fn build_import_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "import" ~ import_list ~ "from" ~ module_path
        let import_list = inner.next()
            .ok_or("Missing import list in import statement")?;

        let module_path_pair = inner.next()
            .ok_or("Missing module path in import statement")?;

        // Extract items from import_list
        let items = self.build_import_list(import_list)?;

        // Extract module path (it's a string_literal)
        let module_path = self.extract_string_literal(module_path_pair)?;

        Ok(AstNode::Import {
            items,
            module_path,
        })
    }

    pub(super) fn build_export_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "export" ~ import_list
        let import_list = inner.next()
            .ok_or("Missing export list in export statement")?;

        // Extract items from import_list (reuse same structure)
        let items = self.build_import_list(import_list)?;

        Ok(AstNode::Export {
            items,
        })
    }

    pub(super) fn build_import_list(&mut self, pair: Pair<Rule>) -> Result<Vec<ImportItem>, String> {
        let mut items = Vec::new();

        // Grammar: "{" ~ import_item ~ ("," ~ import_item)* ~ "}"
        for item_pair in pair.into_inner() {
            if item_pair.as_rule() == Rule::import_item {
                items.push(self.build_import_item(item_pair)?);
            }
        }

        if items.is_empty() {
            return Err("Import list cannot be empty".to_string());
        }

        Ok(items)
    }

    pub(super) fn build_import_item(&mut self, pair: Pair<Rule>) -> Result<ImportItem, String> {
        let mut inner = pair.into_inner();

        // Grammar: identifier ~ ("as" ~ identifier)?
        let name = inner.next()
            .ok_or("Missing identifier in import item")?
            .as_str()
            .to_string();

        let alias = inner.next().map(|p| p.as_str().to_string());

        Ok(ImportItem { name, alias })
    }

    pub(super) fn extract_string_literal(&mut self, pair: Pair<Rule>) -> Result<String, String> {
        // Navigate through module_path -> string_literal
        let inner = pair.into_inner().next()
            .ok_or("Missing string literal in module path")?;

        if inner.as_rule() != Rule::string_literal {
            return Err(format!("Expected string_literal, got {:?}", inner.as_rule()));
        }

        // Parse the string literal (remove quotes and handle escapes)
        let s = inner.as_str();
        let s = &s[1..s.len()-1]; // Remove surrounding quotes

        // Handle escape sequences
        let s = s.replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\r", "\r")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");

        Ok(s)
    }

    pub(super) fn build_let_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "let" ~ identifier ~ (":" ~ type_annotation)? ~ "=" ~ expr
        //        | "let" ~ destructuring_pattern ~ (":" ~ type_annotation)? ~ "=" ~ expr
        let first = inner.next()
            .ok_or("Missing identifier or pattern in let statement")?;

        // Check if it's a destructuring pattern or a simple identifier
        if first.as_rule() == Rule::destructuring_pattern {
            // Destructuring let
            let pattern = self.build_destructuring_pattern(first)?;

            // Parse optional type annotation
            let mut type_annotation = None;
            let mut next_pair = inner.next()
                .ok_or("Missing initializer in let statement")?;

            // Check if next element is a type annotation or the initializer
            if next_pair.as_rule() == Rule::type_annotation {
                type_annotation = Some(self.parse_type_annotation(next_pair)?);
                next_pair = inner.next()
                    .ok_or("Missing initializer after type annotation")?;
            }

            // next_pair is now the initializer
            let initializer = self.build_ast_from_expr(next_pair)?;

            Ok(AstNode::LetDestructuring {
                pattern,
                type_annotation,
                initializer: Box::new(initializer),
            })
        } else {
            // Simple identifier let
            let identifier = first.as_str().to_string();

            // Parse optional type annotation
            let mut type_annotation = None;
            let mut next_pair = inner.next()
                .ok_or("Missing initializer in let statement")?;

            // Check if next element is a type annotation or the initializer
            if next_pair.as_rule() == Rule::type_annotation {
                type_annotation = Some(self.parse_type_annotation(next_pair)?);
                next_pair = inner.next()
                    .ok_or("Missing initializer after type annotation")?;
            }

            // next_pair is now the initializer
            let initializer = self.build_ast_from_expr(next_pair)?;

            Ok(AstNode::VariableDecl {
                name: identifier,
                type_annotation,
                initializer: Box::new(initializer),
            })
        }
    }

    /// Build a destructuring pattern from a destructuring_pattern rule
    pub(super) fn build_destructuring_pattern(&mut self, pair: Pair<Rule>) -> Result<crate::ast::Pattern, String> {
        let inner = pair.into_inner().next()
            .ok_or("Empty destructuring pattern")?;

        match inner.as_rule() {
            Rule::record_pattern => self.build_record_pattern(inner),
            Rule::vector_pattern => self.build_vector_pattern(inner),
            _ => Err(format!("Unexpected destructuring pattern rule: {:?}", inner.as_rule()))
        }
    }

    pub(super) fn build_mut_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "mut" ~ identifier ~ (":" ~ type_annotation)? ~ "=" ~ expr
        //        | "mut" ~ destructuring_pattern ~ (":" ~ type_annotation)? ~ "=" ~ expr
        let first = inner.next()
            .ok_or("Missing identifier or pattern in mut statement")?;

        // Check if it's a destructuring pattern or a simple identifier
        if first.as_rule() == Rule::destructuring_pattern {
            // Destructuring mut
            let pattern = self.build_destructuring_pattern(first)?;

            // Parse optional type annotation
            let mut type_annotation = None;
            let mut next_pair = inner.next()
                .ok_or("Missing initializer in mut statement")?;

            // Check if next element is a type annotation or the initializer
            if next_pair.as_rule() == Rule::type_annotation {
                type_annotation = Some(self.parse_type_annotation(next_pair)?);
                next_pair = inner.next()
                    .ok_or("Missing initializer after type annotation")?;
            }

            // next_pair is now the initializer
            let initializer = self.build_ast_from_expr(next_pair)?;

            Ok(AstNode::MutableDestructuring {
                pattern,
                type_annotation,
                initializer: Box::new(initializer),
            })
        } else {
            // Simple identifier mut
            let identifier = first.as_str().to_string();

            // Parse optional type annotation
            let mut type_annotation = None;
            let mut next_pair = inner.next()
                .ok_or("Missing initializer in mut statement")?;

            // Check if next element is a type annotation or the initializer
            if next_pair.as_rule() == Rule::type_annotation {
                type_annotation = Some(self.parse_type_annotation(next_pair)?);
                next_pair = inner.next()
                    .ok_or("Missing initializer after type annotation")?;
            }

            // next_pair is now the initializer
            let initializer = self.build_ast_from_expr(next_pair)?;

            Ok(AstNode::MutableDecl {
                name: identifier,
                type_annotation,
                initializer: Box::new(initializer),
            })
        }
    }

    pub(super) fn build_assignment(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: postfix_expression ~ "=" ~ expr
        let target = inner.next()
            .ok_or("Missing target in assignment")?;

        let value = inner.next()
            .ok_or("Missing value in assignment")?;

        Ok(AstNode::Assignment {
            target: Box::new(self.build_ast_from_expr(target)?),
            value: Box::new(self.build_ast_from_expr(value)?),
        })
    }

    pub(super) fn build_return_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "return" ~ expr
        let value = inner.next()
            .ok_or("Missing value in return statement")?;

        Ok(AstNode::Return {
            value: Box::new(self.build_ast_from_expr(value)?),
        })
    }

    pub(super) fn build_type_alias_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "type" ~ identifier ~ "=" ~ type_annotation
        let identifier = inner.next()
            .ok_or("Missing identifier in type alias statement")?
            .as_str()
            .to_string();

        let type_annotation_pair = inner.next()
            .ok_or("Missing type annotation in type alias statement")?;

        let type_definition = self.parse_type_annotation(type_annotation_pair)?;

        Ok(AstNode::TypeAlias {
            name: identifier,
            type_definition,
        })
    }

    pub(super) fn build_yield_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "yield" ~ expr
        let value = inner.next()
            .ok_or("Missing value in yield statement")?;

        Ok(AstNode::Yield {
            value: Box::new(self.build_ast_from_expr(value)?),
        })
    }

    pub(super) fn build_throw_statement(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "throw" ~ expr
        let value = inner.next()
            .ok_or("Missing value in throw statement")?;

        Ok(AstNode::Throw {
            value: Box::new(self.build_ast_from_expr(value)?),
        })
    }
}