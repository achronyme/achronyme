/// Symbol extraction module for Achronyme code
/// Extracts let/mut/type declarations and other symbols from AST
use achronyme_parser::AstNode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub line: usize,
}

/// Extract symbols from parsed AST
pub fn extract_symbols(ast: &[AstNode], source: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for node in ast {
        collect_symbols(node, &mut symbols, &lines);
    }

    // Sort by line number
    symbols.sort_by_key(|s| s.line);
    symbols
}

/// Recursively collect symbols from AST node
fn collect_symbols(node: &AstNode, symbols: &mut Vec<Symbol>, lines: &[&str]) {
    match node {
        AstNode::VariableDecl { name, .. } => {
            let line = find_line_for_identifier(name, lines);
            symbols.push(Symbol {
                name: name.clone(),
                kind: "variable".to_string(),
                line,
            });
        }

        AstNode::MutableDecl { name, .. } => {
            let line = find_line_for_identifier(name, lines);
            symbols.push(Symbol {
                name: name.clone(),
                kind: "mutable".to_string(),
                line,
            });
        }

        AstNode::LetDestructuring { pattern, .. } => {
            let destructured_names = extract_names_from_pattern(pattern);
            for name in destructured_names {
                let line = find_line_for_identifier(&name, lines);
                symbols.push(Symbol {
                    name,
                    kind: "destructure".to_string(),
                    line,
                });
            }
        }

        AstNode::MutableDestructuring { pattern, .. } => {
            let destructured_names = extract_names_from_pattern(pattern);
            for name in destructured_names {
                let line = find_line_for_identifier(&name, lines);
                symbols.push(Symbol {
                    name,
                    kind: "destructure_mut".to_string(),
                    line,
                });
            }
        }

        AstNode::Lambda { params, .. } => {
            for (param_name, _, _) in params {
                let line = find_line_for_identifier(param_name, lines);
                symbols.push(Symbol {
                    name: param_name.clone(),
                    kind: "parameter".to_string(),
                    line,
                });
            }
        }

        AstNode::FunctionCall { name, args } => {
            // Record function calls as symbols
            let line = find_line_for_identifier(name, lines);
            symbols.push(Symbol {
                name: name.clone(),
                kind: "function_call".to_string(),
                line,
            });

            // Recursively process arguments
            for arg in args {
                collect_symbols(arg, symbols, lines);
            }
        }

        AstNode::Edge { from, to, .. } => {
            let line_from = find_line_for_identifier(from, lines);
            let line_to = find_line_for_identifier(to, lines);
            symbols.push(Symbol {
                name: from.clone(),
                kind: "edge_node".to_string(),
                line: line_from,
            });
            symbols.push(Symbol {
                name: to.clone(),
                kind: "edge_node".to_string(),
                line: line_to,
            });
        }

        AstNode::Sequence { statements } => {
            for stmt in statements {
                collect_symbols(stmt, symbols, lines);
            }
        }

        AstNode::BinaryOp { left, right, .. } => {
            collect_symbols(left, symbols, lines);
            collect_symbols(right, symbols, lines);
        }

        AstNode::UnaryOp { operand, .. } => {
            collect_symbols(operand, symbols, lines);
        }

        AstNode::If {
            condition,
            then_expr,
            else_expr,
        } => {
            collect_symbols(condition, symbols, lines);
            collect_symbols(then_expr, symbols, lines);
            collect_symbols(else_expr, symbols, lines);
        }

        AstNode::FieldAccess { record, .. } => {
            collect_symbols(record, symbols, lines);
        }

        AstNode::IndexAccess { object, .. } => {
            collect_symbols(object, symbols, lines);
        }

        AstNode::CallExpression { callee, args } => {
            collect_symbols(callee, symbols, lines);
            for arg in args {
                collect_symbols(arg, symbols, lines);
            }
        }

        AstNode::ArrayLiteral(elements) => {
            for elem in elements {
                match elem {
                    achronyme_parser::ArrayElement::Single(node) => {
                        collect_symbols(node, symbols, lines);
                    }
                    achronyme_parser::ArrayElement::Spread(node) => {
                        collect_symbols(node, symbols, lines);
                    }
                }
            }
        }

        AstNode::RecordLiteral(fields) => {
            for field in fields {
                match field {
                    achronyme_parser::RecordFieldOrSpread::Field { value, .. } => {
                        collect_symbols(value, symbols, lines);
                    }
                    achronyme_parser::RecordFieldOrSpread::MutableField { value, .. } => {
                        collect_symbols(value, symbols, lines);
                    }
                    achronyme_parser::RecordFieldOrSpread::Spread(node) => {
                        collect_symbols(node, symbols, lines);
                    }
                }
            }
        }

        AstNode::Return { value } => {
            collect_symbols(value, symbols, lines);
        }

        AstNode::Assignment { target, value } => {
            collect_symbols(target, symbols, lines);
            collect_symbols(value, symbols, lines);
        }

        AstNode::CompoundAssignment { target, value, .. } => {
            collect_symbols(target, symbols, lines);
            collect_symbols(value, symbols, lines);
        }

        AstNode::Piecewise { cases, default } => {
            for (cond, expr) in cases {
                collect_symbols(cond, symbols, lines);
                collect_symbols(expr, symbols, lines);
            }
            if let Some(def) = default {
                collect_symbols(def, symbols, lines);
            }
        }

        // Control flow
        AstNode::DoBlock { statements } => {
            for stmt in statements {
                collect_symbols(stmt, symbols, lines);
            }
        }

        AstNode::WhileLoop { condition, body } => {
            collect_symbols(condition, symbols, lines);
            collect_symbols(body, symbols, lines);
        }

        AstNode::ForInLoop { iterable, body, .. } => {
            collect_symbols(iterable, symbols, lines);
            collect_symbols(body, symbols, lines);
        }

        AstNode::GenerateBlock { statements } => {
            for stmt in statements {
                collect_symbols(stmt, symbols, lines);
            }
        }

        AstNode::Yield { value } => {
            collect_symbols(value, symbols, lines);
        }

        AstNode::TryCatch {
            try_block,
            catch_block,
            ..
        } => {
            collect_symbols(try_block, symbols, lines);
            collect_symbols(catch_block, symbols, lines);
        }

        AstNode::Throw { value } => {
            collect_symbols(value, symbols, lines);
        }

        AstNode::Match { value, arms } => {
            collect_symbols(value, symbols, lines);
            for arm in arms {
                collect_symbols(&arm.body, symbols, lines);
            }
        }

        AstNode::Break { value } => {
            if let Some(v) = value {
                collect_symbols(v, symbols, lines);
            }
        }

        AstNode::Continue => {}

        AstNode::InterpolatedString { parts } => {
            for part in parts {
                match part {
                    achronyme_parser::StringPart::Expression(expr) => {
                        collect_symbols(expr, symbols, lines);
                    }
                    achronyme_parser::StringPart::Literal(_) => {}
                }
            }
        }

        AstNode::RangeExpr { start, end, .. } => {
            collect_symbols(start, symbols, lines);
            collect_symbols(end, symbols, lines);
        }

        // Module/type system - not tracking as symbols for now
        AstNode::Import { .. } => {}
        AstNode::Export { .. } => {}
        AstNode::TypeAlias { .. } => {}

        // Base cases - no nested symbols
        AstNode::Number(_)
        | AstNode::Boolean(_)
        | AstNode::StringLiteral(_)
        | AstNode::ComplexLiteral { .. }
        | AstNode::VariableRef(_)
        | AstNode::SelfReference
        | AstNode::RecReference
        | AstNode::Null => {}
    }
}

/// Extract names from destructuring pattern
fn extract_names_from_pattern(pattern: &achronyme_parser::Pattern) -> Vec<String> {
    let mut names = Vec::new();
    match pattern {
        achronyme_parser::Pattern::Record { fields } => {
            for (field_name, _, _) in fields {
                names.push(field_name.clone());
            }
        }
        achronyme_parser::Pattern::Vector { elements } => {
            for elem in elements {
                match elem {
                    achronyme_parser::VectorPatternElement::Pattern(pat, _) => {
                        let nested = extract_names_from_pattern(pat);
                        names.extend(nested);
                    }
                    achronyme_parser::VectorPatternElement::Rest(name) => {
                        names.push(name.clone());
                    }
                }
            }
        }
        achronyme_parser::Pattern::Variable(name) => {
            names.push(name.clone());
        }
        achronyme_parser::Pattern::Wildcard
        | achronyme_parser::Pattern::Literal(_)
        | achronyme_parser::Pattern::Type(_) => {
            // Skip wildcards, literals, and type patterns
        }
    }
    names
}

/// Find the line number where an identifier first appears
fn find_line_for_identifier(identifier: &str, lines: &[&str]) -> usize {
    for (line_num, line) in lines.iter().enumerate() {
        // Simple check: if the identifier appears in the line
        if line.contains(identifier) {
            return line_num + 1; // Line numbers are 1-indexed
        }
    }
    1 // Default to first line if not found
}
