use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Get document symbols (outline) from the AST
pub fn get_document_symbols(doc: &Document) -> Option<DocumentSymbolResponse> {
    let ast = doc.ast()?;
    let source = doc.text();

    let symbols = extract_symbols(ast, source);

    if symbols.is_empty() {
        None
    } else {
        Some(DocumentSymbolResponse::Flat(symbols))
    }
}

/// Extract symbols from the AST
fn extract_symbols(ast: &[achronyme_parser::ast::AstNode], source: &str) -> Vec<SymbolInformation> {
    use achronyme_parser::ast::AstNode;

    let mut symbols = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    for node in ast {
        match node {
            AstNode::VariableDecl { name, .. } => {
                if let Some((line, col)) = find_symbol_location(&lines, name, "let") {
                    #[allow(deprecated)]
                    symbols.push(SymbolInformation {
                        name: name.clone(),
                        kind: SymbolKind::VARIABLE,
                        tags: None,
                        deprecated: None,
                        location: Location {
                            uri: Url::parse("file:///").unwrap(), // Will be replaced by caller
                            range: Range {
                                start: Position {
                                    line,
                                    character: col,
                                },
                                end: Position {
                                    line,
                                    character: col + name.len() as u32,
                                },
                            },
                        },
                        container_name: None,
                    });
                }
            }
            AstNode::MutableDecl { name, .. } => {
                if let Some((line, col)) = find_symbol_location(&lines, name, "mut") {
                    #[allow(deprecated)]
                    symbols.push(SymbolInformation {
                        name: name.clone(),
                        kind: SymbolKind::VARIABLE,
                        tags: None,
                        deprecated: None,
                        location: Location {
                            uri: Url::parse("file:///").unwrap(),
                            range: Range {
                                start: Position {
                                    line,
                                    character: col,
                                },
                                end: Position {
                                    line,
                                    character: col + name.len() as u32,
                                },
                            },
                        },
                        container_name: None,
                    });
                }
            }
            AstNode::TypeAlias { name, .. } => {
                if let Some((line, col)) = find_symbol_location(&lines, name, "type") {
                    #[allow(deprecated)]
                    symbols.push(SymbolInformation {
                        name: name.clone(),
                        kind: SymbolKind::TYPE_PARAMETER,
                        tags: None,
                        deprecated: None,
                        location: Location {
                            uri: Url::parse("file:///").unwrap(),
                            range: Range {
                                start: Position {
                                    line,
                                    character: col,
                                },
                                end: Position {
                                    line,
                                    character: col + name.len() as u32,
                                },
                            },
                        },
                        container_name: None,
                    });
                }
            }
            AstNode::Sequence { statements } => {
                let nested = extract_symbols(statements, source);
                symbols.extend(nested);
            }
            AstNode::DoBlock { statements } => {
                let nested = extract_symbols(statements, source);
                symbols.extend(nested);
            }
            // Lambda assigned to variable is handled by VariableDecl above
            _ => {}
        }
    }

    symbols
}

/// Find the location of a symbol in the source code
fn find_symbol_location(lines: &[&str], name: &str, keyword: &str) -> Option<(u32, u32)> {
    for (line_idx, line) in lines.iter().enumerate() {
        // Look for "keyword name" pattern
        if let Some(pos) = line.find(&format!("{} {} ", keyword, name)) {
            let name_start = pos + keyword.len() + 1;
            return Some((line_idx as u32, name_start as u32));
        }
        if let Some(pos) = line.find(&format!("{} {}:", keyword, name)) {
            let name_start = pos + keyword.len() + 1;
            return Some((line_idx as u32, name_start as u32));
        }
        if let Some(pos) = line.find(&format!("{} {}=", keyword, name)) {
            let name_start = pos + keyword.len() + 1;
            return Some((line_idx as u32, name_start as u32));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_symbols() {
        let source = "let x = 42\nmut counter = 0\ntype Point = { x: Number, y: Number }";
        let ast = achronyme_parser::parse(source).unwrap();
        let symbols = extract_symbols(&ast, source);
        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "x");
        assert_eq!(symbols[1].name, "counter");
        assert_eq!(symbols[2].name, "Point");
    }
}
