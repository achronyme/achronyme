use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Get the definition location for a symbol at the given position
pub fn get_definition(
    doc: &Document,
    position: Position,
    uri: Url,
) -> Option<GotoDefinitionResponse> {
    let word = doc.word_at_position(position.line, position.character)?;

    // Search for variable definition in the AST
    if let Some(ast) = doc.ast() {
        if let Some((def_line, def_col)) = find_definition_location(ast, &word, doc.text()) {
            let location = Location {
                uri,
                range: Range {
                    start: Position {
                        line: def_line,
                        character: def_col,
                    },
                    end: Position {
                        line: def_line,
                        character: def_col + word.len() as u32,
                    },
                },
            };
            return Some(GotoDefinitionResponse::Scalar(location));
        }
    }

    None
}

/// Find the location (line, column) where a variable is defined
fn find_definition_location(
    ast: &[achronyme_parser::ast::AstNode],
    name: &str,
    source: &str,
) -> Option<(u32, u32)> {
    use achronyme_parser::ast::AstNode;

    // Simple approach: search for "let name" or "mut name" in the source
    // This is a basic implementation; a proper one would track AST node positions

    let lines: Vec<&str> = source.lines().collect();

    for (line_idx, line) in lines.iter().enumerate() {
        // Check for "let name ="
        if let Some(pos) = line.find(&format!("let {} ", name)) {
            let name_start = pos + 4; // "let " is 4 chars
            return Some((line_idx as u32, name_start as u32));
        }
        if let Some(pos) = line.find(&format!("let {}:", name)) {
            let name_start = pos + 4;
            return Some((line_idx as u32, name_start as u32));
        }
        if let Some(pos) = line.find(&format!("let {}=", name)) {
            let name_start = pos + 4;
            return Some((line_idx as u32, name_start as u32));
        }

        // Check for "mut name ="
        if let Some(pos) = line.find(&format!("mut {} ", name)) {
            let name_start = pos + 4; // "mut " is 4 chars
            return Some((line_idx as u32, name_start as u32));
        }
        if let Some(pos) = line.find(&format!("mut {}:", name)) {
            let name_start = pos + 4;
            return Some((line_idx as u32, name_start as u32));
        }
        if let Some(pos) = line.find(&format!("mut {}=", name)) {
            let name_start = pos + 4;
            return Some((line_idx as u32, name_start as u32));
        }
    }

    // Also check for function parameters (lambda)
    for node in ast {
        if let AstNode::Lambda { params, .. } = node {
            for (param_name, _, _) in params {
                if param_name == name {
                    // Find in source where this parameter is defined
                    // This is simplified - we'd need span info for accuracy
                    for (line_idx, line) in lines.iter().enumerate() {
                        if let Some(pos) = line.find(param_name) {
                            return Some((line_idx as u32, pos as u32));
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_let_definition() {
        let source = "let x = 42\nlet y = x + 1";
        let ast = achronyme_parser::parse(source).unwrap();
        let result = find_definition_location(&ast, "x", source);
        assert_eq!(result, Some((0, 4)));
    }
}
