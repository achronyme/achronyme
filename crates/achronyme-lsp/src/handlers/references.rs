use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Find all references to a symbol at the given position
pub fn find_references(doc: &Document, position: Position, uri: Url) -> Option<Vec<Location>> {
    let word = doc.word_at_position(position.line, position.character)?;

    let mut locations = Vec::new();

    // Search for all occurrences of the word in the document
    for (line_idx, line) in doc.lines().iter().enumerate() {
        let mut search_start = 0;
        while let Some(pos) = line[search_start..].find(&word) {
            let actual_pos = search_start + pos;

            // Check if it's a whole word match
            let before_ok = actual_pos == 0
                || !line
                    .chars()
                    .nth(actual_pos - 1)
                    .map(is_word_char)
                    .unwrap_or(false);

            let after_ok = actual_pos + word.len() >= line.len()
                || !line
                    .chars()
                    .nth(actual_pos + word.len())
                    .map(is_word_char)
                    .unwrap_or(false);

            if before_ok && after_ok {
                locations.push(Location {
                    uri: uri.clone(),
                    range: Range {
                        start: Position {
                            line: line_idx as u32,
                            character: actual_pos as u32,
                        },
                        end: Position {
                            line: line_idx as u32,
                            character: (actual_pos + word.len()) as u32,
                        },
                    },
                });
            }

            search_start = actual_pos + word.len();
        }
    }

    if locations.is_empty() {
        None
    } else {
        Some(locations)
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_references() {
        let doc = Document::new("let x = 1\nlet y = x + 2\nlet z = x * y".to_string());
        let uri = Url::parse("file:///test.acr").unwrap();
        let refs = find_references(
            &doc,
            Position {
                line: 0,
                character: 4,
            },
            uri,
        );
        assert!(refs.is_some());
        let refs = refs.unwrap();
        assert_eq!(refs.len(), 3); // x appears 3 times
    }
}
