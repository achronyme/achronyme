use achronyme_lsp_core::{get_all_completions, CompletionEntry as CoreCompletionEntry};
use rustyline::completion::{Completer, Pair};
use rustyline::hint::Hinter;
use rustyline::Context;

/// Wrapper struct that holds a reference to the shared completion data
#[derive(Clone, Debug)]
pub struct CompletionEntry {
    pub label: String,
    pub kind: String,
    pub detail: String,
    pub documentation: String,
    pub insert_text: String,
}

impl From<&CoreCompletionEntry> for CompletionEntry {
    fn from(entry: &CoreCompletionEntry) -> Self {
        CompletionEntry {
            label: entry.label.clone(),
            kind: entry.kind.as_str().to_string(),
            detail: entry.detail.clone(),
            documentation: entry.documentation.clone(),
            insert_text: entry.insert_text.clone(),
        }
    }
}

pub struct LspCompleter;

impl LspCompleter {
    pub fn new() -> Self {
        // Force initialization of lazy static in the core crate
        let _ = get_all_completions().len();
        Self
    }

    pub fn fuzzy_complete(&self, word: &str) -> Vec<CompletionEntry> {
        if word.is_empty() {
            return vec![];
        }

        let word_lower = word.to_lowercase();
        let mut matches: Vec<(f64, &CoreCompletionEntry)> = get_all_completions()
            .iter()
            .filter_map(|item| {
                let label_lower = item.label.to_lowercase();
                // Prefix match gets highest priority
                if label_lower.starts_with(&word_lower) {
                    Some((1.0, item))
                } else {
                    // Fuzzy match for typos
                    let score = strsim::jaro_winkler(&label_lower, &word_lower);
                    if score > 0.7 {
                        Some((score * 0.8, item)) // Lower priority than prefix
                    } else {
                        None
                    }
                }
            })
            .collect();

        // Sort by score descending
        matches.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

        // Return top 15 matches
        matches
            .into_iter()
            .take(15)
            .map(|(_, e)| CompletionEntry::from(e))
            .collect()
    }
}

impl Completer for LspCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Extract word being typed
        let (start, word) = extract_word_at_position(line, pos);

        let matches = self.fuzzy_complete(&word);

        let pairs: Vec<Pair> = matches
            .iter()
            .map(|entry| Pair {
                display: format!("{:<20} {}", entry.label, entry.detail),
                replacement: entry.label.clone(),
            })
            .collect();

        Ok((start, pairs))
    }
}

impl Hinter for LspCompleter {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context) -> Option<Self::Hint> {
        if pos < line.len() {
            return None;
        }

        let (_, word) = extract_word_at_position(line, pos);
        if word.len() < 2 {
            return None;
        }

        let matches = self.fuzzy_complete(&word);
        matches.first().and_then(|entry| {
            // Only show hint if it's a prefix match
            if entry.label.to_lowercase().starts_with(&word.to_lowercase()) {
                // Show remaining part of the completion in gray
                let remaining = &entry.label[word.len()..];
                if !remaining.is_empty() {
                    Some(format!("{} ({})", remaining, entry.detail))
                } else {
                    None
                }
            } else {
                None
            }
        })
    }
}

fn extract_word_at_position(line: &str, pos: usize) -> (usize, String) {
    let before_cursor = &line[..pos];

    // Find start of current word (identifier)
    let start = before_cursor
        .rfind(|c: char| !c.is_alphanumeric() && c != '_')
        .map(|i| i + 1)
        .unwrap_or(0);

    let word = before_cursor[start..].to_string();
    (start, word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_total_completion_items() {
        let completions = get_all_completions();
        // We should have 151 items total (109 functions + 19 keywords + 9 constants + 14 types)
        assert!(
            completions.len() >= 150,
            "Expected at least 150 completion items, got {}",
            completions.len()
        );
    }

    #[test]
    fn test_function_count() {
        let completions = get_all_completions();
        let functions: Vec<_> = completions
            .iter()
            .filter(|i| i.kind == achronyme_lsp_core::CompletionKind::Function)
            .collect();
        assert!(
            functions.len() >= 109,
            "Expected at least 109 functions, got {}",
            functions.len()
        );
    }

    #[test]
    fn test_keyword_count() {
        let completions = get_all_completions();
        let keywords: Vec<_> = completions
            .iter()
            .filter(|i| i.kind == achronyme_lsp_core::CompletionKind::Keyword)
            .collect();
        assert_eq!(keywords.len(), 19, "Expected 19 keywords");
    }

    #[test]
    fn test_constant_count() {
        let completions = get_all_completions();
        let constants: Vec<_> = completions
            .iter()
            .filter(|i| i.kind == achronyme_lsp_core::CompletionKind::Constant)
            .collect();
        assert_eq!(constants.len(), 9, "Expected 9 constants");
    }

    #[test]
    fn test_type_count() {
        let completions = get_all_completions();
        let types: Vec<_> = completions
            .iter()
            .filter(|i| i.kind == achronyme_lsp_core::CompletionKind::Type)
            .collect();
        assert_eq!(types.len(), 14, "Expected 14 types");
    }

    #[test]
    fn test_fuzzy_complete_prefix() {
        let completer = LspCompleter::new();
        let matches = completer.fuzzy_complete("sin");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].label, "sin");
    }

    #[test]
    fn test_fuzzy_complete_typo() {
        let completer = LspCompleter::new();
        let matches = completer.fuzzy_complete("siinh"); // typo for "sinh"
        // Should still find "sinh" due to fuzzy matching
        let has_sinh = matches.iter().any(|m| m.label == "sinh");
        assert!(has_sinh, "Should find 'sinh' despite typo");

        // Also test prefix match
        let matches2 = completer.fuzzy_complete("si");
        let has_sin = matches2.iter().any(|m| m.label == "sin");
        assert!(has_sin, "Should find 'sin' with prefix match");
    }

    #[test]
    fn test_extract_word_at_position() {
        let (start, word) = extract_word_at_position("let x = sin", 11);
        assert_eq!(start, 8);
        assert_eq!(word, "sin");

        let (start, word) = extract_word_at_position("ma", 2);
        assert_eq!(start, 0);
        assert_eq!(word, "ma");
    }
}
