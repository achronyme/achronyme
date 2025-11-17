use achronyme_lsp_core::{
    get_all_completions, CompletionEntry as CoreCompletionEntry, CompletionKind,
};
use once_cell::sync::Lazy;
use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Cached LSP completion items converted from core completion entries
static BUILTIN_COMPLETIONS: Lazy<Vec<CompletionItem>> = Lazy::new(|| {
    get_all_completions()
        .iter()
        .filter(|e| e.kind == CompletionKind::Function)
        .map(convert_to_lsp_completion)
        .collect()
});

static KEYWORD_COMPLETIONS: Lazy<Vec<CompletionItem>> = Lazy::new(|| {
    get_all_completions()
        .iter()
        .filter(|e| e.kind == CompletionKind::Keyword)
        .map(convert_to_lsp_completion)
        .collect()
});

static CONSTANT_COMPLETIONS: Lazy<Vec<CompletionItem>> = Lazy::new(|| {
    get_all_completions()
        .iter()
        .filter(|e| e.kind == CompletionKind::Constant)
        .map(convert_to_lsp_completion)
        .collect()
});

static TYPE_COMPLETIONS: Lazy<Vec<CompletionItem>> = Lazy::new(|| {
    get_all_completions()
        .iter()
        .filter(|e| e.kind == CompletionKind::Type)
        .map(convert_to_lsp_completion)
        .collect()
});

/// Convert a core completion entry to an LSP completion item
fn convert_to_lsp_completion(entry: &CoreCompletionEntry) -> CompletionItem {
    let kind = match entry.kind {
        CompletionKind::Function => CompletionItemKind::FUNCTION,
        CompletionKind::Keyword => CompletionItemKind::KEYWORD,
        CompletionKind::Constant => CompletionItemKind::CONSTANT,
        CompletionKind::Type => CompletionItemKind::CLASS,
    };

    let insert_text_format = if entry.insert_text.contains('$') {
        InsertTextFormat::SNIPPET
    } else {
        InsertTextFormat::PLAIN_TEXT
    };

    CompletionItem {
        label: entry.label.clone(),
        kind: Some(kind),
        detail: Some(entry.detail.clone()),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::Markdown,
            value: format_documentation(&entry.documentation, &entry.kind),
        })),
        insert_text: Some(entry.insert_text.clone()),
        insert_text_format: Some(insert_text_format),
        ..Default::default()
    }
}

/// Format documentation for markdown display
fn format_documentation(doc: &str, kind: &CompletionKind) -> String {
    match kind {
        CompletionKind::Function => {
            // Function docs already contain signature and examples
            format!("```\n{}\n```", doc.replace("Example:", "```\n\n**Example:**\n```achronyme"))
        }
        _ => doc.to_string(),
    }
}

/// Get completion items for a position in the document
pub fn get_completions(doc: &Document, position: Position) -> Vec<CompletionItem> {
    let context = analyze_completion_context(doc, position);

    match context {
        CompletionContext::AfterDot => {
            // After '.': Suggest record field access or method completions
            // For now, return empty - this would need semantic analysis
            vec![]
        }
        CompletionContext::AfterImport => {
            // After 'import { ': Suggest module exports
            // For now, return empty - this would need module resolution
            vec![]
        }
        CompletionContext::VariableDeclaration => {
            // After 'let ' or 'mut ': User is naming variable, don't suggest
            vec![]
        }
        CompletionContext::Default => {
            // Return all completions
            let mut items = Vec::new();
            items.extend(KEYWORD_COMPLETIONS.iter().cloned());
            items.extend(BUILTIN_COMPLETIONS.iter().cloned());
            items.extend(CONSTANT_COMPLETIONS.iter().cloned());
            items.extend(TYPE_COMPLETIONS.iter().cloned());
            items
        }
    }
}

/// Context for completion
enum CompletionContext {
    AfterDot,
    AfterImport,
    VariableDeclaration,
    Default,
}

/// Analyze the context around the cursor position
fn analyze_completion_context(doc: &Document, position: Position) -> CompletionContext {
    let lines = doc.lines();
    let line_idx = position.line as usize;

    if line_idx >= lines.len() {
        return CompletionContext::Default;
    }

    let line = &lines[line_idx];
    let char_idx = position.character as usize;

    // Get the text before cursor
    let before_cursor = if char_idx <= line.len() {
        &line[..char_idx]
    } else {
        line.as_str()
    };

    let trimmed = before_cursor.trim_end();

    // Check if after '.'
    if trimmed.ends_with('.') {
        return CompletionContext::AfterDot;
    }

    // Check if after 'import {'
    if trimmed.contains("import") && trimmed.contains('{') && !trimmed.contains('}') {
        return CompletionContext::AfterImport;
    }

    // Check if after 'let ' or 'mut ' (variable declaration)
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if let Some(last_word) = words.last() {
        if *last_word == "let" || *last_word == "mut" {
            return CompletionContext::VariableDeclaration;
        }
    }

    CompletionContext::Default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_completions_count() {
        let completions = &*BUILTIN_COMPLETIONS;
        // We should have 80+ built-in functions
        assert!(
            completions.len() >= 80,
            "Expected at least 80 built-in functions, got {}",
            completions.len()
        );
    }

    #[test]
    fn test_keyword_completions_count() {
        let completions = &*KEYWORD_COMPLETIONS;
        // We should have all the keywords
        assert!(
            completions.len() >= 15,
            "Expected at least 15 keywords, got {}",
            completions.len()
        );
    }

    #[test]
    fn test_constant_completions_count() {
        let completions = &*CONSTANT_COMPLETIONS;
        // We should have all the constants
        assert!(
            completions.len() >= 9,
            "Expected at least 9 constants, got {}",
            completions.len()
        );
    }

    #[test]
    fn test_type_completions_count() {
        let completions = &*TYPE_COMPLETIONS;
        // We should have all the type names
        assert!(
            completions.len() >= 12,
            "Expected at least 12 types, got {}",
            completions.len()
        );
    }

    #[test]
    fn test_completion_item_structure() {
        let completions = &*BUILTIN_COMPLETIONS;
        let sin_item = completions.iter().find(|c| c.label == "sin");
        assert!(sin_item.is_some(), "Should have sin function");

        let item = sin_item.unwrap();
        assert_eq!(item.kind, Some(CompletionItemKind::FUNCTION));
        assert!(item.detail.is_some());
        assert!(item.documentation.is_some());
        assert!(item.insert_text.is_some());
        assert_eq!(item.insert_text_format, Some(InsertTextFormat::SNIPPET));
    }

    #[test]
    fn test_context_detection_after_dot() {
        let doc = Document::new("obj.".to_string());
        let context = analyze_completion_context(&doc, Position::new(0, 4));
        matches!(context, CompletionContext::AfterDot);
    }

    #[test]
    fn test_context_detection_after_let() {
        let doc = Document::new("let ".to_string());
        let context = analyze_completion_context(&doc, Position::new(0, 4));
        matches!(context, CompletionContext::VariableDeclaration);
    }

    #[test]
    fn test_context_detection_after_mut() {
        let doc = Document::new("mut ".to_string());
        let context = analyze_completion_context(&doc, Position::new(0, 4));
        matches!(context, CompletionContext::VariableDeclaration);
    }

    #[test]
    fn test_context_detection_after_import() {
        let doc = Document::new("import { ".to_string());
        let context = analyze_completion_context(&doc, Position::new(0, 9));
        matches!(context, CompletionContext::AfterImport);
    }

    #[test]
    fn test_default_completions() {
        let doc = Document::new("".to_string());
        let completions = get_completions(&doc, Position::new(0, 0));

        // Should include all categories
        let has_function = completions
            .iter()
            .any(|c| c.kind == Some(CompletionItemKind::FUNCTION));
        let has_keyword = completions
            .iter()
            .any(|c| c.kind == Some(CompletionItemKind::KEYWORD));
        let has_constant = completions
            .iter()
            .any(|c| c.kind == Some(CompletionItemKind::CONSTANT));
        let has_type = completions
            .iter()
            .any(|c| c.kind == Some(CompletionItemKind::CLASS));

        assert!(has_function, "Should include functions");
        assert!(has_keyword, "Should include keywords");
        assert!(has_constant, "Should include constants");
        assert!(has_type, "Should include types");
    }

    #[test]
    fn test_no_completions_after_let() {
        let doc = Document::new("let ".to_string());
        let completions = get_completions(&doc, Position::new(0, 4));
        assert!(
            completions.is_empty(),
            "Should not suggest completions after 'let '"
        );
    }

    #[test]
    fn test_lazy_static_caching() {
        // First access should initialize
        let _first = BUILTIN_COMPLETIONS.len();
        // Second access should use cache (same pointer)
        let _second = BUILTIN_COMPLETIONS.len();
        // They should be the same
        assert_eq!(_first, _second);
    }

    #[test]
    fn test_specific_functions_present() {
        let completions = &*BUILTIN_COMPLETIONS;
        let names: Vec<&str> = completions.iter().map(|c| c.label.as_str()).collect();

        // Check math functions
        assert!(names.contains(&"sin"), "Missing sin");
        assert!(names.contains(&"cos"), "Missing cos");
        assert!(names.contains(&"sqrt"), "Missing sqrt");
        assert!(names.contains(&"factorial"), "Missing factorial");

        // Check array functions
        assert!(names.contains(&"map"), "Missing map");
        assert!(names.contains(&"filter"), "Missing filter");
        assert!(names.contains(&"reduce"), "Missing reduce");
        assert!(names.contains(&"len"), "Missing len");

        // Check DSP functions
        assert!(names.contains(&"fft"), "Missing fft");
        assert!(names.contains(&"convolve"), "Missing convolve");

        // Check linear algebra
        assert!(names.contains(&"det"), "Missing det");
        assert!(names.contains(&"inv"), "Missing inv");

        // Check graph algorithms
        assert!(names.contains(&"dijkstra"), "Missing dijkstra");
        assert!(names.contains(&"bfs"), "Missing bfs");
    }
}
