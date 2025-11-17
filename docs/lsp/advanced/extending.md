---
title: "Extending the LSP Server"
description: "How to add new features to the Achronyme LSP server"
section: "lsp-advanced"
order: 2
---

# Extending the Achronyme LSP Server

This guide explains how to add new features and capabilities to the Achronyme LSP server.

## Overview

The LSP server is designed with extension in mind. Common extension points include:

- **New completion items** - Add more autocompletion suggestions
- **New handlers** - Implement a new LSP feature
- **New diagnostics** - Add error detection rules
- **Code actions** - Provide quick fixes

## Adding Completion Items

### 1. Add to achronyme-lsp-core

First, add the completion item to the shared core crate.

**File:** `crates/achronyme-lsp-core/src/completion.rs`

```rust
pub fn get_all_completions() -> Vec<CompletionEntry> {
    vec![
        // Existing items...

        // Add new function
        CompletionEntry {
            label: "newFunction".to_string(),
            kind: CompletionKind::Function,
            detail: "newFunction(param: Type) -> ReturnType".to_string(),
            insert_text: "newFunction($1)".to_string(),
            documentation: "Description of what newFunction does.

Example:
    newFunction(value)  // Returns something".to_string(),
        },
    ]
}
```

### 2. Update the Handler

The handler automatically picks up new items via lazy-static caching.

**File:** `crates/achronyme-lsp/src/handlers/completion.rs`

The `BUILTIN_COMPLETIONS` lazy-static will automatically include your new item:

```rust
static BUILTIN_COMPLETIONS: Lazy<Vec<CompletionItem>> = Lazy::new(|| {
    get_all_completions()
        .iter()
        .filter(|e| e.kind == CompletionKind::Function)
        .map(convert_to_lsp_completion)
        .collect()
    // Your new item is included automatically!
});
```

### 3. Test the Addition

```bash
cd crates/achronyme-lsp
cargo build
cargo test

# Then test in your editor:
# 1. Open a .soc file
# 2. Type "new" and press Ctrl+Space
# 3. Should see "newFunction" in suggestions
```

## Adding Function Signatures

### 1. Add to achronyme-lsp-core

**File:** `crates/achronyme-lsp-core/src/signature_help.rs`

```rust
pub fn get_signature(name: &str) -> Option<FunctionSignature> {
    match name {
        // Existing signatures...

        "newFunction" => Some(FunctionSignature {
            signature: "newFunction(param: Type) -> ReturnType".to_string(),
            documentation: "Complete description of newFunction.

This function does something useful.

Parameters:
  param: Type - Description of the parameter

Returns: ReturnType - Description of return value

Example:
  newFunction(value)  // Returns result".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "param: Type".to_string(),
                    documentation: "Description of param".to_string(),
                }
            ],
        }),

        _ => None,
    }
}
```

### 2. Test Signature Help

```bash
# Open .soc file
# Type: newFunction(|
# Should show signature popup
```

## Adding a New Handler

To implement a new LSP feature (e.g., code actions), follow these steps:

### 1. Create Handler Module

**File:** `crates/achronyme-lsp/src/handlers/codeactions.rs`

```rust
use tower_lsp::lsp_types::*;
use crate::document::Document;

pub fn get_code_actions(doc: &Document, range: Range)
    -> Vec<CodeAction> {
    // Analyze document in range
    // Find potential issues or improvements
    // Return suggested code actions

    vec![
        CodeAction {
            title: "Add semicolon".to_string(),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![
                // Associated diagnostics
            ]),
            edit: Some(WorkspaceEdit {
                changes: Some(std::collections::HashMap::new()),
                // Details...
            }),
            ..Default::default()
        }
    ]
}
```

### 2. Add to Handler Module Exports

**File:** `crates/achronyme-lsp/src/handlers/mod.rs`

```rust
pub mod completion;
pub mod formatting;
pub mod signature_help;
pub mod hover;
pub mod definition;
pub mod references;
pub mod symbols;
pub mod diagnostics;
pub mod codeactions;  // Add this line
```

### 3. Update Server Capabilities

**File:** `crates/achronyme-lsp/src/capabilities.rs`

```rust
pub fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        // Existing capabilities...

        // Add code action support
        code_action_provider: Some(OneOf::Left(true)),

        ..Default::default()
    }
}
```

### 4. Add Handler to Backend

**File:** `crates/achronyme-lsp/src/server.rs`

```rust
#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    // Existing handlers...

    async fn code_action(&self, params: CodeActionParams)
        -> Result<Option<Vec<Command, CodeAction>>> {
        let uri = params.text_document.uri;

        if let Some(doc) = self.documents.get(&uri) {
            let actions = handlers::codeactions::get_code_actions(
                &doc,
                params.range
            );
            Ok(Some(actions))
        } else {
            Ok(None)
        }
    }
}
```

### 5. Test the Handler

```bash
cd crates/achronyme-lsp
cargo build
cargo test

# Test in editor:
# Look for code action indicators (light bulb icon)
# Click to see suggested actions
```

## Adding a Diagnostic Rule

### 1. Implement Analysis

**File:** `crates/achronyme-lsp/src/handlers/diagnostics.rs`

```rust
pub fn compute_diagnostics(doc: &Document) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    // Existing parse error diagnostics...

    // Add new semantic analysis
    if let Some(ast) = doc.ast() {
        // Check for unused variables
        for variable in find_unused_variables(&ast) {
            diagnostics.push(Diagnostic {
                range: variable.location.to_lsp_range(),
                severity: Some(DiagnosticSeverity::WARNING),
                code: Some(NumberOrString::String("unused-variable".to_string())),
                message: format!("Variable '{}' is never used", variable.name),
                ..Default::default()
            });
        }
    }

    diagnostics
}

// Helper to find unused variables
fn find_unused_variables(ast: &Ast) -> Vec<UnusedVariable> {
    // Implementation...
    vec![]
}
```

### 2. Test the Diagnostic

```bash
# Open .soc file with unused variable
# Should see warning/error indicator
# Hover to see diagnostic message
```

## Adding Hover Information

### 1. Extend Hover Handler

**File:** `crates/achronyme-lsp/src/handlers/hover.rs`

```rust
fn get_custom_info(name: &str) -> Option<String> {
    match name {
        "mySpecialFunction" => Some(
            "```achronyme\nmySpecialFunction(x: Number) -> Number\n```\n\
            Custom documentation for my function.".to_string()
        ),
        _ => None,
    }
}

pub fn get_hover(doc: &Document, position: Position) -> Option<Hover> {
    let word = doc.word_at_position(position.line, position.character)?;

    // Check custom info first
    if let Some(info) = get_custom_info(&word) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: info,
            }),
            range: None,
        });
    }

    // Fall through to existing checks...
    // ...
}
```

### 2. Test Hover

```bash
# Open .soc file
# Hover over custom function name
# Should see documentation
```

## Adding a New Completion Context

### 1. Extend Context Detection

**File:** `crates/achronyme-lsp/src/handlers/completion.rs`

```rust
enum CompletionContext {
    AfterDot,
    AfterImport,
    VariableDeclaration,
    AfterPipe,         // New context
    Default,
}

fn analyze_completion_context(doc: &Document, position: Position)
    -> CompletionContext {
    // ... existing analysis ...

    // Check if after pipe operator |
    if trimmed.ends_with('|') {
        return CompletionContext::AfterPipe;
    }

    CompletionContext::Default
}

pub fn get_completions(doc: &Document, position: Position)
    -> Vec<CompletionItem> {
    let context = analyze_completion_context(doc, position);

    match context {
        CompletionContext::AfterDot => {
            // ... existing ...
        }
        CompletionContext::AfterPipe => {
            // New: suggest filter predicates or transformations
            vec![
                // completion items for pipe context
            ]
        }
        CompletionContext::Default => {
            // ... existing ...
        }
        _ => vec![],
    }
}
```

### 2. Test Context

```bash
# Open .soc file
# Type: some_function |
# Should show completions for pipe operations
```

## Testing Your Extensions

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_completion() {
        let doc = Document::new("let x = new");
        let completions = get_completions(&doc, Position {
            line: 0,
            character: 10,
        });

        assert!(completions.iter().any(|c| c.label == "newFunction"));
    }

    #[test]
    fn test_new_handler() {
        // Test your new handler
    }
}
```

### Integration Tests

```bash
# Create a test .soc file
# Open in your editor
# Test the feature manually
# Verify it works as expected
```

### Automated Testing

```bash
# Run all tests
cargo test -p achronyme-lsp

# Run specific test
cargo test test_new_completion

# Run with output
cargo test -- --nocapture
```

## Performance Considerations

### Lazy Initialization

Use `once_cell::Lazy` for expensive computations:

```rust
static EXPENSIVE_DATA: Lazy<Vec<Item>> = Lazy::new(|| {
    // Computed only once, on first access
    expensive_computation()
});
```

### Caching

Cache frequently accessed data:

```rust
// In Document struct
pub struct Document {
    text: String,
    cached_lines: RefCell<Option<Vec<String>>>,  // Cached
    cached_ast: RefCell<Option<Ast>>,             // Cached
}
```

### Avoid Blocking Operations

All handlers are async; avoid blocking:

```rust
// ✗ Wrong - blocks the async runtime
let result = std::process::Command::new("cmd").output();

// ✓ Right - use async alternatives
let result = tokio::process::Command::new("cmd").output().await;
```

## Debugging Extensions

### Enable Debug Logging

```bash
# Start server with debug flag
achronyme-lsp --stdio --debug

# Check editor output/debug console
```

### Use println! or eprintln!

```rust
eprintln!("Debug: Processing completion at {:?}", position);
```

Check the LSP output panel in your editor.

### Common Issues

| Issue | Solution |
|-------|----------|
| Handler not called | Check capabilities.rs |
| Completions don't appear | Check completion.rs context |
| Slow performance | Use Lazy caching, avoid blocking |
| Parser errors | Check document.rs AST caching |

## Submitting Extensions

To contribute new features:

1. **Fork the repository**
2. **Create a branch** for your feature
3. **Write tests** for your extension
4. **Test thoroughly** in multiple editors
5. **Document your changes**
6. **Submit a pull request** with description

## Best Practices

### 1. Follow Existing Patterns

Study existing handlers for patterns to follow:

- Use `handlers/` module structure
- Follow naming conventions
- Use `Document` methods for access

### 2. Add Comprehensive Tests

```rust
#[cfg(test)]
mod tests {
    // Test your feature thoroughly
    #[test]
    fn test_basic_case() { }

    #[test]
    fn test_edge_case() { }

    #[test]
    fn test_error_handling() { }
}
```

### 3. Document with Examples

```rust
/// Returns code actions for the given range.
///
/// # Arguments
/// * `doc` - The document to analyze
/// * `range` - The range to check
///
/// # Example
/// ```
/// let doc = Document::new("let x = 5");
/// let actions = get_code_actions(&doc, range);
/// ```
pub fn get_code_actions(doc: &Document, range: Range) -> Vec<CodeAction> {
    // ...
}
```

### 4. Handle Errors Gracefully

```rust
pub fn my_handler(doc: &Document, pos: Position) -> Option<Result> {
    // Return None for missing data
    // Return Err for actual errors
    // Return Ok(data) for success
}
```

---

**Next**: [Troubleshooting](troubleshooting.md)
