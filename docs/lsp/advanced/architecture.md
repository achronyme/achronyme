---
title: "LSP Server Architecture"
description: "Internal architecture of the Achronyme LSP server"
section: "lsp-advanced"
order: 1
---

# Achronyme LSP Server Architecture

This document describes the internal architecture and design of the Achronyme LSP server.

## High-Level Overview

The Achronyme LSP server follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────┐
│   Editor/Client (VS Code, Neovim, Emacs)   │
├─────────────────────────────────────────────┤
│  LSP Protocol (JSON-RPC over stdio)         │
├─────────────────────────────────────────────┤
│  Tower-LSP Framework                        │
│  ├─ Protocol Handling                       │
│  └─ Message Routing                         │
├─────────────────────────────────────────────┤
│  Achronyme LSP Backend                      │
│  ├─ Server (main.rs / server.rs)            │
│  ├─ Document Management                    │
│  ├─ Handlers (Feature Implementation)       │
│  └─ Capabilities                            │
├─────────────────────────────────────────────┤
│  Shared Components                          │
│  ├─ achronyme-lsp-core (Completion, Sigs)  │
│  ├─ achronyme-parser (Syntax Analysis)      │
│  └─ achronyme-interpreter (Evaluation)      │
└─────────────────────────────────────────────┘
```

## Crate Structure

### achronyme-lsp

The main LSP server crate.

```
crates/achronyme-lsp/
├── src/
│   ├── main.rs              # Entry point, CLI argument parsing
│   ├── server.rs            # Backend struct, protocol handlers
│   ├── capabilities.rs      # Server capability declarations
│   ├── document.rs          # Document state management
│   └── handlers/            # Feature implementations
│       ├── mod.rs           # Handler module exports
│       ├── completion.rs    # Code completion
│       ├── formatting.rs    # Code formatting
│       ├── signature_help.rs # Function signatures
│       ├── hover.rs         # Hover information
│       ├── definition.rs    # Go to definition
│       ├── references.rs    # Find references
│       ├── symbols.rs       # Document symbols/outline
│       └── diagnostics.rs   # Error reporting
├── Cargo.toml               # Package metadata & dependencies
└── README.md                # Project documentation
```

### achronyme-lsp-core

Shared business logic and data.

```
crates/achronyme-lsp-core/
├── src/
│   ├── lib.rs               # Public API
│   ├── completion.rs        # Completion items (151 total)
│   │   ├── functions.rs     # 109 function completions
│   │   ├── keywords.rs      # 19 keyword completions
│   │   ├── constants.rs     # 9 constant completions
│   │   └── types.rs         # 14 type completions
│   └── signature_help.rs    # Function signatures (56+)
├── Cargo.toml
└── README.md
```

## Component Details

### Main Entry Point (main.rs)

Responsibilities:
- Parse command-line arguments
- Set up async runtime (Tokio)
- Create LSP service with tower-lsp
- Configure stdin/stdout channels
- Start the server and handle shutdown

**Key structs:**
```rust
struct Cli {
    stdio: bool,     // Required LSP flag
    debug: bool,     // Optional debug logging
}
```

### Server Backend (server.rs)

The core LSP server implementation implementing the `LanguageServer` trait.

**Key struct:**
```rust
pub struct Backend {
    client: Client,              // Communication channel to editor
    documents: DashMap<Url, Document>,  // Open documents
    debug: bool,                 // Debug mode flag
}
```

**Main methods implement LSP lifecycle:**

| Method | Purpose |
|--------|---------|
| `initialize()` | Server startup, capability announcement |
| `initialized()` | After client confirms initialization |
| `shutdown()` | Graceful server shutdown |
| `did_open()` | Document opened event |
| `did_change()` | Document changed event |
| `did_close()` | Document closed event |

**Request handlers (async):**

```rust
impl LanguageServer for Backend {
    // Notification handlers (fire-and-forget)
    async fn did_open(&self, params) { ... }
    async fn did_change(&self, params) { ... }

    // Request handlers (require response)
    async fn completion(&self, params) -> Result<Option<Vec<CompletionItem>>> { ... }
    async fn hover(&self, params) -> Result<Option<Hover>> { ... }
    async fn formatting(&self, params) -> Result<Option<Vec<TextEdit>>> { ... }
    // ... more handlers
}
```

### Server Capabilities (capabilities.rs)

Declares which LSP features the server supports.

```rust
pub fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncKind::FULL),
        hover_provider: Some(true),
        definition_provider: Some(true),
        references_provider: Some(true),
        document_symbol_provider: Some(true),
        completion_provider: Some(CompletionOptions { ... }),
        signature_help_provider: Some(SignatureHelpOptions { ... }),
        document_formatting_provider: Some(true),
        // ... more capabilities
    }
}
```

### Document Management (document.rs)

Manages the state of open documents.

**Key struct:**
```rust
pub struct Document {
    text: String,              // Current text content
    lines: Vec<String>,        // Cached line splits
    ast: Option<ParseResult>,  // Cached AST
    error: Option<String>,     // Parse error if any
}
```

**Key methods:**

| Method | Purpose |
|--------|---------|
| `new(text)` | Create from text content |
| `update_text(text)` | Update document text |
| `text()` | Get current text |
| `lines()` | Get split lines |
| `ast()` | Get AST (parse) |
| `parse_error()` | Get parse error if any |
| `word_at_position()` | Find word at position |
| `offset_from_position()` | Convert LSP position to byte offset |

**Position handling:**

The LSP uses 0-based line and column numbers. Document converts between:
- LSP Positions: `(line: u32, character: u32)` (0-based)
- Internal offsets: Byte positions in the text
- Line/column pairs for navigation

### Handler Modules

Each handler implements a specific LSP feature:

#### completion.rs (151 items)

```rust
pub fn get_completions(doc: &Document, position: Position)
    -> Vec<CompletionItem>

// Categorized completion items:
// - Functions (109) from achronyme-lsp-core
// - Keywords (19)
// - Constants (9)
// - Types (14)
```

**Context analysis:**
- Detects if after `.` (field access)
- Detects if after `import {` (module imports)
- Detects if naming variable (after `let`/`mut`)
- Returns context-appropriate suggestions

#### formatting.rs

```rust
pub fn format_document(doc: &Document, options: &FormattingOptions)
    -> Vec<TextEdit>

// Applies transformations:
// - Operator spacing
// - Indentation fixing
// - Brace normalization
// - Comma spacing
// - Type annotation spacing
```

**Stateful formatting:**
- Tracks indentation level
- Maintains brace stack for nesting
- Processes line-by-line
- Returns TextEdits for each change

#### signature_help.rs (56+ signatures)

```rust
pub fn get_signature_help(doc: &Document, position: Position)
    -> Option<SignatureHelp>

// Finds function call context at cursor
// Extracts function name
// Counts active parameter
// Looks up signature from achronyme-lsp-core
```

#### hover.rs

```rust
pub fn get_hover(doc: &Document, position: Position)
    -> Option<Hover>

// Checks if word is:
// 1. Built-in function (provides signature + docs)
// 2. Keyword (provides explanation)
// 3. Variable (looks up in AST)
```

#### definition.rs

```rust
pub fn find_definition(doc: &Document, position: Position)
    -> Option<Location>

// Finds where a symbol is defined
// Searches AST for variable bindings
// Returns file location
```

#### references.rs

```rust
pub fn find_references(doc: &Document, position: Position)
    -> Vec<Location>

// Finds all uses of a symbol
// Scans AST for references
// Returns all locations
```

#### symbols.rs

```rust
pub fn get_document_symbols(doc: &Document)
    -> Vec<DocumentSymbol>

// Extracts all top-level definitions
// Returns variables, functions, types
// Includes kind and location info
```

#### diagnostics.rs

```rust
pub fn compute_diagnostics(doc: &Document)
    -> Vec<Diagnostic>

// Parses document
// Extracts parse errors
// Converts to LSP Diagnostics
// Includes line/column info
```

## Data Flow

### Document Change Flow

```
Editor sends: DidChangeTextDocumentParams
    ↓
Backend.did_change() receives params
    ↓
Update document text in DashMap
    ↓
Reparse document (update AST and errors)
    ↓
Call handlers::diagnostics::compute_diagnostics()
    ↓
Publish diagnostics back to editor
    ↓
Editor updates error display
```

### Completion Request Flow

```
Editor sends: CompletionParams with position
    ↓
Backend.completion() receives request
    ↓
Look up document from DashMap
    ↓
Call handlers::completion::get_completions()
    ↓
Analyze context at cursor
    ↓
Return filtered completion items
    ↓
Send response back to editor
    ↓
Editor displays completion popup
```

## External Dependencies

### tower-lsp

Framework for implementing LSP servers.

```
Provides:
- LanguageServer trait to implement
- Async message handling
- LSP types (Position, Range, TextEdit, etc.)
- JSON-RPC protocol support
```

### tokio

Async runtime for handling concurrent operations.

```
Provides:
- async/await support
- Multi-threaded runtime
- Channels for communication
- Timer utilities
```

### achronyme-parser

Provides parsing and AST generation.

```
Provides:
- Pest-based parser
- AST nodes and structures
- Parse error information
- Token positions
```

### achronyme-lsp-core

Shared business logic.

```
Provides:
- Completion items (151 total)
- Function signatures (56+)
- Keyword information
- Constant definitions
```

## Concurrency Model

The server is fully asynchronous:

```rust
// Multiple editors can send requests simultaneously
// Each handled by a separate async task

tokio::spawn(async move {
    // Handle one request in parallel
    handle_completion(params).await
})
```

**Document access:**

Uses `DashMap` for thread-safe, concurrent document storage:

```rust
// Multiple handlers can read same document simultaneously
// Only one can write at a time (via mut reference)
```

**Performance implications:**

- Fast concurrent reads (shared access)
- Safe concurrent writes (exclusive access)
- No locks blocking the async runtime

## Error Handling

### Parse Errors

Caught and converted to diagnostics:

```rust
if let Some(error) = doc.parse_error() {
    // Convert Pest ParseError to LSP Diagnostic
    let diagnostic = Diagnostic {
        range: parse_location_to_range(error),
        severity: Some(DiagnosticSeverity::ERROR),
        message: error.to_string(),
        ...
    };
    publish_diagnostics(uri, vec![diagnostic]).await;
}
```

### LSP Handler Errors

Handlers return `Result` types:

```rust
async fn completion(&self, params: CompletionParams)
    -> Result<Option<Vec<CompletionItem>>> {
    // Errors are sent back as LSP error response
    // Editor shows error message
}
```

## Performance Characteristics

### Parsing
- **Pest parser:** O(n) where n = file size
- **Typical files (< 10k lines):** < 100ms
- **Large files (> 100k lines):** May slow down

### Completion
- **Cache:** Lazy-static cache for all 151 items
- **Return time:** < 10ms
- **No I/O:** All data in memory

### Formatting
- **Algorithm:** O(n) single-pass per line
- **Large files:** < 500ms for 100k lines

### Hover/Signature Help
- **Built-ins:** < 1ms (hash lookup)
- **User variables:** < 50ms (AST search)

## Extension Points

For adding new features:

### Adding a New Completion Category

1. Add items to `achronyme-lsp-core/src/completion.rs`
2. Create category filter in `handlers/completion.rs`
3. Update `BUILTIN_COMPLETIONS` lazy static

### Adding a New Handler

1. Create `handlers/newfeature.rs`
2. Implement handler function
3. Add to `handlers/mod.rs`
4. Add capability in `capabilities.rs`
5. Add request handler in `server.rs`

### Adding a New Diagnostic

1. Implement analysis in `handlers/diagnostics.rs`
2. Convert to LSP `Diagnostic`
3. Publish via `client.publish_diagnostics()`

## Future Architecture Improvements

Planned enhancements:

- **Incremental parsing** - Only parse changed regions
- **Symbol indexing** - Fast cross-file symbol lookup
- **Custom language extensions** - Plugin system
- **Language configuration** - Per-project settings
- **Test infrastructure** - Dedicated test helpers
- **Performance profiling** - Built-in monitoring

---

**Next**: [Extending the Server](extending.md)
