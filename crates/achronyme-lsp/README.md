# Achronyme Language Server Protocol (LSP)

Language Server Protocol implementation for the Achronyme programming language.

## Building

```bash
cargo build -p achronyme-lsp
```

For release build:

```bash
cargo build -p achronyme-lsp --release
```

## Running

The server must be started with the `--stdio` flag:

```bash
achronyme-lsp --stdio
```

With debug logging:

```bash
achronyme-lsp --stdio --debug
```

## Capabilities

### Implemented

- **Diagnostics**: Parse errors are reported with line/column information
- **Hover**:
  - Builtin function signatures and descriptions
  - Keyword documentation
  - Variable type information (from declarations)
- **Go to Definition**: Jump to variable declarations (`let`, `mut`)
- **Find References**: Find all occurrences of a symbol in the document
- **Document Symbols**: Outline view of variables, mutable variables, and type aliases

### Configuration

The server uses full text synchronization (the entire document is sent on each change).

### Supported LSP Methods

- `initialize`
- `initialized`
- `shutdown`
- `textDocument/didOpen`
- `textDocument/didChange`
- `textDocument/didClose`
- `textDocument/hover`
- `textDocument/definition`
- `textDocument/references`
- `textDocument/documentSymbol`

## Editor Integration

### VS Code

1. Install a generic LSP client extension (e.g., "vscode-languageclient")
2. Configure it to use:
   ```json
   {
     "command": "path/to/achronyme-lsp",
     "args": ["--stdio"],
     "filetypes": ["achronyme", "acr"]
   }
   ```

### Neovim

Using `nvim-lspconfig`:

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

configs.achronyme = {
  default_config = {
    cmd = { 'achronyme-lsp', '--stdio' },
    filetypes = { 'achronyme', 'acr' },
    root_dir = lspconfig.util.find_git_ancestor,
  },
}

lspconfig.achronyme.setup{}
```

## Architecture

```
src/
├── main.rs           # Entry point, CLI parsing
├── server.rs         # LSP server implementation (LanguageServer trait)
├── capabilities.rs   # Server capability definitions
├── document.rs       # Document management and caching
└── handlers/
    ├── mod.rs
    ├── diagnostics.rs  # Parse error reporting
    ├── hover.rs        # Hover information
    ├── definition.rs   # Go to definition
    ├── references.rs   # Find all references
    └── symbols.rs      # Document outline
```

## Future Enhancements

1. **Semantic Highlighting**: Provide semantic tokens for better syntax highlighting
2. **Completion**: Auto-complete for variables, functions, and keywords
3. **Code Actions**: Quick fixes and refactoring suggestions
4. **Formatting**: Auto-format Achronyme code
5. **Workspace Support**: Multi-file analysis and cross-file references
6. **Type Inference**: Show inferred types for expressions
7. **Rename Symbol**: Rename variables across the document
8. **Signature Help**: Show function signatures while typing

## Dependencies

- `tower-lsp`: LSP protocol implementation
- `tokio`: Async runtime
- `dashmap`: Concurrent hashmap for document storage
- `clap`: CLI argument parsing
- `achronyme-parser`: Achronyme language parser
