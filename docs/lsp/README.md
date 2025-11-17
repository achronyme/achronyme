---
title: "Achronyme LSP Server"
description: "Language Server Protocol implementation for Achronyme"
section: "lsp"
order: 1
---

# Achronyme LSP Server

The Achronyme Language Server provides intelligent code assistance for the Achronyme programming language. It implements the Language Server Protocol (LSP) to enable rich editor integrations with features like code completion, formatting, navigation, and diagnostics.

## Features

- **Code Completion** (151 items) - Functions, keywords, constants, and types with documentation
- **Signature Help** (56+ signatures) - Parameter hints and documentation while typing
- **Code Formatting** - Operator spacing, indentation, brace normalization
- **Diagnostics** - Real-time parse error detection and reporting
- **Navigation** - Go to definition, find references to symbols
- **Hover Information** - Rich documentation on mouse hover
- **Document Symbols** - Outline view of variables and types in your code

## Quick Start

### Installation

Build from source:

```bash
cd achronyme-core
cargo build --release -p achronyme-lsp
```

The binary will be at `target/release/achronyme-lsp` (or `.exe` on Windows).

### Basic Usage

The LSP server communicates via stdio (standard input/output). Most editors use a client plugin to manage this automatically.

```bash
achronyme-lsp --stdio
```

See [Editor Setup](getting-started/editor-setup.md) for detailed instructions for your editor.

## Version

Current version: 0.1.0

## Available Sections

- **[Getting Started](getting-started/)** - Installation and editor setup
  - [Installation Guide](getting-started/installation.md)
  - [Editor Setup](getting-started/editor-setup.md)
  - [Configuration](getting-started/configuration.md)

- **[Features](features/)** - Detailed documentation of LSP capabilities
  - [Code Completion](features/completion.md)
  - [Code Formatting](features/formatting.md)
  - [Signature Help](features/signature-help.md)
  - [Hover Information](features/hover.md)
  - [Navigation](features/navigation.md)
  - [Diagnostics](features/diagnostics.md)
  - [Document Symbols](features/symbols.md)

- **[Advanced](advanced/)** - Architecture and extension
  - [LSP Architecture](advanced/architecture.md)
  - [Extending the Server](advanced/extending.md)
  - [Troubleshooting](advanced/troubleshooting.md)

## Why Use the Achronyme LSP Server?

### Better Code Writing Experience

The LSP server integrates with modern editors to provide:
- **Instant feedback** on syntax errors as you type
- **Smart completions** that understand Achronyme's syntax
- **Auto-formatting** to keep code clean and consistent
- **Quick navigation** to definitions and usages

### Integration with Your Favorite Tools

The Language Server Protocol is a standardized communication protocol that works with:
- **VS Code** (most popular)
- **Neovim** (native support)
- **Emacs** (via lsp-mode)
- **Sublime Text**
- **IntelliJ IDEs**
- **Vim** (via vim-lsp or other plugins)

## Architecture Overview

The Achronyme LSP server is built with:

- **tower-lsp** - LSP protocol implementation in Rust
- **tokio** - Async runtime for handling concurrent requests
- **achronyme-parser** - Parser for syntax analysis
- **achronyme-lsp-core** - Shared completion and signature data

See [LSP Architecture](advanced/architecture.md) for a detailed overview.

## System Requirements

- Rust 1.70+ (if building from source)
- Modern editor with LSP client support
- 10-50 MB disk space for the LSP binary

## Getting Help

If you encounter issues:

1. Check [Troubleshooting](advanced/troubleshooting.md) for common problems
2. Enable debug mode: `achronyme-lsp --stdio --debug`
3. Check the server logs in your editor

## Next Steps

1. Start with [Installation](getting-started/installation.md)
2. Follow [Editor Setup](getting-started/editor-setup.md) for your editor
3. Explore [Features](features/) to learn about available capabilities
4. Check [Advanced Topics](advanced/) for configuration and customization

---

**Contributing**: Found a bug or have a feature request? Please visit the [GitHub repository](https://github.com/achronyme/achronyme-core) to report issues or contribute improvements.
