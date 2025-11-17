---
title: "LSP Configuration"
description: "Configure the Achronyme LSP server behavior"
section: "lsp-getting-started"
order: 3
---

# LSP Server Configuration

This guide covers configuration options for the Achronyme LSP server.

## Server Flags

The LSP server accepts command-line flags:

```bash
achronyme-lsp --stdio [--debug]
```

### Available Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--stdio` | **Required** - Use stdio for LSP communication | N/A |
| `--debug` | Enable debug logging to editor console | false |

### Example: Enabling Debug Mode

In your editor configuration:

**VS Code:**
```json
"lsp": {
  "languages": {
    "achronyme": {
      "command": "achronyme-lsp",
      "args": ["--stdio", "--debug"]
    }
  }
}
```

**Neovim:**
```lua
lspconfig.achronyme.setup {
  cmd = { 'achronyme-lsp', '--stdio', '--debug' }
}
```

## Server Capabilities

The LSP server advertises support for:

| Feature | Status | Trigger |
|---------|--------|---------|
| Code Completion | Enabled | Manual (Ctrl+Space) or `.`, `:` |
| Signature Help | Enabled | `(`, `,` |
| Hover Information | Enabled | Mouse hover |
| Go to Definition | Enabled | Keyboard shortcut |
| Find References | Enabled | Keyboard shortcut |
| Document Symbols | Enabled | Outline/Symbol view |
| Document Formatting | Enabled | Format command |
| Diagnostics | Enabled | On file open/change |

## Feature Configuration

### Code Completion

**Trigger Characters:** `.`, `:` (plus manual trigger)

The server provides:
- 151 total completion items
- Functions with full documentation
- Keywords with examples
- Built-in constants
- Type definitions

**Context-Aware Suggestions:**

The server analyzes the code context to provide relevant suggestions:

```javascript
// After 'let ' or 'mut ' - no suggestions (you're naming a variable)
let |  // No completions here

// Default context - all categories
|  // Shows all completions

// After '.' - field/method access (future enhancement)
obj.|  // Will show object members

// After 'import {' - module exports (future enhancement)
import {|  // Will show available exports
```

### Signature Help

**Trigger Characters:** `(`, `,`

Displays:
- Function signature with parameter names
- Parameter documentation
- Example usage
- 56+ built-in function signatures

**Example:**

When typing `sin(`, the server shows:

```
sin(x: Number) -> Number

Returns the sine of x (x in radians)

↑ Parameter 1
```

### Document Formatting

**Format on Save:** Configure in your editor

The server normalizes:
- Operator spacing: `a+b` → `a + b`
- Indentation: Consistent 4-space indentation
- Brace formatting: Consistent style
- Comma spacing: After commas in lists/tuples

**Options:**

You can pass formatting options through the editor:

```json
{
  "tabSize": 4,
  "insertSpaces": true
}
```

### Diagnostics

**Real-time Error Reporting:**

The server publishes diagnostics on:
- File open
- Text changes
- File save

**Error Types:**

Currently reports:
- Parse errors (syntax)
- Compilation errors (future)

Each diagnostic includes:
- Error location (line, column)
- Error message
- Error code
- Suggested fix (future)

## Editor-Specific Configuration

### VS Code

In `.vscode/settings.json` (workspace) or `settings.json` (user):

```json
{
  "[achronyme]": {
    "editor.defaultFormatter": "achronyme",
    "editor.formatOnSave": true,
    "editor.wordBasedSuggestions": false,
    "editor.quickSuggestions": {
      "other": true,
      "comments": false,
      "strings": false
    }
  },
  "lsp": {
    "languages": {
      "achronyme": {
        "command": "achronyme-lsp",
        "args": ["--stdio"],
        "filetypes": ["achronyme"]
      }
    }
  }
}
```

### Neovim

In `~/.config/nvim/init.lua`:

```lua
local lspconfig = require('lspconfig')
local util = lspconfig.util

lspconfig.achronyme.setup {
  cmd = { 'achronyme-lsp', '--stdio' },
  root_dir = util.find_git_ancestor,
  settings = {
    achronyme = {
      debug = false
    }
  },
  on_attach = function(client, bufnr)
    -- Format on save
    vim.api.nvim_create_autocmd("BufWritePre", {
      buffer = bufnr,
      callback = function()
        vim.lsp.buf.format { async = false }
      end
    })
  end
}
```

### Emacs

In `~/.emacs.d/init.el`:

```elisp
(use-package lsp-mode
  :ensure t
  :hook ((achronyme-mode . lsp-deferred))
  :init
  (setq lsp-enable-file-watchers t
        lsp-file-watch-threshold 2000
        lsp-auto-configure t
        lsp-enable-on-type-formatting t))

(use-package lsp-ui
  :ensure t
  :commands lsp-ui-mode
  :init
  (setq lsp-ui-doc-enable t
        lsp-ui-doc-show-with-hover t
        lsp-ui-sideline-enable t))
```

## Advanced Configuration

### Disabling Features

To disable specific features, configure your editor's LSP client:

**VS Code:**
```json
{
  "lsp": {
    "diagnostics.disabled": ["achronyme"],
    "completion.disabled": false
  }
}
```

**Neovim:**
```lua
lspconfig.achronyme.setup {
  handlers = {
    -- Disable hover
    ['textDocument/hover'] = vim.lsp.with(
      vim.lsp.handlers.hover,
      { border = 'rounded' }
    ),
    -- Disable diagnostics
    ['textDocument/publishDiagnostics'] = function() end
  }
}
```

### Multi-Root Workspaces

Some editors support multi-root workspaces. The LSP server handles:
- Multiple folders with separate document management
- Independent diagnostics per file
- Workspace-level symbol search (future)

**Neovim with Workspaces:**
```lua
-- LSP will automatically manage multiple roots
lspconfig.achronyme.setup {
  root_dir = lspconfig.util.root_pattern('.git', '.root')
}
```

## Performance Tuning

### For Large Files

If you experience slowness with large `.soc` files:

1. **Disable certain features temporarily:**
   ```json
   {
     "lsp": {
       "completion.disabled": false,
       "hover.disabled": true
     }
   }
   ```

2. **Increase timeout values (in milliseconds):**
   **Neovim:**
   ```lua
   lspconfig.achronyme.setup {
     settings = {
       client = {
         timeout = 5000
       }
     }
   }
   ```

3. **Split large files into modules** (when supported)

### Memory Usage

The server uses:
- ~15-30 MB for the binary
- ~5-50 MB for document caching (depends on number of files open)

Monitor with system tools:
- **Linux:** `top`, `htop`
- **macOS:** Activity Monitor
- **Windows:** Task Manager

## Uninstalling/Resetting

### Remove from VS Code

1. Delete from `settings.json`
2. Uninstall LSP client extension

### Remove from Neovim

1. Remove from `init.lua`
2. Remove from plugin manager

### Reset to Defaults

Simply remove all custom configuration and reinstall the LSP server.

## Getting Help

For configuration issues:

1. Check [Troubleshooting](../advanced/troubleshooting.md)
2. Enable debug mode to see what's happening
3. Check editor-specific documentation
4. Report issues with:
   - Your editor version
   - Your configuration
   - Error messages from debug logs

---

**Next**: Explore [LSP Features](../features/)
