---
title: "Troubleshooting"
description: "Solutions for common LSP server issues"
section: "lsp-advanced"
order: 3
---

# Troubleshooting the Achronyme LSP Server

This guide helps you diagnose and resolve common issues with the Achronyme LSP server.

## General Troubleshooting Steps

Before diving into specific issues, try these:

### 1. Enable Debug Mode

Start the LSP server with debug logging:

**In your editor configuration:**

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

Then check the debug output console in your editor.

### 2. Verify Installation

Check the LSP server is installed:

**Linux/macOS:**
```bash
which achronyme-lsp
achronyme-lsp --help
```

**Windows:**
```bash
where achronyme-lsp
achronyme-lsp.exe --help
```

### 3. Check Editor Configuration

Verify your editor's LSP configuration:
- Correct command path
- Correct arguments
- File type associations (`.soc` files)

### 4. Restart Everything

Sometimes a fresh start helps:
1. Close all `.soc` files
2. Restart your editor
3. Reopen a `.soc` file
4. Check if LSP connects

### 5. Check for Syntax Errors

Parser errors prevent some features from working:

```bash
# Use achronyme compiler to check file
achronyme --check myfile.soc
```

## LSP Server Won't Start

### "Command not found: achronyme-lsp"

**Cause:** LSP binary not in PATH or not installed

**Solutions:**

1. **Verify installation:**
   ```bash
   which achronyme-lsp        # Linux/macOS
   where achronyme-lsp        # Windows
   ```

2. **Use full path if not in PATH:**
   ```json
   "lsp": {
     "languages": {
       "achronyme": {
         "command": "/full/path/to/achronyme-lsp",
         "args": ["--stdio"]
       }
     }
   }
   ```

3. **Reinstall LSP server:**
   ```bash
   cargo install --path crates/achronyme-lsp --force
   ```

### "Missing --stdio flag"

**Cause:** Server started without required flag

**Solution:** Add `--stdio` to server command

**VS Code:**
```json
"args": ["--stdio"]
```

**Neovim:**
```lua
cmd = { 'achronyme-lsp', '--stdio' }
```

### "Failed to start LSP server"

**Causes:** Various startup issues

**Diagnostics:**
1. Check editor debug console for error message
2. Try running the server manually:
   ```bash
   achronyme-lsp --stdio
   # Should start without error
   # Press Ctrl+C to exit
   ```

3. Check for permission issues:
   ```bash
   ls -la $(which achronyme-lsp)
   # Should show executable bit
   ```

## LSP Won't Connect to Editor

### "LSP Status: Not Initialized"

**Cause:** Server started but communication failed

**Solutions:**

1. **Restart the editor**
   - Close all files
   - Quit editor completely
   - Reopen editor
   - Open a `.soc` file

2. **Check file association:**
   ```json
   "files.associations": {
     "*.soc": "achronyme"
   }
   ```

3. **Verify LSP client extension is enabled**
   - VS Code: Check Extensions panel
   - Verify extension is active

### "Connection timeout"

**Cause:** LSP server slow to respond

**Causes & solutions:**

1. **Large files:**
   - Close other open files
   - Split the file into smaller modules

2. **System resources:**
   - Check available memory and CPU
   - Close other applications
   - Restart system if needed

3. **Increase timeout:**
   **VS Code:**
   ```json
   "lsp": {
     "client": {
       "timeout": 10000
     }
   }
   ```

## Features Not Working

### Code Completion Not Showing

**Symptoms:** No suggestions when typing, or triggering with Ctrl+Space

**Causes & solutions:**

1. **File not recognized as Achronyme:**
   - Check file extension: `.soc`
   - Check `files.associations` in editor settings
   - Try explicitly setting language mode

2. **Syntax errors in file:**
   - Open LSP debug console (check for errors)
   - Fix parse errors first
   - Completions may not show with parse errors

3. **Completion disabled:**
   ```json
   "[achronyme]": {
     "editor.suggest.enabled": true
   }
   ```

4. **Trigger characters issue:**
   - Try manual trigger: `Ctrl+Space`
   - Check that `.` and `:` trigger completions

**Debug:**
```bash
# In editor debug console, look for:
# "[DEBUG] Completing at position..."
```

### Signature Help Not Working

**Symptoms:** No parameter hints when typing function calls

**Causes & solutions:**

1. **Not triggered properly:**
   - Type `(` should trigger automatically
   - Type `,` should show next parameter
   - Manual trigger: `Ctrl+Shift+Space`

2. **Function not recognized:**
   - Only built-in and user-defined functions show hints
   - Custom functions need to be in scope

3. **Configuration issue:**
   ```json
   "[achronyme]": {
     "editor.parameterHints.enabled": true
   }
   ```

### Hover Information Not Showing

**Symptoms:** No tooltip when hovering over code

**Causes & solutions:**

1. **Hover disabled:**
   ```json
   "editor.hover.enabled": true
   ```

2. **Mouse hover too fast:**
   - Editor has hover delay (usually 500ms)
   - Try waiting longer
   - Check editor settings for hover delay

3. **Hovering over unsupported items:**
   - Works for: built-in functions, keywords, variables
   - Doesn't work for: arbitrary expressions (yet)

### Formatting Not Working

**Symptoms:** Format document has no effect, or errors

**Causes & solutions:**

1. **Formatting disabled:**
   ```json
   "[achronyme]": {
     "editor.defaultFormatter": "achronyme"
   }
   ```

2. **Parse errors prevent formatting:**
   - Fix syntax errors first
   - Formatting needs valid AST

3. **File is read-only:**
   - Check file permissions
   - Make file writable

4. **Too many syntax errors:**
   - Formatter may fail on severely broken code
   - Fix major syntax issues first

### Go to Definition Not Working

**Symptoms:** F12 does nothing or shows error

**Causes & solutions:**

1. **Definition not found:**
   - Only works for user-defined variables/functions
   - Built-ins don't have definitions (use hover instead)
   - Check variable is in scope

2. **Wrong position:**
   - Cursor must be on the symbol name
   - Example: `square(` - position on 's' in 'square'

3. **Feature disabled:**
   - Check `definition_provider` in capabilities
   - Verify keybinding is set

### Find References Not Working

**Symptoms:** No references found, or jumps to wrong location

**Causes & solutions:**

1. **Variable not referenced:**
   - Check if variable is actually used
   - Try different variable (e.g., a parameter)

2. **Current scope only:**
   - Finds references in current file only
   - Cross-file references not yet supported

3. **Keybinding not set:**
   - Neovim: Add `vim.keymap.set('n', 'gr', vim.lsp.buf.references)`
   - VS Code: Should work with Shift+F12 by default

### Document Symbols Not Showing

**Symptoms:** Outline panel empty, or missing symbols

**Causes & solutions:**

1. **File has no top-level definitions:**
   ```javascript
   // This shows in outline:
   let x = 5

   // This doesn't (expression only):
   5 + 3
   ```

2. **Parse errors:**
   - Fix syntax errors to get symbol parsing

3. **Outline disabled:**
   ```json
   "breadcrumbs.enabled": true,
   "outline.enabled": true
   ```

### Diagnostics Not Showing

**Symptoms:** No error indicators or error list empty

**Causes & solutions:**

1. **Diagnostics disabled:**
   ```json
   "[achronyme]": {
     "problemsPanel.enabled": true
   }
   ```

2. **File has no errors:**
   - No diagnostics if file parses successfully
   - This is correct behavior

3. **Diagnostics turned off in LSP:**
   - Check LSP output for diagnostic publishing
   - Enable with `--debug` flag

## Performance Issues

### LSP Server Using Too Much Memory

**Symptoms:** Editor becomes slow, LSP uses >200MB memory

**Causes & solutions:**

1. **Large open files:**
   - Close large `.soc` files
   - Keep file size < 100k lines if possible

2. **Many open files:**
   - Close unused `.soc` files
   - Each file cached in memory

3. **Memory leak (rare):**
   - Restart editor
   - Report issue on GitHub

**Check memory usage:**

**Linux/macOS:**
```bash
ps aux | grep achronyme-lsp
```

**Windows:**
- Task Manager → Achronyme-LSP → Memory

### LSP Server Using Too Much CPU

**Symptoms:** Editor is slow, high CPU usage

**Causes & solutions:**

1. **Parsing large files:**
   - Most CPU during file open/edit
   - Large files take longer to parse
   - Split files into modules if possible

2. **Continuous reparse:**
   - Normal during editing
   - Should settle down when you stop typing

3. **System too slow:**
   - Check available system resources
   - Close other applications
   - Increase RAM if possible

### Completions/Hover Slow

**Symptoms:** Suggestions or hover delayed or laggy

**Causes & solutions:**

1. **Large file:**
   - Parsing delays completion response
   - Close other files
   - Keep files reasonably sized

2. **Complex syntax:**
   - Many operators or nested structures
   - Parser is slower on complex code

3. **System resources:**
   - Low memory/CPU available
   - Close other applications

**Measure performance:**
```bash
# With debug enabled, check console for timing:
[DEBUG] Completing at position line:col (completed in Xms)
```

## Editor-Specific Issues

### VS Code Issues

#### "Request failed: -32600"

**Cause:** Invalid LSP request

**Solution:**
- Update VS Code to latest version
- Update LSP extension
- Check server version: `achronyme-lsp --version`

#### IntelliSense shows nothing

**Solution:**
```json
"[achronyme]": {
  "editor.quickSuggestions": {
    "other": true,
    "comments": false,
    "strings": false
  }
}
```

#### Tooltip overlaps code

**Solution:**
```json
"editor.hover.above": true
```

### Neovim Issues

#### LSP not found by nvim-lspconfig

**Cause:** Custom configuration needed for Achronyme

**Solution:**
Register the server in lspconfig:

```lua
local lspconfig = require 'lspconfig'
local util = lspconfig.util
local configs = require 'lspconfig.configs'

if not configs.achronyme then
  configs.achronyme = {
    default_config = {
      cmd = { 'achronyme-lsp', '--stdio' },
      filetypes = { 'achronyme' },
      root_dir = util.find_git_ancestor,
    }
  }
end

lspconfig.achronyme.setup {}
```

#### Keybindings not working

**Solution:**
```lua
local on_attach = function(client, bufnr)
  vim.keymap.set('n', 'gd', vim.lsp.buf.definition, {buffer = bufnr})
  vim.keymap.set('n', 'K', vim.lsp.buf.hover, {buffer = bufnr})
  vim.keymap.set('n', 'gr', vim.lsp.buf.references, {buffer = bufnr})
end

lspconfig.achronyme.setup { on_attach = on_attach }
```

### Emacs Issues

#### lsp-mode not connecting

**Solution:**
```elisp
(lsp-register-client
  (make-lsp-client :new-connection
    (lsp-stdio-connection '("achronyme-lsp" "--stdio"))
    :server-id 'achronyme
    :activation-fn (lsp-activate-on "achronyme")))
```

#### Hover doesn't work

**Solution:**
```elisp
(use-package lsp-ui
  :ensure t
  :custom
  (lsp-ui-doc-enable t)
  (lsp-ui-doc-show-with-hover t))
```

## Reporting Issues

If you can't solve an issue, report it:

### Prepare Diagnostic Information

1. **Version info:**
   ```bash
   achronyme-lsp --version
   rustc --version
   # Editor version
   ```

2. **Configuration:**
   - LSP server command and args
   - Editor configuration (relevant parts)

3. **Minimal reproduction:**
   - Small `.soc` file that triggers the issue
   - Steps to reproduce
   - Expected vs actual behavior

4. **Debug output:**
   ```
   Run with --debug flag
   Copy relevant debug console output
   ```

### Open an Issue

1. Visit [GitHub Issues](https://github.com/achronyme/achronyme-core/issues)
2. Click "New Issue"
3. Choose "LSP Server Issue"
4. Provide diagnostic information
5. Describe the problem clearly

## Frequently Asked Questions

### Q: LSP server crashes randomly

**A:** Enable debug mode and check error messages. Report the issue with crash logs.

### Q: Features work in VS Code but not Neovim

**A:** Each editor's LSP client is different. Check editor-specific configuration. See [Editor Setup](../getting-started/editor-setup.md).

### Q: Can I use an older/newer version of the LSP?

**A:** Use the version matching your Achronyme compiler. Check version compatibility.

### Q: Does LSP server cache data between sessions?

**A:** No. LSP server is stateless per-session. Each document handled independently.

### Q: Can I run multiple LSP servers?

**A:** Yes. Multiple instances can run simultaneously for different editor windows.

## Advanced Debugging

### Run LSP Server Standalone

Test without an editor:

```bash
# Start server
achronyme-lsp --stdio --debug

# In another terminal, send JSON-RPC messages:
# (This requires knowledge of JSON-RPC protocol)

# Control+C to exit
```

### Check Server Logs

Enable verbose logging:

```bash
RUST_LOG=debug achronyme-lsp --stdio --debug
```

### Profile Performance

Use system profiling tools:

**Linux:**
```bash
perf record achronyme-lsp --stdio
perf report
```

**macOS:**
```bash
instruments -t "Time Profiler" achronyme-lsp
```

## Getting Help

- **Documentation:** Read [LSP Server Guide](../)
- **Editor Docs:** Check editor-specific LSP documentation
- **GitHub Issues:** Search existing issues
- **Community:** Ask in Achronyme discussions

---

**End of Troubleshooting Guide**
