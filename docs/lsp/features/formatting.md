---
title: "Code Formatting"
description: "Automatic code formatting rules in Achronyme LSP"
section: "lsp-features"
order: 2
---

# Code Formatting

The Achronyme LSP server provides automatic code formatting to keep your code clean, consistent, and readable.

## Overview

The formatter normalizes:
- Operator spacing
- Indentation
- Brace alignment
- Comma spacing
- Type annotations

## Formatting Rules

### Operator Spacing

Binary operators are surrounded by spaces.

**Before:**
```javascript
let x=a+b*c-d/e
let y=value==5
let z=!flag
```

**After:**
```javascript
let x = a + b * c - d / e
let y = value == 5
let z = !flag
```

**Affected operators:**
- Arithmetic: `+`, `-`, `*`, `/`, `%`, `^`
- Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Logical: `&&`, `||`, `!`
- Assignment: `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `^=`
- Range: `..`, `..=`

### Indentation

Code blocks are indented consistently with 4 spaces per level.

**Before:**
```javascript
if(x > 0) {
let y = 5
let z = y * 2
}
```

**After:**
```javascript
if(x > 0) {
    let y = 5
    let z = y * 2
}
```

**Indentation contexts:**
- Function bodies
- If/else blocks
- While loops
- For loops
- Match expressions
- Records
- Arrays (multi-line)

### Brace Normalization

Opening braces remain on the same line as the statement.

**Before:**
```javascript
if(condition)
{
    doSomething()
}
```

**After:**
```javascript
if(condition) {
    doSomething()
}
```

**Closing brace alignment:**
- Closing braces at same indentation as opening statement
- Empty lines between blocks are removed

### Comma Spacing

Commas have a space after them, but not before.

**Before:**
```javascript
let array = [1,2,3 , 4, 5]
func(a , b,c , d)
type Point = {x: Number,y: Number , z: Number}
```

**After:**
```javascript
let array = [1, 2, 3, 4, 5]
func(a, b, c, d)
type Point = {x: Number, y: Number, z: Number}
```

### Function Definitions

Functions are formatted with consistent spacing.

**Before:**
```javascript
let f=x=>x^2
let add=(a,b)=>a+b
let greet=(name,greeting="Hello")=>'${greeting}, ${name}!'
```

**After:**
```javascript
let f = x => x ^ 2
let add = (a, b) => a + b
let greet = (name, greeting = "Hello") => '${greeting}, ${name}!'
```

### Type Annotations

Type annotations have consistent spacing.

**Before:**
```javascript
let x:Number=42
let f=(x:Number,y:Number)->Number=>x+y
type Point={x:Number,y:Number}
```

**After:**
```javascript
let x: Number = 42
let f = (x: Number, y: Number) -> Number => x + y
type Point = {x: Number, y: Number}
```

### Multi-line Expressions

Long expressions are indented consistently.

**Before:**
```javascript
let result = map(x => x * 2,
filter(y => y > 0, data))
```

**After:**
```javascript
let result = map(x => x * 2,
    filter(y => y > 0, data))
```

### String Literals

String content is preserved exactly; only spacing around strings changes.

**Before:**
```javascript
let message='Hello, world!'
let interpolated='Value: ${value}'
```

**After:**
```javascript
let message = 'Hello, world!'
let interpolated = 'Value: ${value}'
```

### Comments

Single-line comments are adjusted for indentation.

**Before:**
```javascript
let x = 5
// Comment at same indent as code
if(x > 0) {
// Inside block
doSomething()
}
```

**After:**
```javascript
let x = 5
// Comment at same indent as code
if(x > 0) {
    // Inside block
    doSomething()
}
```

## Using Code Formatting

### Format Entire Document

**VS Code:**
- `Shift+Alt+F` (Windows/Linux)
- `Shift+Option+F` (macOS)
- Or right-click → Format Document

**Neovim:**
```vim
:lua vim.lsp.buf.format()
```

Or with keybinding:
```lua
vim.keymap.set('n', '<leader>f', vim.lsp.buf.format)
```

**Emacs:**
```elisp
M-x lsp-format-buffer
```

### Format on Save

Configure automatic formatting when saving files.

**VS Code:**
```json
"[achronyme]": {
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "achronyme"
}
```

**Neovim:**
```lua
lspconfig.achronyme.setup {
  on_attach = function(client, bufnr)
    vim.api.nvim_create_autocmd("BufWritePre", {
      buffer = bufnr,
      callback = function()
        vim.lsp.buf.format { async = false }
      end
    })
  end
}
```

**Emacs:**
```elisp
(add-hook 'achronyme-mode-hook
  (lambda ()
    (add-hook 'before-save-hook #'lsp-format-buffer nil t)))
```

### Format Selected Text

**VS Code:**
1. Select text with mouse or keyboard
2. Press `Shift+Alt+F`

**Neovim:**
```vim
:lua vim.lsp.buf.format()
" Or with visual selection - formatter applies to whole document
```

## Formatting Examples

### Example 1: Basic Cleanup

**Before:**
```javascript
let data=[1,2,3,4,5]
let squared=map(x=>x^2,data)
let filtered=filter(x=>x>4,squared)
filtered
```

**After:**
```javascript
let data = [1, 2, 3, 4, 5]
let squared = map(x => x ^ 2, data)
let filtered = filter(x => x > 4, squared)
filtered
```

### Example 2: Nested Structures

**Before:**
```javascript
type Person={name:String,age:Number,email?:String}
let person:Person={
name:"Alice",
age:30,
email:"alice@example.com"
}
```

**After:**
```javascript
type Person = {name: String, age: Number, email?: String}
let person: Person = {
    name: "Alice",
    age: 30,
    email: "alice@example.com"
}
```

### Example 3: Control Flow

**Before:**
```javascript
if(x>0){
let y=x*2
if(y>10){
print("Large")
}else{
print("Small")
}
}
```

**After:**
```javascript
if(x > 0) {
    let y = x * 2
    if(y > 10) {
        print("Large")
    } else {
        print("Small")
    }
}
```

## Formatting Configuration

### Tab Size

Default: 4 spaces per indentation level

Configure in your editor:

**VS Code:**
```json
"[achronyme]": {
  "editor.tabSize": 4,
  "editor.insertSpaces": true
}
```

**Neovim:**
```lua
vim.bo.shiftwidth = 4
vim.bo.tabstop = 4
vim.bo.expandtab = true
```

## Formatting Limitations

The current formatter:
- ✅ Normalizes spacing around operators
- ✅ Fixes indentation
- ✅ Normalizes commas
- ✅ Handles brace positions
- ⚠️ Limited multi-line expression handling
- ⚠️ Does not reflow long lines (future)
- ⚠️ Does not reorder imports (future)

### Cases Not Modified

Formatting preserves:
- **String content** - No changes to string values
- **Comments** - Content unchanged, indentation fixed
- **Line structure** - Empty lines preserved
- **Code logic** - Only spacing/indentation changes

## Disabling Formatting

If you prefer to format manually or use another formatter:

**VS Code:**
```json
"[achronyme]": {
  "editor.formatOnSave": false
}
```

Or uninstall the LSP extension's formatting support.

**Neovim:**
```lua
lspconfig.achronyme.setup {
  on_attach = function(client, bufnr)
    client.server_capabilities.documentFormattingProvider = false
  end
}
```

## Performance

The formatter:
- Works on files up to 100k lines efficiently
- Takes <500ms on typical files
- Operates on document save (no background processing)

For very large files (>100k lines):
1. Consider splitting into modules
2. Disable format-on-save if slow
3. Format manually less frequently

## Keyboard Shortcuts Reference

| Editor | Format Document | Format Selection |
|--------|-----------------|------------------|
| VS Code | `Shift+Alt+F` | `Shift+Alt+F` |
| Neovim | `:lua vim.lsp.buf.format()` | Same |
| Emacs | `M-x lsp-format-buffer` | Same |
| Sublime | Cmd/Ctrl+Shift+P → Format | Same |

## Future Enhancements

Planned improvements:
- Line length limit enforcement
- Import reordering
- Custom formatting styles
- Per-project configuration files
- Semantic formatting

---

**Next**: [Signature Help](signature-help.md)
