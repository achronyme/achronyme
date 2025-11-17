---
title: "Document Symbols"
description: "Code outline and symbol navigation in Achronyme LSP"
section: "lsp-features"
order: 7
---

# Document Symbols

Document symbols provide an outline of all variables, functions, and types defined in your file, making it easy to navigate and understand code structure.

## Overview

The symbol outline shows:
- **All definitions** - Variables, functions, and types
- **Hierarchical structure** - How symbols are organized
- **Quick navigation** - Jump to any symbol instantly
- **Symbol kind** - What type each symbol is (variable, function, etc.)

## Accessing the Outline

### VS Code

Open the Outline view:

1. **Side panel:** Click the Outline icon (or search "Outline")
2. **Breadcrumb:** Click the breadcrumb at top of editor
3. **Command:** `Ctrl+Shift+O` (Go to Symbol in Editor)
4. **Global search:** `Ctrl+T` to search all symbols

### Neovim

Use LSP symbol navigation:

```lua
-- Configure keybinding
vim.keymap.set('n', '<leader>s', vim.lsp.buf.document_symbol)
```

Or use a symbol browser plugin like `telescope.nvim`:

```lua
require('telescope.builtin').lsp_document_symbols()
```

### Emacs

Access symbols with:

```elisp
M-x lsp-ui-imenu
```

Or configure a keybinding:

```elisp
(define-key lsp-mode-map (kbd "C-c l s") #'lsp-ui-imenu)
```

## Symbol Types

The outline shows different symbol kinds:

### Variables

```javascript
let x = 42
let data = [1, 2, 3]
let user = {name: "Alice"}
```

Displayed as:
- **Variable icon** (often looks like a box or lowercase v)
- Label: `x`, `data`, `user`
- Kind: Variable

### Functions

```javascript
let square = x => x^2
let greet = (name) => "Hello, " + name
```

Displayed as:
- **Function icon** (often looks like a function symbol)
- Label: `square`, `greet`
- Kind: Function

### Type Definitions

```javascript
type Point = {x: Number, y: Number}
type Color = {r: Number, g: Number, b: Number}
```

Displayed as:
- **Type/Class icon**
- Label: `Point`, `Color`
- Kind: Class/Type

## Using the Outline

### Example File Structure

Consider this file:

```javascript
// analysis.soc

// Data loading
let data = [1, 2, 3, 4, 5]

// Type definitions
type Statistics = {
  mean: Number,
  std: Number,
  median: Number
}

// Analysis functions
let calculateMean = arr => mean(arr)
let calculateStd = arr => std(arr)
let analyze = arr => ({
  mean: calculateMean(arr),
  std: calculateStd(arr),
  median: median(arr)
})

// Results
let result = analyze(data)
```

### Outline Display

The outline would show:

```
analysis.soc
├─ data (Variable)
├─ Statistics (Class)
├─ calculateMean (Function)
├─ calculateStd (Function)
├─ analyze (Function)
└─ result (Variable)
```

### Jumping to a Symbol

Click on any symbol in the outline to jump to it:

```javascript
// Click "analyze" in outline
// → Jumps to:
let analyze = arr => ({
    ↑ Cursor position
```

### Filtering Symbols

Some editors allow filtering the outline:

**VS Code:**
- Type in the outline search box
- Shows only matching symbols

**Neovim with Telescope:**
```lua
require('telescope.builtin').lsp_document_symbols({
  symbols = { "Variable", "Function" }
})
```

## Symbol Navigation Shortcuts

### VS Code

| Action | Shortcut |
|--------|----------|
| Go to symbol | `Ctrl+Shift+O` |
| Search all symbols | `Ctrl+T` |
| Focus outline | Click outline tab |
| Collapse all | Click collapse icon |
| Jump to symbol | Click symbol in outline |

### Neovim

After setup:

| Action | Shortcut |
|--------|----------|
| Document symbols | `<leader>s` (or configured) |
| Next symbol | Navigate in symbol picker |
| Open symbol | `Enter` in picker |

### Emacs

| Action | Shortcut |
|--------|----------|
| Open Imenu | `C-c l s` (or configured) |
| Jump to symbol | `Enter` in Imenu |

## Practical Use Cases

### Exploring Code Structure

Understanding a file you just opened:

1. Open outline/symbols view
2. See all top-level definitions
3. Scroll through to understand structure
4. Click to jump to interesting parts

**Example:**
```
mylib.soc
├─ Configuration (Type)
├─ init (Function)
├─ process (Function)
├─ analyze (Function)
└─ cleanup (Function)

" Quick understanding: This file has setup, main logic, and teardown"
```

### Refactoring

Finding all related functions:

1. Open outline
2. See all functions
3. Related functions likely nearby
4. Update them together

**Example:**
```
stats.soc
├─ calculateMean (Function)
├─ calculateStd (Function)
├─ calculateMedian (Function)
└─ analyze (Function) ← calls all the above
```

### Documentation

Generating documentation by reading outline:

```
api.soc outline shows:
├─ parseInput (Function)
├─ validate (Function)
├─ transform (Function)
├─ applyRules (Function)
└─ formatOutput (Function)

" Perfect structure for API docs:
  Input parsing → Validation → Transformation → Rules → Output"
```

## Symbol Hierarchy

While current implementation shows flat symbols, future versions may support nested symbols:

```javascript
type Point = {
  x: Number,
  y: Number,
  distance: (p: Point) => Number
}
```

Future outline might show:

```
Point (Class)
├─ x (Field)
├─ y (Field)
└─ distance (Method)
```

For now, all symbols appear at the top level.

## Outline Performance

The outline:
- **Updates instantly** - As you type/edit
- **Works with large files** - Handles 10k+ lines
- **Scales efficiently** - O(n) parsing
- **No lag** - Sub-100ms updates

Performance tips:
- Close editor if outline lags (check system resources)
- Avoid extremely deeply nested structures
- Keep files reasonably sized

## Keyboard Shortcuts by Editor

### Quick Reference

| Editor | Show Symbols | Global Search |
|--------|--------------|---------------|
| VS Code | `Ctrl+Shift+O` | `Ctrl+T` |
| Neovim | `<leader>s` | Varies |
| Emacs | `C-c l s` | Varies |
| Sublime | `Ctrl+Shift+R` | Varies |

## Customizing Symbol Display

### VS Code

Configure outline appearance:

```json
"[achronyme]": {
  "outline.icons": true,
  "outline.problems": true,
  "breadcrumbs.enabled": true,
  "breadcrumbs.symbolPath": true
}
```

### Neovim

Configure symbol picker:

```lua
require('telescope').setup {
  extensions = {
    lsp_handlers = {
      document_symbol = {
        previewer = false,
        symbol_width = 50,
      }
    }
  }
}
```

## Symbol Display Options

### Show Only Functions

Some use cases only want functions:

**VS Code Configuration:**
```json
"[achronyme]": {
  "outline.scope": "function"
}
```

**Neovim:**
```lua
require('telescope.builtin').lsp_document_symbols({
  symbols = "Function"
})
```

### Show with Details

Show additional info for each symbol:

**Details might include:**
- Line number
- Column position
- Symbol type
- Sort order

## Best Practices

### 1. Use Descriptive Names

Good symbol names make the outline more useful:

```javascript
✓ let calculateDailyAverage = ...
✗ let calc = ...

✓ type UserProfile = ...
✗ type U = ...
```

### 2. Group Related Functions

Put related functions near each other:

```javascript
// Good structure:
// Data loading
let loadData = ...

// Processing
let processData = ...
let validateData = ...

// Output
let formatOutput = ...
```

### 3. Use Types for Structure

Type definitions help document structure:

```javascript
type DataPoint = {time: Number, value: Number}
type DataSet = {points: Array, label: String}

let analyze = (data: DataSet) => ...
```

These types appear in the outline, making structure clear.

## Limitations

Current symbol support:
- ✅ Shows all top-level definitions
- ✅ Shows variables, functions, types
- ⚠️ No nested symbol hierarchies
- ⚠️ No symbol filtering options
- ⚠️ Limited sorting options

## Future Enhancements

Planned improvements:
- Nested symbol hierarchies
- Symbol filtering by kind
- Symbol sorting options
- Call graph visualization
- Symbol usage counting
- Breadcrumb navigation
- Custom symbol icons

## Tips and Tricks

### 1. Use Outline for Quick Navigation

Instead of scrolling, use the outline:

```
File has 500 lines
With outline: Click symbol → instant jump
Without outline: Scroll through all 500 lines
```

### 2. Understand Code Structure

New to a codebase?

1. Open file
2. Look at outline
3. See organization without reading details
4. Click symbols to explore

### 3. Keep Outline Visible

Many editors allow keeping outline visible:

**VS Code:**
- Click outline icon in sidebar
- Keep it open while editing

This provides always-visible navigation.

### 4. Search All Symbols

Find symbols across all files:

**VS Code:** `Ctrl+T`

Type function name to find it anywhere.

---

**Next**: [Advanced Topics](../advanced/architecture.md)
