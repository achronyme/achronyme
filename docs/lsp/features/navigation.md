---
title: "Navigation"
description: "Go to definition and find references in Achronyme LSP"
section: "lsp-features"
order: 5
---

# Navigation Features

The Achronyme LSP server provides navigation tools to quickly jump to variable definitions and find all usages of a symbol throughout your code.

## Go to Definition

Jump directly to where a variable, function, or type is defined.

### Using Go to Definition

**Triggering the command:**

- **VS Code:** Click on a name then `F12` or `Ctrl+Click`
- **Neovim:** `gd` (after setup)
- **Emacs:** `M-x lsp-find-definition`

### What It Does

When you use "Go to Definition" on a symbol, the editor:

1. Finds where that symbol is defined
2. Opens the file containing the definition
3. Jumps to the exact line and column

**Example:**

```javascript
// In file main.soc
let result = square(5)
             ↑ Go to definition here

// Jumps to the definition:
let square = x => x * 2
    ↑ Here's where it's defined
```

### Supported Symbols

Go to definition works for:

- **User-defined variables** - Jump to `let` binding
- **User-defined functions** - Jump to function definition
- **Type definitions** - Jump to `type` declaration
- **Module imports** - Jump to imported symbol (future)

## Find References

Find all places where a symbol is used in your code.

### Using Find References

**Triggering the command:**

- **VS Code:** Right-click → "Find All References" or `Shift+F12`
- **Neovim:** `gr` (after setup)
- **Emacs:** `M-x lsp-find-references`

### What It Shows

The find references command shows:
- **Count** - How many places the symbol is used
- **File names** - Which files contain usages
- **Line numbers** - Where each usage occurs
- **Context** - Code snippet showing the usage

**Example Output:**

```
"square" used 3 places
├─ main.soc:5 - let result = square(5)
├─ main.soc:10 - values = map(square, data)
└─ tests.soc:12 - test_square = square(4) == 16
```

### Supported Symbols

Find references works for:

- **Any variable** - Find where it's used
- **Functions** - Find all calls to that function
- **Types** - Find all uses of that type
- **Imported symbols** - Find usages in different files (future)

## Practical Examples

### Example 1: Finding a Function Definition

**Scenario:** You see `calculateMean()` called but don't know where it's defined.

```javascript
// Cursor on 'calculateMean'
let result = calculateMean([1, 2, 3])
             ↑ Press F12 (VS Code)
```

**Result:** Editor jumps to:

```javascript
let calculateMean = data => mean(data)
    ↑ Definition found here
```

### Example 2: Finding All Uses of a Variable

**Scenario:** You want to see everywhere a variable `data` is used.

```javascript
// Right-click on 'data'
let data = [1, 2, 3, 4, 5]
    ↑ Find References

// Shows all locations:
// Line 1: let data = [1, 2, 3, 4, 5]
// Line 3: let sum = reduce((a, b) => a + b, 0, data)
// Line 4: let avg = mean(data)
// Line 5: let std = std(data)
```

### Example 3: Tracking Function Usage

**Scenario:** You want to know if a function is used and where.

```javascript
let processData = data => {
    return map(x => x * 2, data)
}
↑ Find references on 'processData'

// Results show:
// main.soc:15 - result = processData(input)
// main.soc:20 - values.map(processData)
```

## Navigation Limitations

Current limitations:

- ✅ Works within a single file
- ✅ Works with variables and functions
- ⚠️ Limited cross-file navigation (future)
- ⚠️ Doesn't track module imports (future)
- ⚠️ May miss some complex scoping (future)

## Keyboard Shortcuts

### VS Code

| Action | Shortcut |
|--------|----------|
| Go to definition | `F12` |
| Go to definition (new editor) | `Ctrl+K Ctrl+I` |
| Peek definition | `Alt+F12` |
| Find all references | `Shift+F12` |
| Go back | `Ctrl+-` |
| Go forward | `Ctrl+Shift+-` |

### Neovim

Configure keybindings:

```lua
local on_attach = function(client, bufnr)
  local opts = { noremap = true, silent = true, buffer = bufnr }

  -- Go to definition
  vim.keymap.set('n', 'gd', vim.lsp.buf.definition, opts)

  -- Find references
  vim.keymap.set('n', 'gr', vim.lsp.buf.references, opts)

  -- Go back
  vim.keymap.set('n', '<C-t>', '<C-o>', opts)
end

require('lspconfig').achronyme.setup { on_attach = on_attach }
```

Then use:

| Action | Shortcut |
|--------|----------|
| Go to definition | `gd` |
| Find references | `gr` |
| Go back | `Ctrl+o` (Vim standard) |
| Go forward | `Ctrl+i` (Vim standard) |

### Emacs

Configure with `lsp-mode`:

```elisp
(use-package lsp-mode
  :bind (:map lsp-mode-map
         ("C-c l d" . lsp-find-definition)
         ("C-c l r" . lsp-find-references)))
```

| Action | Shortcut |
|--------|----------|
| Go to definition | `C-c l d` |
| Find references | `C-c l r` |

## Navigation Workflows

### Workflow 1: Exploring Code

```
1. See a function call: square(5)
2. Press F12 to go to definition
3. See the implementation: x => x * 2
4. Use Ctrl+- to go back
5. Continue exploring
```

### Workflow 2: Refactoring

```
1. Find all references to old_name: Shift+F12
2. See all places to update
3. Rename in each location
4. (Future: automated rename)
```

### Workflow 3: Testing

```
1. Find all references to calculateMean
2. See where it's called
3. Check if all important paths use it
4. Add new test for missing cases
```

## Integration with Other Features

Navigation works alongside:

- **Hover:** After going to definition, hover for documentation
- **Completions:** See suggestions for names you can navigate to
- **Formatting:** Format code while navigating
- **Diagnostics:** See errors at definition locations

## Advanced Navigation

### Multi-step Navigation

Navigate through a chain of definitions:

```javascript
let result = calculate(data)
             ↑ Go to definition

let calculate = transform  // Definition 1
                 ↑ Go to definition again

let transform = compose(processA, processB)
                ↑ Continue navigating
```

### Finding by Type

Find all references to a type definition:

```javascript
type Point = {x: Number, y: Number}
     ↑ Find references

// Shows all places Point is used:
// let p: Point = {x: 1, y: 2}
// let points: Point[] = [...]
// func process(p: Point) => ...
```

## Performance

Navigation is fast:

- **Go to definition:** <10ms
- **Find references:** <50ms for typical files
- **Works with files up to 100k lines**

For slow navigation:

1. Check if there are parse errors
2. Try closing other large open files
3. Check available system memory

## Disabling Navigation

If you don't need these features:

**VS Code:**
```json
"[achronyme]": {
  "editor.gotoLocation.multipleDefinitions": "goto",
  "editor.gotoLocation.multipleReferences": "goto"
}
```

Or disable via extensions.

**Neovim:**
```lua
lspconfig.achronyme.setup {
  handlers = {
    ['textDocument/definition'] = function() end,
    ['textDocument/references'] = function() end
  }
}
```

## Navigation Tips

1. **Use hover after jumping** - Understand code at the definition
2. **Use Go Back frequently** - Ctrl+- / Alt+Left Arrow to return
3. **Look for patterns** - References show how functions are used
4. **Check for unused code** - If no references found, might be unused
5. **Explore the codebase** - Navigate to understand structure

## Future Enhancements

Planned navigation improvements:

- Cross-file navigation for modules
- Rename symbol (refactor)
- Find symbol by name
- Call hierarchy (who calls this?)
- Class/type hierarchy
- Import/export tracking
- Smart go to implementation

## Troubleshooting Navigation

### "No definition found"

- Symbol might be built-in (try hover instead)
- Variable might not be in scope
- Try opening the file containing the definition manually

### "No references found"

- Variable might be unused
- Try searching manually with `Ctrl+Shift+F`
- Symbol might be defined elsewhere

### Navigation jumps to wrong place

- This might be a parsing issue
- Check file for syntax errors
- Try reformatting the file

---

**Next**: [Diagnostics](diagnostics.md)
