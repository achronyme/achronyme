---
title: "Diagnostics"
description: "Error reporting in Achronyme LSP"
section: "lsp-features"
order: 6
---

# Diagnostics

Diagnostics provide real-time error reporting, showing syntax errors and other issues as you type.

## Overview

The LSP server analyzes your code and reports:
- **Parse errors** - Syntax mistakes that prevent compilation
- **Error location** - Exact line and column of the problem
- **Error message** - Clear description of what's wrong
- **Visual indicators** - Red squiggles in the editor

## When Diagnostics Run

Diagnostics are computed automatically when:

1. **File is opened** - Initial parse when you open a `.soc` file
2. **Text changes** - After each edit or keystroke
3. **File is saved** - When you save the file

There's no manual action needed; diagnostics appear automatically.

## Understanding Diagnostic Messages

### Parse Error Example

```javascript
let x = ;
         ↑ Red squiggle here

Diagnostic message:
"Parse error: Expected expression, found ';'"
Location: line 1, column 9
```

### Common Parse Errors

#### Missing Expression

```javascript
let x =  // Incomplete
```

**Error:** "Expected expression"

**Fix:** Add a value after `=`

```javascript
let x = 5  // Fixed
```

#### Mismatched Brackets

```javascript
let arr = [1, 2, 3
           ↑ Not closed
```

**Error:** "Unexpected end of file"

**Fix:** Close the bracket

```javascript
let arr = [1, 2, 3]  // Fixed
```

#### Invalid Function Syntax

```javascript
let f = x -> x^2  // Wrong operator
          ↑
```

**Error:** "Expected '(', 'mut', 'let', or expression"

**Fix:** Use `=>` not `->`

```javascript
let f = x => x^2  // Fixed
```

#### Missing Parentheses

```javascript
let result = map x => x * 2, data
                ↑ Needs parentheses
```

**Error:** "Expected '(' after function name"

**Fix:** Add parentheses around the lambda

```javascript
let result = map(x => x * 2, data)  // Fixed
```

## Visual Indicators

### In the Editor

Red squiggles show under problematic code:

```javascript
let x = ;
        ~~  // Red squiggle under ;
```

Hovering over the squiggle shows the error message.

### Error List

Most editors show an error panel:

**VS Code:**
- Panel → Problems (Ctrl+Shift+M)

Shows:
- File name
- Line and column
- Error message
- Quick fixes (when available)

### Status Bar

The editor status bar typically shows:
- Total number of errors/warnings
- Current file's error count

## Fixing Errors

### Quick Fix Workflow

1. **See the error** - Red squiggle appears
2. **Read the message** - Hover or check error list
3. **Understand the issue** - Review the code
4. **Make the fix** - Edit the code
5. **Verify** - Error disappears when fixed

### Example Fix Process

```javascript
// Step 1: You type this
let data = [1, 2, 3
// Red squiggle: Expected ']'

// Step 2: You add the missing bracket
let data = [1, 2, 3]
// Error disappears - diagnostic updates

// Step 3: Code is now valid
```

## Diagnostic Severity

Current diagnostics use these severity levels:

| Level | Color | Meaning |
|-------|-------|---------|
| Error | Red | Prevents execution |
| Warning | Yellow | May cause issues (future) |
| Info | Blue | Informational (future) |

## Diagnostic Codes

Each diagnostic has a code for categorization:

| Code | Description |
|------|-------------|
| `parse-error` | Syntax error in parsing |

(More codes will be added as LSP server features expand)

## Diagnostics in Different Editors

### VS Code

Diagnostics appear:
- **Inline:** Red squiggles in the editor
- **Panel:** Problems panel (Ctrl+Shift+M)
- **Status bar:** Error count shown

**Configuration:**

```json
"[achronyme]": {
  "editor.codeActionsOnSave": {
    "source.fixAll": true
  },
  "problems.decorations.enabled": true
}
```

**Navigation:**
- `F8` - Jump to next error
- `Shift+F8` - Jump to previous error

### Neovim

Diagnostics shown with signs and highlighting:

```lua
lspconfig.achronyme.setup {
  on_attach = function(client, bufnr)
    -- Configure diagnostic display
    vim.diagnostic.config({
      virtual_text = true,
      signs = true,
      underline = true,
      update_in_insert = false,
    })
  end
}
```

**Navigation:**
```vim
]d  " Jump to next diagnostic
[d  " Jump to previous diagnostic
```

### Emacs

Diagnostics shown via `lsp-mode`:

```elisp
(use-package lsp-ui
  :ensure t
  :commands lsp-ui-mode
  :custom
  (lsp-ui-sideline-enable t)
  (lsp-ui-doc-enable t))
```

**Navigation:**
```
M-x lsp-next-error
M-x lsp-previous-error
```

## Advanced Diagnostic Features

### Disabling Diagnostics

If you prefer not to see diagnostics:

**VS Code:**
```json
"[achronyme]": {
  "editor.diagnostics.disable": true
}
```

Or disable via editor settings.

**Neovim:**
```lua
lspconfig.achronyme.setup {
  handlers = {
    ['textDocument/publishDiagnostics'] = function() end
  }
}
```

### Filtering Diagnostics

Show only certain types:

**VS Code:**
```json
"problems.filters": [
  {
    "resource": "{**/*.soc}",
    "severity": "error"
  }
]
```

### Ignoring Specific Lines

When you want to suppress a diagnostic for one line:

Comment approach (not yet implemented):

```javascript
// achronyme-ignore-next-line
let x =  // This error would be ignored
```

Currently not supported; may be added in future.

## Diagnostic Workflow

### Step 1: Initial Parse

When you open a file, the server parses it immediately:

```javascript
// Save as test.soc
let x = 5
// No errors - status shows "OK"
```

### Step 2: Edit and See Errors

As you edit, diagnostics update:

```javascript
// You add an error
let y =
        ↑ Error appears immediately

// Fix it
let y = 10
// Error disappears
```

### Step 3: Check Error List

View all errors in one place:

**VS Code:**
- `Ctrl+Shift+M` shows Problems panel
- Lists all current errors in the file

### Step 4: Navigate and Fix

Use keyboard shortcuts to jump between errors:

```
F8  → Jump to next error
Edit the code → Error fixes
Repeat for all errors
```

## Performance and Diagnostics

The diagnostic system:
- **Parses on every change** - Ensures up-to-date errors
- **Works with large files** - Efficient parsing
- **Scales to multiple files** - Independent per-file diagnostics
- **Fast updates** - <100ms even for large files

Performance tips:
- Close very large files if diagnostics slow down
- Check for infinite syntax issues
- Keep files organized and manageable

## Common Diagnostic Scenarios

### Scenario 1: Syntax Error in Expression

```javascript
// You see red squiggle:
let result = sqrt(-5)
// Not an error - sqrt(negative) returns NaN

// But this is an error:
let result = sqrt
// Error: Expected '(' after identifier
```

### Scenario 2: Unclosed Bracket

```javascript
// Red squiggle at end of file:
let data = [1, 2, 3
let more = [4, 5]
// Error: Expected ']'
```

### Scenario 3: Type in Wrong Position

```javascript
// Not valid Achronyme syntax:
let x: = 5
      ↑
// Error: Expected type, found '='
```

## Understanding Error Messages

### Parse Error Messages

The parser provides detailed error messages:

**Format:**
```
Parse error: [Expected thing], [Found thing]
At: line:column
```

**Example:**
```
Parse error: Expected expression, found ';'
At: 1:9
```

This tells you:
- The parser expected an expression (a value)
- It found a `;` instead
- The error is at line 1, column 9

## Clearing Diagnostics

Diagnostics clear automatically when:
- You fix the error
- The file parses successfully
- You close the file

There's no need to manually clear diagnostics.

## Tips for Avoiding Errors

### 1. Use the Correct Arrow Syntax

```javascript
✓ let f = x => x * 2     // Correct
✗ let f = x -> x * 2     // Wrong - causes parse error
```

### 2. Close All Brackets

```javascript
✓ let arr = [1, 2, 3]    // All brackets closed
✗ let arr = [1, 2, 3     // Missing closing ]
```

### 3. Use Correct Keywords

```javascript
✓ let x = 5              // Correct
✗ let x =                // Incomplete

✓ if(x > 0) {}           // Correct
✗ if x > 0 {}            // Missing parentheses
```

### 4. Proper Function Call Syntax

```javascript
✓ map(x => x * 2, data)          // Correct
✗ map x => x * 2, data           // Wrong syntax
✗ map(x => x * 2) data           // Missing comma
```

## Future Diagnostic Features

Planned improvements:
- Semantic errors (type checking)
- Warnings for potentially problematic code
- Suggested fixes (quick fixes)
- Custom diagnostic rules
- Lint rule configuration
- Multiple diagnostic passes

---

**Next**: [Document Symbols](symbols.md)
